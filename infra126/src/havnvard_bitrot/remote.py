from __future__ import annotations

import base64
import json
import shlex
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .transport import PubkeySshTransport, SshTransport
from .types import FileCandidate, HashOutcome, HashResult


@dataclass(frozen=True)
class RemoteJob:
    ssh_target: str
    work_dir: str
    pid: int
    result_file: str
    heartbeat_file: str
    token: str


class RemoteBatchHasher:
    def __init__(
        self,
        helper_script: Path,
        timeout_seconds: int = 1200,
        poll_seconds: int = 15,
        heartbeat_stale_seconds: int = 300,
        transport: SshTransport | None = None,
    ):
        self.helper_script = helper_script
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self.heartbeat_stale_seconds = heartbeat_stale_seconds
        self.transport = transport

    def _transport_for(self, ssh_target: str) -> SshTransport:
        """An injected transport always wins; otherwise fall back to plain
        key-based ssh against the target the caller supplied."""
        if self.transport is not None:
            return self.transport
        return PubkeySshTransport(ssh_target)

    def launch(self, ssh_target: str, scratch_root: str, run_id: str, candidates: list[FileCandidate]) -> RemoteJob:
        if scratch_root.rstrip("/") == "/tmp" or scratch_root.startswith("/tmp/"):
            raise ValueError("INFRA-126 forbids NAS /tmp; configure persistent diskaudit scratch space")
        transport = self._transport_for(ssh_target)
        safe_run = "".join(ch for ch in run_id if ch.isalnum() or ch in "-_")
        token = f"infra126-{safe_run}-{time.time_ns()}"
        work_dir = f"{scratch_root.rstrip('/')}/{token}"
        with tempfile.TemporaryDirectory(prefix="infra126-manifest-") as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.tsv"
            with manifest_path.open("w", encoding="utf-8") as manifest:
                for item in candidates:
                    encoded = base64.b64encode(item.path.encode("utf-8", errors="surrogateescape")).decode("ascii")
                    manifest.write(f"{item.item_id}\t{encoded}\n")
            remote_manifest = f"{work_dir}/manifest.tsv"
            remote_helper = f"{work_dir}/remote_hash_batch.sh"
            result_file = f"{work_dir}/results.jsonl"
            heartbeat_file = f"{work_dir}/heartbeat"
            pid_file = f"{work_dir}/pid"
            token_file = f"{work_dir}/token"
            transport.ssh(
                f"umask 077; mkdir -p {shlex.quote(work_dir)}; printf %s {shlex.quote(token)} > {shlex.quote(token_file)}",
                timeout=60,
            )
            transport.scp_put(str(manifest_path), remote_manifest, timeout=120)
            transport.scp_put(str(self.helper_script), remote_helper, timeout=120)
            # `chmod 700 X && nohup ... &` backgrounds the ENTIRE `&&` chain as
            # one async job (shell grammar: `&` terminates the whole preceding
            # and-or list) — over an ssh pipe (no pty) the local client then
            # blocks until that whole job, including the long-running hash
            # script, actually exits. Confirmed live: launch() hung to its
            # 60s timeout against agent-1 even with `< /dev/null` added.
            # Wrapping the backgrounding step in its own `( ... )` subshell
            # makes that subshell's only job "start the background process
            # and record its pid", which completes immediately, so `cat` runs
            # right after instead of the ssh channel waiting on job exit.
            #
            # QNAP QTS's busybox ash (the nas-1 shell) has no `nohup`
            # binary at all ("nohup: command not found") but does ship
            # `setsid`; detect availability on the remote side rather than
            # assuming either exists, falling back to a bare backgrounded
            # command (already stdin/stdout/stderr-redirected and subshell
            # -detached) if neither is present.
            runner_pick = (
                "if command -v nohup >/dev/null 2>&1; then RUNNER=nohup; "
                "elif command -v setsid >/dev/null 2>&1; then RUNNER=setsid; "
                "else RUNNER=; fi"
            )
            command = (
                f"chmod 700 {shlex.quote(remote_helper)} && "
                f"( {runner_pick}; $RUNNER sh {shlex.quote(remote_helper)} {shlex.quote(remote_manifest)} {shlex.quote(result_file)} "
                f"{shlex.quote(heartbeat_file)} {shlex.quote(token_file)} "
                f"< /dev/null > {shlex.quote(work_dir + '/stdout.log')} 2>&1 & "
                f"echo $! > {shlex.quote(pid_file)} ) ; cat {shlex.quote(pid_file)}"
            )
            started = transport.ssh(command, timeout=60, background=True)
            pid = int(started.stdout.strip().splitlines()[-1])
            return RemoteJob(transport.target, work_dir, pid, result_file, heartbeat_file, token)

    def _probe(self, job: RemoteJob) -> tuple[str, int | None]:
        command = (
            f"if test -f {shlex.quote(job.work_dir + '/done')}; then echo done; "
            f"elif kill -0 {job.pid} 2>/dev/null; then echo running; else echo exited; fi; "
            f"cat {shlex.quote(job.heartbeat_file)} 2>/dev/null || true"
        )
        result = self._transport_for(job.ssh_target).ssh(command, timeout=30, check=False)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        state = lines[0] if lines else "exited"
        heartbeat = int(lines[1]) if len(lines) > 1 and lines[1].isdigit() else None
        return state, heartbeat

    def terminate(self, job: RemoteJob) -> None:
        # Kill only the exact PID after validating the per-run token. Never use pkill -f.
        command = (
            f"test \"$(cat {shlex.quote(job.work_dir + '/token')} 2>/dev/null)\" = {shlex.quote(job.token)} "
            f"&& kill {job.pid} 2>/dev/null || true"
        )
        self._transport_for(job.ssh_target).ssh(command, timeout=30, check=False)

    def wait(self, job: RemoteJob, heartbeat_callback: Callable[[int | None], None] | None = None) -> list[HashResult]:
        deadline = time.monotonic() + self.timeout_seconds
        last_remote_heartbeat: int | None = None
        last_heartbeat_change = time.monotonic()
        while time.monotonic() < deadline:
            state, remote_heartbeat = self._probe(job)
            if heartbeat_callback:
                heartbeat_callback(remote_heartbeat)
            if remote_heartbeat is not None and remote_heartbeat != last_remote_heartbeat:
                last_remote_heartbeat = remote_heartbeat
                last_heartbeat_change = time.monotonic()
            if state == "done":
                break
            if state != "running":
                raise RuntimeError(f"remote hash process exited without completion marker: pid={job.pid}, work_dir={job.work_dir}")
            if time.monotonic() - last_heartbeat_change > self.heartbeat_stale_seconds:
                self.terminate(job)
                raise TimeoutError(
                    f"remote heartbeat stale for >{self.heartbeat_stale_seconds}s; exact PID {job.pid} was terminated"
                )
            time.sleep(self.poll_seconds)
        else:
            self.terminate(job)
            raise TimeoutError(f"remote batch exceeded {self.timeout_seconds}s and exact PID {job.pid} was terminated")

        with tempfile.TemporaryDirectory(prefix="infra126-results-") as temp_dir:
            local_path = Path(temp_dir) / "results.jsonl"
            self._transport_for(job.ssh_target).scp_get(job.result_file, str(local_path), timeout=120)
            parsed: list[HashResult] = []
            with local_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    row = json.loads(line)
                    parsed.append(HashResult(
                        item_id=int(row["item_id"]),
                        path=row.get("path", ""),
                        status=HashOutcome(row["status"]),
                        sha256=row.get("sha256"),
                        size=row.get("size"),
                        mtime_ns=row.get("mtime_ns"),
                        inode=row.get("inode"),
                        duration_ms=int(row.get("duration_ms", 0)),
                        error=row.get("error"),
                    ))
            return parsed

    def recovery_command(self, job: RemoteJob) -> str:
        prefix = self._transport_for(job.ssh_target).recovery_prefix()
        return (
            f"{prefix} "
            f"'test \"$(cat {shlex.quote(job.work_dir + '/token')} 2>/dev/null)\" = {shlex.quote(job.token)} "
            f"&& kill {job.pid}'"
        )
