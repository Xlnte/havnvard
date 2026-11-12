"""`health-relay`: for a hub that cannot alert by itself. Runs on a machine that can, runs `health --json --no-alert` on the
hub over ssh, and raises/resolves the alert locally through backup/alerts.py. A failed ssh, a remote error or output
that is not the expected JSON is itself an alert: the relay never passes silently (review F4)."""
from __future__ import annotations

import json
import shlex
from pathlib import Path

from . import alerts, config
from .config import BackupError
from .render import render_task
from .util import run, systemd_arg

KEY = "havnvard-backup-health"


def remote_command(python: str, repo_dir: str) -> str:
    return f"cd {shlex.quote(repo_dir)} && {shlex.quote(python)} -m backup health --json --no-alert"


def interpret(rc: int, stdout: str, stderr: str = "") -> tuple[bool, str]:
    """(healthy, problem_text). Anything that is not a well-formed health result is a problem."""
    doc = None
    for ln in reversed(stdout.splitlines()):
        if ln.lstrip().startswith("{"):
            try:
                doc = json.loads(ln)
            except ValueError:
                pass
            break
    if not isinstance(doc, dict) or "ok" not in doc or "checks" not in doc and "error" not in doc:
        return False, f"relay: unparsable remote output (rc {rc}): {(stdout or stderr).strip()[-200:]!r}"
    if "error" in doc:
        return False, f"relay: remote health could not run: {doc['error']}"
    if rc not in (0, 1) or bool(doc["ok"]) != (rc == 0):
        return False, f"relay: remote exit code {rc} disagrees with its JSON (ok={doc['ok']})"
    bad = [c for c in doc["checks"] if not c.get("ok")]
    if bad:
        return False, "; ".join(f"{c.get('name')}: {c.get('detail')}" for c in bad)
    return True, ""


def relay(host: str, python: str, repo_dir: str, runner=run) -> int:
    """Exit 0 healthy, 1 hub reported a problem (alert raised), 2 relay itself failed (alert raised)."""
    key = f"{KEY}-{host}"
    try:
        r = runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", host, remote_command(python, repo_dir)],
                   timeout=120)
        healthy, text = interpret(r.returncode, r.stdout, r.stderr)
        failed_relay = r.returncode not in (0, 1) or text.startswith("relay:")
        if r.returncode == 255:
            healthy, text, failed_relay = False, f"relay: ssh to {host} failed: {r.stderr.strip()[-200:]}", True
    except BackupError as e:
        healthy, text, failed_relay = False, f"relay: {e}", True
    if healthy:
        alerts.resolve(key)
        print(f"health-relay {host}: healthy")
        return 0
    sent, detail = alerts.fire(key, f"HavnVard Backup ({host}): {text}")
    print(f"health-relay {host}: PROBLEM {text}")
    print(f"alert: {detail}" if sent else f"ALERT NOT SENT: {detail}")
    return config.ERROR_EXIT if (failed_relay or not sent) else config.PROBLEM_EXIT


def render_units(out_dir: Path, host: str, python: str, repo_dir: str, schedule: str = "hourly") -> list[Path]:
    cmd = f"health-relay --ssh {systemd_arg(host)} --python {systemd_arg(python)} --repo-dir {systemd_arg(repo_dir)}"
    return render_task(out_dir, "havnvard-health-relay", f"HavnVard backup health relay for {host}", cmd,
                       f"OnCalendar={schedule}\nRandomizedDelaySec=5m", success_exit="1", timeout="3m")
