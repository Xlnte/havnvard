#!/usr/bin/env python3
"""diskaudit (HavnVard) — cross-host content-hash verification.

Answers the two questions the owner actually cares about, with cryptographic
evidence, non-destructively:
    1. "Is my the server/agent-1 data genuinely intact on the NAS?"
    2. "What can I safely delete from the server?"

Why this tool exists (not just more dedup.py): dedup.py drives `rdfind`, which
needs local filesystem access. The NAS is not mounted on the server (mount-based
crawling plateaued at ~20 files/sec and was abandoned for the SSH-based
native crawl in load_nas_inventory.py/nas_native_crawl.sh) -- so NAS files
have never been deduped or cross-checked: `dedup_checked_at` is NULL for
every nas-1 and agent-1 row.

Key insight (verified against production data 2026-07-25): cross-host
duplicates MUST share a byte size, so we never need to hash everything.
Filtering diskaudit.files to sizes appearing on >=2 hosts, size >= 1MB,
collapses the hashing work from ~8.6M candidate rows down to a small,
tractable candidate set per host (see `candidates` subcommand). That
candidate set is what every other subcommand here operates on.

Never deletes/moves/renames/overwrites any scanned file -- read-only against
every scanned filesystem. This tool only ever writes: its own DB rows
(diskaudit.files.content_sha256/hashed_at/hash_source, diskaudit.integrity_checks,
diskaudit.crosshost_verify_runs, diskaudit.files.duplicate_group_id via the
existing dedup.py convention), its own log output, its own markdown reports
under reports/, and its own scratch files (which it cleans up).

Subcommands:
    candidates                          -- report the candidate set per host (no hashing)
    hash --host <h> [--limit N] [--min-size BYTES]
                                         -- hash candidate files on one host
    match                                -- join hashes across hosts, populate
                                             duplicate_group_id + integrity_checks
    report                               -- render dedup + integrity + cleanup-candidate
                                             markdown reports to reports/

Usage:
    crosshost_verify.py candidates
    crosshost_verify.py hash --host agent-1
    crosshost_verify.py hash --host nas-1 --limit 500
    crosshost_verify.py hash --host server-1
    crosshost_verify.py match
    crosshost_verify.py report
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heartbeat import HeartbeatThrottle, write_heartbeat  # noqa: E402

# ---- DSN resolution -- same SoT + fallback order as scan.py/dedup.py ------
from havnvard_site import get_dsn  # noqa: E402,F401  (3.0.0: one shared lookup; see havnvard_site.py)


# ---- candidate-set constants -----------------------------------------------
# Digest sanity: hash_batch.sh output's hash field must be exactly 64
# lowercase hex chars (see the parse loop in hash_remote_host for the
# 2026-08-30 corruption incident this guards against).
_HEX64_RE = re.compile(r"[0-9a-f]{64}")

MIN_SIZE_DEFAULT = 1_048_576  # 1 MiB -- verified 2026-07-25 against production
HASH_READ_BUFFER = 4 * 1024 * 1024  # matches dedup.py's content_hash() convention
import havnvard_site as _site  # noqa: E402

# 3.0.0: hosts are roles from the site file -- the local machine, the NAS, and remote agent machines.
KNOWN_HOSTS = tuple(dict.fromkeys((_site.local_host(), _site.nas_host()) + _site.agent_hosts()))

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

# The size-candidate CTE is the one piece of SQL every subcommand shares --
# defined once here so "what counts as a candidate" can never drift between
# `candidates`, `hash`, and `match`.
_CANDIDATE_SIZES_CTE = """
    sizes_multi_host AS (
        SELECT size_bytes
        FROM diskaudit.files
        WHERE still_exists AND file_type = 'regular' AND size_bytes >= %(min_size)s
        GROUP BY size_bytes
        HAVING count(DISTINCT host) >= 2
    )
"""


def candidate_size_summary(conn, min_size: int = MIN_SIZE_DEFAULT):
    """Per-host file count + total bytes for the cross-host candidate set.

    Returns list[(host, n_files, total_bytes)] ordered by host. This is the
    "candidates" subcommand's core query -- no hashing, pure read.
    """
    sql = f"""
        WITH {_CANDIDATE_SIZES_CTE}
        SELECT f.host, count(*) AS n_files, coalesce(sum(f.size_bytes), 0) AS total_bytes
        FROM diskaudit.files f
        JOIN sizes_multi_host s ON s.size_bytes = f.size_bytes
        WHERE f.still_exists AND f.file_type = 'regular' AND f.size_bytes >= %(min_size)s
        GROUP BY f.host
        ORDER BY f.host
    """
    with conn.cursor() as cur:
        cur.execute(sql, {"min_size": min_size})
        return cur.fetchall()


def candidate_files(
    conn,
    host: str,
    min_size: int = MIN_SIZE_DEFAULT,
    limit: int | None = None,
    only_unhashed: bool = False,
):
    """Candidate files on ONE host: regular, still-existing, size >= min_size,
    and size shared with >=2 hosts overall. Returns list[(path, size_bytes, mtime,
    content_sha256, hashed_at)].

    `only_unhashed=True` restricts to rows never successfully hashed --
    used by the remote (NAS/agent-1) hash paths, which can't cheaply re-stat
    the file locally to check for drift the way the local server-1 path can.

    Includes `inode`/`nlink` so callers can dedupe hashing work across
    hardlinked paths: on the SAME host, the same inode is guaranteed to be
    the same bytes on disk (that's what a hardlink means), so there is no
    need to re-read-and-hash it once per path. server-1 alone has ~2M
    hardlinked file rows (nlink>1) -- hashing each path independently would
    mean redundant disk reads for data that's already known-identical by
    construction. `hash_local_host()` groups by inode and hashes one
    representative path per group, then fans the resulting sha256 out to
    every sibling path sharing that inode.
    """
    unhashed_filter = "AND f.content_sha256 IS NULL" if only_unhashed else ""
    limit_clause = "LIMIT %(limit)s" if limit else ""
    sql = f"""
        WITH {_CANDIDATE_SIZES_CTE}
        SELECT f.path, f.size_bytes, f.mtime, f.content_sha256, f.hashed_at, f.inode, f.nlink
        FROM diskaudit.files f
        JOIN sizes_multi_host s ON s.size_bytes = f.size_bytes
        WHERE f.host = %(host)s AND f.still_exists AND f.file_type = 'regular'
          AND f.size_bytes >= %(min_size)s
          {unhashed_filter}
        ORDER BY f.size_bytes DESC
        {limit_clause}
    """
    params = {"host": host, "min_size": min_size}
    if limit:
        params["limit"] = limit
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def cmd_candidates(conn, args):
    rows = candidate_size_summary(conn, min_size=args.min_size)
    print(f"[crosshost_verify] candidate set (size shared across >=2 hosts, >= {args.min_size:,} bytes):")
    grand_files = 0
    grand_bytes = 0
    for host, n_files, total_bytes in rows:
        total_bytes = int(total_bytes)
        grand_files += n_files
        grand_bytes += total_bytes
        print(f"  {host:<12} {n_files:>10,} files / {total_bytes / 1e9:>10,.1f} GB")
    print(f"  {'TOTAL':<12} {grand_files:>10,} files / {grand_bytes / 1e9:>10,.1f} GB")
    return rows


# ---------------------------------------------------------------------------
# hash: server-1 (local)
# ---------------------------------------------------------------------------

def _renice_self():
    """Best-effort: drop CPU + IO priority so hashing never competes with
    anything time-sensitive on the server. Never fatal if unsupported."""
    try:
        os.nice(19)
    except OSError:
        pass
    try:
        subprocess.run(
            ["ionice", "-c3", "-p", str(os.getpid())],
            check=False, capture_output=True,
        )
    except FileNotFoundError:
        pass


def local_content_hash(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(HASH_READ_BUFFER):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _write_integrity_unreadable(conn, host: str, path: str, size_bytes, notes: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO diskaudit.integrity_checks
                (spark_path, spark_host, size_bytes, verdict, notes)
            VALUES (%s, %s, %s, 'unreadable_source', %s)
            """,
            (path, host, size_bytes, notes),
        )
    conn.commit()


def hash_local_host(conn, host: str, run_id: int, min_size: int, limit: int | None, batch_commit: int = 200,
                    reuse_stored: bool = True):
    """Hash candidate files on THIS host (server-1) directly via os.stat +
    hashlib. Resumable: a row that already has content_sha256 is skipped
    UNLESS a fresh os.stat() shows its size/mtime has drifted from what's
    recorded in diskaudit.files, in which case it is re-hashed (self-heal
    against a stale hash surviving a file being overwritten in place).

    Small transactions (commit every `batch_commit` rows) so this tolerates
    the concurrent full-disk metadata rescan (diskaudit-scan.service) running
    UPDATEs against diskaudit.files at the same time -- no long-held locks.

    Inode-aware: candidate rows are grouped by `inode` first (same host, same
    inode == guaranteed-identical bytes -- that IS what a hardlink means).
    Only ONE representative path per inode is actually read off disk and
    hashed; the resulting sha256 is then fanned out to every sibling path
    sharing that inode with a single UPDATE ... WHERE inode = . This avoids
    ~2M redundant disk reads on server-1 alone (nlink>1 rows there), and
    keeps `files_hashed` reporting the real number of disk reads performed
    (fan-out rows are counted separately, not double-counted as "hashed").
    """
    _renice_self()
    rows = candidate_files(conn, host, min_size=min_size, limit=limit, only_unhashed=False)
    # End the implicit transaction this read-only SELECT opened before doing
    # any (potentially slow, per-file) hashing work below -- same reasoning
    # as the identical fix in hash_remote_host(): a large group with no
    # early fan-out could otherwise go a while before the first flush()
    # commit, holding a snapshot open the whole time. Cheap insurance.
    conn.commit()
    considered = len(rows)
    hashed = 0            # representative paths actually read + hashed
    fanned_out = 0        # sibling paths that inherited a hash via inode match, no disk read
    skipped_unchanged = 0
    errored = 0
    hb = HeartbeatThrottle(min_interval_s=15.0)

    # Group by inode (when present -- inode is only meaningful/unique within
    # one host's filesystem, which is exactly the scope here since rows are
    # already filtered to a single `host`). Rows with inode IS NULL (e.g. a
    # stat that failed to capture it) are each treated as their own group of one.
    groups: dict[object, list[tuple]] = {}
    singleton_key = object()
    for row in rows:
        inode = row[5]
        key = inode if inode is not None else (singleton_key, row[0])
        groups.setdefault(key, []).append(row)

    pending: list[tuple] = []  # (path, digest) for representative-path UPDATEs

    def flush(cur):
        nonlocal pending
        if not pending:
            return
        now = datetime.now(timezone.utc)
        for path, digest in pending:
            cur.execute(
                """
                UPDATE diskaudit.files
                SET content_sha256 = %s, hashed_at = %s, hash_source = 'local'
                WHERE host = %s AND path = %s
                """,
                (digest, now, host, path),
            )
        conn.commit()
        pending = []

    idx = 0
    with conn.cursor() as cur:
        for key, group_rows in groups.items():
            # Pick a representative: prefer one that's already hashed and
            # still matches its recorded size/mtime (cheapest possible path
            # -- confirms via os.stat, no re-read), else the first row.
            representative = group_rows[0]
            digest = None
            # INFRA-538: reuse is an inventory shortcut only (size+mtime unchanged is NOT
            # proof of unchanged bytes). --no-reuse rehashes every representative. No
            # deletion is ever based on these digests: integrity_checks rows built from
            # them carry basis='stored'; deletions require verify_tree (basis='fresh') or
            # the delete script's own in-run rehash.
            for candidate_row in (group_rows if reuse_stored else ()):
                path, size_bytes, mtime, existing_sha, _hashed_at, _inode, _nlink = candidate_row
                if existing_sha:
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    if st.st_size == size_bytes and mtime is not None and abs(st.st_mtime - mtime.timestamp()) < 1.0:
                        digest = existing_sha
                        representative = candidate_row
                        break

            if digest is None:
                path, size_bytes, mtime, existing_sha, _hashed_at, _inode, _nlink = representative
                digest = local_content_hash(path)
                if digest is None:
                    errored += len(group_rows)
                    for r in group_rows:
                        _write_integrity_unreadable(conn, host, r[0], r[1], "unreadable at hash time (permission/vanished)")
                    idx += len(group_rows)
                    continue
                hashed += 1
                pending.append((path, digest))
            else:
                skipped_unchanged += 1

            # Fan out to sibling paths sharing this inode that don't already
            # carry this exact hash -- one UPDATE per remaining sibling, no
            # disk read (the whole point of the inode grouping).
            for sib_path, sib_size, sib_mtime, sib_existing_sha, *_ in group_rows:
                if sib_path == representative[0]:
                    continue
                if sib_existing_sha == digest:
                    skipped_unchanged += 1
                    continue
                cur.execute(
                    """
                    UPDATE diskaudit.files
                    SET content_sha256 = %s, hashed_at = now(), hash_source = 'local'
                    WHERE host = %s AND path = %s
                    """,
                    (digest, host, sib_path),
                )
                fanned_out += 1

            idx += len(group_rows)

            if len(pending) >= batch_commit or fanned_out % batch_commit == 0:
                flush(cur)
                if hb.due():
                    write_heartbeat(
                        conn, "crosshost_verify", run_id, host, "hashing",
                        note=(
                            f"{idx}/{considered} considered ({len(groups)} inode-groups), "
                            f"{hashed} hashed, {fanned_out} fanned-out-via-inode, "
                            f"{skipped_unchanged} skipped-unchanged, {errored} errored"
                        ),
                    )
                    print(
                        f"[crosshost_verify] hash host={host}: {idx}/{considered} considered "
                        f"({len(groups)} inode-groups), {hashed} hashed, {fanned_out} fanned-out, "
                        f"{skipped_unchanged} skipped-unchanged, {errored} errored",
                        file=sys.stderr,
                    )
        flush(cur)
        conn.commit()

    return {
        "files_considered": considered,
        "files_hashed": hashed + fanned_out,
        "files_skipped_unchanged": skipped_unchanged,
        "files_errored": errored,
    }


# ---------------------------------------------------------------------------
# hash: nas-1 / agent-1 (remote, via hash_batch.sh)
# ---------------------------------------------------------------------------

HASH_BATCH_SCRIPT_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hash_batch.sh")
HASH_BATCH_SCRIPT_NAME = "hash_batch.sh"

_SSH_OPTS_COMMON = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]

# NAS scratch dir -- MUST be real disk, never /tmp (64MB tmpfs shared with
# live NAS system processes; a prior test writing ~40MB there caused real
# ENOSPC failures -- see nas_native_crawl.sh / load_nas_inventory.py).
NAS_SCRATCH_DIR = _site.nas("scratch_dir") or _site.nas_share_base() + "/.diskaudit_scratch"
NAS_HOST_TOKEN_FILE = _site.nas("backup_token_file") or "/etc/havnvard/nas_backup.env"
# Intentionally DIFFERENT credential than load_nas_inventory.py's crawl path
# (which uses /etc/havnvard/nas_admin.env, an admin-group account). This
# tool uses the nas_backup account instead -- verified 2026-07-25 to have
# read access across shares (e.g. homes/ and backup shares), which is all
# this tool needs (read-only content hashing, no crawl/find of whole shares).
# Both accounts reject publickey auth; both use sshpass + a password file.

# agent-1: normal Ubuntu box, passwordless sudo, real disk /tmp (no NAS-style
# tmpfs constraint) -- reachable via plain key-based ssh, no sshpass needed.
# (3.0.0: one class per remote agent machine, settings from [agents.NAME] in the site file.)


def _nas_backup_creds() -> tuple[str, str, str]:
    """(user, host, password) from the NAS backup token file ([nas] backup_token_file), root-owned.
    Never inline these. Mirrors load_nas_inventory.py's `sudo cat` pattern,
    just against the backup token file instead of the admin one."""
    result = subprocess.run(
        ["sudo", "cat", NAS_HOST_TOKEN_FILE], capture_output=True, text=True, check=True,
    )
    user = host = pw = None
    for line in result.stdout.splitlines():
        if line.startswith("NAS_USER="):
            user = line.split("=", 1)[1].strip()
        elif line.startswith("NAS_HOST="):
            host = line.split("=", 1)[1].strip()
        elif line.startswith("NAS_PASS="):
            pw = line.split("=", 1)[1].strip()
    if not user or not host or not pw:
        raise RuntimeError(f"could not parse NAS_USER/NAS_HOST/NAS_PASS from {NAS_HOST_TOKEN_FILE}")
    return user, host, pw


# Bound every remote ssh/scp call so a hang on the OTHER end (a stuck NAS
# process, a wedged sshd session, a network stall -- none of which this
# script controls) fails within minutes instead of blocking a multi-hour
# dedup/search run forever with zero visibility. Found live 2026-08-30: an
# unrelated 2-day-hung restic process against the same NAS silently stalled
# a nas_trigkey_dedup.py run with no error, no progress, and no way to tell
# it apart from "just slow" until someone went looking. See Plane INFRA-240.
_REMOTE_CALL_TIMEOUT_SEC = 600


def _run_with_timeout(argv: list[str], timeout_sec: int | None = None, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run wrapper that converts a timeout into a normal failed
    CompletedProcess (returncode=124, the standard shell timeout convention)
    instead of raising -- callers here already check `r.returncode != 0` and
    raise a RuntimeError with `r.stderr`, so this keeps that error path
    working unchanged rather than requiring every call site to also catch
    subprocess.TimeoutExpired.

    `timeout_sec` (INFRA-520, nas_trigkey_dedup.py byte-scaled batch timeout)
    overrides the 600 s default for ONE call; None keeps the default, so every
    existing caller behaves exactly as before."""
    limit = timeout_sec if timeout_sec is not None else _REMOTE_CALL_TIMEOUT_SEC
    try:
        return subprocess.run(argv, timeout=limit, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            argv, returncode=124, stdout="",
            stderr=f"timed out after {limit}s (see Plane INFRA-240)",
        )


def _with_sshpass(argv: list[str], password: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
    """Never pass the password as a bare -p arg (leaks via `ps aux`) --
    write it to a private 0600 tempfile and hand sshpass the file."""
    fd, tmppath = tempfile.mkstemp(prefix="crosshost-naspw-")
    try:
        os.chmod(tmppath, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password)
        full = ["sshpass", "-f", tmppath] + argv
        return _run_with_timeout(full, timeout_sec, capture_output=True, text=True)
    finally:
        os.remove(tmppath)


class _RemoteHashTarget:
    """Abstracts the remote-hashing transport differences between nas-1
    (sshpass + BusyBox, must avoid /tmp) and agent-1 (key-based ssh, normal
    /tmp is fine) behind one interface, so the batch-orchestration logic in
    `hash_remote_host()` is written once."""

    def ssh(self, remote_cmd: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def scp_put(self, local_path: str, remote_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def scp_get(self, remote_path: str, local_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        raise NotImplementedError

    scratch_dir: str


class _NasTarget(_RemoteHashTarget):
    scratch_dir = NAS_SCRATCH_DIR

    def __init__(self):
        self.user, self.host, self.password = _nas_backup_creds()

    def ssh(self, remote_cmd: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["ssh"] + _SSH_OPTS_COMMON + ["-o", "PubkeyAuthentication=no", f"{self.user}@{self.host}", remote_cmd]
        return _with_sshpass(argv, self.password, timeout_sec)

    def scp_put(self, local_path: str, remote_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["scp"] + _SSH_OPTS_COMMON + ["-o", "PubkeyAuthentication=no", local_path, f"{self.user}@{self.host}:{remote_path}"]
        return _with_sshpass(argv, self.password, timeout_sec)

    def scp_get(self, remote_path: str, local_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["scp"] + _SSH_OPTS_COMMON + ["-o", "PubkeyAuthentication=no", f"{self.user}@{self.host}:{remote_path}", local_path]
        return _with_sshpass(argv, self.password, timeout_sec)


class _AgentTarget(_RemoteHashTarget):
    def __init__(self, name: str):
        a = _site.agent(name)
        self.scratch_dir = a["scratch_dir"]
        self._key, self._dest = a["ssh_key"], f"{a['ssh_user']}@{a['ssh_host']}"

    def ssh(self, remote_cmd: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["ssh", "-i", self._key] + _SSH_OPTS_COMMON + [self._dest, remote_cmd]
        return _run_with_timeout(argv, timeout_sec, capture_output=True, text=True)

    def scp_put(self, local_path: str, remote_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["scp", "-i", self._key] + _SSH_OPTS_COMMON + [local_path, f"{self._dest}:{remote_path}"]
        return _run_with_timeout(argv, timeout_sec, capture_output=True, text=True)

    def scp_get(self, remote_path: str, local_path: str, timeout_sec: int | None = None) -> subprocess.CompletedProcess:
        argv = ["scp", "-i", self._key] + _SSH_OPTS_COMMON + [f"{self._dest}:{remote_path}", local_path]
        return _run_with_timeout(argv, timeout_sec, capture_output=True, text=True)


def _target_for_host(host: str) -> _RemoteHashTarget:
    if host == _site.nas_host():
        return _NasTarget()
    if host in _site.agent_hosts():
        return _AgentTarget(host)
    raise ValueError(f"no remote hash target for host={host!r}")


def _chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def hash_remote_host(
    conn, host: str, run_id: int, min_size: int, limit: int | None,
    batch_size: int = 500,
):
    """Hash candidate files on a remote host (nas-1 or agent-1) by
    scp'ing hash_batch.sh + a path-list to the host's own scratch dir,
    running it over ssh, scp'ing the two result files back, loading them
    into Postgres, and cleaning up scratch files on BOTH sides -- same
    lifecycle shape as load_nas_inventory.py's crawl/fetch/cleanup dance.

    Only ever hashes files never successfully hashed before (content_sha256
    IS NULL) -- resumable in the sense that a killed/restarted run picks up
    exactly where it left off, without re-doing already-hashed files. Unlike
    the local server-1 path, this does not cheaply re-verify mtime/size
    drift on every already-hashed row (that would mean a live remote stat
    per file, defeating the point of batching) -- if a remote file changes
    content in place, `dedup_checked_at`/`hashed_at` staleness is a known,
    accepted gap here, not silently claimed as covered.
    """
    target = _target_for_host(host)

    rows = candidate_files(conn, host, min_size=min_size, limit=limit, only_unhashed=True)
    # candidate_files() is a plain SELECT, but under autocommit=False it still
    # opens a transaction that Postgres holds open (and a snapshot it pins)
    # until the next commit/rollback on this connection. Everything below is
    # potentially long-running remote SSH/SCP work (minutes to hours per
    # host) -- left uncommitted, that would sit "idle in transaction" for
    # the whole run, violating the "small transactions, no long-held locks"
    # requirement this tool must honor alongside the concurrently-running
    # diskaudit-scan.service. End it here (read-only, so commit/rollback are
    # equivalent) before doing any remote work. Found live via
    # pg_stat_activity during this build (2026-07-25): a running hash job's
    # connection sat idle-in-transaction for 20+ minutes on this exact query.
    conn.commit()
    considered = len(rows)
    hashed = 0
    errored = 0
    hb = HeartbeatThrottle(min_interval_s=15.0)

    if considered == 0:
        return {"files_considered": 0, "files_hashed": 0, "files_skipped_unchanged": 0, "files_errored": 0}

    r = target.ssh(f"mkdir -p {target.scratch_dir} && chmod 700 {target.scratch_dir}")
    if r.returncode != 0:
        raise RuntimeError(f"could not create scratch dir on {host}: {r.stderr}")

    # Script only needs to land once per run, not once per batch.
    remote_script = f"{target.scratch_dir}/{HASH_BATCH_SCRIPT_NAME}"
    r = target.scp_put(HASH_BATCH_SCRIPT_LOCAL, remote_script)
    if r.returncode != 0:
        raise RuntimeError(f"could not scp hash_batch.sh to {host}: {r.stderr}")

    size_by_path = {path: size_bytes for path, size_bytes, *_ in rows}
    paths = [path for path, *_ in rows]

    for batch_idx, batch_paths in enumerate(_chunked(paths, batch_size)):
        batch_name = f"hashbatch_{run_id}_{batch_idx}"
        local_list = tempfile.NamedTemporaryFile(mode="w", suffix=".paths", delete=False, encoding="utf-8")
        try:
            for p in batch_paths:
                local_list.write(p + "\n")
            local_list.close()

            remote_list = f"{target.scratch_dir}/{batch_name}.paths"
            remote_hashes = f"{target.scratch_dir}/{batch_name}.hashes"
            remote_errs = f"{target.scratch_dir}/{batch_name}.hasherrs"

            r = target.scp_put(local_list.name, remote_list)
            if r.returncode != 0:
                raise RuntimeError(f"could not scp path list to {host}: {r.stderr}")

            r = target.ssh(f"sh {remote_script} {target.scratch_dir} {batch_name}")
            if r.returncode != 0:
                raise RuntimeError(f"hash_batch.sh failed on {host} (rc={r.returncode}): {r.stderr}")

            local_hashes = tempfile.NamedTemporaryFile(mode="w", suffix=".hashes", delete=False)
            local_hashes.close()
            local_errs = tempfile.NamedTemporaryFile(mode="w", suffix=".hasherrs", delete=False)
            local_errs.close()
            # INFRA-242: a failed/timed-out fetch of the batch results MUST
            # be loud. Ignoring these returncodes let a rc=124 transport
            # timeout leave the local files empty, record the batch as
            # "0 hashed", and then the scratch cleanup removed the remote result
            # files -- silently discarding completed work as if nothing had matched
            # (docs/STANDARDS/SILENT_FAILURE_STANDARD.md).
            r = target.scp_get(remote_hashes, local_hashes.name)
            if r.returncode != 0:
                raise RuntimeError(
                    f"could not scp hash results back from {host} "
                    f"(rc={r.returncode}): {r.stderr}"
                )
            r = target.scp_get(remote_errs, local_errs.name)
            if r.returncode != 0:
                raise RuntimeError(
                    f"could not scp hash-error list back from {host} "
                    f"(rc={r.returncode}): {r.stderr}"
                )

            now = datetime.now(timezone.utc)
            hash_source = "nas-native" if host == _site.nas_host() else "trigkey-agent"   # DB label for any remote agent (CHECK constraint)
            batch_hashed = 0
            with conn.cursor() as cur, open(local_hashes.name, encoding="utf-8", errors="surrogateescape") as hf:
                for line in hf:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    parts = line.split("|", 1)
                    if len(parts) != 2:
                        continue
                    digest, path = parts
                    # Must be EXACTLY 64 lowercase hex -- a bare length check
                    # let hash_batch.sh's (now-fixed, 2026-08-30) echo-mangled
                    # digests for backslash-named files through: 24 garbage
                    # digests landed in diskaudit.files via this very UPDATE
                    # (hash_source='trigkey-agent') before the guard existed.
                    if not _HEX64_RE.fullmatch(digest):
                        continue
                    cur.execute(
                        """
                        UPDATE diskaudit.files
                        SET content_sha256 = %s, hashed_at = %s, hash_source = %s
                        WHERE host = %s AND path = %s
                        """,
                        (digest, now, hash_source, host, path),
                    )
                    batch_hashed += 1
            conn.commit()
            hashed += batch_hashed

            batch_errored = 0
            with open(local_errs.name, encoding="utf-8", errors="surrogateescape") as ef:
                for line in ef:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    parts = line.split("|", 1)
                    if len(parts) != 2:
                        continue
                    reason, path = parts
                    batch_errored += 1
                    _write_integrity_unreadable(
                        conn, host, path, size_by_path.get(path), f"remote hash {reason.lower()}",
                    )
            errored += batch_errored

            # Clean up THIS batch's scratch files on both sides now, rather
            # than waiting for the whole run to finish -- keeps NAS scratch
            # usage bounded across a long multi-batch run.
            target.ssh(f"rm -f {remote_list} {remote_hashes} {remote_errs}")
        finally:
            for p in (local_list.name, getattr(locals().get("local_hashes"), "name", None), getattr(locals().get("local_errs"), "name", None)):
                if p and os.path.exists(p):
                    os.remove(p)

        if hb.due():
            done = min((batch_idx + 1) * batch_size, considered)
            write_heartbeat(
                conn, "crosshost_verify", run_id, host, "hashing",
                note=f"{done}/{considered} considered, {hashed} hashed, {errored} errored",
            )
            print(
                f"[crosshost_verify] hash host={host}: batch {batch_idx + 1} done "
                f"({done}/{considered} considered, {hashed} hashed so far, {errored} errored)",
                file=sys.stderr,
            )

    # Final cleanup: remove the (reused) script from the remote scratch dir.
    target.ssh(f"rm -f {remote_script}")

    return {
        "files_considered": considered,
        "files_hashed": hashed,
        "files_skipped_unchanged": 0,
        "files_errored": errored,
    }


def cmd_hash(conn, args):
    if args.host not in KNOWN_HOSTS:
        sys.exit(f"unknown host {args.host!r}; must be one of {KNOWN_HOSTS}")

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO diskaudit.crosshost_verify_runs (subcommand, host) VALUES ('hash', %s) RETURNING run_id",
            (args.host,),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    write_heartbeat(conn, "crosshost_verify", run_id, args.host, "starting")

    print(f"[crosshost_verify] hash run_id={run_id} host={args.host} min_size={args.min_size} limit={args.limit}", file=sys.stderr)

    try:
        if args.host == _site.local_host():
            stats = hash_local_host(conn, args.host, run_id, args.min_size, args.limit,
                                    reuse_stored=not args.no_reuse)
        else:
            stats = hash_remote_host(conn, args.host, run_id, args.min_size, args.limit)

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.crosshost_verify_runs SET
                    finished_at = now(), status = 'completed',
                    files_considered = %(files_considered)s,
                    files_hashed = %(files_hashed)s,
                    files_skipped_unchanged = %(files_skipped_unchanged)s,
                    files_errored = %(files_errored)s
                WHERE run_id = %(run_id)s
                """,
                {**stats, "run_id": run_id},
            )
        conn.commit()
        print(f"[crosshost_verify] hash run_id={run_id} status=completed stats={stats}", file=sys.stderr)
    except Exception as e:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE diskaudit.crosshost_verify_runs SET finished_at=now(), status='failed', notes=%s WHERE run_id=%s",
                (str(e)[:2000], run_id),
            )
        conn.commit()
        write_heartbeat(conn, "crosshost_verify", run_id, args.host, "failed", note=str(e)[:500])
        raise


# ---------------------------------------------------------------------------
# match
# ---------------------------------------------------------------------------

_MATCH_GROUP_SQL = """
    UPDATE diskaudit.files SET
        duplicate_group_id = content_sha256,
        dedup_tool = 'crosshost-sha256',
        dedup_method = 'sha256',
        dedup_checked_at = now()
    WHERE content_sha256 IN (
        SELECT content_sha256 FROM diskaudit.files
        WHERE content_sha256 IS NOT NULL
        GROUP BY content_sha256
        HAVING count(DISTINCT host) >= 2
    )
"""

# 1) Exact content match: every spark/agent-1 file with a hashed NAS
#    counterpart sharing the SAME content_sha256 -- cryptographic proof of
#    bit-identity at time of test.
_MATCH_INTEGRITY_MATCH_SQL = """
    INSERT INTO diskaudit.integrity_checks
        (spark_path, spark_host, nas_path, size_bytes, sha_source, sha_dest, verdict, notes, basis)
    SELECT src.path, src.host, nas.path, src.size_bytes, src.content_sha256, nas.content_sha256,
           'match',
           'content-hash match: proves bit-identity AT TIME OF TEST only, not against later corruption',
           'stored'  -- INFRA-538: digests read back from diskaudit.files; never a deletion basis
    FROM diskaudit.files src
    JOIN LATERAL (
        SELECT n.path, n.content_sha256
        FROM diskaudit.files n
        WHERE n.host = %(nas_host)s AND n.still_exists AND n.content_sha256 = src.content_sha256
        ORDER BY n.path
        LIMIT 1
    ) nas ON true
    WHERE src.host = ANY(%(source_hosts)s) AND src.still_exists AND src.content_sha256 IS NOT NULL
"""

# 2) No NAS file anywhere shares this file's content hash -- not (yet) known
#    to be safely on the NAS.
_MATCH_INTEGRITY_MISSING_SQL = """
    INSERT INTO diskaudit.integrity_checks
        (spark_path, spark_host, size_bytes, sha_source, verdict, notes, basis)
    SELECT src.path, src.host, src.size_bytes, src.content_sha256,
           'missing_dest',
           'no NAS file found with matching content-hash (checked against currently-hashed NAS candidate set only)',
           'stored'
    FROM diskaudit.files src
    WHERE src.host = ANY(%(source_hosts)s) AND src.still_exists AND src.content_sha256 IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM diskaudit.files n
          WHERE n.host = %(nas_host)s AND n.still_exists AND n.content_sha256 = src.content_sha256
      )
"""

# 3) Best-effort "suspicious near miss": same basename + same size on the
#    NAS, but a DIFFERENT content hash, and no exact match exists elsewhere.
#    Honest caveat: this could be genuine corruption/staleness, OR simply a
#    coincidentally same-named/same-sized unrelated file -- surfaced for
#    manual review, never asserted as proven corruption.
_MATCH_INTEGRITY_MISMATCH_SQL = """
    INSERT INTO diskaudit.integrity_checks
        (spark_path, spark_host, nas_path, size_bytes, sha_source, sha_dest, verdict, notes, basis)
    SELECT src.path, src.host, nas.path, src.size_bytes, src.content_sha256, nas.content_sha256,
           'mismatch',
           'same basename+size on NAS but different content-hash -- may be genuine corruption/staleness OR an unrelated file that happens to share name+size; investigate manually, not asserted as proven',
           'stored'
    FROM diskaudit.files src
    JOIN diskaudit.files nas
        ON nas.host = %(nas_host)s AND nas.still_exists
       AND nas.size_bytes = src.size_bytes
       AND regexp_replace(nas.path, '^.*/', '') = regexp_replace(src.path, '^.*/', '')
    WHERE src.host = ANY(%(source_hosts)s) AND src.still_exists AND src.content_sha256 IS NOT NULL
      AND nas.content_sha256 IS NOT NULL AND nas.content_sha256 <> src.content_sha256
      AND NOT EXISTS (
          SELECT 1 FROM diskaudit.files n2
          WHERE n2.host = %(nas_host)s AND n2.still_exists AND n2.content_sha256 = src.content_sha256
      )
"""


def run_match(conn, run_id: int, source_hosts=None):
    source_hosts = tuple(source_hosts) if source_hosts else _site.source_hosts()
    with conn.cursor() as cur:
        cur.execute(_MATCH_GROUP_SQL)
        groups_touched = cur.rowcount

        cur.execute(_MATCH_INTEGRITY_MATCH_SQL, {"source_hosts": list(source_hosts), "nas_host": _site.nas_host()})
        n_match = cur.rowcount

        cur.execute(_MATCH_INTEGRITY_MISSING_SQL, {"source_hosts": list(source_hosts), "nas_host": _site.nas_host()})
        n_missing = cur.rowcount

        cur.execute(_MATCH_INTEGRITY_MISMATCH_SQL, {"source_hosts": list(source_hosts), "nas_host": _site.nas_host()})
        n_mismatch = cur.rowcount
    conn.commit()

    return {
        "groups_found": groups_touched,
        "files_considered": n_match + n_missing + n_mismatch,
        "files_hashed": n_match,  # reuse column: "matched" count
        "files_errored": n_mismatch,
        "files_skipped_unchanged": n_missing,
    }


def cmd_match(conn, args):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO diskaudit.crosshost_verify_runs (subcommand, host) VALUES ('match', NULL) RETURNING run_id")
        run_id = cur.fetchone()[0]
    conn.commit()
    write_heartbeat(conn, "crosshost_verify", run_id, "cross-host", "starting")

    try:
        stats = run_match(conn, run_id)
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.crosshost_verify_runs SET
                    finished_at = now(), status = 'completed',
                    files_considered = %(files_considered)s,
                    files_hashed = %(files_hashed)s,
                    files_skipped_unchanged = %(files_skipped_unchanged)s,
                    files_errored = %(files_errored)s,
                    groups_found = %(groups_found)s
                WHERE run_id = %(run_id)s
                """,
                {**stats, "run_id": run_id},
            )
        conn.commit()
        print(f"[crosshost_verify] match run_id={run_id} status=completed stats={stats}", file=sys.stderr)
    except Exception as e:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE diskaudit.crosshost_verify_runs SET finished_at=now(), status='failed', notes=%s WHERE run_id=%s",
                (str(e)[:2000], run_id),
            )
        conn.commit()
        write_heartbeat(conn, "crosshost_verify", run_id, "cross-host", "failed", note=str(e)[:500])
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="subcommand", required=True)

    p_cand = sub.add_parser("candidates", help="report the candidate set per host (no hashing)")
    p_cand.add_argument("--min-size", type=int, default=MIN_SIZE_DEFAULT)

    p_hash = sub.add_parser("hash", help="hash candidate files on one host")
    p_hash.add_argument("--host", required=True, choices=KNOWN_HOSTS)
    p_hash.add_argument("--limit", type=int, default=None)
    p_hash.add_argument("--min-size", type=int, default=MIN_SIZE_DEFAULT)
    p_hash.add_argument("--no-reuse", action="store_true",
                        help="Rehash every file even when size+mtime are unchanged (INFRA-538).")

    sub.add_parser("match", help="join hashes across hosts, populate duplicate_group_id + integrity_checks")

    p_report = sub.add_parser("report", help="render dedup + integrity + cleanup-candidate markdown reports")
    p_report.add_argument("--out-dir", default=REPORTS_DIR)

    args = ap.parse_args()
    conn = psycopg.connect(get_dsn(), autocommit=False)
    try:
        if args.subcommand == "candidates":
            cmd_candidates(conn, args)
        elif args.subcommand == "hash":
            cmd_hash(conn, args)
        elif args.subcommand == "match":
            cmd_match(conn, args)
        elif args.subcommand == "report":
            import report as report_mod  # local import: keeps `report` optional/lazy
            report_mod.generate_all(conn, out_dir=args.out_dir)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
