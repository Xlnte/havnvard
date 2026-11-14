#!/usr/bin/env python3
"""diskaudit — within-host dedup for the NAS and remote agent machines (HavnVard 1.4.0).

Finds files with IDENTICAL CONTENT on one host. Its output feeds an operator
quarantine script that moves files, so the two failures this tool exists to
prevent are (a) a file reported as a duplicate that is not one, and (b) a
failure that reads as "no duplicates". Design + requirements (HV-REQ-01..38):
/home/user/runbooks/20261109-havnvard-nas-dedup/ (Plane INFRA-519 / INFRA-520).

How it works (all remote work is READ-ONLY sha256sum/stat; HavnVard never
deletes, moves or renames a scanned file):

  1. PLAN (SQL, scoped): candidate rows = regular files, size > 0, whose size
     occurs >= 2x on the host. Rows are grouped by (inode, size, mtime); one
     representative per group needs bytes read, its hardlink siblings get a
     cheap stat-only check. A digest is REUSED only while it is FRESH: the
     dedup_digest_bindings row recorded the size/mtime/inode it was computed
     against and the inventory row still matches (legacy digests have no
     binding and are re-hashed once).
  2. HASH in size-ascending, byte-capped batches via hash_stat_batch.sh (stat
     before AND after the read, completion trailer). Every ssh/scp return code
     is checked; every batch must account for exactly the paths it was sent.
     A failed batch is retried once; a second failure FAILS THE RUN.
  3. PUBLISH in ONE transaction: groups are recomputed from fresh bindings,
     written to an immutable per-run snapshot (dedup_group_snapshots/members),
     the shared files.duplicate_group_id labels are refreshed, and stale labels
     in scope are cleared. A failed or partial (--limit) run publishes nothing.

Usage:
    nas_trigkey_dedup.py --host NAS_HOST [--path DIR] [--exclude DIR]... [--limit N]
                         [--batch-size 500] [--batch-bytes 4294967296] [--assumed-mbps 20]
    nas_trigkey_dedup.py --export RUN_ID [--format csv|json]       # reproducible snapshot export
    nas_trigkey_dedup.py --host NAS_HOST [--path DIR] --dry-run     # plan only: read-only, no run row, no ssh
    nas_trigkey_dedup.py --host NAS_HOST [--path DIR] --publish-only  # groups from fresh digests, no ssh (G5)

Default is a LIVE run: it reads files on the host (read-only) and writes ONLY database rows (digests, groups,
labels). It never deletes, moves or renames a file, so --dry-run is opt-in, not the default.

Exit codes: 0 completed | 2 run failed | 3 database unreachable | 4 refused
(a whole-host run is already active) | 143/130 terminated by SIGTERM/SIGINT.

Run supervised, never bare background:
    systemd-run --unit=havnvard-nas-dedup --uid=havnvard --working-directory=/opt/havnvard \\
        .venv/bin/python3 nas_trigkey_dedup.py --host NAS_HOST \\
        --exclude /share/CACHEDEV1_DATA/bkup_server
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crosshost_verify import (  # noqa: E402
    get_dsn,
    _target_for_host,
    _renice_self,
)
from heartbeat import write_heartbeat  # noqa: E402
import nas_dedup_core as core  # noqa: E402
import havnvard_site as _site  # noqa: E402  (3.0.0)

KNOWN_HOSTS = (_site.nas_host(),) + _site.agent_hosts()   # 3.0.0: the NAS and remote agent machines
HASH_STAT_SCRIPT_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hash_stat_batch.sh")
HASH_STAT_SCRIPT_NAME = "hash_stat_batch.sh"
HEARTBEAT_INTERVAL_S = 15.0
FULL_RUN_STALE_MINUTES = 30
TOOL = "sha256-within-host"

EXIT_OK, EXIT_FAILED, EXIT_DB_DOWN, EXIT_REFUSED = 0, 2, 3, 4


class RunFailed(Exception):
    """The run cannot produce a trustworthy result: it ends status='failed',
    publishes nothing, and the process exits non-zero (HV-REQ-18, 22)."""


class BatchTransportError(Exception):
    """An ssh/scp step of one batch returned non-zero (including 124 timeout)."""


class Terminated(BaseException):
    """SIGTERM/SIGINT. BaseException so no `except Exception` can swallow it."""

    def __init__(self, signum: int):
        super().__init__(f"terminated by signal {signum}")
        self.signum = signum


def _log(host, run_id, stage, msg):
    print(f"[nas_trigkey_dedup] host={host} run_id={run_id} {stage}: {msg}", file=sys.stderr, flush=True)


def _hash_source(host: str) -> str:
    return "nas-native" if host == _site.nas_host() else "trigkey-agent"   # files_hash_source_check values (DB labels)


def _safe_text(s: str) -> str:
    """A string psycopg can send (lone surrogates -> \\udcXX escapes)."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _code_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "module.yaml"), encoding="utf-8") as f:
            for line in f:
                m = re.match(r"version:\s*['\"]?([0-9][0-9A-Za-z.\-]*)", line)
                if m:
                    return m.group(1)
    except OSError as e:
        print(f"[nas_trigkey_dedup] WARN: cannot read module.yaml version: {e}", file=sys.stderr)
    return "unknown"


# ---------------------------------------------------------------------------
# remote scratch hygiene: the ONLY remote cleanup this tool issues (its own scratch files)
# ---------------------------------------------------------------------------

def _remote_cleanup(target, remote_paths: list[str]) -> bool:
    """Best-effort removal of THIS TOOL'S OWN remote scratch files (never a scanned path).
    Returns False (and warns) when it fails; a leftover scratch file is harmless."""
    if not remote_paths:
        return True
    r = target.ssh("rm -f " + " ".join(remote_paths))
    if r.returncode != 0:
        print(f"[nas_trigkey_dedup] WARN: remote scratch cleanup rc={r.returncode}: {r.stderr[:200]}", file=sys.stderr)
        return False
    return True


# ---------------------------------------------------------------------------
# diagnostics for a failed batch (journal only -- nothing recovered here is written to the DB)
# ---------------------------------------------------------------------------

def _recover_partial_progress(target, remote_hashes, remote_errs):
    """hash_stat_batch.sh appends its output ONE FILE AT A TIME, so after a dead
    ssh whatever it had finished is still on the remote disk. Pull it back (fresh
    ssh/scp; the remote host may well still be reachable) to find which path was
    in flight. DIAGNOSTIC ONLY: a digest recovered this way has no verified
    completion trailer and is never written (HV-REQ-17/18).

    Returns (n_hash_lines, n_err_lines, accounted_for_paths). Never raises."""
    n_h = n_e = 0
    accounted: set[str] = set()
    try:
        with tempfile.TemporaryDirectory(prefix="nasdedup-rec-") as td:
            lh, le = os.path.join(td, "h"), os.path.join(td, "e")
            r1 = target.scp_get(remote_hashes, lh)
            r2 = target.scp_get(remote_errs, le)
            if r1.returncode != 0 or r2.returncode != 0:
                print(f"[nas_trigkey_dedup] WARN: partial-progress recovery: scp rc={r1.returncode}/{r2.returncode}",
                      file=sys.stderr)
                return 0, 0, set()
            with open(lh, encoding="utf-8", errors="surrogateescape") as f:
                for line in f.read().split("\n"):
                    if line.startswith("H|"):
                        parts = line.split("|", 7)
                        if len(parts) == 8:
                            n_h += 1
                            accounted.add(parts[7])
                    elif line.startswith("S|"):
                        parts = line.split("|", 6)
                        if len(parts) == 7:
                            n_h += 1
                            accounted.add(parts[6])
            with open(le, encoding="utf-8", errors="surrogateescape") as f:
                for line in f.read().split("\n"):
                    reason, sep, path = line.partition("|")
                    if sep and reason in core.ERROR_REASONS:
                        n_e += 1
                        accounted.add(path)
    except (OSError, UnicodeError, ValueError) as e:
        print(f"[nas_trigkey_dedup] WARN: could not recover partial progress: {e}", file=sys.stderr)
        return 0, 0, set()
    return n_h, n_e, accounted


def _verify_suspect(target, host, suspect_path, run_id, batch_idx):
    """Re-run the hash script against ONLY the suspect path to see whether it is
    really the file that hangs, vs general contention (INFRA-240). Returns a
    verdict string, never raises."""
    verify_name = f"nasdedup_{run_id}_{batch_idx}_verify"
    remote_list = f"{target.scratch_dir}/{verify_name}.paths"
    remote_script = f"{target.scratch_dir}/{HASH_STAT_SCRIPT_NAME}"
    try:
        with tempfile.TemporaryDirectory(prefix="nasdedup-ver-") as td:
            local_list = os.path.join(td, "v.paths")
            with open(local_list, "w", encoding="utf-8") as f:
                f.write("H|" + suspect_path + "\n")
            r = target.scp_put(local_list, remote_list)
            if r.returncode != 0:
                return f"UNVERIFIED (could not scp isolated path list: {r.stderr})"
            r = target.ssh(f"sh {remote_script} {target.scratch_dir} {verify_name}")
            _remote_cleanup(target, [remote_list, f"{target.scratch_dir}/{verify_name}.hashes",
                                     f"{target.scratch_dir}/{verify_name}.hasherrs"])
        if r.returncode == 124:
            return f"CONFIRMED -- hung again in isolation on {host} (timed out)"
        if r.returncode != 0:
            return f"CONFIRMED -- failed again in isolation on {host} (rc={r.returncode}): {r.stderr[:200]}"
        return (f"NOT CONFIRMED -- completed fine in isolation on {host}; cause was likely "
                f"transient/external (contention, network), not this specific file")
    except (OSError, ValueError) as e:
        return f"UNVERIFIED (verification attempt itself errored: {e})"


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_SCOPE_PRED = r"(%(scope)s::text IS NULL OR f.path = %(scope)s::text OR f.path LIKE %(scope_like)s::text ESCAPE '\')"
_EXCL_PRED = r"NOT EXISTS (SELECT 1 FROM unnest(%(exclude_likes)s::text[]) x WHERE f.path LIKE x ESCAPE '\')"
_EXCL_PRED_S = _EXCL_PRED.replace("f.path", "s.path")

_SCOPE_COUNT_SQL = f"""
SELECT count(*) AS rows_in_scope,
       count(*) FILTER (WHERE f.file_type = 'regular' AND f.size_bytes = 0) AS zero_byte
FROM diskaudit.files f
WHERE f.host = %(host)s AND f.still_exists AND {_SCOPE_PRED} AND {_EXCL_PRED}
"""

# Size prefilter is HOST-WIDE (minus --exclude subtrees): an in-scope file whose only twin is
# outside the scope is still hashed and bound, ready for the next wider run (design §2.9).
_PLAN_SQL = f"""
SELECT f.path, f.size_bytes, extract(epoch FROM f.mtime), f.inode, f.nlink, f.content_sha256,
       b.sha256, b.size_bytes, extract(epoch FROM b.mtime), b.st_ino, b.st_dev, b.bound_at
FROM diskaudit.files f
JOIN (
    SELECT s.size_bytes FROM diskaudit.files s
    WHERE s.host = %(host)s AND s.still_exists AND s.file_type = 'regular' AND s.size_bytes > 0
      AND {_EXCL_PRED_S}
    GROUP BY s.size_bytes HAVING count(*) >= 2
) sh ON sh.size_bytes = f.size_bytes
LEFT JOIN diskaudit.dedup_digest_bindings b ON b.host = f.host AND b.path = f.path
WHERE f.host = %(host)s AND f.still_exists AND f.file_type = 'regular' AND f.size_bytes > 0
  AND {_SCOPE_PRED} AND {_EXCL_PRED}
"""

_BINDING_UPSERT_SQL = """
INSERT INTO diskaudit.dedup_digest_bindings
    (host, path, sha256, size_bytes, mtime, mtime_ns, st_ino, st_dev, nlink, bound_at, dedup_run_id, inherited_from)
VALUES (%s, %s, %s, %s, to_timestamp(%s), NULL, %s, %s, %s, %s, %s, %s)
ON CONFLICT (host, path) DO UPDATE SET
    sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, mtime = EXCLUDED.mtime, mtime_ns = EXCLUDED.mtime_ns,
    st_ino = EXCLUDED.st_ino, st_dev = EXCLUDED.st_dev, nlink = EXCLUDED.nlink, bound_at = EXCLUDED.bound_at,
    dedup_run_id = EXCLUDED.dedup_run_id, inherited_from = EXCLUDED.inherited_from
"""
_FILES_DIGEST_SQL = ("UPDATE diskaudit.files SET content_sha256 = %s, hashed_at = %s, hash_source = %s "
                     "WHERE host = %s AND path = %s")
_ITEM_UPSERT_SQL = """
INSERT INTO diskaudit.dedup_run_items (dedup_run_id, host, path, outcome, reason, detail)
VALUES (%s, %s, %s, %s, %s, %s)
ON CONFLICT (dedup_run_id, host, path) DO UPDATE SET outcome = EXCLUDED.outcome,
    reason = EXCLUDED.reason, detail = EXCLUDED.detail
"""

# Run-row counts are COUNT(*) over the per-path / snapshot rows, not Python counters (HV-REQ-23).
_ITEM_COUNTS_SQL = """
    files_hashed = (SELECT count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id = %(run_id)s AND outcome = 'hashed'),
    files_inherited = (SELECT count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id = %(run_id)s AND outcome = 'inherited'),
    errors_by_reason = (SELECT coalesce(jsonb_object_agg(reason, n), '{}'::jsonb) FROM (
        SELECT reason, count(*) AS n FROM diskaudit.dedup_run_items
        WHERE dedup_run_id = %(run_id)s AND outcome = 'error' GROUP BY reason) e)
"""
_GROUP_COUNTS_SQL = """
    duplicate_groups_found = (SELECT count(*) FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id = %(run_id)s),
    duplicate_files_found = (SELECT count(*) FROM diskaudit.dedup_group_members WHERE dedup_run_id = %(run_id)s),
    grouped_identities = (SELECT count(DISTINCT (st_dev, st_ino)) FROM diskaudit.dedup_group_members WHERE dedup_run_id = %(run_id)s),
    bytes_reclaimable = (SELECT coalesce(sum(bytes_reclaimable), 0) FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id = %(run_id)s)
"""


def _mark_missing(conn, host: str, missing_paths: list[str]) -> int:
    """Mark paths the remote host affirmatively reported MISSING as still_exists=false
    (same columns scan.py sets; scan.py flips them back if the file reappears, so this
    is self-healing, not destructive). Without it every MISSING file is retried on every
    run forever (a stale inventory once produced a ~100% error rate on rerun)."""
    ok_paths = []
    for p in missing_paths:
        try:
            p.encode("utf-8")  # skip surrogate-escaped (non-UTF8) paths
            ok_paths.append(p)
        except UnicodeEncodeError:
            continue
    if not ok_paths:
        return 0
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE diskaudit.files SET still_exists=false, disappeared_at=now(), updated_at=now() "
            "WHERE host=%s AND still_exists AND path = ANY(%s)",
            (host, ok_paths),
        )
        marked = cur.rowcount
    conn.commit()
    return marked


# ---------------------------------------------------------------------------
# run row
# ---------------------------------------------------------------------------

def _start_run(conn, host: str, scope: Optional[str], excludes: list[str], is_partial: bool, code_version: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO diskaudit.dedup_runs
                (host, root_dirs, dedup_tool, dedup_method, status, current_stage, code_version,
                 exclude_paths, is_partial, last_heartbeat_at)
            VALUES (%s, %s::text[], %s, 'sha256', 'running', 'planning', %s, %s::text[], %s, now())
            RETURNING dedup_run_id
            """,
            (host, [scope] if scope else [], TOOL, code_version, excludes, is_partial),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def _finish_run(conn, run_id: int, status: str, *, failure_reason: Optional[str] = None,
                current_stage: Optional[str] = None, considered: Optional[int] = None,
                zero_byte: Optional[int] = None, reused: Optional[int] = None,
                transport_failures: int = 0, retries: int = 0, raw_stdout: Optional[str] = None):
    """Close a run that did NOT publish (failed, or completed-partial). A failed run never
    reads current_stage='done' (HV-REQ-22)."""
    if current_stage is None:
        current_stage = "failed" if status == "failed" else "published"
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE diskaudit.dedup_runs SET status = %(status)s, finished_at = now(), current_stage = %(stage)s,
                failure_reason = %(reason)s, raw_stdout = %(raw)s,
                total_files_considered = coalesce(%(considered)s, total_files_considered),
                excluded_zero_byte = coalesce(%(zero)s, excluded_zero_byte),
                files_reused = coalesce(%(reused)s, files_reused),
                transport_failures = %(tf)s, retries = %(retries)s,
                {_ITEM_COUNTS_SQL}
            WHERE dedup_run_id = %(run_id)s
            """,
            {"status": status, "stage": current_stage, "reason": (failure_reason or None) and failure_reason[:2000],
             "raw": (raw_stdout or failure_reason or "")[:8000] or None, "considered": considered, "zero": zero_byte,
             "reused": reused, "tf": transport_failures, "retries": retries, "run_id": run_id},
        )
    conn.commit()


# ---------------------------------------------------------------------------
# progress + heartbeat thread (HV-REQ-24; keeps the monitor's 10-min STALE rule quiet during a 40-min batch)
# ---------------------------------------------------------------------------

@dataclass
class Progress:
    stage: str = "planning"
    total_files: int = 0
    total_bytes: int = 0
    done_files: int = 0
    done_bytes: int = 0
    t_start: float = field(default_factory=time.monotonic)
    last_files: int = 0
    last_bytes: int = 0
    last_elapsed: float = 0.0
    batch_no: Optional[int] = None
    batch_files: int = 0
    batch_bytes: int = 0
    batch_t0: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_stage(self, stage: str):
        with self._lock:
            self.stage = stage
            self.batch_no = None

    def start_batch(self, no: int, files: int, nbytes: int):
        with self._lock:
            self.batch_no, self.batch_files, self.batch_bytes, self.batch_t0 = no, files, nbytes, time.monotonic()

    def end_batch(self):
        with self._lock:
            el = time.monotonic() - self.batch_t0
            self.done_files += self.batch_files
            self.done_bytes += self.batch_bytes
            self.last_files, self.last_bytes, self.last_elapsed = self.batch_files, self.batch_bytes, el
            self.batch_no = None

    def note(self) -> str:
        with self._lock:
            if self.stage != "remote hashing":
                return self.stage
            return core.format_progress(
                self.done_files, self.total_files, self.done_bytes, self.total_bytes,
                time.monotonic() - self.t_start, self.last_files, self.last_bytes, self.last_elapsed,
                self.batch_no, self.batch_files if self.batch_no is not None else None,
                self.batch_bytes if self.batch_no is not None else None,
                (time.monotonic() - self.batch_t0) if self.batch_no is not None else None)


class HeartbeatThread(threading.Thread):
    """Writes dedup_runs.last_heartbeat_at + a run_heartbeats row every `interval` seconds from
    its OWN connection, independent of how long a single batch's ssh takes."""

    def __init__(self, conn_factory: Callable, run_id: int, host: str, progress: Progress, interval: float):
        super().__init__(name="nasdedup-heartbeat", daemon=True)
        self._factory, self._run_id, self._host, self._progress, self._interval = conn_factory, run_id, host, progress, interval
        self._stop_evt = threading.Event()
        self.errors = 0

    def run(self):
        conn = None
        try:
            while not self._stop_evt.wait(self._interval):
                if conn is None:                      # (re)connect on every beat until it works: a DB blip or a full
                    try:                              # connection table must not silence the heartbeat for the whole run
                        conn = self._factory()
                    except (psycopg.Error, OSError) as e:
                        self.errors += 1
                        print(f"[nas_trigkey_dedup] WARN: heartbeat thread cannot connect: {e}", file=sys.stderr)
                        continue
                try:
                    write_heartbeat(conn, "dedup", self._run_id, self._host, self._progress.stage,
                                    note=self._progress.note(), only_running=True)
                except psycopg.Error as e:
                    self.errors += 1
                    print(f"[nas_trigkey_dedup] WARN: heartbeat write failed: {e}", file=sys.stderr)
                    try:
                        conn.close()
                    except psycopg.Error:
                        pass
                    conn = None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except psycopg.Error:
                    pass

    def stop(self):
        self._stop_evt.set()
        self.join(timeout=10)


# ---------------------------------------------------------------------------
# run context
# ---------------------------------------------------------------------------

@dataclass
class RunCtx:
    conn: object
    host: str
    run_id: int
    target: object = None
    remote_script: str = ""
    bindings: dict = field(default_factory=dict)       # path -> core.Binding (planned + bound this run)
    sizes: dict = field(default_factory=dict)          # sibling path -> size (for straggler work)
    batch_timeout_mbps: float = core.DEFAULT_ASSUMED_MBPS
    transport_failures: int = 0
    retries: int = 0
    batch_no: int = 0
    progress: Progress = field(default_factory=Progress)


def _note(ctx: RunCtx, stage: str, msg: str):
    ctx.progress.set_stage(stage)
    write_heartbeat(ctx.conn, "dedup", ctx.run_id, ctx.host, stage, note=msg)
    ctx.conn.commit()
    _log(ctx.host, ctx.run_id, stage, msg)


def _scope_params(host, scope, excludes):
    return {"host": host, "scope": scope, "scope_like": core.like_prefix(scope) if scope else None,
            "exclude_likes": [core.like_prefix(e) for e in excludes]}


def _load_candidates(conn, host, scope, excludes):
    """Returns (cands, bindings, rows_in_scope, zero_byte). Reads then releases the transaction
    before any remote work (small-transactions requirement)."""
    params = _scope_params(host, scope, excludes)
    with conn.cursor() as cur:
        cur.execute(_SCOPE_COUNT_SQL, params)
        rows_in_scope, zero_byte = cur.fetchone()
        cur.execute(_PLAN_SQL, params)
        cands, bindings = [], {}
        for (path, size, mtime, inode, nlink, sha, b_sha, b_size, b_mtime, b_ino, b_dev, b_at) in cur:
            cands.append(core.Cand(path, size, mtime, inode, nlink, sha))
            if b_sha is not None:
                bindings[path] = core.Binding(b_sha, b_size, b_mtime, b_ino, b_dev, b_at)
    conn.commit()
    return cands, bindings, rows_in_scope, zero_byte


# ---------------------------------------------------------------------------
# one batch: transport + completeness (HV-REQ-16, 17)
# ---------------------------------------------------------------------------

def _run_batch(ctx: RunCtx, name: str, batch: core.Batch):
    """ssh the batch, fetch both result files, prove completeness. Returns
    (BatchResult, bound_at, remote_files). Raises BatchTransportError / BatchIntegrityError."""
    t, d = ctx.target, ctx.target.scratch_dir
    remote_list, remote_hashes, remote_errs = f"{d}/{name}.paths", f"{d}/{name}.hashes", f"{d}/{name}.hasherrs"
    with tempfile.TemporaryDirectory(prefix="nasdedup-") as td:
        local_list = os.path.join(td, "b.paths")
        with open(local_list, "w", encoding="utf-8", newline="\n") as f:
            for kind, path in batch.items:
                f.write(f"{kind}|{path}\n")
        r = t.scp_put(local_list, remote_list)
        if r.returncode != 0:
            raise BatchTransportError(f"scp_put path list rc={r.returncode}: {r.stderr[:200]}")
        timeout = core.batch_timeout(batch.h_bytes, ctx.batch_timeout_mbps)
        r = t.ssh(f"sh {ctx.remote_script} {d} {name}", timeout_sec=timeout)
        bound_at = datetime.now(timezone.utc)
        if r.returncode != 0:
            raise BatchTransportError(f"hash_stat_batch.sh rc={r.returncode} (timeout {timeout}s): {r.stderr[:200]}")
        lh, le = os.path.join(td, "b.hashes"), os.path.join(td, "b.hasherrs")
        r = t.scp_get(remote_hashes, lh)
        if r.returncode != 0:
            raise BatchTransportError(f"scp_get .hashes rc={r.returncode}: {r.stderr[:200]}")
        r = t.scp_get(remote_errs, le)
        if r.returncode != 0:
            raise BatchTransportError(f"scp_get .hasherrs rc={r.returncode}: {r.stderr[:200]}")
        with open(lh, encoding="utf-8", errors="surrogateescape", newline="") as f:
            hashes_text = f.read()
        with open(le, encoding="utf-8", errors="surrogateescape", newline="") as f:
            errs_text = f.read()
    result = core.verify_batch(batch.items, hashes_text, errs_text)
    return result, bound_at, [remote_list, remote_hashes, remote_errs]


def _diagnose_failed_batch(ctx: RunCtx, name: str, batch: core.Batch, idx: int, err: Exception):
    """Journal-only: which path was in flight? Never raises, writes nothing to the DB."""
    d = ctx.target.scratch_dir
    n_h, n_e, accounted = _recover_partial_progress(ctx.target, f"{d}/{name}.hashes", f"{d}/{name}.hasherrs")
    sent_paths = [p for _k, p in batch.items]
    _log(ctx.host, ctx.run_id, "batch-failed",
         f"batch {idx} ({name}): {type(err).__name__}: {err}; recovered {n_h} result + {n_e} error lines "
         f"({len(accounted)}/{len(sent_paths)} accounted for)")
    suspect = next((p for k, p in batch.items if k == "H" and p not in accounted), None)
    if suspect:
        _log(ctx.host, ctx.run_id, "batch-failed",
             f"batch {idx}: SUSPECT FILE = {suspect!r} -- {_verify_suspect(ctx.target, ctx.host, suspect, ctx.run_id, idx)}")


def _hash_batch_with_retry(ctx: RunCtx, batch: core.Batch):
    """Retry ONCE under a new batch name (so stale remote files never alias), then fail the run."""
    idx = ctx.batch_no
    ctx.batch_no += 1
    name = f"nasdedup_{ctx.run_id}_{idx}"
    errors = []
    for attempt in (0, 1):
        try:
            result, bound_at, remote_files = _run_batch(ctx, name, batch)
            return result, bound_at, remote_files
        except (BatchTransportError, core.BatchIntegrityError) as e:
            ctx.transport_failures += 1
            errors.append(f"{type(e).__name__}: {e}")
            _diagnose_failed_batch(ctx, name, batch, idx, e)
            d = ctx.target.scratch_dir
            _remote_cleanup(ctx.target, [f"{d}/{name}.paths", f"{d}/{name}.hashes", f"{d}/{name}.hasherrs"])
            if attempt == 0:
                ctx.retries += 1
                name = f"{name}_r1"
    raise RunFailed(f"batch {idx} failed twice: first: {errors[0][:300]} | second: {errors[1][:300]}")


# ---------------------------------------------------------------------------
# apply one verified batch to the DB (one transaction, committed BEFORE remote cleanup)
# ---------------------------------------------------------------------------

def _apply_batch(ctx: RunCtx, batch: core.Batch, result: core.BatchResult, bound_at: datetime) -> list[str]:
    """Returns the stragglers: stat-only siblings that could NOT inherit (stat differs from the
    representative's binding, or the representative failed) and must be hashed themselves."""
    host, run_id, src = ctx.host, ctx.run_id, _hash_source(ctx.host)
    items: list[tuple] = []
    new_bind: dict[str, core.Binding] = {}
    stragglers: list[str] = []
    missing: list[str] = []
    with ctx.conn.cursor() as cur:
        for rec in result.hashed:
            if rec.size_bytes <= 0:
                items.append((run_id, host, rec.path, "error", "UNSTABLE", "size 0 at hash time (file changed since inventory)"))
                continue
            cur.execute(_BINDING_UPSERT_SQL, (host, rec.path, rec.sha256, rec.size_bytes, rec.mtime, rec.st_ino,
                                              rec.st_dev, rec.nlink, bound_at, run_id, None))
            cur.execute(_FILES_DIGEST_SQL, (rec.sha256, bound_at, src, host, rec.path))
            b = core.Binding(rec.sha256, rec.size_bytes, rec.mtime, rec.st_ino, rec.st_dev, bound_at)
            new_bind[rec.path] = b
            ctx.bindings[rec.path] = b
            items.append((run_id, host, rec.path, "hashed", None, None))
        for rec in result.stat:
            rep = batch.rep_of.get(rec.path)
            rb = new_bind.get(rep) or ctx.bindings.get(rep)
            if (rb is not None and (rec.st_ino, rec.st_dev, rec.size_bytes, rec.mtime)
                    == (rb.st_ino, rb.st_dev, rb.size_bytes, int(rb.mtime))):
                # inherit: SAME (dev, ino) proven on the NAS; bound_at is the REPRESENTATIVE's, never now() (HV-REQ-07)
                cur.execute(_BINDING_UPSERT_SQL, (host, rec.path, rb.sha256, rec.size_bytes, rec.mtime, rec.st_ino,
                                                  rec.st_dev, rec.nlink, rb.bound_at, run_id, rep))
                cur.execute(_FILES_DIGEST_SQL, (rb.sha256, rb.bound_at, src, host, rec.path))
                ctx.bindings[rec.path] = core.Binding(rb.sha256, rec.size_bytes, rec.mtime, rec.st_ino, rec.st_dev, rb.bound_at)
                items.append((run_id, host, rec.path, "inherited", None, f"from {_safe_text(rep)}"))
            else:
                stragglers.append(rec.path)
        for reason, path in result.errors:
            items.append((run_id, host, path, "error", reason, None))
            if reason == "MISSING":
                missing.append(path)
        if items:
            cur.executemany(_ITEM_UPSERT_SQL, items)
    ctx.conn.commit()                                   # <- durable BEFORE the caller removes the remote files (HV-REQ-16)
    if missing:
        marked = _mark_missing(ctx.conn, host, missing)
        _log(host, run_id, "missing", f"{len(missing)} paths reported MISSING; marked {marked} rows still_exists=false (stale inventory)")
    return stragglers


def _process_batches(ctx: RunCtx, batches: list[core.Batch]) -> list[str]:
    stragglers: list[str] = []
    for batch in batches:
        ctx.progress.start_batch(ctx.batch_no, batch.h_count, batch.h_bytes)
        result, bound_at, remote_files = _hash_batch_with_retry(ctx, batch)
        stragglers += _apply_batch(ctx, batch, result, bound_at)
        _remote_cleanup(ctx.target, remote_files)          # only AFTER the commit above
        ctx.progress.end_batch()
    return stragglers


# ---------------------------------------------------------------------------
# publish: ONE transaction (HV-REQ-10, 11, 12, 15, 26, 27, 28)
# ---------------------------------------------------------------------------

_PUBLISH_STEPS = [
    ("""CREATE TEMP TABLE _nd_fresh (path text PRIMARY KEY, size_bytes bigint, mtime timestamptz, sha text,
          st_dev bigint, st_ino bigint, nlink integer, bound_at timestamptz,
          in_recycle_bin boolean, in_backup_tree boolean) ON COMMIT DROP""", None),
    # freshness is evaluated HERE, inside the publish transaction (HV-REQ-26)
    (f"""INSERT INTO _nd_fresh
        SELECT f.path, f.size_bytes, f.mtime, f.content_sha256, b.st_dev, b.st_ino, b.nlink, b.bound_at,
               (f.path ~ %(recycle)s), (f.path LIKE %(backup_like)s ESCAPE '\\')
        FROM diskaudit.files f
        JOIN diskaudit.dedup_digest_bindings b ON b.host = f.host AND b.path = f.path
        WHERE f.host = %(host)s AND f.still_exists AND f.file_type = 'regular' AND f.size_bytes > 0
          AND {_SCOPE_PRED} AND {_EXCL_PRED} AND f.path !~ %(unsafe_re)s
          AND b.sha256 = f.content_sha256 AND b.size_bytes = f.size_bytes AND b.mtime = f.mtime AND b.st_ino = f.inode
          AND b.bound_at >= f.mtime + make_interval(secs => %(racy_s)s)""",
     "all"),
    ("""CREATE TEMP TABLE _nd_grp (group_id text PRIMARY KEY, size_bytes bigint, identity_count integer,
          member_count integer, n_sizes integer) ON COMMIT DROP""", None),
    # a group needs >= 2 distinct (dev, ino) identities with an identical digest (HV-REQ-01, 02)
    ("""INSERT INTO _nd_grp
        SELECT sha, max(size_bytes), count(DISTINCT (st_dev, st_ino)), count(*), count(DISTINCT size_bytes)
        FROM _nd_fresh GROUP BY sha HAVING count(DISTINCT (st_dev, st_ino)) >= 2""", None),
]


def _publish(ctx: RunCtx, scope, excludes, code_version, considered, zero_byte, reused, note: str = "") -> dict:
    conn, host, run_id = ctx.conn, ctx.host, ctx.run_id
    params = {**_scope_params(host, scope, excludes), "recycle": core.RECYCLE_REGEX, "backup_like": core.BACKUP_TREE_LIKE,
              "unsafe_re": core.UNSAFE_PATH_REGEX, "run_id": run_id, "code_version": code_version,
              "racy_s": core.RACY_MARGIN_S}
    conn.commit()
    with conn.transaction():
        with conn.cursor() as cur:
            # serialises only publishes (HV-REQ-25). Taken BEFORE lock_timeout is set: a scoped publish queued behind a
            # long whole-host publish must wait for it, not die after 30 s; the timeout then bounds table/row lock waits only.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"nasdedup:publish:{host}",))
            cur.execute("SET LOCAL lock_timeout = '30s'")
            for sql, uses_params in _PUBLISH_STEPS:
                if uses_params:
                    cur.execute(sql, params)
                else:
                    cur.execute(sql)
            cur.execute("SELECT group_id, size_bytes FROM _nd_grp WHERE n_sizes > 1 ORDER BY group_id LIMIT 5")
            conflict = cur.fetchall()
            if conflict:                                    # impossible for intact data: a corrupt binding is a safety fault
                raise RunFailed("SHA_SIZE_CONFLICT:" + ",".join(g for g, _s in conflict))
            cur.execute("""CREATE TEMP TABLE _nd_members (group_id text, path text PRIMARY KEY, st_dev bigint, st_ino bigint,
                  nlink integer, size_bytes bigint, mtime timestamptz, sha text, bound_at timestamptz,
                  in_recycle_bin boolean, in_backup_tree boolean, links_outside boolean NOT NULL DEFAULT false,
                  role text) ON COMMIT DROP""")
            cur.execute("""INSERT INTO _nd_members (group_id, path, st_dev, st_ino, nlink, size_bytes, mtime, sha, bound_at,
                    in_recycle_bin, in_backup_tree)
                SELECT g.group_id, f.path, f.st_dev, f.st_ino, f.nlink, f.size_bytes, f.mtime, f.sha, f.bound_at,
                       f.in_recycle_bin, f.in_backup_tree
                FROM _nd_fresh f JOIN _nd_grp g ON g.group_id = f.sha""")
            # links_outside_inventory: the identity has more links than the inventory lists (set-based, one scan)
            cur.execute("""UPDATE _nd_members m SET links_outside = (m.nlink > c.n)
                FROM (SELECT x.inode, count(*) AS n FROM diskaudit.files x
                      WHERE x.host = %(host)s AND x.still_exists
                        AND x.inode IN (SELECT DISTINCT st_ino FROM _nd_members) GROUP BY x.inode) c
                WHERE c.inode = m.st_ino""", params)
            # ONE keeper per group (HV-REQ-28): not recycle -> not backup tree -> earliest mtime -> shortest path -> bytewise
            cur.execute("""CREATE TEMP TABLE _nd_keeper ON COMMIT DROP AS
                SELECT DISTINCT ON (group_id) group_id, path, st_dev, st_ino
                FROM _nd_members ORDER BY group_id, in_recycle_bin, in_backup_tree, mtime, length(path), path COLLATE "C" """)
            cur.execute("""UPDATE _nd_members m SET role = CASE
                    WHEN m.st_dev = k.st_dev AND m.st_ino = k.st_ino THEN CASE WHEN m.path = k.path THEN 'keeper' ELSE 'keeper_link' END
                    WHEN r.rn = 1 THEN 'victim' ELSE 'victim_link' END
                FROM _nd_keeper k,
                     (SELECT path, row_number() OVER (PARTITION BY group_id, st_dev, st_ino
                                                      ORDER BY length(path), path COLLATE "C") AS rn FROM _nd_members) r
                WHERE k.group_id = m.group_id AND r.path = m.path""")
            cur.execute("""INSERT INTO diskaudit.dedup_group_snapshots
                    (dedup_run_id, host, group_id, size_bytes, identity_count, member_count, keeper_path, bytes_reclaimable, code_version)
                SELECT %(run_id)s, %(host)s, g.group_id, g.size_bytes, g.identity_count, g.member_count, k.path,
                       coalesce(v.reclaim, 0), %(code_version)s
                FROM _nd_grp g
                JOIN _nd_keeper k ON k.group_id = g.group_id
                LEFT JOIN (   -- victims only, fully-listed hardlink identities only
                    SELECT group_id, sum(size_bytes) AS reclaim FROM (
                        SELECT DISTINCT group_id, st_dev, st_ino, size_bytes, links_outside
                        FROM _nd_members WHERE role IN ('victim', 'victim_link')) i
                    WHERE NOT links_outside GROUP BY group_id) v ON v.group_id = g.group_id""", params)
            cur.execute("""INSERT INTO diskaudit.dedup_group_members
                    (dedup_run_id, group_id, host, path, st_dev, st_ino, nlink, size_bytes, mtime, sha256, bound_at,
                     role, in_recycle_bin, in_backup_tree, links_outside_inventory)
                SELECT %(run_id)s, group_id, %(host)s, path, st_dev, st_ino, nlink, size_bytes, mtime, sha, bound_at,
                       role, in_recycle_bin, in_backup_tree, links_outside
                FROM _nd_members""", params)
            # shared columns, in scope only. Rows labelled by ANOTHER tool (crosshost-sha256, rdfind) are never relabelled.
            cur.execute("""UPDATE diskaudit.files f SET duplicate_group_id = m.group_id, dedup_tool = %(tool)s,
                    dedup_method = 'sha256', dedup_checked_at = now()
                FROM _nd_members m
                WHERE f.host = %(host)s AND f.path = m.path AND (f.dedup_tool IS NULL OR f.dedup_tool = %(tool)s)
                  AND (f.duplicate_group_id IS DISTINCT FROM m.group_id OR f.dedup_tool IS DISTINCT FROM %(tool)s)""",
                        {**params, "tool": TOOL})
            cur.execute(f"""UPDATE diskaudit.files f SET duplicate_group_id = NULL, dedup_tool = NULL, dedup_method = NULL,
                    dedup_checked_at = now()
                WHERE f.host = %(host)s AND f.dedup_tool = %(tool)s AND f.duplicate_group_id IS NOT NULL
                  AND {_SCOPE_PRED} AND {_EXCL_PRED}
                  AND NOT EXISTS (SELECT 1 FROM _nd_members m WHERE m.path = f.path)""", {**params, "tool": TOOL})
            cleared = cur.rowcount
            cur.execute(f"""UPDATE diskaudit.dedup_runs SET status = 'completed', finished_at = now(), published_at = now(),
                    current_stage = 'published', failure_reason = NULL,
                    total_files_considered = %(considered)s, excluded_zero_byte = %(zero)s, files_reused = %(reused)s,
                    transport_failures = %(tf)s, retries = %(retries)s,
                    raw_stdout = %(raw)s,
                    {_GROUP_COUNTS_SQL}, {_ITEM_COUNTS_SQL}
                WHERE dedup_run_id = %(run_id)s""",
                        {**params, "considered": considered, "zero": zero_byte, "reused": reused, "tf": ctx.transport_failures,
                         "retries": ctx.retries, "raw": f"{note}published; stale labels cleared in scope: {cleared}"})
            cur.execute("SELECT duplicate_groups_found, duplicate_files_found, bytes_reclaimable "
                        "FROM diskaudit.dedup_runs WHERE dedup_run_id = %s", (run_id,))
            groups, files, reclaim = cur.fetchone()
    return {"groups": groups, "files": files, "bytes_reclaimable": reclaim, "labels_cleared": cleared}


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

def _setup_remote(ctx: RunCtx):
    if ctx.target is None:                       # resolved only when there is remote work
        ctx.target = _make_target(ctx.host)
    t = ctx.target
    _renice_self()
    r = t.ssh(f"mkdir -p {t.scratch_dir} && chmod 700 {t.scratch_dir}")
    if r.returncode != 0:
        raise RunFailed(f"could not create scratch dir on {ctx.host}: rc={r.returncode} {r.stderr[:200]}")
    ctx.remote_script = f"{t.scratch_dir}/{HASH_STAT_SCRIPT_NAME}"
    r = t.scp_put(HASH_STAT_SCRIPT_LOCAL, ctx.remote_script)
    if r.returncode != 0:
        raise RunFailed(f"could not scp {HASH_STAT_SCRIPT_NAME} to {ctx.host}: rc={r.returncode} {r.stderr[:200]}")


def run_dedup(ctx: RunCtx, scope, excludes, limit, batch_size, batch_bytes, code_version, publish_only=False) -> dict:
    conn, host, run_id = ctx.conn, ctx.host, ctx.run_id
    _note(ctx, "planning", f"loading candidates (scope={scope or 'whole host'}, exclude={excludes or 'none'})")
    cands, bindings, rows_in_scope, zero_byte = _load_candidates(conn, host, scope, excludes)
    if rows_in_scope == 0:                                   # HV-REQ-13: a typo'd scope must not read as "no duplicates"
        raise RunFailed(f"scope not in inventory: {scope or host}")
    ctx.bindings = dict(bindings)

    safe, unsafe_items = [], []
    for c in cands:
        reason = core.classify_path(c.path)
        if reason:
            unsafe_items.append((run_id, host, _safe_text(c.path), "error", reason, None))
        else:
            safe.append(c)
    if unsafe_items:
        with conn.cursor() as cur:
            cur.executemany(_ITEM_UPSERT_SQL, unsafe_items)
        conn.commit()

    plan = core.plan_hash_work(safe, ctx.bindings)
    to_hash = plan.to_hash[:limit] if limit else plan.to_hash          # --limit: first N representatives, ascending size
    for w in plan.to_hash + plan.inherit_only:
        for s in w.siblings:
            ctx.sizes[s] = w.size_bytes
    considered = len(cands)
    is_partial = bool(limit)
    ctx.progress.total_files = len(to_hash)
    ctx.progress.total_bytes = sum(w.size_bytes for w in to_hash)
    _note(ctx, "remote hashing",
          f"{len(to_hash)} representatives to hash ({ctx.progress.total_bytes / 1e9:.1f} GB), "
          f"{sum(len(w.siblings) for w in plan.inherit_only)} sibling stat-checks, {plan.reused} fresh reused, "
          f"{zero_byte} zero-byte excluded, {len(unsafe_items)} unsafe paths")

    batches = core.plan_batches(to_hash, batch_size, batch_bytes) + core.plan_stat_batches(plan.inherit_only)
    if publish_only:                      # G5: no remote I/O; groups come only from digests that are already fresh
        _log(host, run_id, "publish-only", f"skipping {len(to_hash)} representatives to hash and "
             f"{sum(len(w.siblings) for w in plan.inherit_only)} sibling stat-checks (no ssh/scp)")
        batches = []
    stragglers: list[str] = []
    if batches:
        _setup_remote(ctx)
        try:
            stragglers = _process_batches(ctx, batches)
            if stragglers:
                _log(host, run_id, "stragglers", f"{len(stragglers)} siblings could not inherit; hashing them individually")
                work = sorted((core.RepWork(p, ctx.sizes.get(p, 0)) for p in stragglers), key=lambda w: (w.size_bytes, w.path))
                ctx.progress.total_files += len(work)
                _process_batches(ctx, core.plan_batches(work, batch_size, batch_bytes))
        finally:
            _remote_cleanup(ctx.target, [ctx.remote_script])
    else:
        _log(host, run_id, "remote hashing", f"nothing to hash: all {considered} candidates fresh")

    if is_partial:                                                       # HV-REQ-14: hash only, publish nothing
        _finish_run(conn, run_id, "completed", current_stage="hashed-only (partial)", considered=considered,
                    zero_byte=zero_byte, reused=plan.reused, transport_failures=ctx.transport_failures,
                    retries=ctx.retries, raw_stdout=f"partial (--limit {limit}): hashed only, nothing published")
        return {"published": False, "considered": considered}

    ctx.progress.set_stage("publishing")
    write_heartbeat(conn, "dedup", run_id, host, "publishing", note="recomputing groups from fresh digests")
    stats = _publish(ctx, scope, excludes, code_version, considered, zero_byte, plan.reused,
                     note="publish-only (no hashing); " if publish_only else "")
    stats.update(published=True, considered=considered)
    return stats


def plan_only(conn, host, scope, excludes, limit) -> dict:
    """--dry-run: what a run WOULD do, from the inventory alone. Read-only SQL; no run row, no item rows,
    no binding, no label, no ssh/scp. Freshness is judged exactly as a real run judges it."""
    cands, bindings, rows_in_scope, zero_byte = _load_candidates(conn, host, scope, list(excludes))
    safe = [c for c in cands if not core.classify_path(c.path)]
    plan = core.plan_hash_work(safe, bindings)
    to_hash = plan.to_hash[:limit] if limit else plan.to_hash
    return {"host": host, "scope": scope, "excludes": list(excludes), "rows_in_scope": rows_in_scope,
            "zero_byte_excluded": zero_byte, "candidates": len(cands), "unsafe_paths": len(cands) - len(safe),
            "to_hash": len(to_hash), "to_hash_bytes": sum(w.size_bytes for w in to_hash),
            "sibling_stat_checks": sum(len(w.siblings) for w in plan.inherit_only), "reused": plan.reused,
            "is_partial": bool(limit)}


def _prune_old_items(conn):
    """run_items older than 30 days are this tool's own bookkeeping; snapshots are never pruned by the tool."""
    with conn.cursor() as cur:
        cur.execute("""DELETE FROM diskaudit.dedup_run_items WHERE dedup_run_id IN (
                           SELECT dedup_run_id FROM diskaudit.dedup_runs WHERE started_at < now() - interval '30 days')""")
    conn.commit()


def run_once(conn, host, *, scope=None, excludes=(), limit=None, batch_size=core.DEFAULT_BATCH_SIZE,
             batch_bytes=core.DEFAULT_BATCH_BYTES, assumed_mbps=core.DEFAULT_ASSUMED_MBPS, target=None,
             conn_factory=None, heartbeat_interval=HEARTBEAT_INTERVAL_S, code_version=None, publish_only=False):
    """_start_run -> run_dedup -> publish/_finish_run. Returns (run_id, status). A RunFailed or any
    unexpected error ends the run 'failed' (status returned); Terminated is recorded then re-raised.
    publish_only (G5): skip all hashing and publish groups from the digests already fresh (no remote I/O)."""
    if publish_only and limit:
        raise ValueError("--publish-only cannot be combined with --limit (a partial run publishes nothing)")
    code_version = code_version or _code_version()
    excludes = list(excludes)
    conn_factory = conn_factory or (lambda: psycopg.connect(get_dsn(), autocommit=False))
    _prune_old_items(conn)
    run_id = _start_run(conn, host, scope, excludes, bool(limit), code_version)
    ctx = RunCtx(conn=conn, host=host, run_id=run_id, target=target, batch_timeout_mbps=assumed_mbps)
    hb = HeartbeatThread(conn_factory, run_id, host, ctx.progress, heartbeat_interval)
    hb.start()
    try:
        stats = run_dedup(ctx, scope, excludes, limit, batch_size, batch_bytes, code_version, publish_only)
        _log(host, run_id, "done", f"status=completed stats={stats}")
        return run_id, "completed"
    except Terminated:
        _rollback_quietly(conn)
        _finish_run(conn, run_id, "failed", failure_reason="terminated", transport_failures=ctx.transport_failures, retries=ctx.retries)
        raise
    except RunFailed as e:
        _rollback_quietly(conn)
        _log(host, run_id, "failed", str(e))
        _finish_run(conn, run_id, "failed", failure_reason=str(e), transport_failures=ctx.transport_failures, retries=ctx.retries)
        return run_id, "failed"
    except psycopg.OperationalError as e:
        # lock_timeout (55P03), deadlock (40P01), serialization failure and statement cancel are ALSO
        # OperationalError while the DB is perfectly reachable (e.g. the publish waiting > 30 s on a crawl's row
        # locks). Record the run 'failed' with the real error; only if THAT write fails is the DB really gone,
        # and then main() alerts via alertlib (HV-REQ-20). Review fix 20261109: before it, a lock timeout left
        # the run row 'running' forever and raised a false "database unreachable" alert.
        traceback.print_exc()
        _rollback_quietly(conn)
        try:
            _finish_run(conn, run_id, "failed", failure_reason=f"{type(e).__name__}: {e}",
                        transport_failures=ctx.transport_failures, retries=ctx.retries)
        except psycopg.Error as e2:
            print(f"[nas_trigkey_dedup] ERROR: could not record the failure ({type(e2).__name__}: {e2}); "
                  f"treating the database as unreachable", file=sys.stderr)
            raise e from None
        return run_id, "failed"
    except Exception as e:  # noqa: BLE001 -- recorded as failed with the real traceback, then surfaced via exit code 2
        traceback.print_exc()
        _rollback_quietly(conn)
        _finish_run(conn, run_id, "failed", failure_reason=f"{type(e).__name__}: {e}",
                    transport_failures=ctx.transport_failures, retries=ctx.retries)
        return run_id, "failed"
    finally:
        hb.stop()


def _rollback_quietly(conn):
    try:
        conn.rollback()
    except psycopg.Error as e:
        print(f"[nas_trigkey_dedup] WARN: rollback failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# transport selection (+ test-only fault hook for the live negative test, HV-REQ-33)
# ---------------------------------------------------------------------------

class _FaultInjectingTarget:
    """NASDEDUP_FAULT=scp_get:<idx>[,<idx>...] makes scp_get of .hashes for those BATCH INDEXES
    (every attempt, retry included) return rc 124. Touches nothing on the NAS."""

    def __init__(self, inner, batch_indexes: set[int]):
        self._inner, self._idx = inner, batch_indexes

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def scp_get(self, remote_path, local_path, timeout_sec=None):
        m = re.search(r"nasdedup_\d+_(\d+)(?:_r1)?\.hashes$", remote_path)
        if m and int(m.group(1)) in self._idx:
            return subprocess.CompletedProcess([], 124, stdout="", stderr="NASDEDUP_FAULT injected: scp_get timed out")
        return self._inner.scp_get(remote_path, local_path, timeout_sec)


def _make_target(host):
    t = _target_for_host(host)
    fault = os.environ.get("NASDEDUP_FAULT", "")
    if fault.startswith("scp_get:"):
        try:
            idx = {int(x) for x in fault.split(":", 1)[1].split(",") if x.strip()}
        except ValueError:
            raise RunFailed(f"bad NASDEDUP_FAULT value {fault!r}") from None
        print(f"[nas_trigkey_dedup] NASDEDUP_FAULT active: scp_get fails for batch indexes {sorted(idx)}", file=sys.stderr)
        return _FaultInjectingTarget(t, idx)
    return t


# ---------------------------------------------------------------------------
# whole-host mutex (HV-REQ-25)
# ---------------------------------------------------------------------------

def _acquire_full_run_lock(conn, host) -> Optional[str]:
    """None when this process may start a whole-host run; otherwise the refusal reason.
    The advisory lock is SESSION-level on `conn` and lives as long as the connection."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(hashtext(%s))", (f"nasdedup:full:{host}",))
        if not cur.fetchone()[0]:
            return "another whole-host run holds the advisory lock"
        cur.execute(
            """SELECT dedup_run_id FROM diskaudit.dedup_runs
               WHERE host = %s AND dedup_tool = %s AND status = 'running' AND root_dirs = %s::text[]
                 AND last_heartbeat_at > now() - make_interval(mins => %s)
               ORDER BY dedup_run_id LIMIT 1""",
            (host, TOOL, [], FULL_RUN_STALE_MINUTES),
        )
        row = cur.fetchone()
        if row:
            cur.execute("SELECT pg_advisory_unlock(hashtext(%s))", (f"nasdedup:full:{host}",))
            conn.commit()
            return f"whole-host run {row[0]} is still running (heartbeat < {FULL_RUN_STALE_MINUTES} min old)"
    conn.commit()
    return None


# ---------------------------------------------------------------------------
# export (HV-REQ-29)
# ---------------------------------------------------------------------------

_EXPORT_COLS = ["run_id", "group_id", "role", "path", "st_dev", "st_ino", "nlink", "size_bytes", "mtime", "sha256",
                "bound_at", "in_recycle_bin", "in_backup_tree", "links_outside_inventory"]


def export_snapshot(conn, run_id: int, fmt: str = "csv") -> str:
    """The snapshot, canonically ordered: group, keeper first, then path bytewise. Two exports of
    unchanged data differ only in run_id and timestamps."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT dedup_run_id, group_id, role, path, st_dev, st_ino, nlink, size_bytes, mtime, sha256, bound_at,
                      in_recycle_bin, in_backup_tree, links_outside_inventory
               FROM diskaudit.dedup_group_members WHERE dedup_run_id = %s
               ORDER BY group_id, (role <> 'keeper'), path COLLATE "C" """, (run_id,))
        rows = cur.fetchall()
    conn.commit()
    if fmt == "json":
        return json.dumps([dict(zip(_EXPORT_COLS, [str(v) if isinstance(v, datetime) else v for v in r])) for r in rows],
                          indent=1, ensure_ascii=False)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_EXPORT_COLS)
    for r in rows:
        w.writerow([v.isoformat() if isinstance(v, datetime) else v for v in r])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# alerting + CLI
# ---------------------------------------------------------------------------

def _alertlib_db_down(source: str, err) -> bool:
    """One deduped 'database unreachable' alert via alertlib (HV-REQ-20). Never raises."""
    try:
        import havnvard_site as _hs  # noqa: PLC0415
        alertlib = _hs.import_alertlib()
        return bool(alertlib.db_down(source, err))
    except (ImportError, OSError, AttributeError, TypeError) as e:
        print(f"[nas_trigkey_dedup] WARN: alertlib.db_down unavailable: {e}", file=sys.stderr)
        return False


def _raise_terminated(signum, _frame):
    raise Terminated(signum)


def _connect():
    return psycopg.connect(get_dsn(), autocommit=False, connect_timeout=15)


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host")
    ap.add_argument("--path", "--path-prefix", dest="path",
                    help="absolute directory: hash and group only files at/below it (directory boundary; the size "
                         "prefilter stays host-wide). --path-prefix is an alias (INFRA-520 G4)")
    ap.add_argument("--exclude", action="append", default=[], help="absolute directory left out of hashing, grouping and clearing (repeatable)")
    ap.add_argument("--limit", type=int, default=None, help="hash only the first N representatives; PARTIAL run, publishes nothing")
    ap.add_argument("--batch-size", type=int, default=core.DEFAULT_BATCH_SIZE)
    ap.add_argument("--batch-bytes", type=int, default=core.DEFAULT_BATCH_BYTES)
    ap.add_argument("--assumed-mbps", type=float, default=core.DEFAULT_ASSUMED_MBPS)
    ap.add_argument("--export", type=int, metavar="RUN_ID", help="print the snapshot of RUN_ID and exit")
    ap.add_argument("--format", choices=("csv", "json"), default="csv")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan (candidates, files/bytes to hash, fresh digests reused) and exit; "
                         "no run row, no remote I/O, no database write")
    ap.add_argument("--publish-only", action="store_true",
                    help="no hashing and no remote I/O: publish groups from the digests that are already fresh "
                         "(e.g. after a killed long run). Not combinable with --limit (INFRA-520 G5)")
    return ap


def main(argv=None) -> int:
    ap = _build_parser()
    args = ap.parse_args(argv)
    if args.publish_only and (args.limit or args.dry_run):
        print("[nas_trigkey_dedup] ERROR: --publish-only cannot be combined with --limit or --dry-run", file=sys.stderr)
        return EXIT_FAILED

    try:
        conn = _connect()
    except psycopg.OperationalError as e:
        print(f"[nas_trigkey_dedup] ERROR: database unreachable: {e}", file=sys.stderr)
        _alertlib_db_down("nas_trigkey_dedup", e)
        return EXIT_DB_DOWN
    try:
        if args.export is not None:
            sys.stdout.write(export_snapshot(conn, args.export, args.format))
            return EXIT_OK
        if args.host not in KNOWN_HOSTS:
            print(f"[nas_trigkey_dedup] ERROR: --host must be one of {KNOWN_HOSTS}", file=sys.stderr)
            return EXIT_FAILED
        try:
            scope = core.normalize_scope(args.path) if args.path else None
            ex = args.exclude or (list(_site.nas("dedup_excludes") or []) if args.host == _site.nas_host() else [])
            excludes = [core.normalize_scope(e) for e in ex]   # 3.0.0: default excludes from [nas] dedup_excludes
        except ValueError as e:
            print(f"[nas_trigkey_dedup] ERROR: {e}", file=sys.stderr)
            return EXIT_FAILED

        if args.dry_run:                                                     # read-only: no lock, no run row
            plan = plan_only(conn, args.host, scope, excludes, args.limit)
            print(json.dumps(plan, indent=1, ensure_ascii=False))
            return EXIT_OK

        if scope is None:                                                    # whole-host run (also --exclude / --limit)
            refusal = _acquire_full_run_lock(conn, args.host)
            if refusal:
                print(f"[nas_trigkey_dedup] REFUSED: {refusal}; no run row created", file=sys.stderr)
                return EXIT_REFUSED

        prev = {s: signal.signal(s, _raise_terminated) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            run_id, status = run_once(conn, args.host, scope=scope, excludes=excludes, limit=args.limit,
                                      batch_size=args.batch_size, batch_bytes=args.batch_bytes,
                                      assumed_mbps=args.assumed_mbps, conn_factory=_connect,
                                      publish_only=args.publish_only)
        except Terminated as t:
            print("[nas_trigkey_dedup] terminated; run marked failed", file=sys.stderr)
            return 128 + t.signum
        finally:
            for s, h in prev.items():
                signal.signal(s, h)
        print(f"[nas_trigkey_dedup] host={args.host} run_id={run_id} status={status}")
        return EXIT_OK if status == "completed" else EXIT_FAILED
    except psycopg.OperationalError as e:
        print(f"[nas_trigkey_dedup] ERROR: database error: {e}", file=sys.stderr)
        _alertlib_db_down("nas_trigkey_dedup", e)
        return EXIT_DB_DOWN
    finally:
        try:
            conn.close()
        except psycopg.Error:
            pass


if __name__ == "__main__":
    sys.exit(main())
