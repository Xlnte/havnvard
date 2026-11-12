"""`coverage-sync DEVICE`: mark files BACKED_UP_UNVERIFIED (never VERIFIED) when the device's latest restic snapshot holds the same
path + size + mtime (to the second). Matching is pure (no DB, no restic); the DB write takes a connection argument.

Honest limit: this proves "the snapshot lists this file as it is now", not a SHA-256 compare (restic uses its own
hashes; the restore drill is the byte-level proof). Rows are therefore tagged match_method='restic_snapshot_listing'
and the note says so. Review 20261111: a listing is not a hash check, so it never promotes past
BACKED_UP_UNVERIFIED (backup_coverage.py rule; HavnVard 1.6.0: VERIFIED means full SHA-256). `backup_coverage.py classify` rewrites every row, so run coverage-sync AFTER classify.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
from typing import Iterable, Iterator

from . import config, drill
from .config import BackupError
from .util import restic_bin

PROMOTABLE = ("BACKED_UP_UNVERIFIED", "NOT_BACKED_UP")
BATCH = 20000
NOTE = "restic snapshot listing: same path+size+mtime (not a SHA-256 compare)"


def _epoch(s: str) -> int:
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    return int(dt.datetime.fromisoformat(s).timestamp())


def parse_ls_json(lines: Iterable[str]) -> tuple[str | None, dict[str, tuple[int, int]]]:
    """restic `ls --json` lines -> (snapshot_id, {path: (size, mtime_epoch_s)}) for regular files only.
    Unparsable file nodes are an error, not a skip: a silently short listing would under-report coverage."""
    snap, files = None, {}
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            o = json.loads(ln)
        except ValueError as e:
            raise BackupError(f"restic ls produced a non-JSON line: {ln[:80]!r}") from e
        if o.get("struct_type") == "snapshot":
            snap = o.get("short_id") or o.get("id")
        elif o.get("struct_type") == "node" and o.get("type") == "file":
            try:
                files[o["path"]] = (int(o["size"]), _epoch(o["mtime"]))
            except (KeyError, ValueError, TypeError) as e:
                raise BackupError(f"restic ls file node missing path/size/mtime: {str(o)[:120]}") from e
    return snap, files


def match_listing(candidates: Iterable[tuple[str, int | None, int | None]],
                  listing: dict[str, tuple[int, int]]) -> list[str]:
    """candidates = (path, size, mtime_epoch_s) from diskaudit.files; returns the paths the snapshot holds
    with identical size and mtime. A missing size or mtime never matches."""
    out = []
    for path, size, mtime in candidates:
        got = listing.get(path)
        if got and size is not None and mtime is not None and got == (size, int(mtime)):
            out.append(path)
    return out


def list_latest(device: str) -> tuple[str | None, dict[str, tuple[int, int]]]:
    from .catalog import latest_data_snapshot   # 2.2.0: never the catalog snapshot
    dev_env = drill._env_for(device)
    snap0 = latest_data_snapshot(restic_bin(), dev_env)
    if not snap0:
        raise BackupError(f"{device}: repository has no data snapshots")
    env = {**os.environ, **dev_env}
    p = subprocess.Popen([restic_bin(), "ls", "--json", snap0["id"]], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    snap, files = parse_ls_json(p.stdout)
    err = p.stderr.read()
    if p.wait() != 0:
        raise BackupError(f"restic ls {snap0['id'][:8]} failed (rc {p.returncode}): {err.strip()[-300:]}")
    if not files:
        raise BackupError(f"latest snapshot of {device} lists no files; refusing to mark anything")
    return snap, files


CANDIDATES_SQL = (
    "SELECT bc.path, bc.size_bytes, extract(epoch from f.mtime)::bigint "
    "FROM diskaudit.backup_coverage bc JOIN diskaudit.files f ON f.host = bc.host AND f.path = bc.path "
    "WHERE bc.host = %s AND bc.classification = ANY(%s) AND f.still_exists"
)
UPDATE_SQL = (
    "UPDATE diskaudit.backup_coverage SET classification = 'BACKED_UP_UNVERIFIED', "
    "match_method = 'restic_snapshot_listing', matched_restic_target = %s, restic_snapshot_id = %s, "
    "restic_verified_at = now(), checked_at = now(), "
    "notes = COALESCE(notes || '; ', '') || %s WHERE host = %s AND path = %s "
    "AND classification = ANY(%s)"
)


def sync_coverage(conn, host: str, snapshot_id: str | None, listing: dict[str, tuple[int, int]],
                  dry_run: bool = False) -> int:
    """Promote matching rows. `conn` is a DB-API connection (psycopg); one transaction, rolled back on error."""
    cur = conn.cursor()
    promoted = 0
    try:
        cur.execute(CANDIDATES_SQL, (host, list(PROMOTABLE)))
        while True:
            rows = cur.fetchmany(BATCH)
            if not rows:
                break
            hit = match_listing(rows, listing)
            promoted += len(hit)
            if hit and not dry_run:
                # separate cursor: the candidate cursor is still streaming
                w = conn.cursor()
                w.executemany(UPDATE_SQL, [(host, snapshot_id, NOTE, host, p, list(PROMOTABLE)) for p in hit])
        if dry_run:
            conn.rollback()
        else:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    return promoted


def connect():
    dsn = os.environ.get("POSTGRES_URL")
    if not dsn:
        raise BackupError("POSTGRES_URL is not set (the HavnVard inventory database; see README \"Inventory database\")")
    try:
        import psycopg as pg          # the repo's driver
    except ImportError:
        import psycopg2 as pg         # fallback
    return pg.connect(dsn)


def coverage_sync(device: str, dry_run: bool = False) -> int:
    snap, listing = list_latest(device)
    conn = connect()
    try:
        n = sync_coverage(conn, device, snap, listing, dry_run)
    finally:
        conn.close()
    print(f"coverage-sync {device}: snapshot {snap}, {len(listing)} files listed, "
          f"{n} {'would be ' if dry_run else ''}marked BACKED_UP_UNVERIFIED (in a restic snapshot; not hash-verified)")
    return 0
