"""HavnVard 1.4.3 (INFRA-522): per-(host, root) scan lock and per-scan staging cleanup, shared by scan.py and
load_nas_inventory.py.

files_staging is shared by every scan. Before 1.4.3 a scan start did DELETE ... WHERE host = X, so a second scan of the
same host wiped the first scan's staged rows and the first merge then marked its own rows disappeared. Now:
  1. acquire_scan_lock(): a session-level Postgres advisory lock per (host, root). A second scan of the same root is
     REFUSED (exit 3, logged), never run in parallel. It is released when the connection closes, so a crashed or
     SIGKILLed scan cannot leave a stale lock.
  2. staged rows carry scan_id and merge() reads only its own; clear_stale_staging() deletes only rows no live scan
     can own (finished scans, legacy NULL scan_id (only while no other
     recent scan of the host is running), and 'running' scans of this very (host, root) -- which, because
     we hold the lock, are dead).
"""
from __future__ import annotations

import sys

EXIT_SCAN_REFUSED = 3
_LOCK_NS = "havnvard-scan:"
LEGACY_LIVE_WINDOW = "2 days"  # a pre-1.4.3 scan running longer than this is treated as dead


def normalize_root(root: str) -> str:
    return (root.rstrip("/") or "/")


def acquire_scan_lock(conn, host: str, root: str) -> bool:
    """Try to take the (host, root) scan lock on this connection. True = held until the connection closes."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(hashtext(%s), hashtext(%s))",
                    (_LOCK_NS + host, normalize_root(root)))
        return bool(cur.fetchone()[0])


def refuse_if_locked(conn, host: str, root: str, tool: str) -> None:
    """Exit non-zero, loudly, when another scan of the same (host, root) is running. Call before any DB write."""
    if not acquire_scan_lock(conn, host, root):
        print(f"[{tool}] REFUSED: another scan of host={host} root={normalize_root(root)} is already running "
              f"(scan lock held). Nothing was staged or merged; wait for it to finish.", file=sys.stderr)
        conn.close()
        sys.exit(EXIT_SCAN_REFUSED)


def clear_stale_staging(cur, host: str, root: str, scan_id: int) -> int:
    """Delete this host's staged rows that no live scan can own. Never touches another host's rows, another
    root's running scan, or this scan's own rows. Returns the number deleted."""
    # Legacy rows (scan_id NULL) come from <= 1.4.2 code, which takes no lock: one of those may still be running on this
    # host across the 1.4.3 switchover, and deleting its staging would make its merge mark its whole root disappeared.
    # So legacy rows are deleted only when no OTHER scan of this host is 'running' and recent (LEGACY_LIVE_WINDOW;
    # older 'running' rows are SIGKILLed/rebooted leftovers). Keeping them is harmless: 1.4.3 merges read only their
    # own scan_id. (1.4.3 Opus review, R143-1.)
    cur.execute(
        "DELETE FROM diskaudit.files_staging s WHERE s.host = %(host)s AND s.scan_id IS DISTINCT FROM %(scan_id)s AND ("
        " (s.scan_id IS NULL AND NOT EXISTS (SELECT 1 FROM diskaudit.scan_runs o WHERE o.host = %(host)s"
        "   AND o.status = 'running' AND o.scan_id <> %(scan_id)s AND o.started_at > now() - %(win)s::interval))"
        " OR s.scan_id IN (SELECT r.scan_id FROM diskaudit.scan_runs r WHERE r.status <> 'running'"
        "   OR (r.host = %(host)s AND r.root_path = %(root)s)))",
        {"host": host, "scan_id": scan_id, "root": root, "win": LEGACY_LIVE_WINDOW},
    )
    return cur.rowcount
