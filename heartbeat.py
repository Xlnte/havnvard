#!/usr/bin/env python3
"""diskaudit v2 — heartbeat/stage tracking helper, shared by scan.py, dedup.py,
crosshost_verify.py, and the restic backup wrapper scripts (restic-app-c*.sh,
via a small CLI/psycopg call -- see monitor.py's docstring for the
run_type='restic_backup' convention).

Updates last_heartbeat_at/current_stage on scan_runs, dedup_runs, or backup_runs (a
single "most recent" value a monitor can check for staleness -- see monitor.py), and
appends to diskaudit.run_heartbeats (an append-only history log for retroactive
analysis, not live monitoring -- e.g. "which stage took the longest" after the fact).

Callers should throttle via HeartbeatThrottle to avoid hammering the DB from a tight
loop -- a heartbeat on every one of millions of files would add real overhead for no
benefit; once every ~15s is plenty for a human or monitor to tell "still working" from
"stuck." Plane: INFRA-98.
"""
from __future__ import annotations

import time


class HeartbeatThrottle:
    """due() returns True at most once per min_interval_s seconds (wall clock)."""

    def __init__(self, min_interval_s: float = 15.0):
        self.min_interval_s = min_interval_s
        self._last = 0.0

    def due(self) -> bool:
        now = time.monotonic()
        if now - self._last >= self.min_interval_s:
            self._last = now
            return True
        return False


def write_heartbeat(
    conn,
    run_type: str,
    run_id: int,
    host: str,
    stage: str,
    worker_idx: int | None = None,
    note: str | None = None,
    only_running: bool = False,
):
    """run_type is 'scan', 'dedup', 'restic_backup', 'crosshost_verify', or
    'backup_coverage'. worker_idx=None updates the overall run row; an int updates
    (and upserts) that specific parallel worker's status row -- only meaningful for
    'dedup' (all other run_types must always pass worker_idx=None; there is no
    per-worker table for them).

    only_running=True (INFRA-520, for a BACKGROUND heartbeat thread) makes the run-row
    UPDATE conditional on status='running', evaluated atomically at row-lock time, so a
    late beat can never overwrite the final current_stage of a run that just finished."""
    table_map = {
        "scan": "scan_runs",
        "dedup": "dedup_runs",
        "restic_backup": "backup_runs",
        "crosshost_verify": "crosshost_verify_runs",
        "backup_coverage": "backup_coverage_runs",
    }
    id_col_map = {
        "scan": "scan_id",
        "dedup": "dedup_run_id",
        "restic_backup": "run_id",
        "crosshost_verify": "run_id",
        "backup_coverage": "run_id",
    }
    table = table_map[run_type]
    id_col = id_col_map[run_type]
    with conn.cursor() as cur:
        if worker_idx is None:
            cur.execute(
                f"UPDATE diskaudit.{table} SET last_heartbeat_at = now(), current_stage = %s "
                f"WHERE {id_col} = %s" + (" AND status = 'running'" if only_running else ""),
                (stage, run_id),
            )
        else:
            cur.execute(
                """
                INSERT INTO diskaudit.dedup_worker_status
                    (dedup_run_id, worker_idx, current_stage, last_heartbeat_at, status)
                VALUES (%s, %s, %s, now(), 'running')
                ON CONFLICT (dedup_run_id, worker_idx) DO UPDATE SET
                    current_stage = EXCLUDED.current_stage, last_heartbeat_at = now()
                """,
                (run_id, worker_idx, stage),
            )
        cur.execute(
            "INSERT INTO diskaudit.run_heartbeats (run_type, run_id, worker_idx, host, stage, note) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (run_type, run_id, worker_idx, host, stage, note),
        )
    conn.commit()


def mark_worker_done(conn, dedup_run_id: int, worker_idx: int, status: str):
    """status is 'completed' or 'failed'."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE diskaudit.dedup_worker_status
            SET status = %s, finished_at = now(), last_heartbeat_at = now()
            WHERE dedup_run_id = %s AND worker_idx = %s
            """,
            (status, dedup_run_id, worker_idx),
        )
    conn.commit()
