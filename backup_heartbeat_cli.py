#!/usr/bin/env python3
"""diskaudit v2 — thin CLI wrapper around heartbeat.py's backup_runs support, for
bash-based backup wrapper scripts (restic-app-c*.sh and future restic targets)
that can't import heartbeat.py directly. Mirrors the scan_runs/dedup_runs create+close
convention already used by scan.py/dedup.py (INSERT ... status='running' RETURNING
<id>, write_heartbeat() for stage transitions, UPDATE status/finished_at on completion).

Usage:
    run_id=$(python3 backup_heartbeat_cli.py start <backup_job> <host>)
    python3 backup_heartbeat_cli.py finish <run_id> <completed|failed> ["<note>"]

Exits 0 on success. On any DB error, prints to stderr and exits 1 -- a heartbeat
failure must never abort the actual backup (callers should not `set -e` around
these calls), but should be visible in the log.
"""
from __future__ import annotations

import os
import sys

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heartbeat import write_heartbeat  # noqa: E402
from scan import get_dsn  # noqa: E402


def cmd_start(backup_job: str, host: str) -> int:
    conn = psycopg.connect(get_dsn(), autocommit=False)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO diskaudit.backup_runs (backup_job, host, status, last_heartbeat_at, current_stage) "
            "VALUES (%s, %s, 'running', now(), 'starting') RETURNING run_id",
            (backup_job, host),
        )
        run_id = cur.fetchone()[0]
    conn.commit()
    write_heartbeat(conn, "restic_backup", run_id, host, "starting")
    print(run_id)
    return 0


def cmd_finish(run_id: int, status: str, note: str | None) -> int:
    if status not in ("completed", "failed"):
        print(f"backup_heartbeat_cli: invalid status {status!r}, must be completed|failed", file=sys.stderr)
        return 1
    conn = psycopg.connect(get_dsn(), autocommit=False)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE diskaudit.backup_runs SET status=%s, finished_at=now(), "
            "last_heartbeat_at=now(), current_stage='done', note=%s WHERE run_id=%s",
            (status, note, run_id),
        )
    conn.commit()
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: backup_heartbeat_cli.py start <job> <host> | finish <run_id> <status> [note]", file=sys.stderr)
        return 1
    try:
        if sys.argv[1] == "start" and len(sys.argv) == 4:
            return cmd_start(sys.argv[2], sys.argv[3])
        if sys.argv[1] == "finish" and len(sys.argv) in (4, 5):
            note = sys.argv[4] if len(sys.argv) == 5 else None
            return cmd_finish(int(sys.argv[2]), sys.argv[3], note)
    except Exception as e:
        print(f"backup_heartbeat_cli: DB error, not fatal to the backup itself: {e}", file=sys.stderr)
        return 1
    print("usage: backup_heartbeat_cli.py start <job> <host> | finish <run_id> <status> [note]", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
