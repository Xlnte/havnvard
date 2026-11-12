#!/usr/bin/env python3
"""diskaudit — classification materialized-view refresh (companion to refresh_load_bearing_paths.py).

Calls diskaudit.refresh_file_status() (REFRESH MATERIALIZED VIEW CONCURRENTLY diskaudit.mv_file_status).
refresh_load_bearing_paths.py already calls this at the end of its own (weekly) run, so this
script's own timer only needs to cover the OTHER trigger for staleness: diskaudit.files itself
changing after the monthly scan.py + nas_native_crawl.sh + dedup.py pipeline completes. Without
this second trigger, a newly-scanned file (or a newly-populated duplicate_group_id from a fresh
dedup run) would not show up with a correct file_status until the next incidental weekly
load-bearing refresh -- up to ~3 weeks of drift between "file data changed" and "classification
reflects it."

Standalone CLI, no side effects on import -- same traceability convention as
refresh_load_bearing_paths.py. See runbook: /home/parker/runbooks/20260718-diskaudit-classification/README.md

Usage:
  refresh_classification_mv.py
"""
from __future__ import annotations

import sys
import time

import psycopg

_SOT_ENV = "/srv/forge/.secrets/prod/diskaudit.env"


def _dsn_from_sot():
    try:
        with open(_SOT_ENV) as f:
            for line in f:
                if line.startswith("POSTGRES_URL="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return None


def get_dsn() -> str:
    import os
    return (
        os.environ.get("POSTGRES_URL")
        or _dsn_from_sot()
        or "postgresql://ultra_crm@127.0.0.1:5432/ultra_crm"
    )


def main():
    conn = psycopg.connect(get_dsn(), autocommit=True)
    t0 = time.monotonic()
    print("[refresh_classification_mv] REFRESH MATERIALIZED VIEW CONCURRENTLY diskaudit.mv_file_status starting", file=sys.stderr)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT diskaudit.refresh_file_status()")
    finally:
        conn.close()
    print(f"[refresh_classification_mv] done in {time.monotonic() - t0:.1f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
