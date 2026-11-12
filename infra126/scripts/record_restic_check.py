#!/usr/bin/env python3
"""Record the result of a restic integrity check without duplicating restic's checker."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime,timezone


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-id",required=True)
    parser.add_argument("--host",required=True)
    parser.add_argument("--passed",action=argparse.BooleanOptionalAction,default=None)
    parser.add_argument("--corrupt-count",type=int,default=0)
    parser.add_argument("--details-json",default="{}")
    args = parser.parse_args()
    if args.passed is None:
        parser.error("provide --passed or --no-passed")
    if args.corrupt_count < 0:
        parser.error("--corrupt-count cannot be negative")
    details = json.loads(args.details_json)
    import psycopg
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO diskaudit.backup_verification_state
                (restic_snapshot_id,host,verification_passed,last_verified_at,corrupt_count,details)
            VALUES (%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT(restic_snapshot_id,host) DO UPDATE
            SET verification_passed=EXCLUDED.verification_passed,
                last_verified_at=EXCLUDED.last_verified_at,
                corrupt_count=EXCLUDED.corrupt_count,
                details=EXCLUDED.details
            """,
            (args.snapshot_id,args.host,args.passed,datetime.now(timezone.utc),args.corrupt_count,json.dumps(details)),
        )
        conn.commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
