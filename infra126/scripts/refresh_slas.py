#!/usr/bin/env python3
from __future__ import annotations

import os


def main() -> int:
    import psycopg
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT host,tier FROM diskaudit.hash_verification_sla ORDER BY host,tier")
        rows = cur.fetchall()
        for host,tier in rows:
            cur.execute("SELECT diskaudit.infra126_refresh_sla(%s,%s)",(host,tier))
        conn.commit()
    print(f"refreshed {len(rows)} SLA rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
