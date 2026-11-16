#!/usr/bin/env python3
"""Fill the database rows that depend on the site file's hosts (INFRA-562, INFRA-563, 3.3.9).

Run once after installing the schema, and again whenever you add a host to the site file:

    python3 init_site_hosts.py            # apply
    python3 init_site_hosts.py --dry-run  # print what would be inserted

It writes only rows that are missing (ON CONFLICT DO NOTHING), so a schedule you tuned by hand is never overwritten, and a
second run changes nothing. Tables:
  * diskaudit.site_hosts: each source host (role 'source') and the NAS host (role 'nas'); v_nas_orphans reads it.
  * diskaudit.hash_verification_sla: one row per (host, tier) for every host, tiers A/B/C/E; the monitor's overdue alarm
    and infra126/scripts/validate_live.py (hosts x 4 rows) read it.
"""
from __future__ import annotations

import argparse
import sys

import havnvard_site

# Tier, target re-check days, schedule mode: the schedule infra126/migrations/001 seeded for the original deployment.
TIERS = (("A", 7, "weekly"), ("B", 30, "monthly"), ("C", 90, "quarterly"), ("E", 1, "daily"))


def site_host_rows() -> list[tuple[str, str]]:
    """(host, role) for every host in the site file; the NAS host is role 'nas', all others 'source'."""
    nas = havnvard_site.nas_host()
    return [(h, "nas" if h == nas else "source") for h in havnvard_site.all_hosts()]


def sla_rows() -> list[tuple[str, str, int, str]]:
    return [(h, t, d, m) for h, _ in site_host_rows() for t, d, m in TIERS]


def apply(conn) -> dict[str, int]:
    """Insert the missing rows on `conn` (caller commits). Returns rows actually inserted per table."""
    done = {}
    with conn.cursor() as cur:
        n = 0
        for host, role in site_host_rows():
            cur.execute("INSERT INTO diskaudit.site_hosts (host, role) VALUES (%s, %s) ON CONFLICT (host) DO NOTHING",
                        (host, role))
            n += cur.rowcount
        done["site_hosts"] = n
        n = 0
        for row in sla_rows():
            cur.execute("INSERT INTO diskaudit.hash_verification_sla (host, tier, target_recheck_days, schedule_mode) "
                        "VALUES (%s, %s, %s, %s) ON CONFLICT (host, tier) DO NOTHING", row)
            n += cur.rowcount
        done["hash_verification_sla"] = n
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="print the rows, change nothing")
    a = ap.parse_args()
    if a.dry_run:
        for h, r in site_host_rows():
            print(f"site_hosts: {h} {r}")
        for row in sla_rows():
            print("hash_verification_sla:", *row)
        return 0
    import psycopg  # noqa: PLC0415
    with psycopg.connect(havnvard_site.require_dsn()) as conn:
        done = apply(conn)
        conn.commit()
    print("inserted: " + ", ".join(f"{k}={v}" for k, v in done.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
