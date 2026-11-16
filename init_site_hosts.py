#!/usr/bin/env python3
"""Fill the database rows that depend on the site file's hosts (INFRA-562, INFRA-563, 3.3.9).

Run once after installing the schema, and again whenever you add a host to the site file:

    python3 init_site_hosts.py            # apply
    python3 init_site_hosts.py --dry-run  # print what would be inserted (and, with --prune, deleted)
    python3 init_site_hosts.py --prune --confirm-prune [--include-sla]   # also delete rows the site file no longer lists

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


def _prune_guard(existing: list[tuple[str, str]], want: set[tuple[str, str]]) -> None:
    """Review 3.3.10: --prune deletes live rows, so it refuses unless the site file clearly names the hosts. Without these
    checks a missing site file (wrong user, wrong $HAVNVARD_SITE) would fall back to the built-in defaults (this machine's
    hostname + a NAS called 'nas') and prune would delete every real host's rows, and with --include-sla their tuned SLA."""
    s = havnvard_site.site()
    if not s.get("_path"):
        raise havnvard_site.SiteConfigError(
            "--prune refused: no site file was read (looked in " + ", ".join(map(str, havnvard_site.site_paths()))
            + "); the built-in defaults name no real host")
    hosts = s.get("hosts") or {}
    if not hosts.get("nas") or not (hosts.get("sources") or hosts.get("all")):
        raise havnvard_site.SiteConfigError(
            f"--prune refused: site file {s['_path']} must set [hosts] nas and [hosts] sources or all explicitly")
    if not any(r == "nas" for _, r in want):
        raise havnvard_site.SiteConfigError(
            f"--prune refused: the NAS host {hosts.get('nas')!r} is not in [hosts] all of {s['_path']}; pruning would "
            "delete the nas row and v_nas_orphans would stop working")
    if existing and not (set(existing) & want):
        raise havnvard_site.SiteConfigError(
            f"--prune refused: it would delete every diskaudit.site_hosts row ({len(existing)}); site file {s['_path']} "
            "shares no (host, role) with the database. Check the site file and the database before pruning")


def extra_rows(conn) -> dict[str, list]:
    """INFRA-635: rows the database holds that the site file does not call for. site_hosts rows whose (host, role) differ
    from the site file (a host removed, or a changed NAS role) and hash_verification_sla rows for hosts no longer in it.
    Raises SiteConfigError (see _prune_guard) instead of listing rows when the site file cannot be trusted for a prune."""
    want_hosts = set(site_host_rows())
    want_names = {h for h, _ in want_hosts}
    with conn.cursor() as cur:
        cur.execute("SELECT host, role FROM diskaudit.site_hosts ORDER BY host")
        existing = [tuple(r) for r in cur.fetchall()]
        _prune_guard(existing, want_hosts)
        sh = [r for r in existing if r not in want_hosts]
        cur.execute("SELECT host, tier FROM diskaudit.hash_verification_sla ORDER BY host, tier")
        sla = [r for r in cur.fetchall() if r[0] not in want_names]
    return {"site_hosts": sh, "hash_verification_sla": sla}


def prune(conn, include_sla: bool = False) -> dict[str, int]:
    """Delete the extra site_hosts rows (caller commits). hash_verification_sla rows are tuned data and are deleted
    only when include_sla is True. A site_hosts row whose role changed is deleted, then re-inserted by apply()."""
    extra = extra_rows(conn)
    done = {"site_hosts": 0, "hash_verification_sla": 0}
    with conn.cursor() as cur:
        for host, role in extra["site_hosts"]:
            cur.execute("DELETE FROM diskaudit.site_hosts WHERE host=%s AND role=%s", (host, role))
            done["site_hosts"] += cur.rowcount
        if include_sla:
            for host, tier in extra["hash_verification_sla"]:
                cur.execute("DELETE FROM diskaudit.hash_verification_sla WHERE host=%s AND tier=%s", (host, tier))
                done["hash_verification_sla"] += cur.rowcount
    return done


def main() -> int:
    try:
        return _main()
    except havnvard_site.SiteConfigError as e:
        print(f"init_site_hosts: {e}", file=sys.stderr)
        return 2


def _main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="print the rows, change nothing")
    ap.add_argument("--prune", action="store_true", help="also remove site_hosts rows the site file no longer lists (needs --confirm-prune; --dry-run lists them)")
    ap.add_argument("--confirm-prune", action="store_true", help="explicit confirmation that --prune may delete rows")
    ap.add_argument("--include-sla", action="store_true", help="with --prune: also delete hash_verification_sla rows (tuned data) of removed hosts")
    a = ap.parse_args()
    if (a.confirm_prune or a.include_sla) and not a.prune:
        ap.error("--confirm-prune and --include-sla only apply with --prune")
    if a.prune and not (a.confirm_prune or a.dry_run):
        ap.error("--prune deletes rows: add --confirm-prune (or --dry-run to list them)")
    import psycopg  # noqa: PLC0415
    if a.dry_run:
        for h, r in site_host_rows():
            print(f"site_hosts: {h} {r}")
        for row in sla_rows():
            print("hash_verification_sla:", *row)
        if a.prune:
            with psycopg.connect(havnvard_site.require_dsn()) as conn:
                conn.read_only = True            # review 3.3.10: the dry run cannot write, even by mistake
                extra = extra_rows(conn)
            for h, r in extra["site_hosts"]:
                print(f"WOULD DELETE site_hosts: {h} {r}")
            for h, t in extra["hash_verification_sla"]:
                print(f"{'WOULD DELETE' if a.include_sla else 'KEEP (tuned; add --include-sla to delete)'} hash_verification_sla: {h} {t}")
        return 0
    with psycopg.connect(havnvard_site.require_dsn()) as conn:
        pruned = prune(conn, a.include_sla) if a.prune else None
        done = apply(conn)
        conn.commit()
    if pruned is not None:
        print("deleted: " + ", ".join(f"{k}={v}" for k, v in pruned.items()))
    print("inserted: " + ", ".join(f"{k}={v}" for k, v in done.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
