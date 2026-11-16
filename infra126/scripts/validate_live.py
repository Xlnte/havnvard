#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


REQUIRED_TABLES = {
    "hash_verification_sla","hash_verification_runs","hash_verification_items",
    "hash_observations","hash_divergences","mutable_file_registry",
    "corruption_suspects","hash_copy_evidence","hash_baseline_stabilizations",
}
REQUIRED_FILE_COLUMNS = {
    "first_hash","first_hashed_at","last_hash_attempt_at","last_verified_at",
    "last_baseline_accepted_at","verification_count","baseline_revision_count",
    "hash_divergence_count","hash_status","hash_error",
    "hash_baseline_mtime_ns","hash_baseline_size","hash_baseline_inode",
    "hash_baseline_metadata_trusted",
}


SLA_TIERS = ("A", "B", "C", "E")


def site_hosts() -> tuple[str, ...]:
    """The site file's hosts. havnvard_site.py sits in the repo root (two levels above infra126/scripts); $HAVNVARD_HOME
    names it when this package is installed elsewhere."""
    for root in (os.environ.get("HAVNVARD_HOME"), str(Path(__file__).resolve().parents[2])):
        if root and (Path(root) / "havnvard_site.py").is_file():
            sys.path.insert(0, root)
            import havnvard_site  # noqa: PLC0415
            return tuple(havnvard_site.all_hosts())
    raise SystemExit("validate_live: havnvard_site.py not found; set HAVNVARD_HOME to the HavnVard checkout")


def sla_failures(found: set[tuple[str, str]], hosts) -> list[str]:
    """Every site host needs one SLA row per tier (hosts x 4). A host the site file lacks, or a row the database lacks, fails."""
    want = {(h, t) for h in hosts for t in SLA_TIERS}
    out = []
    if found != want:
        out.append(f"expected {len(want)} scheduled SLA rows ({len(set(hosts))} hosts x {len(SLA_TIERS)} tiers), found {len(found)}"
                   f"; missing {sorted(want - found)}; unexpected {sorted(found - want)}")
    return out


def main() -> int:
    import psycopg
    findings: dict[str,object] = {}
    failures: list[str] = []
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='diskaudit'")
        tables={row[0] for row in cur.fetchall()}
        missing_tables=sorted(REQUIRED_TABLES-tables)
        findings["missing_tables"]=missing_tables
        if missing_tables: failures.append(f"missing tables: {missing_tables}")

        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='diskaudit' AND table_name='files'")
        columns={row[0] for row in cur.fetchall()}
        missing_columns=sorted(REQUIRED_FILE_COLUMNS-columns)
        findings["missing_file_columns"]=missing_columns
        if missing_columns: failures.append(f"missing diskaudit.files columns: {missing_columns}")

        cur.execute("SELECT host, tier FROM diskaudit.hash_verification_sla")
        sla={(h, str(t).strip()) for h, t in cur.fetchall()}
        findings["sla_rows"]=len(sla)
        failures.extend(sla_failures(sla, site_hosts()))

        cur.execute("SELECT count(*) FROM diskaudit.mutable_file_registry")
        findings["registry_rows"]=cur.fetchone()[0]
        if findings["registry_rows"] < 20: failures.append("mutable/immutable registry has fewer than 20 rules")

        cur.execute("SELECT count(*) FROM diskaudit.files WHERE content_sha256 IS NOT NULL AND (first_hash IS NULL OR first_hashed_at IS NULL)")
        findings["unbackfilled_hash_rows"]=cur.fetchone()[0]
        if findings["unbackfilled_hash_rows"]: failures.append("existing hashes were not fully backfilled as baseline-only")

        cur.execute("SELECT count(*) FROM diskaudit.files WHERE verification_count>0 AND last_verified_at IS NULL")
        findings["invalid_verification_rows"]=cur.fetchone()[0]
        if findings["invalid_verification_rows"]: failures.append("verification_count rows missing last_verified_at")

        cur.execute("""
            SELECT count(*) FROM diskaudit.files
            WHERE hash_baseline_metadata_trusted
              AND (hash_baseline_mtime_ns IS NULL OR hash_baseline_size IS NULL OR hash_baseline_inode IS NULL)
        """)
        findings["invalid_trusted_metadata_rows"]=cur.fetchone()[0]
        if findings["invalid_trusted_metadata_rows"]:
            failures.append("trusted baseline metadata rows contain null metadata")

        cur.execute("SELECT count(*) FROM diskaudit.hash_verification_runs WHERE status='running' AND last_heartbeat_at<now()-interval '5 minutes'")
        findings["stale_running_rows"]=cur.fetchone()[0]
        conn.rollback()

    findings["failures"]=failures
    print(json.dumps(findings,default=str,indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
