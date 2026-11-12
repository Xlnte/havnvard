#!/usr/bin/env python3
"""diskaudit weekly PRESCAB operational review.

Runs weekly (Sunday 18:00) to give PRESCAB (VP-Operations) a high-level summary of
diskaudit system health: total files/bytes tracked, duplicate/reclaimable space,
recent (7-day) stale or failed runs.

Dispatches via POST to :9103/dispatch (logic_governance mode) and logs response to
havnvard.jobs.cabinet_runs. This is an operational state review, not a creative task,
so logic_governance (cold, deterministic, source-bound) is appropriate.

Usage:
  weekly_prescab_review.py --dry-run  # print task_text, do not dispatch
  weekly_prescab_review.py             # dispatch to PRESCAB, log response
  weekly_prescab_review.py --test-mode # dispatch with [TEST] prefix to TG

See: /home/user/runbooks/20260718-diskaudit-prescab-weekly-review/README.md
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg
from prescab_client import dispatch as prescab_dispatch

# ---- Logging setup ----

BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "weekly_prescab_review.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("weekly_prescab_review")


# ---- DSN resolution — same pattern as monitor.py/scan.py ----

import havnvard_site as _site  # noqa: E402  (3.0.0)


def get_dsn() -> str:
    """CRM_DB_DSN if set, else the HavnVard site database (never a guessed default)."""
    return os.environ.get("CRM_DB_DSN") or _site.require_dsn()


# ---- Database queries ----


def query_host_summary(conn) -> dict:
    """
    Query total files/bytes per host from diskaudit.files.
    Returns {"host1": {"files": N, "bytes": B}, ...}
    """
    summary = {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT host, COUNT(*) as file_count, COALESCE(SUM(size_bytes), 0) as total_bytes
            FROM diskaudit.files
            WHERE still_exists = true
            GROUP BY host
            ORDER BY host
            """
        )
        for host, file_count, total_bytes in cur.fetchall():
            summary[host] = {"files": file_count, "bytes": total_bytes}
    return summary


def query_recent_issues(conn, days: int = 7) -> dict:
    """
    Query scan_runs, dedup_runs, dedup_worker_status for recent (N days) stale/failed runs.
    Returns {"failed_scans": [...], "failed_dedups": [...], "stale_scans": [...], ...}
    """
    issues = {
        "failed_scans": [],
        "failed_dedups": [],
        "failed_dedup_workers": [],
        "stale_scans": [],
        "stale_dedups": [],
        "stale_dedup_workers": [],
    }

    threshold = f"now() - make_interval(days => {days})"

    with conn.cursor() as cur:
        # Failed scans in last N days
        cur.execute(
            f"""
            SELECT scan_id, host, current_stage, finished_at
            FROM diskaudit.scan_runs
            WHERE status = 'failed' AND finished_at > {threshold}
            ORDER BY finished_at DESC
            """
        )
        for scan_id, host, stage, finished_at in cur.fetchall():
            issues["failed_scans"].append({
                "scan_id": scan_id,
                "host": host,
                "stage": stage,
                "finished_at": finished_at,
            })

        # Failed dedups in last N days
        cur.execute(
            f"""
            SELECT dedup_run_id, host, current_stage, finished_at
            FROM diskaudit.dedup_runs
            WHERE status = 'failed' AND finished_at > {threshold}
            ORDER BY finished_at DESC
            """
        )
        for dedup_run_id, host, stage, finished_at in cur.fetchall():
            issues["failed_dedups"].append({
                "dedup_run_id": dedup_run_id,
                "host": host,
                "stage": stage,
                "finished_at": finished_at,
            })

        # Failed dedup workers in last N days
        cur.execute(
            f"""
            SELECT dws.dedup_run_id, dws.worker_idx, dr.host, dws.current_stage, dws.finished_at
            FROM diskaudit.dedup_worker_status dws
            JOIN diskaudit.dedup_runs dr ON dr.dedup_run_id = dws.dedup_run_id
            WHERE dws.status = 'failed' AND dws.finished_at > {threshold}
            ORDER BY dws.finished_at DESC
            """
        )
        for dedup_run_id, worker_idx, host, stage, finished_at in cur.fetchall():
            issues["failed_dedup_workers"].append({
                "dedup_run_id": dedup_run_id,
                "worker_idx": worker_idx,
                "host": host,
                "stage": stage,
                "finished_at": finished_at,
            })

        # Stale scans (running for >10 min without heartbeat)
        cur.execute(
            """
            SELECT scan_id, host, current_stage, last_heartbeat_at
            FROM diskaudit.scan_runs
            WHERE status = 'running' AND last_heartbeat_at < now() - make_interval(mins => 10)
            ORDER BY scan_id DESC
            """
        )
        for scan_id, host, stage, last_hb in cur.fetchall():
            issues["stale_scans"].append({
                "scan_id": scan_id,
                "host": host,
                "stage": stage,
                "last_heartbeat_at": last_hb,
            })

        # Stale dedups
        cur.execute(
            """
            SELECT dedup_run_id, host, current_stage, last_heartbeat_at
            FROM diskaudit.dedup_runs
            WHERE status = 'running' AND last_heartbeat_at < now() - make_interval(mins => 10)
            ORDER BY dedup_run_id DESC
            """
        )
        for dedup_run_id, host, stage, last_hb in cur.fetchall():
            issues["stale_dedups"].append({
                "dedup_run_id": dedup_run_id,
                "host": host,
                "stage": stage,
                "last_heartbeat_at": last_hb,
            })

        # Stale dedup workers
        cur.execute(
            """
            SELECT dws.dedup_run_id, dws.worker_idx, dr.host, dws.current_stage, dws.last_heartbeat_at
            FROM diskaudit.dedup_worker_status dws
            JOIN diskaudit.dedup_runs dr ON dr.dedup_run_id = dws.dedup_run_id
            WHERE dws.status = 'running' AND dws.last_heartbeat_at < now() - make_interval(mins => 10)
            ORDER BY dws.dedup_run_id DESC, dws.worker_idx
            """
        )
        for dedup_run_id, worker_idx, host, stage, last_hb in cur.fetchall():
            issues["stale_dedup_workers"].append({
                "dedup_run_id": dedup_run_id,
                "worker_idx": worker_idx,
                "host": host,
                "stage": stage,
                "last_heartbeat_at": last_hb,
            })

    return issues


def query_duplicate_summary(dsn: str) -> Optional[dict]:
    """
    Query duplicate summary. Attempts to use diskaudit.v_duplicate_groups if it exists.
    Returns {"total_group_count": N, "reclaimable_bytes": B} or None if view doesn't exist.
    Opens its own connection to avoid transaction failures.
    """
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                # Try the view first
                # NOTE: v_duplicate_groups' column is reclaimable_bytes_total (aggregated
                # across hosts), not reclaimable_bytes (that name only exists on the
                # per-host view v_duplicate_groups_by_host) -- verified against live schema
                # 2026-07-18 after the first version of this query silently mismatched and
                # got misclassified as "view not yet available".
                cur.execute(
                    """
                    SELECT COUNT(*) as group_count, COALESCE(SUM(reclaimable_bytes_total), 0) as total_reclaimable
                    FROM diskaudit.v_duplicate_groups
                    """
                )
                row = cur.fetchone()
                if row:
                    return {
                        "total_groups": row[0],
                        "reclaimable_bytes": row[1],
                    }
    except psycopg.ProgrammingError:
        # View doesn't exist yet
        log.info("v_duplicate_groups view not yet available")
    except Exception as e:
        log.warning(f"Error querying v_duplicate_groups: {e}")
    return None


def query_backup_coverage(dsn: str) -> Optional[dict]:
    """
    Query backup coverage if v_backup_coverage view exists.
    Returns {"coverage_percent": P} or None if view doesn't exist.
    Opens its own connection to avoid transaction failures.

    NOTE: v_backup_coverage is a row-per-critical-file view (host, path, size_bytes,
    duplicate_group_id, covering_hosts, is_backed_up) -- it has no pre-aggregated
    coverage_percent column. That was the original (wrong) assumption here, silently
    caught by the except below and misreported as "view not yet available" even after
    the view existed. Fixed 2026-07-18: aggregate by bytes -- percent of critical bytes
    that are confirmed backed up on another host.
    """
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COALESCE(
                        100.0 * SUM(CASE WHEN is_backed_up THEN size_bytes ELSE 0 END)
                        / NULLIF(SUM(size_bytes), 0),
                        0
                    ) AS coverage_percent
                    FROM diskaudit.v_backup_coverage
                    """
                )
                row = cur.fetchone()
                if row:
                    return {"coverage_percent": float(row[0])}
    except psycopg.ProgrammingError:
        # View doesn't exist yet
        log.info("v_backup_coverage view not yet available")
    except Exception as e:
        log.warning(f"Error querying v_backup_coverage: {e}")
    return None


# ---- Task text formatting ----


def format_task_text(
    host_summary: dict,
    issues: dict,
    duplicates: Optional[dict],
    backup_coverage: Optional[dict],
) -> str:
    """Format a concise PRESCAB-friendly task summary."""
    lines = [
        "=== diskaudit Weekly Operational Review ===",
        "",
        "INVENTORY SUMMARY:",
    ]

    # Host summaries
    for host in sorted(host_summary.keys()):
        data = host_summary[host]
        files = data["files"]
        bytes_gb = data["bytes"] / (1024 ** 3)
        lines.append(f"  {host}: {files:,} files, {bytes_gb:.2f} GB")

    lines.append("")
    lines.append("RECENT FAILURES (last 7 days):")
    if issues["failed_scans"]:
        lines.append(f"  Failed scans: {len(issues['failed_scans'])}")
        for item in issues["failed_scans"][:3]:  # Show top 3
            lines.append(
                f"    - scan_id={item['scan_id']} host={item['host']} "
                f"stage={item['stage']} at {item['finished_at']}"
            )
        if len(issues["failed_scans"]) > 3:
            lines.append(f"    ... and {len(issues['failed_scans']) - 3} more")
    else:
        lines.append("  Failed scans: none")

    if issues["failed_dedups"]:
        lines.append(f"  Failed dedups: {len(issues['failed_dedups'])}")
        for item in issues["failed_dedups"][:3]:
            lines.append(
                f"    - dedup_run_id={item['dedup_run_id']} host={item['host']} "
                f"stage={item['stage']} at {item['finished_at']}"
            )
        if len(issues["failed_dedups"]) > 3:
            lines.append(f"    ... and {len(issues['failed_dedups']) - 3} more")
    else:
        lines.append("  Failed dedups: none")

    if issues["failed_dedup_workers"]:
        lines.append(f"  Failed dedup workers: {len(issues['failed_dedup_workers'])}")
    else:
        lines.append("  Failed dedup workers: none")

    lines.append("")
    lines.append("CURRENTLY STALE (running >10 min without heartbeat):")
    if issues["stale_scans"]:
        lines.append(f"  Stale scans: {len(issues['stale_scans'])}")
    else:
        lines.append("  Stale scans: none")

    if issues["stale_dedups"]:
        lines.append(f"  Stale dedups: {len(issues['stale_dedups'])}")
    else:
        lines.append("  Stale dedups: none")

    if issues["stale_dedup_workers"]:
        lines.append(f"  Stale dedup workers: {len(issues['stale_dedup_workers'])}")
    else:
        lines.append("  Stale dedup workers: none")

    # Optional sections
    if duplicates:
        lines.append("")
        lines.append("DUPLICATE DETECTION:")
        lines.append(f"  Total groups: {duplicates['total_groups']}")
        lines.append(f"  Reclaimable bytes: {duplicates['reclaimable_bytes'] / (1024 ** 3):.2f} GB")
    else:
        lines.append("")
        lines.append("DUPLICATE DETECTION: view v_duplicate_groups not yet built")

    if backup_coverage:
        lines.append("")
        lines.append("BACKUP COVERAGE:")
        lines.append(f"  {backup_coverage['coverage_percent']:.1f}%")
    else:
        lines.append("")
        lines.append("BACKUP COVERAGE: view v_backup_coverage not yet built")

    lines.append("")
    lines.append("NEXT ACTIONS:")
    lines.append("1. Review any recent failures and determine root cause if needed.")
    lines.append("2. If stale runs exist, check mon itor.py alerts for more detail.")
    lines.append("3. Plan for monthly full scan (due on the 1st of next month).")

    return "\n".join(lines)


# ---- PRESCAB dispatch ----


def dispatch_to_prescab(
    task_text: str,
    agent: str = "vp-operations",
    mode: str = "logic_governance",
    dry_run: bool = False,
    base_url: str = "http://127.0.0.1:9103",
) -> Optional[dict]:
    """
    Dispatch task_text to PRESCAB.
    Returns the full response dict or None on error.

    JOBS-119: migrated off raw urllib to prescab_client.dispatch(). Deliberately
    fallback_to_cabinet=False — a failed/empty single-VP call must NOT silently
    escalate to a ~10-20x-more-expensive /cabinet call.
    """
    if dry_run:
        log.info(f"[dry-run] Would dispatch to {agent} in {mode} mode")
        log.info(f"Task text:\n{task_text}")
        return None

    try:
        result = prescab_dispatch(
            agent, task_text,
            mode=mode,
            submitted_by="weekly_prescab_review",
            include_memory=False,  # Operational review, not creative ideation
            base_url=base_url,
            timeout_s=300,
            fallback_to_cabinet=False,
        )
        if result.outcome != "success":
            log.error(f"Dispatch failed: outcome={result.outcome}")
            return None
        log.info(f"Dispatch succeeded: {result.raw}")
        return {**result.raw, "elapsed_ms": result.duration_ms}
    except Exception as e:
        log.error(f"Dispatch error: {e}")
        return None


# ---- Logging to jobs.cabinet_runs ----


def log_dispatch_result(
    conn,
    outcome: str,
    duration_ms: int,
    prompt_size_bytes: int,
    response_size_bytes: int,
    helm_layer: Optional[str] = None,
) -> None:
    """
    Log dispatch result to havnvard.jobs.cabinet_runs.
    Follows the pattern from dispatch_client.py.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs.cabinet_runs
                  (endpoint, target_vp, prompt_size_bytes, response_size_bytes,
                   duration_ms, helm_layer, fallback_used, outcome, completed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (
                    "dispatch",
                    "vp-operations",
                    prompt_size_bytes,
                    response_size_bytes,
                    duration_ms,
                    helm_layer,
                    False,
                    outcome,
                ),
            )
        conn.commit()
        log.info(f"Logged to jobs.cabinet_runs: outcome={outcome}")
    except Exception as e:
        log.warning(f"Failed to log to jobs.cabinet_runs: {e}")


# ---- Main ----


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print task_text; do not dispatch to PRESCAB",
    )
    ap.add_argument(
        "--test-mode",
        action="store_true",
        help="[Placeholder for future use] Test mode prefix",
    )
    ap.add_argument(
        "--base-url",
        default="http://127.0.0.1:9103",
        help="PRESCAB dispatcher base URL (default: http://127.0.0.1:9103)",
    )
    args = ap.parse_args()

    try:
        dsn = get_dsn()
        log.info("Connecting to havnvard...")
        with psycopg.connect(dsn) as conn:
            log.info("Querying diskaudit state...")
            host_summary = query_host_summary(conn)
            issues = query_recent_issues(conn)
            # These query optional views that may not exist yet; pass dsn to open their own connection
            duplicates = query_duplicate_summary(dsn)
            backup_coverage = query_backup_coverage(dsn)

            log.info(f"Found {len(host_summary)} hosts, {sum(len(v) for v in issues.values() if isinstance(v, list))} recent issues")

            # Format task text
            task_text = format_task_text(host_summary, issues, duplicates, backup_coverage)

            if args.dry_run:
                print(task_text)
                print("\n[dry-run mode - no dispatch]")
                return

            # Dispatch to PRESCAB
            log.info("Dispatching to PRESCAB (vp-operations, logic_governance)...")
            result = dispatch_to_prescab(
                task_text,
                agent="vp-operations",
                mode="logic_governance",
                dry_run=False,
                base_url=args.base_url,
            )

            if result:
                elapsed_ms = result.get("elapsed_ms", 0)
                response_text = result.get("response", "")
                log.info(f"PRESCAB response ({elapsed_ms}ms): {response_text[:200]}")

                # Log to jobs.cabinet_runs
                log_dispatch_result(
                    conn,
                    outcome="success",
                    duration_ms=elapsed_ms,
                    prompt_size_bytes=len(task_text.encode("utf-8")),
                    response_size_bytes=len(response_text.encode("utf-8")),
                    helm_layer=result.get("layer"),
                )
            else:
                log_dispatch_result(
                    conn,
                    outcome="dispatch_error",
                    duration_ms=0,
                    prompt_size_bytes=len(task_text.encode("utf-8")),
                    response_size_bytes=0,
                )
                sys.exit(1)

    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
