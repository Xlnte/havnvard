from __future__ import annotations

from .repository import Repository


def verification_report(repository: Repository) -> str:
    with repository.connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT host,
                   count(*) FILTER (WHERE last_verified_at >= now()-interval '7 days') AS within_7d,
                   count(*) FILTER (WHERE last_verified_at >= now()-interval '30 days') AS within_30d,
                   count(*) FILTER (WHERE last_verified_at >= now()-interval '90 days') AS within_90d,
                   count(*) FILTER (WHERE content_sha256 IS NOT NULL) AS baselined,
                   count(*) FILTER (WHERE content_sha256 IS NOT NULL AND last_verified_at IS NULL) AS baseline_only
            FROM diskaudit.v_infra126_verification_age
            GROUP BY host ORDER BY host
            """
        )
        coverage = cur.fetchall()
        cur.execute("SELECT count(*) FROM diskaudit.corruption_suspects WHERE operator_verdict IS NULL")
        suspects = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM diskaudit.hash_divergences WHERE created_at>=date_trunc('month',now())")
        divergences = int(cur.fetchone()[0])
        cur.execute(
            """
            SELECT host,tier,last_completed_at,last_successful_at,next_scheduled_at,
                   files_total,files_on_time,files_pending,pct_on_time,sla_state,last_completed_status
            FROM diskaudit.v_infra126_sla_status ORDER BY host,tier
            """
        )
        slas = cur.fetchall()
        conn.rollback()

    lines = ["Verification Assurance Status"]
    for host,d7,d30,d90,total,baseline_only in coverage:
        pct = lambda value: 0.0 if not total else 100.0*value/total
        lines.append(
            f"{host}: {pct(d7):.1f}% re-verified <7d; {pct(d30):.1f}% <30d; "
            f"{pct(d90):.1f}% <90d; {total:,} baselined; {baseline_only:,} baseline-only"
        )
    lines.append(f"Open corruption suspects: {suspects:,}")
    lines.append(f"Hash divergences this month: {divergences:,}")
    for host,tier,last_done,last_success,next_due,total,on_time,pending,pct,state,last_status in slas:
        lines.append(
            f"{host} Tier-{tier}: {pct:.1f}% on-time ({on_time:,}/{total:,}); pending={pending:,}; "
            f"state={state}; last={last_done or 'NEVER'}; successful={last_success or 'NEVER'}; "
            f"next={next_due or 'UNSCHEDULED'}; last_status={last_status or 'NONE'}"
        )
    return "\n".join(lines)
