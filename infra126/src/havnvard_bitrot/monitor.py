from __future__ import annotations

from .alerts import AlertSink, fingerprint
from .repository import Repository


def _send_reserved(repository: Repository, sink: AlertSink, key: str, event_type: str, severity: str, host: str, path: str | None, payload: dict, *, suppress_hours: int) -> bool:
    if not repository.reserve_alert(key,event_type,severity,host,path,payload,suppress_hours=suppress_hours):
        return False
    try:
        sink.send(event_type,severity,payload)
    except Exception as exc:
        repository.mark_alert_failed(key,str(exc))
        raise
    repository.mark_alert_sent(key)
    return True


def monitor_once(
    repository: Repository,
    tg_sink: AlertSink,
    plane_sink: AlertSink | None = None,
    *,
    stale_minutes: int = 5,
    blocked_minutes: int = 30,
    sla_grace_days: int = 2,
) -> dict:
    plane_sink = plane_sink or tg_sink
    sent = 0
    findings: dict[str, list | int] = {"stale_runs": [], "blocked_runs": [], "overdue_slas": [], "confirmed_corruption": []}
    with repository.connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT run_id::text,host,tier,status,last_heartbeat_at,recovery_command,last_error
            FROM diskaudit.hash_verification_runs
            WHERE status='running' AND last_heartbeat_at < now()-make_interval(mins=>%s)
            """,
            (stale_minutes,),
        )
        columns = ["run_id","host","tier","status","last_heartbeat_at","recovery_command","last_error"]
        findings["stale_runs"] = [dict(zip(columns,row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT run_id::text,host,tier,status,last_heartbeat_at,recovery_command,last_error
            FROM diskaudit.hash_verification_runs
            WHERE status='blocked' AND last_heartbeat_at < now()-make_interval(mins=>%s)
            """,
            (blocked_minutes,),
        )
        findings["blocked_runs"] = [dict(zip(columns,row)) for row in cur.fetchall()]
        cur.execute(
            """
            SELECT host,tier,target_recheck_days,last_completed_at,last_successful_at,
                   next_scheduled_at,files_pending,critical_overdue_count,last_completed_status
            FROM diskaudit.hash_verification_sla
            WHERE (next_scheduled_at IS NOT NULL AND now()>next_scheduled_at +
                    CASE tier WHEN 'E' THEN interval '1 hour'
                              WHEN 'A' THEN interval '1 day'
                              ELSE make_interval(days=>%s) END)
               OR (next_scheduled_at IS NULL AND last_successful_at IS NULL
                   AND now()>created_at+make_interval(days=>target_recheck_days+%s))
            """,
            (sla_grace_days,sla_grace_days),
        )
        columns = ["host","tier","target_recheck_days","last_completed_at","last_successful_at","next_scheduled_at","files_pending","critical_overdue_count","last_completed_status"]
        findings["overdue_slas"] = [dict(zip(columns,row)) for row in cur.fetchall()]
        conn.rollback()

    for run in [*findings["stale_runs"],*findings["blocked_runs"]]:
        event = "stale_verification_run" if run["status"] == "running" else "waitingroom_blocked_too_long"
        key = fingerprint(event,run["host"],None,run["run_id"])
        payload = {**run,"message":"Verification control-plane progress is stale. Use the exact recovery command; never use pkill -f."}
        if _send_reserved(repository,tg_sink,key,event,"urgent",run["host"],None,payload,suppress_hours=1):
            sent += 1

    for sla in findings["overdue_slas"]:
        severity = "urgent" if sla["tier"] == "E" else "warning"
        key = fingerprint("verification_sla_overdue",sla["host"],None,sla["tier"])
        if _send_reserved(repository,tg_sink,key,"verification_sla_overdue",severity,sla["host"],None,sla,suppress_hours=24):
            sent += 1

    confirmed = repository.confirmed_corruption_pending_escalation()
    findings["confirmed_corruption"] = confirmed
    for suspect in confirmed:
        discriminator = str(suspect["divergence_id"])
        tg_key = fingerprint("confirmed_corruption",suspect["host"],suspect["path"],discriminator)
        plane_key = fingerprint("confirmed_corruption_plane",suspect["host"],suspect["path"],discriminator)
        if _send_reserved(repository,tg_sink,tg_key,"confirmed_corruption","critical",suspect["host"],suspect["path"],suspect,suppress_hours=168):
            sent += 1
        if _send_reserved(repository,plane_sink,plane_key,"confirmed_corruption","highest",suspect["host"],suspect["path"],suspect,suppress_hours=8760):
            repository.mark_suspect_plane_escalated(suspect["suspect_id"])
            sent += 1

    findings["alerts_sent"] = sent
    return findings
