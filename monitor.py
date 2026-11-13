#!/usr/bin/env python3
"""diskaudit v2 — monitor for stale/hung and failed scan/dedup/backup runs.

Polls diskaudit.scan_runs, diskaudit.dedup_runs, diskaudit.dedup_worker_status, and
diskaudit.backup_runs for two independent conditions and alerts to Telegram
(PRESIDENT group) when found:

  - STALE:  status='running' AND last_heartbeat_at older than --stale-minutes.
            Idempotent via `alerted_at IS NULL OR alerted_at < last_heartbeat_at` --
            a run that goes stale, gets alerted, then emits a NEW heartbeat (still
            running, just slow) becomes eligible to re-alert only if it goes stale
            AGAIN after that heartbeat. Without the `< last_heartbeat_at` half this
            would either spam (plain IS NULL, reset every run) or go permanently
            silent after the first alert.
  - ERROR:  status='failed' AND alerted_at IS NULL. One-shot -- failed is terminal
            for a run row, no re-check against heartbeat needed.

diskaudit.backup_runs (run_type='restic_backup' in heartbeat.py) is a lightweight
sibling of scan_runs/dedup_runs added for the havnvard-restic-* systemd timers
(daily backup; the weekly forget/prune timers are disabled since 3.2.0, INFRA-571). Same status/last_heartbeat_at/current_stage/
alerted_at columns, same STALE/ERROR semantics, no per-worker table (backups don't
fan out) -- see check_stale()/check_errors() below. Plane INFRA-98.

Meant to run periodically (systemd timer, e.g. every 5 minutes) but installing/
enabling that timer is a follow-up step for whoever reviews this -- this script
only needs to exist and work correctly when invoked.

Usage:
  monitor.py --dry-run                  # print what would be alerted, touch nothing
  monitor.py                            # real run: alert + stamp alerted_at
  monitor.py --test-mode                # prefix all outgoing messages with [TEST]
  monitor.py --stale-minutes 15         # override staleness threshold (default 10)

See: /home/user/.claude/plans/witty-swinging-shore.md, Plane INFRA-98.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import psycopg

# ---- DSN resolution — identical to scan.py / dedup.py get_dsn(), copied not
# reimported (heartbeat.py is the only intentionally shared module so far).
from havnvard_site import get_dsn  # noqa: E402,F401  (3.0.0: one shared lookup; see havnvard_site.py)


# ---- Telegram — direct HTTPS POST via urllib (requests is not installed in
# this venv: only psycopg[binary] is in requirements.txt/checked at runtime
# below). Deliberately NOT importing a full Telegram bot -- that would be
# a large stateful bot with its own dedup-claim/psycopg2
# machinery meant for a different purpose; this is a minimal standalone POST.
import havnvard_site as _site  # noqa: E402  (3.0.0: token and chat id come from env or the site's env_file)


def get_bot_token() -> str | None:
    return _site.secret_value("AGENT_BOT_TOKEN")


def get_chat_id() -> int | None:
    """TG_PRESIDENT_CHAT from env or the site's env_file, else [telegram] chat_id in the site file. No built-in
    default: an unconfigured chat means the alert is NOT sent, and send_telegram() says so."""
    v = _site.secret_value("TG_PRESIDENT_CHAT") or _site.section("telegram").get("chat_id")
    return int(v) if v not in (None, "") else None


def _esc(s) -> str:
    """HTML-escape for parse_mode=HTML, same three substitutions tg_bot.py uses.
    Checks `is None` rather than truthiness -- worker_idx=0 and similar falsy-
    but-meaningful values must not be blanked out."""
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send_telegram(text: str, test_mode: bool) -> bool:
    """Returns True on confirmed delivery (Telegram API responded ok=true).
    Raises/returns False (with a stderr print) on any failure -- caller must
    NOT stamp alerted_at unless this returns True, so a Telegram outage
    naturally results in a retry next monitor cycle instead of a silent miss."""
    token = get_bot_token()
    if not token:
        print("[monitor] ERROR: AGENT_BOT_TOKEN not set (env or the site env_file) "
              "-- cannot send Telegram alert", file=sys.stderr)
        return False
    chat_id = get_chat_id()
    if chat_id is None:
        print("[monitor] ERROR: no Telegram chat configured (TG_PRESIDENT_CHAT or [telegram] chat_id) "
              "-- cannot send Telegram alert", file=sys.stderr)
        return False
    if test_mode:
        text = "[TEST] " + text
    payload = {
        "chat_id": str(chat_id),
        "text": text[:4000],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[monitor] ERROR: Telegram send failed: {e}", file=sys.stderr)
        return False
    if not data.get("ok"):
        print(f"[monitor] ERROR: Telegram API returned not-ok: {data}", file=sys.stderr)
        return False
    mid = data.get("result", {}).get("message_id")
    print(f"[monitor] Telegram message sent, message_id={mid}", file=sys.stderr)
    return True


# ---- detection ----

def _age_str(last_heartbeat_at: datetime) -> str:
    if last_heartbeat_at is None:
        return "unknown"
    now = datetime.now(timezone.utc)
    delta = now - last_heartbeat_at
    total_s = int(delta.total_seconds())
    m, s = divmod(max(total_s, 0), 60)
    return f"{m}m{s:02d}s"


def check_stale(conn, stale_minutes: int, host_filter: str | None = None) -> list[dict]:
    alerts = []
    host_clause = "AND host = %s" if host_filter else ""
    host_clause_dr = "AND dr.host = %s" if host_filter else ""
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT scan_id, host, current_stage, last_heartbeat_at
            FROM diskaudit.scan_runs
            WHERE status = 'running'
              AND last_heartbeat_at < now() - make_interval(mins => %s)
              AND (alerted_at IS NULL OR alerted_at < last_heartbeat_at)
              {host_clause}
            """,
            (stale_minutes, host_filter) if host_filter else (stale_minutes,),
        )
        for scan_id, host, stage, hb in cur.fetchall():
            alerts.append({
                "kind": "stale", "run_type": "scan", "table": "diskaudit.scan_runs",
                "pk": {"scan_id": scan_id}, "run_id": scan_id, "host": host,
                "stage": stage, "last_heartbeat_at": hb,
            })

        cur.execute(
            f"""
            SELECT dedup_run_id, host, current_stage, last_heartbeat_at
            FROM diskaudit.dedup_runs
            WHERE status = 'running'
              AND last_heartbeat_at < now() - make_interval(mins => %s)
              AND (alerted_at IS NULL OR alerted_at < last_heartbeat_at)
              {host_clause}
            """,
            (stale_minutes, host_filter) if host_filter else (stale_minutes,),
        )
        for dedup_run_id, host, stage, hb in cur.fetchall():
            alerts.append({
                "kind": "stale", "run_type": "dedup", "table": "diskaudit.dedup_runs",
                "pk": {"dedup_run_id": dedup_run_id}, "run_id": dedup_run_id, "host": host,
                "stage": stage, "last_heartbeat_at": hb,
            })

        cur.execute(
            f"""
            SELECT dws.dedup_run_id, dws.worker_idx, dr.host, dws.current_stage, dws.last_heartbeat_at
            FROM diskaudit.dedup_worker_status dws
            JOIN diskaudit.dedup_runs dr ON dr.dedup_run_id = dws.dedup_run_id
            WHERE dws.status = 'running'
              AND dws.last_heartbeat_at < now() - make_interval(mins => %s)
              AND (dws.alerted_at IS NULL OR dws.alerted_at < dws.last_heartbeat_at)
              {host_clause_dr}
            """,
            (stale_minutes, host_filter) if host_filter else (stale_minutes,),
        )
        for dedup_run_id, worker_idx, host, stage, hb in cur.fetchall():
            alerts.append({
                "kind": "stale", "run_type": "dedup_worker", "table": "diskaudit.dedup_worker_status",
                "pk": {"dedup_run_id": dedup_run_id, "worker_idx": worker_idx},
                "run_id": dedup_run_id, "worker_idx": worker_idx, "host": host,
                "stage": stage, "last_heartbeat_at": hb,
            })

        cur.execute(
            f"""
            SELECT run_id, host, current_stage, last_heartbeat_at
            FROM diskaudit.backup_runs
            WHERE status = 'running'
              AND last_heartbeat_at < now() - make_interval(mins => %s)
              AND (alerted_at IS NULL OR alerted_at < last_heartbeat_at)
              {host_clause}
            """,
            (stale_minutes, host_filter) if host_filter else (stale_minutes,),
        )
        for run_id, host, stage, hb in cur.fetchall():
            alerts.append({
                "kind": "stale", "run_type": "restic_backup", "table": "diskaudit.backup_runs",
                "pk": {"run_id": run_id}, "run_id": run_id, "host": host,
                "stage": stage, "last_heartbeat_at": hb,
            })
    return alerts


def check_errors(conn, host_filter: str | None = None) -> list[dict]:
    alerts = []
    host_clause = "AND host = %s" if host_filter else ""
    host_clause_dr = "AND dr.host = %s" if host_filter else ""
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT scan_id, host, current_stage, finished_at
            FROM diskaudit.scan_runs
            WHERE status = 'failed' AND alerted_at IS NULL
              {host_clause}
            """,
            (host_filter,) if host_filter else (),
        )
        for scan_id, host, stage, finished_at in cur.fetchall():
            alerts.append({
                "kind": "error", "run_type": "scan", "table": "diskaudit.scan_runs",
                "pk": {"scan_id": scan_id}, "run_id": scan_id, "host": host,
                "stage": stage, "finished_at": finished_at,
            })

        cur.execute(
            f"""
            SELECT dedup_run_id, host, current_stage, finished_at
            FROM diskaudit.dedup_runs
            WHERE status = 'failed' AND alerted_at IS NULL
              {host_clause}
            """,
            (host_filter,) if host_filter else (),
        )
        for dedup_run_id, host, stage, finished_at in cur.fetchall():
            alerts.append({
                "kind": "error", "run_type": "dedup", "table": "diskaudit.dedup_runs",
                "pk": {"dedup_run_id": dedup_run_id}, "run_id": dedup_run_id, "host": host,
                "stage": stage, "finished_at": finished_at,
            })

        cur.execute(
            f"""
            SELECT dws.dedup_run_id, dws.worker_idx, dr.host, dws.current_stage, dws.finished_at
            FROM diskaudit.dedup_worker_status dws
            JOIN diskaudit.dedup_runs dr ON dr.dedup_run_id = dws.dedup_run_id
            WHERE dws.status = 'failed' AND dws.alerted_at IS NULL
              {host_clause_dr}
            """,
            (host_filter,) if host_filter else (),
        )
        for dedup_run_id, worker_idx, host, stage, finished_at in cur.fetchall():
            alerts.append({
                "kind": "error", "run_type": "dedup_worker", "table": "diskaudit.dedup_worker_status",
                "pk": {"dedup_run_id": dedup_run_id, "worker_idx": worker_idx},
                "run_id": dedup_run_id, "worker_idx": worker_idx, "host": host,
                "stage": stage, "finished_at": finished_at,
            })

        cur.execute(
            f"""
            SELECT run_id, host, current_stage, finished_at
            FROM diskaudit.backup_runs
            WHERE status = 'failed' AND alerted_at IS NULL
              {host_clause}
            """,
            (host_filter,) if host_filter else (),
        )
        for run_id, host, stage, finished_at in cur.fetchall():
            alerts.append({
                "kind": "error", "run_type": "restic_backup", "table": "diskaudit.backup_runs",
                "pk": {"run_id": run_id}, "run_id": run_id, "host": host,
                "stage": stage, "finished_at": finished_at,
            })
    return alerts


def format_message(alert: dict) -> str:
    run_type_label = {
        "scan": "scan", "dedup": "dedup", "dedup_worker": "dedup worker",
        "restic_backup": "restic backup",
    }[alert["run_type"]]
    if alert["kind"] == "stale":
        head = "⚠️ <b>STALE diskaudit run</b>"  # warning sign emoji
        lines = [
            head,
            f"type: {run_type_label}",
            f"run_id: {_esc(alert['run_id'])}",
        ]
        if "worker_idx" in alert:
            lines.append(f"worker_idx: {_esc(alert['worker_idx'])}")
        lines += [
            f"host: {_esc(alert['host'])}",
            f"current_stage: {_esc(alert['stage']) or '(none recorded)'}",
            f"last heartbeat: {_age_str(alert['last_heartbeat_at'])} ago"
            f" ({_esc(alert['last_heartbeat_at'])})",
        ]
        return "\n".join(lines)
    else:  # error
        head = "\U0001f534 <b>ERROR diskaudit run</b>"  # red circle emoji
        lines = [
            head,
            f"type: {run_type_label}",
            f"run_id: {_esc(alert['run_id'])}",
        ]
        if "worker_idx" in alert:
            lines.append(f"worker_idx: {_esc(alert['worker_idx'])}")
        lines += [
            f"host: {_esc(alert['host'])}",
            f"current_stage at failure: {_esc(alert['stage']) or '(none recorded)'}",
            f"finished_at: {_esc(alert['finished_at'])}",
        ]
        return "\n".join(lines)


def mark_alerted(conn, alert: dict):
    where = " AND ".join(f"{col} = %s" for col in alert["pk"])
    params = tuple(alert["pk"].values())
    with conn.cursor() as cur:
        cur.execute(f"UPDATE {alert['table']} SET alerted_at = now() WHERE {where}", params)
    conn.commit()


# ---- shared incident dedup (20260725 post-mortem: this script crashed
# silently for 35h while Postgres was down, then burst 5 messages in one
# second at recovery). alertlib coordinates ONE deduped "DB unreachable"
# notice across all DB-dependent alerting scripts; optional import so the
# monitor never dies because the helper is missing.
def _alertlib():
    try:
        import havnvard_site as _hs  # noqa: PLC0415
        alertlib = _hs.import_alertlib()
        return alertlib
    except Exception:  # noqa: BLE001
        return None


def batch_message(alerts: list[dict]) -> str:
    """ONE Telegram message for everything found this run (post-recovery
    catch-up used to send one message per stale table within the same second)."""
    parts = [format_message(a) for a in alerts]
    if len(parts) == 1:
        return parts[0]
    head = (f"\U0001f4e6 <b>diskaudit — {len(alerts)} conditions in one run</b> "
            "(batched; likely one root cause)")
    return "\n\n".join([head] + parts)[:4000]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stale-minutes", type=int, default=10,
                     help="Minutes since last_heartbeat_at before a running run/worker is considered stale (default 10).")
    ap.add_argument("--dry-run", action="store_true",
                     help="Print what WOULD be alerted; do not call Telegram, do not touch alerted_at.")
    ap.add_argument("--test-mode", action="store_true",
                     help="Prefix outgoing Telegram messages with [TEST] (for end-to-end delivery testing).")
    ap.add_argument("--host", default=None,
                     help="Restrict detection to a single host tag (e.g. for scoped testing). Default: all hosts.")
    args = ap.parse_args()

    lib = _alertlib()
    try:
        conn = psycopg.connect(get_dsn(), autocommit=False, connect_timeout=10)
    except psycopg.OperationalError as e:
        # DB outage must surface as ONE deduped actionable alert, not silence
        # (and not six alerts across the six DB-dependent scripts).
        print(f"[monitor] ERROR: database unreachable: {e}", file=sys.stderr)
        if lib and not args.dry_run:
            lib.db_down("diskaudit-monitor", e)
        sys.exit(75)  # EX_TEMPFAIL — unit shows failed; fleet-sweep sees it
    if lib and not args.dry_run:
        lib.db_up("diskaudit-monitor")  # one recovery notice if an outage marker existed
    try:
        stale_alerts = check_stale(conn, args.stale_minutes, args.host)
        error_alerts = check_errors(conn, args.host)
        all_alerts = stale_alerts + error_alerts

        if not all_alerts:
            print(f"[monitor] no stale (>{args.stale_minutes}m) or failed runs found", file=sys.stderr)
            return

        print(f"[monitor] {len(stale_alerts)} stale, {len(error_alerts)} error condition(s) found", file=sys.stderr)

        # ONE batched message per run (defect: post-recovery burst was N
        # messages in the same second, all one incident).
        text = batch_message(all_alerts)
        if args.dry_run:
            print("----- [DRY-RUN] would send (single batched message): -----", file=sys.stderr)
            print(text, file=sys.stderr)
            print("----------------------------------", file=sys.stderr)
            return
        sent = send_telegram(text, test_mode=args.test_mode)
        if sent:
            for alert in all_alerts:
                mark_alerted(conn, alert)
        else:
            print(f"[monitor] WARNING: {len(all_alerts)} condition(s) NOT marked "
                  "alerted (send failed) -- will retry next run", file=sys.stderr)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except _site.SiteConfigError as e:   # review N3: one clear line, non-zero exit (the unit shows failed)
        print(f"[monitor] ERROR: site configuration: {e}", file=sys.stderr)
        sys.exit(2)
