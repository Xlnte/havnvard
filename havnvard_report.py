#!/usr/bin/env python3
"""HavnVard — storage-inventory METADATA report for the TG President group.

Generates a phone-scannable daily metadata report (counts, bytes, freshness,
dedup, backup coverage, errors, growth deltas) from the diskaudit schema and
posts it to TG PRESI. Also persists a daily snapshot so day-over-day deltas work.

Design ratified via PRESCAB:creative cabinet 20260719 (runbook
20260719-havnvard-presi-report). METADATA-only: no file contents, no actions.

Usage:
    havnvard_report.py                 # collect, snapshot, render, SEND to PRESI
    havnvard_report.py --dry-run       # collect + render + print, DO NOT send/snapshot
    havnvard_report.py --no-send       # collect + snapshot + print, do not send

DSN: POSTGRES_URL (same SoT as scan.py/monitor.py). TG: AGENT_BOT_TOKEN +
TG_PRESIDENT_CHAT (or [telegram] chat_id in the site file; no default).
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import date

import psycopg


# ---- config (3.0.0: everything site-specific comes from havnvard_site) ----
import havnvard_site as _site  # noqa: E402


def get_dsn() -> str:
    return _site.require_dsn()


def tg_token() -> str:
    return _site.secret_value("AGENT_BOT_TOKEN") or ""


def tg_chat() -> int | None:
    v = _site.secret_value("TG_PRESIDENT_CHAT") or _site.section("telegram").get("chat_id")
    return int(v) if v not in (None, "") else None


# Optional deep link to a dashboard, shown at the end of the report ([ui] dashboard_url).
DASHBOARD_URL = _site.ui("dashboard_url")
# Display name of this machine in the daily report ([report] local_label; default its host name).
LOCAL_LABEL = _site.section("report").get("local_label") or _site.local_host()


# ---- snapshot table (created on first run) -------------------------------
SNAPSHOT_DDL = """
CREATE TABLE IF NOT EXISTS diskaudit.report_snapshots (
    snap_date        date PRIMARY KEY,
    total_files      bigint,
    total_bytes      bigint,
    spark_files      bigint,
    spark_bytes      bigint,
    nas_files        bigint,
    nas_bytes        bigint,
    dup_files        bigint,
    dup_groups       bigint,
    reclaimable_bytes bigint,
    scan_errors      bigint,
    created_at       timestamptz DEFAULT now()
);
"""


# ---- helpers -------------------------------------------------------------
def human_bytes(n: int | None) -> str:
    if not n:
        return "0 B"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} EB"


def human_count(n: int | None) -> str:
    if not n:
        return "0"
    n = float(n)
    for unit in ("", "K", "M", "B"):
        if abs(n) < 1000:
            return f"{n:.0f}{unit}" if unit == "" else f"{n:.2f}{unit}".rstrip("0").rstrip(".") + unit if False else f"{n:.1f}{unit}"
        n /= 1000
    return f"{n:.1f}T"


def _hc(n):  # compact count: 10.69M
    if not n:
        return "0"
    n = float(n)
    for u in ("", "K", "M", "B"):
        if abs(n) < 1000:
            return (f"{n:.0f}" if u == "" else f"{n:.2f}{u}")
        n /= 1000
    return f"{n:.2f}T"


# ---- data layer (fast aggregates only — no heavy join-views) -------------
def collect_metrics(conn) -> dict:
    cur = conn.cursor()
    m: dict = {"as_of": None}

    cur.execute("select host, count(*), coalesce(sum(size_bytes),0) from diskaudit.files group by host")
    by_host = {r[0]: {"files": r[1], "bytes": r[2]} for r in cur.fetchall()}
    m["spark"] = by_host.get(_site.local_host(), {"files": 0, "bytes": 0})   # key kept: daily-metrics column names
    m["nas"] = by_host.get(_site.nas_host(), {"files": 0, "bytes": 0})
    m["total_files"] = m["spark"]["files"] + m["nas"]["files"]
    m["total_bytes"] = m["spark"]["bytes"] + m["nas"]["bytes"]

    # top NAS shares
    cur.execute("""
        select split_part(regexp_replace(path, %s, ''),'/',1) share,
               count(*) files, coalesce(sum(size_bytes),0) bytes
        from diskaudit.files where host = %s
        group by 1 order by 3 desc nulls last limit 6""", ("^" + _site.nas_share_base().rstrip("/") + "/", _site.nas_host()))
    m["nas_shares"] = [{"share": r[0], "files": r[1], "bytes": r[2]} for r in cur.fetchall()]

    # dedup totals (spark)
    cur.execute("""
        select coalesce(sum(file_count),0), count(*), coalesce(sum(reclaimable_bytes),0)
        from diskaudit.v_duplicate_groups_by_host""")
    d = cur.fetchone()
    m["dup_files"], m["dup_groups"], m["reclaimable_bytes"] = d[0], d[1], d[2]

    # errors + activity
    cur.execute("select count(*) from diskaudit.scan_errors")
    m["scan_errors"] = cur.fetchone()[0]
    cur.execute("select count(*) from diskaudit.scan_runs where status='running'")
    m["running_scans"] = cur.fetchone()[0]

    # freshness: last completed scan per host
    cur.execute("select host, max(finished_at) from diskaudit.scan_runs where status='completed' group by host")
    m["freshness"] = {r[0]: r[1] for r in cur.fetchall()}

    m["capacity"] = collect_capacity()
    return m


def collect_capacity() -> dict:
    """Real filesystem utilization (used vs total provisioned) — the cabinet's #1 ask.

    the server `/` and the NAS volume mounted at /mnt/nas-diskaudit; both read via statvfs.
    Returns {} entries as None if a mount is unavailable (graceful)."""
    out = {}
    for name, path in (("spark", "/"), ("nas", "/mnt/nas-diskaudit")):
        try:
            s = os.statvfs(path)
            total = s.f_blocks * s.f_frsize
            used = (s.f_blocks - s.f_bfree) * s.f_frsize
            out[name] = {"total": total, "used": used, "pct": (used / total * 100) if total else 0.0}
        except Exception:
            out[name] = None
    return out


def snapshot_and_delta(conn, m: dict, *, persist: bool) -> dict:
    """Upsert today's snapshot; return deltas vs the most recent PRIOR snapshot."""
    cur = conn.cursor()
    cur.execute(SNAPSHOT_DDL)
    cur.execute("""
        select total_files, total_bytes, dup_files, reclaimable_bytes, scan_errors, snap_date
        from diskaudit.report_snapshots
        where snap_date < %s order by snap_date desc limit 1""", (date.today(),))
    prev = cur.fetchone()
    delta = {}
    if prev:
        delta = {
            "files": m["total_files"] - (prev[0] or 0),
            "bytes": m["total_bytes"] - (prev[1] or 0),
            "dup_files": m["dup_files"] - (prev[2] or 0),
            "reclaimable_bytes": m["reclaimable_bytes"] - (prev[3] or 0),
            "scan_errors": m["scan_errors"] - (prev[4] or 0),
            "since": prev[5],
        }
    if persist:
        cur.execute("""
            insert into diskaudit.report_snapshots
              (snap_date,total_files,total_bytes,spark_files,spark_bytes,nas_files,nas_bytes,
               dup_files,dup_groups,reclaimable_bytes,scan_errors)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            on conflict (snap_date) do update set
              total_files=excluded.total_files, total_bytes=excluded.total_bytes,
              spark_files=excluded.spark_files, spark_bytes=excluded.spark_bytes,
              nas_files=excluded.nas_files, nas_bytes=excluded.nas_bytes,
              dup_files=excluded.dup_files, dup_groups=excluded.dup_groups,
              reclaimable_bytes=excluded.reclaimable_bytes, scan_errors=excluded.scan_errors""",
            (date.today(), m["total_files"], m["total_bytes"], m["spark"]["files"], m["spark"]["bytes"],
             m["nas"]["files"], m["nas"]["bytes"], m["dup_files"], m["dup_groups"],
             m["reclaimable_bytes"], m["scan_errors"]))
        conn.commit()
    return delta


# ---- render (FINAL layout set after PRESCAB:creative — see render() below)
def _sign(n, unit="", *, bytes_=False):
    if n is None:
        return ""
    arrow = "▲" if n > 0 else ("▼" if n < 0 else "▬")
    val = human_bytes(abs(n)) if bytes_ else f"{abs(n):,}"
    return f" {arrow}{val}{unit}"


def _fresh_flag(ts) -> str:
    if not ts:
        return "⚠️ never"
    from datetime import datetime, timezone
    age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
    stamp = ts.strftime("%m-%d %H:%M")
    return f"{stamp} {'✅' if age_h <= 26 else '⚠️ stale'}"


def _cap_line(label: str, c: dict | None) -> str:
    if not c:
        return f"  {label}  (unmounted)"
    flag = "⚠️" if c["pct"] >= 85 else ("🟡" if c["pct"] >= 75 else "✅")
    return f"  {label}  {c['pct']:.0f}% full · {human_bytes(c['used'])}/{human_bytes(c['total'])}  {flag}"


def render(m: dict, delta: dict) -> str:
    # v2 — PRESCAB:creative SHIP-WITH-TWEAKS (20260719): lead with reclaimable + capacity
    # ratio; errors demoted to a trend line; reclaimable delta elevated.
    sp, na, cap = m["spark"], m["nas"], m.get("capacity", {})
    recl_delta = _sign(delta["reclaimable_bytes"], bytes_=True) if delta else ""
    lines = [
        "🗄️ HAVNVARD · Storage Inventory — METADATA REPORT",
        f"📅 {date.today():%Y%m%d} · daily",
        "",
        f"♻️ RECLAIMABLE  {human_bytes(m['reclaimable_bytes'])}{recl_delta}"
        f"   ({_hc(m['dup_files'])} dupes / {_hc(m['dup_groups'])} groups, {LOCAL_LABEL})",
        "",
        "💾 CAPACITY  (used / provisioned)",
        _cap_line(f"🖥️ {LOCAL_LABEL}", cap.get("spark")),
        _cap_line("🛜 NAS  ", cap.get("nas")),
        "",
        f"📊 {_hc(m['total_files'])} files indexed · 2 hosts",
        f"  🖥️ {LOCAL_LABEL} {_hc(sp['files'])} · {human_bytes(sp['bytes'])}  ⟳ {_fresh_flag(m['freshness'].get(_site.local_host()))}",
        f"  🛜 NAS   {_hc(na['files'])} · {human_bytes(na['bytes'])}  ⟳ {_fresh_flag(m['freshness'].get(_site.nas_host()))}",
        "",
        "📁 Top NAS shares",
    ]
    for s in m["nas_shares"]:
        if s["bytes"] < 1024 * 1024:
            continue
        tag = "  ⏳" if m["running_scans"] and s["share"] in tuple(_site.section("report").get("slow_shares") or ()) else ""
        lines.append(f"  {s['share']:<12}{_hc(s['files']):>7}  {human_bytes(s['bytes']):>9}{tag}")

    # health — errors as a daily trend, not a raw headline number
    err_trend = _sign(delta["scan_errors"]) if delta else " (Δ from next run)"
    lines += ["", f"🩺 Health  {m['scan_errors']:,} scan errors{err_trend} · 🟢 {m['running_scans']} scans running"]

    if delta:
        lines += ["", f"📈 Since {delta['since']:%m-%d}:"
                  f"{_sign(delta['reclaimable_bytes'], bytes_=True)} reclaimable"
                  f" ·{_sign(delta['files'])} files"
                  f" ·{_sign(delta['bytes'], bytes_=True)} data"]
    else:
        lines += ["", "📈 Deltas: baseline set — day-over-day starts next run (reclaimable Δ leads)."]

    if DASHBOARD_URL:
        lines += ["", f"🔗 {DASHBOARD_URL}"]
    return "\n".join(lines)


DESCRIPTORS = (
    "━━━━━━━━━━━━━━━━━━\n"
    "🎨 DESIGN DESCRIPTORS — v2, PRESCAB:creative ratified (SHIP-WITH-TWEAKS, 10/10 VPs)\n\n"
    "• ♻️ RECLAIMABLE (leads) — the actionable 'free GB' number, elevated to the top per unanimous VP ask; "
    "its day-over-day Δ is the single most-wanted daily signal.\n"
    "• 💾 CAPACITY (used/provisioned) — real filesystem utilization per host with ✅/🟡/⚠️ at 75/85%. "
    "The #1 missing metric the cabinet identified; surfaces near-full disks before they bite.\n"
    "• 📊 Files indexed + per-host — inventory scale with ⟳ freshness + ✅/⚠️ staleness (⚠️ if >26h, a stalled crawl).\n"
    "• 📁 Top NAS shares — where bytes live; ⏳ marks an in-flight crawl (partial numbers expected).\n"
    "• 🩺 Health — scan errors shown as a daily TREND (Δ), not a raw headline (VP request), + live scans.\n"
    "• 📈 Deltas — day-over-day ▲/▼ led by reclaimable, then files/data. The reason for the daily cadence.\n"
    "• 🔗 Dashboard — MUNINN/Grafana drill-down, per the completion-report standard.\n\n"
    "Metadata-only by design: no file contents, no actions — just the state of the inventory.\n"
    "Open follow-up (cabinet): per-share used-vs-total capacity needs a provisioning source; tracked for v3."
)


def build_presi_message(m: dict, delta: dict) -> str:
    return render(m, delta) + "\n\n" + DESCRIPTORS


def send_to_presi(text: str) -> dict:
    # stdlib only — the systemd daily job runs under diskaudit/.venv (no httpx).
    import json as _json
    import urllib.request
    tok, chat = tg_token(), tg_chat()
    if not tok:
        raise SystemExit("AGENT_BOT_TOKEN not available")
    if chat is None:
        raise SystemExit("no Telegram chat configured (TG_PRESIDENT_CHAT or [telegram] chat_id)")
    body = _json.dumps({"chat_id": chat, "text": text, "disable_web_page_preview": True}).encode("utf-8")
    req = urllib.request.Request(f"https://api.telegram.org/bot{tok}/sendMessage",
                                 data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return _json.loads(r.read().decode("utf-8"))


def run_prescab_analysis(report_text: str) -> str | None:
    """Dispatch the daily metadata report to PRESCAB for operational analysis.

    logic_governance mode (operational, not creative). Returns the analysis text,
    or None on any error — FAIL-OPEN so the report itself always goes out even if
    the LLM is down/cycling.

    JOBS-119: migrated off raw urllib to prescab_client.dispatch(). Deliberately
    fallback_to_cabinet=False — a failed/empty single-VP call must NOT silently
    escalate to a ~10-20x-more-expensive /cabinet call.
    """
    try:
        from prescab_client import dispatch as _prescab_dispatch  # noqa: PLC0415
    except ImportError as e:   # optional integration (requirements-optional.txt): skip, never kill the report (F3)
        print(f"[analyze] prescab_client not installed (optional); skipping analysis: {e}", file=sys.stderr)
        return None
    agent = os.environ.get("HAVNVARD_ANALYSIS_AGENT", "vp-operations")
    task = (
        "DAILY OPERATIONAL ANALYSIS — HavnVard storage inventory (metadata only).\n"
        "Analyze today's report below. In <=6 terse operational bullets: "
        "(1) is the day-over-day change normal growth or an anomaly; "
        "(2) the single top storage risk right now (unbacked data, stale/stalled crawl, "
        "error spike, a share growing out of control); "
        "(3) reclaimable-space opportunity worth acting on; "
        "(4) ONE concrete recommended action, or 'none — steady state'. "
        "No fluff, no restating the numbers.\n\n" + report_text
    )
    try:
        result = _prescab_dispatch(
            agent, task,
            mode="logic_governance",
            submitted_by="havnvard_daily",
            include_memory=False,
            timeout_s=300,
            fallback_to_cabinet=False,
        )
        if result.outcome != "success":
            print(f"[analyze] PRESCAB dispatch failed (fail-open): outcome={result.outcome}", file=sys.stderr)
            return None
        return result.response or None
    except Exception as e:
        print(f"[analyze] PRESCAB dispatch failed (fail-open): {e}", file=sys.stderr)
        return None


def run_verification_section() -> str | None:
    """INFRA-126 bit-rot verification assurance section.

    Fail-open like run_prescab_analysis: the storage-inventory report must
    always ship even if INFRA-126 is mid-rollout or its DB objects lag.
    """
    try:
        from havnvard_bitrot.reporting import verification_report  # noqa: PLC0415
        from havnvard_bitrot.repository import Repository  # noqa: PLC0415
        return verification_report(Repository(get_dsn()))
    except Exception as e:  # noqa: BLE001
        print(f"[verification] INFRA-126 section unavailable (fail-open): {e}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="collect+render+print; no snapshot, no send")
    ap.add_argument("--no-send", action="store_true", help="snapshot but do not send to TG")
    ap.add_argument("--analyze", action="store_true", help="after report, run daily PRESCAB analysis + post it")
    ap.add_argument("--descriptors", action="store_true", help="append design descriptors to the report")
    args = ap.parse_args()

    # 20260725 post-mortem: this script crashed silently for the whole 35h PG
    # outage. DB-down now surfaces as ONE deduped notice via shared alertlib
    # (coordinated with the other five DB-dependent scripts), then exits 75.
    def _alertlib():
        try:
            import havnvard_site as _hs  # noqa: PLC0415
            alertlib = _hs.import_alertlib()
            return alertlib
        except Exception:  # noqa: BLE001
            return None

    lib = _alertlib()
    try:
        conn = psycopg.connect(get_dsn(), autocommit=False, connect_timeout=10)
    except psycopg.OperationalError as e:
        print(f"[havnvard] ERROR: database unreachable: {e}", file=sys.stderr)
        if lib and not args.dry_run:
            lib.db_down("havnvard-report", e)
        sys.exit(75)  # EX_TEMPFAIL
    if lib and not args.dry_run:
        lib.db_up("havnvard-report")
    try:
        m = collect_metrics(conn)
        delta = snapshot_and_delta(conn, m, persist=not args.dry_run)
        report = render(m, delta)
        text = build_presi_message(m, delta) if args.descriptors else report
        print(text)
        if not args.dry_run and not args.no_send:
            res = send_to_presi(text)
            print("REPORT SENT:", res.get("ok"))
        verification = run_verification_section()
        if verification:
            hdr = "🔍 INFRA-126 — Bit-rot Verification Assurance\n\n"
            if not args.dry_run and not args.no_send:
                v = send_to_presi(hdr + verification)
                print("VERIFICATION SENT:", v.get("ok"))
            else:
                print(hdr + verification)
        else:
            print("VERIFICATION SKIPPED (INFRA-126 unavailable — report still delivered)")
        if args.analyze and not args.dry_run:
            analysis = run_prescab_analysis(report)
            if analysis:
                hdr = "🧠 PRESCAB — HavnVard daily analysis\n\n"
                if not args.no_send:
                    a = send_to_presi(hdr + analysis)
                    print("ANALYSIS SENT:", a.get("ok"))
                else:
                    print(hdr + analysis)
            else:
                print("ANALYSIS SKIPPED (PRESCAB unavailable — report still delivered)")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
