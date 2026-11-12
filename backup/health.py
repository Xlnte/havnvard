"""`health`: is every repo fresh, did the last job work, is there room, is it offsite?

Exit 0 healthy, 1 a check found a problem, 2 the check itself could not run (never a silent pass).
Snapshot age is read from the newest file in <repo>/snapshots/ (written when a snapshot completes), which
needs no repository password. Alerts go through backup/alerts.py (alertlib or an alert command).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import alerts, config
from .config import BackupError

GB = 1024 ** 3
ALERT_KEY = "havnvard-backup-health"


def _newest_snapshot_age_h(repo: Path, now: float, skip: frozenset = frozenset()) -> float | None:
    """`skip` = catalog snapshot ids (2.2.0): those are written by the hub every run and say nothing about
    whether the device itself backed up."""
    sdir = repo / "snapshots"
    if not sdir.is_dir():
        return None
    mt = [e.stat().st_mtime for e in os.scandir(sdir) if e.is_file() and e.name not in skip]
    return (now - max(mt)) / 3600 if mt else None


def collect(now: float | None = None) -> list[tuple[str, bool, str]]:
    now = time.time() if now is None else now
    cfg = config.load()
    h = cfg.get("health", {})
    stale_h = float(h.get("stale_hours", 26))
    res: list[tuple[str, bool, str]] = []
    hub = cfg.get("hub_local")
    if hub:
        root = Path(hub["repo_root"])
        if not root.is_dir():
            res.append(("hub repo root", False, f"{root} is not a directory"))
        else:
            repos = sorted(p for p in root.iterdir() if p.is_dir() and (p / "config").is_file())
            if not repos:
                res.append(("hub repos", False, f"no restic repositories found under {root}"))
            from .catalog import catalog_snapshot_ids
            skip = frozenset(catalog_snapshot_ids())
            archives = set(h.get("archive_repos", []))   # 2.2.5: one-time archives (e.g. an old-laptop-2023 archive): no age limit
            for r in repos:
                age = _newest_snapshot_age_h(r, now, skip)
                if age is None:
                    res.append((f"snapshot age {r.name}", False, "no snapshots in the repository"))
                elif r.name in archives:
                    res.append((f"archive {r.name}", True, f"one-time archive, newest snapshot {age / 24:.0f} days old"))
                else:
                    res.append((f"snapshot age {r.name}", age <= stale_h, f"{age:.1f} h (limit {stale_h:g} h)"))
            free = shutil.disk_usage(root).free / GB
            lim = float(h.get("hub_min_free_gb", 125))
            res.append(("hub free space", free >= lim, f"{free:.0f} GB free (limit {lim:g} GB)"))
    nas = cfg.get("nas")
    if nas:
        mp = Path(nas["mountpoint"])
        if not os.path.ismount(mp):
            res.append(("NAS free space", False, f"{mp} is not mounted"))
        else:
            free = shutil.disk_usage(mp).free / GB
            lim = float(h.get("nas_min_free_gb", 500))
            res.append(("NAS free space", free >= lim, f"{free:.0f} GB free (limit {lim:g} GB)"))
    if cfg.get("device"):
        p = config.state_dir() / "backup-last.json"
        try:
            last = json.loads(p.read_text())
            at = dt.datetime.fromisoformat(last["at"]).timestamp()
        except (OSError, ValueError, KeyError):
            res.append(("last backup job", False, f"no readable result at {p}: no backup has completed yet"))
        else:
            res.append(("last backup job", bool(last.get("ok")), f"rc {last.get('rc')} {last.get('note', '')}".strip()))
            res.append(("last backup age", (now - at) / 3600 <= stale_h, f"{(now - at) / 3600:.1f} h (limit {stale_h:g} h)"))
    for nm in sorted(cfg.get("offsite", {})):
        p = config.state_dir() / f"offsite-{nm}.status.json"
        lim = float(h.get("offsite_stale_hours", 72))
        try:
            s = json.loads(p.read_text())
        except (OSError, ValueError):
            res.append((f"offsite {nm}", False, "no completed offsite run recorded"))
            continue
        ok_at = s.get("ok_at")
        age = (now - ok_at) / 3600 if ok_at else None
        flagged = int(s.get("flagged", 0))
        res.append((f"offsite {nm}", age is not None and age <= lim and flagged == 0,
                    f"last full run {'never' if age is None else f'{age:.0f} h ago'} (limit {lim:g} h), {flagged} flagged file(s)"))
    if not res:
        raise BackupError("nothing to check: no hub, NAS, device or offsite target is configured")
    return res


def to_json(results: list[tuple[str, bool, str]]) -> dict:
    """Machine-readable result. exit_code keeps the CLI meaning: 0 healthy, 1 a check found a problem."""
    ok = all(r[1] for r in results)
    return {"ok": ok, "exit_code": 0 if ok else config.PROBLEM_EXIT,
            "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in results]}


def run_health(send_alerts: bool = True, as_json: bool = False) -> int:
    if as_json:
        try:
            doc = to_json(collect())
        except BackupError as e:   # still machine-readable, exit 2 = the check could not run
            print(json.dumps({"ok": False, "exit_code": config.ERROR_EXIT, "error": str(e), "checks": []}))
            return config.ERROR_EXIT
        print(json.dumps(doc))
        if send_alerts:
            bad = [c for c in doc["checks"] if not c["ok"]]
            if bad:
                sent, detail = alerts.fire(ALERT_KEY, "HavnVard Backup: " + "; ".join(f"{c['name']}: {c['detail']}" for c in bad))
                if not sent:   # review 20261111: never silent about an alert that could not be raised
                    print(f"ALERT NOT SENT: {detail}", file=sys.stderr)
            else:
                alerts.resolve(ALERT_KEY)
        return doc["exit_code"]
    results = collect()
    bad = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"{'OK     ' if ok else 'PROBLEM'} {name}: {detail}")
    print(f"health: {len(results) - len(bad)}/{len(results)} checks ok")
    if bad and send_alerts:
        text = "HavnVard Backup: " + "; ".join(f"{n}: {d}" for n, _, d in bad)
        ok, detail = alerts.fire(ALERT_KEY, text)
        print(f"alert: {detail}" if ok else f"ALERT NOT SENT: {detail}")
    elif not bad and send_alerts:
        alerts.resolve(ALERT_KEY)
    return config.PROBLEM_EXIT if bad else 0
