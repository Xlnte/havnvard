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
import socket
import sys
import time
from pathlib import Path

from . import alerts, config
from .config import BackupError
from .util import run

GB = 1024 ** 3
ALERT_KEY = "havnvard-backup-health"
OFFSITE_KEY = "havnvard-offsite-stale"   # 3.3.2: offsite problems also raise their own key (INFRA-547)
OFFSITE_PREFIX = "offsite "              # every offsite check name starts with this; relay.py relies on it
STATUS_TIMEOUT_S = 120


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
    for nm in sorted(cfg.get("offsite_remote", {})):
        res.extend(_remote_offsite(nm, cfg["offsite_remote"][nm], hub, h, now))
    if not res:
        raise BackupError("nothing to check: no hub, NAS, device or offsite target is configured")
    return res


def _remote_offsite(nm: str, spec: dict, hub: dict | None, h: dict, now: float) -> list[tuple[str, bool, str]]:
    """3.3.2 (INFRA-547): an offsite uploader that runs on ANOTHER machine (for example a desktop that holds a cloud
    drive's sync mount). The hub cannot see its state file, so `status_command` fetches it (typically
    `["ssh", "-o", "BatchMode=yes", "desktop-1", "cat", ".local/state/<uploader>.status.json"]`).

    The status JSON: {"source": "<host>:<dir the uploader read>", "at": <epoch of last run>, "rc": <last exit>,
    "flagged": <n>, "hold": [repo, ...], "repos": {repo: {"ok_at": <epoch the repo was last fully uploaded>}}}.

    Problems (never a silent pass): the status cannot be fetched or parsed; the uploader read a different folder than
    this hub (`expect_source`, default "<this hostname>:<hub repo_root>") - the retired-hub case; the last run is older
    than the limit or failed; flagged files; any hub repo not fully uploaded within `offsite_stale_hours`."""
    label = f"{OFFSITE_PREFIX}{nm}"
    lim = float(spec.get("stale_hours", h.get("offsite_stale_hours", 72)))
    cmd = spec.get("status_command")
    if not isinstance(cmd, list) or not cmd or not all(isinstance(c, str) for c in cmd):
        return [(label, False, "[offsite_remote] status_command must be a list of strings, e.g. "
                               '["ssh", "desktop-1", "cat", ".local/state/uploader.status.json"]')]
    root = (hub or {}).get("repo_root")
    expect = spec.get("expect_source") or (f"{socket.gethostname()}:{root}" if root else None)
    if not expect:
        return [(label, False, "no expect_source and no [hub_local] repo_root to compare the uploader's source with")]
    try:
        r = run(cmd, timeout=STATUS_TIMEOUT_S)
    except BackupError as e:
        return [(label, False, f"status could not be fetched: {e}")]
    if r.returncode != 0:
        return [(label, False, f"status could not be fetched: exit {r.returncode}: "
                               f"{(r.stderr or r.stdout).strip()[-200:]}")]
    try:
        st = json.loads(r.stdout)
        src, at, rc = st["source"], float(st["at"]), int(st["rc"])
        flagged, hold, repos = int(st.get("flagged", 0)), set(st.get("hold") or []), st.get("repos") or {}
        if not isinstance(repos, dict):
            raise TypeError("repos is not an object")
    except (ValueError, KeyError, TypeError) as e:
        return [(label, False, f"status unreadable ({type(e).__name__}: {e}): {r.stdout.strip()[:120]!r}")]
    if src != expect:
        return [(label, False, f"the uploader reads {src}, not this hub {expect}: retired or wrong hub, "
                               "nothing from this hub reaches offsite")]
    run_age = (now - at) / 3600
    problems = []
    if run_age > lim:
        problems.append(f"last run {run_age:.0f} h ago (limit {lim:g} h)")
    if rc not in (0, 75):
        problems.append(f"last run failed rc {rc}")
    if flagged:
        problems.append(f"{flagged} flagged file(s)")
    out = [(label, not problems, "; ".join(problems) or f"last run {run_age:.1f} h ago rc {rc}, source {src}")]
    hub_repos = []
    if root and Path(root).is_dir():
        hub_repos = sorted(p.name for p in Path(root).iterdir() if p.is_dir() and (p / "config").is_file())
    for repo in hub_repos:
        if repo in hold:
            out.append((f"{label} {repo}", True, "held by the operator (not uploaded on purpose)"))
            continue
        ok_at = (repos.get(repo) or {}).get("ok_at") if isinstance(repos.get(repo), dict) else None
        if ok_at is None:
            out.append((f"{label} {repo}", False, "never fully uploaded"))
            continue
        age = (now - float(ok_at)) / 3600
        out.append((f"{label} {repo}", age <= lim, f"last full upload {age:.0f} h ago (limit {lim:g} h)"))
    return out


def _alert_offsite(results: list[tuple[str, bool, str]]) -> None:
    """Raise or clear OFFSITE_KEY from the offsite checks alone (3.3.2)."""
    off = [r for r in results if r[0].startswith(OFFSITE_PREFIX)]
    if not off:
        return
    bad = [r for r in off if not r[1]]
    if bad:
        ok, detail = alerts.fire(OFFSITE_KEY, "HavnVard offsite: " + "; ".join(f"{n}: {d}" for n, _, d in bad))
        if not ok:
            print(f"ALERT NOT SENT ({OFFSITE_KEY}): {detail}", file=sys.stderr)
    else:
        alerts.resolve(OFFSITE_KEY)


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
            _alert_offsite([(c["name"], c["ok"], c["detail"]) for c in doc["checks"]])
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
    if send_alerts:
        _alert_offsite(results)
    return config.PROBLEM_EXIT if bad else 0
