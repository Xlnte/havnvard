"""`health`: is every device (and every backup stream on it) fresh, did the last job work, is there room, is it offsite?

Exit 0 healthy, 1 a check found a problem, 2 the check itself could not run (never a silent pass).
Snapshot age is read from the newest file in <repo>/snapshots/ (written when a snapshot completes), which
needs no repository password. 3.3.3 (INFRA-549): where the hub holds a device's password it reads the snapshot list
and checks EVERY stream (restic's host + paths grouping), because one fresh stream used to hide stopped ones.
Alerts go through backup/alerts.py (alertlib or an alert command).
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
from .util import hub_password_dir, restic_bin, run

GB = 1024 ** 3
ALERT_KEY = "havnvard-backup-health"
OFFSITE_KEY = "havnvard-offsite-stale"   # 3.3.2: offsite problems also raise their own key (INFRA-547)
OFFSITE_PREFIX = "offsite "              # every offsite check name starts with this; relay.py relies on it
STATUS_TIMEOUT_S = 120
DEVICE_KEY = "havnvard-device-stale"     # 3.3.3: one key per device, f"{DEVICE_KEY}-{device}" (INFRA-549)
DEVICE_PREFIX = "device "                # per-device stream verdicts; relay.py relies on it
STREAM_CHECK_PREFIX = "stream check "    # the hub could not read a device's snapshot list: main key, device key untouched
STREAM_TIMEOUT_S = 60                    # per repository; `restic snapshots --no-lock` takes 0-2 s on a live hub
# 3.3.13 (INFRA-644): checks with their own alert key (raised here and, on a hub that cannot alert, by health-relay)
YIELD_CHECK, YIELD_KEY = "yield-overdue", "havnvard-yield-overdue"        # a deferred exclusive step not caught up
DRILL_CHECK, DRILL_KEY = "pullback-drill", "havnvard-pullback-drill"      # the last pullback drill's verdict
WAIT_CHECK, WAIT_KEY = "pullback-waiting", "havnvard-pullback-waiting"  # 3.3.17 (INFRA-649): a pullback waited on a lock
WAIT_WINDOW_S = 24 * 3600
NAMED_KEYS = {YIELD_CHECK: YIELD_KEY, DRILL_CHECK: DRILL_KEY, WAIT_CHECK: WAIT_KEY}


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
            from .pullback_drill import marker_ids      # review L11: the drill marker is never a device's backup
            skip = frozenset(catalog_snapshot_ids() | marker_ids())
            archives = set(h.get("archive_repos", []))   # 2.2.5: one-time archives (e.g. an old-laptop-2023 archive): no age limit
            mode = h.get("check_streams", "auto")
            if not (isinstance(mode, bool) or mode == "auto"):   # `mode in (True, False, "auto")` let 0 and 1 through
                res.append(("health config", False, f'check_streams = {mode!r}: use true, false or "auto"'))
                mode = "auto"
            res.extend(_device_config_problems(h, {r.name for r in repos}))
            for r in repos:
                note = ""
                bad_cfg = False
                if r.name not in archives and mode is not False:
                    try:   # a bad per-device setting is a config problem, not "cannot read the backups"
                        _device_settings(h, r.name, stale_h)
                    except BackupError as e:
                        res.append(("health config", False, str(e)))
                        bad_cfg = True
                if r.name not in archives and mode is not False and not bad_cfg:
                    if mode is True or (hub_password_dir() / f"{r.name}.pass").is_file():
                        try:
                            res.append(_device_check(r, r.name, h, stale_h, now))
                            continue
                        except BackupError as e:   # never "no stale devices": loud, and the file-age check still runs
                            res.append((f"{STREAM_CHECK_PREFIX}{r.name}", False,
                                        f"cannot read the backups: {e}; only the newest snapshot file is checked"))
                    else:
                        note = " (per-stream check off: no hub-side password)"
                age = _newest_snapshot_age_h(r, now, skip)
                if age is None:
                    res.append((f"snapshot age {r.name}", False, "no snapshots in the repository"))
                elif r.name in archives:
                    res.append((f"archive {r.name}", True, f"one-time archive, newest snapshot {age / 24:.0f} days old"))
                else:
                    res.append((f"snapshot age {r.name}", age <= stale_h, f"{age:.1f} h (limit {stale_h:g} h){note}"))
            free = shutil.disk_usage(root).free / GB
            lim = float(h.get("hub_min_free_gb", 125))
            res.append(("hub free space", free >= lim, f"{free:.0f} GB free (limit {lim:g} GB)"))
        res.append(_yield_check(now))
        waiting = _waiting_check(now)
        if waiting:
            res.append(waiting)
    drill = _drill_check(now, h)
    if drill:
        res.append(drill)
    tags = _drill_marker_tags_check()
    if tags:
        res.append(tags)
    if cfg.get("hub_web"):
        res.append(_hub_web_check(str(cfg["hub_web"])))
    nas = cfg.get("nas")
    if nas:
        mp = Path(nas["mountpoint"])
        if not os.path.ismount(mp):
            res.append(("NAS free space", False, f"{mp} is not mounted"))
        else:
            free = shutil.disk_usage(mp).free / GB
            lim = float(h.get("nas_min_free_gb", 500))
            res.append(("NAS free space", free >= lim, f"{free:.0f} GB free (limit {lim:g} GB)"))
    # INFRA-625: a [device] section added only for hub check-in has no backup paths and runs no backup job, so
    # it must not demand backup-last.json (false "no backup has completed yet" PROBLEM on the hub/check-in-only PCs).
    if cfg.get("device") and (cfg["device"] or {}).get("paths"):
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


def _yield_check(now: float) -> tuple[str, bool, str]:
    """INFRA-644 3.2: a catalog name tag deferred for a pullback and not caught up in time is a PROBLEM."""
    from . import precedence
    try:
        late, n_open = precedence.overdue(now)
    except (BackupError, OSError, ValueError, KeyError, TypeError) as e:
        return YIELD_CHECK, False, f"cannot read the deferred steps: {type(e).__name__}: {e}"
    if late:
        return YIELD_CHECK, False, (f"{len(late)} of {n_open} deferred step(s) overdue: " + "; ".join(w for _, w in late[:3])
                                    + ". Run `python -m backup catalog run`; if that does not catch up, look for a "
                                    "stuck pullback (state intent/ folder) or a long prune")
    return YIELD_CHECK, True, f"{n_open} deferred step(s) open, none overdue"


def _drill_check(now: float, h: dict) -> tuple[str, bool, str] | None:
    """The last pullback drill's verdict (state/pullback-drill.json); no check until a drill has run. Review L4: a
    result older than `[health] pullback_drill_max_age_days` (default 8: a weekly drill plus a day) is a PROBLEM, so a
    stopped or disabled timer never leaves the last PASS green."""
    p = config.state_dir() / "pullback-drill.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
        lim = float(h.get("pullback_drill_max_age_days", 8))
        age_d = (now - dt.datetime.fromisoformat(d["at"]).timestamp()) / 86400
        if age_d > lim:
            return DRILL_CHECK, False, (f"no pullback drill since {d['at']} ({age_d:.1f} days, limit {lim:g}); "
                                        f"last result: {'PASSED' if d['ok'] else 'FAILED'}")
        return DRILL_CHECK, bool(d["ok"]), f"{d.get('at', '?')}: {d['summary']}"
    except (OSError, ValueError, KeyError, TypeError) as e:
        return DRILL_CHECK, False, f"last drill result {p} unreadable: {type(e).__name__}: {e}"


DRILL_TAGS_CHECK = "pullback-drill-marker-tags"


def _drill_marker_tags_check() -> tuple[str, bool, str] | None:
    """INFRA-660: the drill's housekeeping (removing old drill tags from the marker) is not a drill check, so a
    failure there left the drill PASSED while tags piled up. It is reported here under its own key. No check until
    a drill result carrying the field exists."""
    p = config.state_dir() / "pullback-drill.json"
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        return DRILL_TAGS_CHECK, False, f"last drill result {p} unreadable: {type(e).__name__}: {e}"
    if "marker_tags_error" not in d:
        return None                                       # result written before INFRA-660
    err = d.get("marker_tags_error")
    if err:
        return DRILL_TAGS_CHECK, False, f"old drill tags were NOT removed from the marker at {d.get('at', '?')}: {err}"
    return DRILL_TAGS_CHECK, True, "old drill marker tags pruned (or nothing to prune)"


def _waiting_check(now: float) -> tuple[str, bool, str] | None:
    """INFRA-649 (review L3, spec 3.3): a pullback that waited on a lock leaves a `pullback_waiting` notice on the hub page;
    an undismissed one from the last 24 h is a PROBLEM under its own key, so the existing alert path (health, or
    health-relay for a hub that cannot alert) sends it to the owner. Read-only; no check on a hub without a hub page."""
    import sqlite3
    from .accounts import default_path
    db = default_path()
    if not db.is_file():
        return None
    cutoff = dt.datetime.fromtimestamp(now - WAIT_WINDOW_S, dt.timezone.utc).isoformat(timespec="seconds")
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        try:
            rows = con.execute("SELECT n.created_at, d.name, n.text FROM notice n JOIN device d ON d.id = n.device_id "
                               "WHERE n.kind = 'pullback_waiting' AND n.dismissed_at IS NULL AND n.created_at >= ? "
                               "ORDER BY n.created_at DESC", (cutoff,)).fetchall()
        finally:
            con.close()
    except sqlite3.Error as e:
        return WAIT_CHECK, False, f"hub page notices unreadable ({db}): {type(e).__name__}: {e}"
    if not rows:
        return WAIT_CHECK, True, "no pullback waited on a lock in the last 24 h (or every such notice was dismissed)"
    at, dev, text = rows[0]
    return WAIT_CHECK, False, (f"{len(rows)} pullback(s) waited on a lock in the last 24 h; newest {at} on {dev}: "
                               f"{' '.join(str(text).split())[:240]}. Dismiss the notice on the hub page once seen")


def _hub_web_check(base: str) -> tuple[str, bool, str]:
    """INFRA-626: ask the running hub web (set `hub_web = "http://127.0.0.1:8001"` in backup.toml) for /healthz.
    Red when it cannot be reached, answers badly, or has counted an internal error or a failed/refused mail since it started."""
    import json as _json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(base.rstrip("/") + "/healthz", timeout=5) as r:
            st = _json.loads(r.read().decode())
        e, m = st["errors"], st["mail"]
        bad = e["internal"] > 0 or m["failed"] > 0 or m["rejected_full"] > 0
        return ("hub web", not bad, f"{e['internal']} internal error(s), {e['bad_request']} bad request(s), mail failed "
                                    f"{m['failed']}, refused {m['rejected_full']}, notices refused {st['notices_refused']}")
    except (OSError, urllib.error.URLError, ValueError, KeyError, TypeError) as e:
        return ("hub web", False, f"cannot read {base}/healthz: {type(e).__name__}: {e}")


def _list_snapshots(repo_dir: Path, repo: str, h: dict) -> list[dict]:
    """The repository's snapshot list, read with the hub-side password (`restic snapshots --json --no-lock`: read-only,
    takes no lock; `--no-cache`: writes nothing on the hub, 0-2 s per repository live). Every failure raises BackupError; never an empty list in place of an error."""
    pw = hub_password_dir() / f"{repo}.pass"
    restic = os.path.expanduser(str(h["restic"])) if h.get("restic") else restic_bin()
    env = {"RESTIC_REPOSITORY": str(repo_dir), "RESTIC_PASSWORD_FILE": str(pw)}
    r = run([restic, "snapshots", "--json", "--no-lock", "--no-cache"], env=env, timeout=STREAM_TIMEOUT_S)
    if r.returncode != 0:
        raise BackupError(f"restic snapshots failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    try:
        snaps = json.loads(r.stdout or "null")
    except ValueError as e:
        raise BackupError(f"restic snapshots output is not JSON: {e}") from e
    if not isinstance(snaps, list):
        raise BackupError(f"restic snapshots output is not a list: {r.stdout.strip()[:120]!r}")
    return snaps


def _device_settings(h: dict, repo: str, default_h: float) -> tuple[float, set[str]]:
    dev = (h.get("devices") or {}).get(repo, {})
    if not isinstance(dev, dict):
        raise BackupError(f"[health.devices.{repo}] must be a table")
    lim = dev.get("stale_hours", default_h)
    if isinstance(lim, bool) or not isinstance(lim, (int, float)) or lim <= 0:
        raise BackupError(f"[health.devices.{repo}] stale_hours = {lim!r}: must be a number of hours above 0")
    retired = dev.get("retired_streams", [])
    if not isinstance(retired, list) or not all(isinstance(x, str) for x in retired):
        raise BackupError(f'[health.devices.{repo}] retired_streams must be a list of "host|path" strings')
    return float(lim), set(retired)


def _device_config_problems(h: dict, repo_names: set[str]) -> list[tuple[str, bool, str]]:
    devs = h.get("devices", {})
    if not isinstance(devs, dict):
        return [("health config", False, "[health.devices] must be a table of [health.devices.<repo>] tables")]
    unknown = sorted(set(devs) - repo_names)
    if unknown:   # a typo would otherwise leave the real device on the default limit, silently
        return [("health config", False, f"[health.devices] names no hub repository: {', '.join(unknown)} "
                                         f"(hub repositories: {', '.join(sorted(repo_names)) or 'none'})")]
    return []


def _fmt_stream(key: str) -> str:
    """'host|/a|/b' -> '/a /b' (the host is the same for every stream of one device, as a rule)."""
    paths = key.split("|")[1:]
    txt = " ".join(paths) or key
    return txt if len(txt) <= 80 else txt[:77] + "..."


def _device_check(repo_dir: Path, repo: str, h: dict, default_h: float, now: float) -> tuple[str, bool, str]:
    """3.3.3 (INFRA-549): one verdict per device from the age of the newest snapshot of EVERY stream in its repository.
    A stream = restic's host + paths grouping (catalog.group_key). Catalog snapshots are not backups. Streams listed in
    [health.devices.<repo>] retired_streams are counted, not judged. Raises BackupError when the list cannot be read."""
    from .catalog import data_snapshots, group_key, parse_time
    lim, retired = _device_settings(h, repo, default_h)
    pw = hub_password_dir() / f"{repo}.pass"
    if not pw.is_file():
        raise BackupError(f"no hub-side password at {pw}")
    snaps = _list_snapshots(repo_dir, repo, h)
    try:
        newest: dict[str, float] = {}
        for s in data_snapshots(snaps):
            k, t = group_key(s), parse_time(s["time"]).timestamp()
            newest[k] = max(t, newest.get(k, t))
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise BackupError(f"unexpected snapshot entry ({type(e).__name__}: {e})") from e
    name = f"{DEVICE_PREFIX}{repo}"
    if not newest:
        return name, False, "no backups in the repository"
    active = {k: (now - t) / 3600 for k, t in newest.items() if k not in retired}
    n_ret = len(newest) - len(active)
    ret_txt = f", {n_ret} retired" if n_ret else ""
    if not active:
        return name, False, f"every stream ({len(newest)}) is retired in [health.devices.{repo}]: nothing backs this device up"
    stale = sorted(((a, k) for k, a in active.items() if a > lim), reverse=True)
    youngest = min(active.values())
    if not stale:
        return name, True, f"{len(active)} stream(s), newest {youngest:.1f} h ago, oldest {max(active.values()):.1f} h (limit {lim:g} h){ret_txt}"
    shown = ", ".join(f"{_fmt_stream(k)} {a:.1f} h" for a, k in stale[:8]) + (f", +{len(stale) - 8} more" if len(stale) > 8 else "")
    return name, False, (f"{len(stale)} of {len(active)} stream(s) stale (limit {lim:g} h): {shown}; "
                         f"newest {youngest:.1f} h ago{ret_txt}")


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


def _is_offsite(name: str) -> bool:
    return str(name).startswith(OFFSITE_PREFIX)


def _is_device(name: str) -> bool:
    return str(name).startswith(DEVICE_PREFIX)


def _own_key(name: str) -> bool:
    """Checks that alert under their own key and never decide the main key (offsite 3.3.2, device 3.3.3,
    yield-overdue and pullback-drill 3.3.13)."""
    return _is_offsite(name) or _is_device(name) or str(name) in NAMED_KEYS


def device_key(device: str) -> str:
    return f"{DEVICE_KEY}-{device}"


def _alert_devices(results: list[tuple[str, bool, str]], label: str = "") -> bool:
    """3.3.3: fire or resolve one key per device from its `device <repo>` verdict. A device with no verdict this run
    (its repository could not be read) is left as it was: the read failure alerts on the main key instead.
    Returns False when a device alert could not be raised (the caller makes that loud)."""
    all_sent = True
    for n, ok, d in results:
        if not _is_device(n):
            continue
        dev = n[len(DEVICE_PREFIX):]
        key = device_key(dev)
        if ok:
            alerts.resolve(key)
            continue
        sent, detail = alerts.fire(key, f"HavnVard backup{label}: {dev} is stale: {d}")
        if not sent:
            all_sent = False
            print(f"ALERT NOT SENT ({key}): {detail}", file=sys.stderr)
    return all_sent


def _alert_offsite(results: list[tuple[str, bool, str]]) -> None:
    """Raise or clear OFFSITE_KEY from the offsite checks alone (3.3.2)."""
    off = [r for r in results if _is_offsite(r[0])]
    if not off:
        return
    bad = [r for r in off if not r[1]]
    if bad:
        ok, detail = alerts.fire(OFFSITE_KEY, "HavnVard offsite: " + "; ".join(f"{n}: {d}" for n, _, d in bad))
        if not ok:
            print(f"ALERT NOT SENT ({OFFSITE_KEY}): {detail}", file=sys.stderr)
    else:
        alerts.resolve(OFFSITE_KEY)


def _alert_named(results: list[tuple[str, bool, str]], label: str = "") -> bool:
    """3.3.13: fire or resolve YIELD_KEY / DRILL_KEY from their own check (only when the check is present).
    Returns False when an alert could not be raised (the caller makes that loud)."""
    all_sent = True
    for n, ok, d in results:
        key = NAMED_KEYS.get(str(n))
        if not key:
            continue
        if ok:
            alerts.resolve(key)
            continue
        sent, detail = alerts.fire(key, f"HavnVard{label} {n}: {d}")
        if not sent:
            all_sent = False
            print(f"ALERT NOT SENT ({key}): {detail}", file=sys.stderr)
    return all_sent


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
            # 3.3.2 review fix 3: offsite checks go out under OFFSITE_KEY only, so an offsite backlog never holds the
            # main key open (a new device problem then gets its own OPEN notice). exit_code/ok still cover everything.
            bad = [c for c in doc["checks"] if not c["ok"] and not _own_key(c["name"])]
            if bad:
                sent, detail = alerts.fire(ALERT_KEY, "HavnVard Backup: " + "; ".join(f"{c['name']}: {c['detail']}" for c in bad))
                if not sent:   # review 20261111: never silent about an alert that could not be raised
                    print(f"ALERT NOT SENT: {detail}", file=sys.stderr)
            else:
                alerts.resolve(ALERT_KEY)
            _alert_offsite([(c["name"], c["ok"], c["detail"]) for c in doc["checks"]])
            _alert_devices([(c["name"], c["ok"], c["detail"]) for c in doc["checks"]])
            _alert_named([(c["name"], c["ok"], c["detail"]) for c in doc["checks"]])
        return doc["exit_code"]
    results = collect()
    bad = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"{'OK     ' if ok else 'PROBLEM'} {name}: {detail}")
    print(f"health: {len(results) - len(bad)}/{len(results)} checks ok")
    main_bad = [r for r in bad if not _own_key(r[0])]   # offsite (3.3.2) and device (3.3.3) checks use their own keys
    if main_bad and send_alerts:
        text = "HavnVard Backup: " + "; ".join(f"{n}: {d}" for n, _, d in main_bad)
        ok, detail = alerts.fire(ALERT_KEY, text)
        print(f"alert: {detail}" if ok else f"ALERT NOT SENT: {detail}")
    elif not main_bad and send_alerts:
        alerts.resolve(ALERT_KEY)
    if send_alerts:
        _alert_offsite(results)
        _alert_devices(results)
        _alert_named(results)
    return config.PROBLEM_EXIT if bad else 0
