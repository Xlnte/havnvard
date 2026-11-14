"""Device side of schedules (3.3.0, INFRA-576): ask the hub "am I due?", run the backup if so, report the run.

Config (backup.toml): [checkin] url = "http://HUB:8001", token_file = "~/.config/havnvard/checkin.token".
* A 10 s reachability probe comes first: when the hub is down the device does not spend ~15 min in restic retries
  (20261113: three runs burned 15 min each against a powered-off hub). The failed attempt is kept in the state dir
  and reported to the hub, with its real times, at the next successful check-in (`reported_via = late`).
* The backup itself is the unchanged `enroll.client_run()` (one backup command line for timer runs and offload).
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request
from pathlib import Path

from . import config
from .config import BackupError
from .util import read_secret

TIMEOUT_S = 10


def _settings() -> tuple[str, str, str]:
    cfg = config.load()
    ck, dev = cfg.get("checkin", {}), cfg.get("device", {})
    url, tf = ck.get("url"), ck.get("token_file")
    if not url or not tf or not dev.get("name"):
        raise BackupError("check-in is not set up: [checkin] url + token_file and [device] name in backup.toml")
    return url.rstrip("/"), dev["name"], read_secret(Path(tf).expanduser())


def _post(url: str, token: str, body: dict, opener=urllib.request.urlopen) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with opener(req, timeout=TIMEOUT_S) as r:
        return json.loads(r.read().decode() or "{}")


def _pending_file() -> Path:
    return config.state_dir() / "checkin-pending.jsonl"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _keep_pending(rec: dict) -> None:
    p = _pending_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")


def _flush_pending(base: str, name: str, token: str, opener) -> int:
    """Send runs that could not be reported while the hub was down. Sent lines are not deleted: the file is replaced
    by the lines still unsent (our own state file, never a backup or a user file)."""
    p = _pending_file()
    if not p.is_file():
        return 0
    left, sent = [], 0
    for ln in p.read_text().splitlines():
        try:
            _post(f"{base}/api/v1/devices/{name}/late", token, json.loads(ln), opener)
            sent += 1
        except (OSError, urllib.error.URLError, ValueError):
            left.append(ln)
    p.write_text("".join(x + "\n" for x in left))
    return sent


def _notices_file() -> Path:
    return config.state_dir() / "notices-pending.jsonl"


def report_notice(kind: str, text: str, opener=urllib.request.urlopen) -> str:
    """Leave a notice on the hub page (stays until someone clicks Dismiss). Never raises, never silent: returns
    "sent", or why not and where the notice was kept on this computer (it is sent at the next check-in)."""
    rec = {"kind": kind, "text": text, "at": _now()}
    try:
        base, name, token = _settings()
    except BackupError as e:
        return _keep_notice(rec, f"not sent: {e}")
    try:
        _post(f"{base}/api/v1/devices/{name}/notice", token, {"kind": kind, "text": text}, opener)
    except (OSError, urllib.error.URLError, ValueError) as e:
        return _keep_notice(rec, f"not sent: hub unreachable at {base} ({e})")
    return "sent"


def _keep_notice(rec: dict, why: str) -> str:
    p = _notices_file()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        return f"{why}; could not keep it on this computer either ({e})"
    return f"{why}; kept on this computer in {p} and sent at the next check-in"


def _flush_notices(base: str, name: str, token: str, opener) -> int:
    """Our own state file: replaced by the lines still unsent (never a backup or a user file)."""
    p = _notices_file()
    if not p.is_file():
        return 0
    left, sent = [], 0
    for ln in p.read_text().splitlines():
        try:
            rec = json.loads(ln)
            _post(f"{base}/api/v1/devices/{name}/notice", token,
                  {"kind": rec["kind"], "text": rec["text"] + f"\n\n(recorded on the computer at {rec['at']})"}, opener)
            sent += 1
        except (OSError, urllib.error.URLError, ValueError, KeyError):
            left.append(ln)
    p.write_text("".join(x + "\n" for x in left))
    return sent


def checkin(run: bool = False, opener=urllib.request.urlopen, runner=None) -> int:
    """Exit 0 = not due or ran OK, 1 = the run failed or the hub could not be reached (kept for a late report)."""
    from . import __version__
    base, name, token = _settings()
    started = _now()
    try:
        ans = _post(f"{base}/api/v1/devices/{name}/checkin", token, {"client_version": __version__}, opener)
    except (OSError, urllib.error.URLError) as e:
        print(f"havnvard checkin: hub unreachable at {base} ({e}); nothing run, kept for a late report")
        _keep_pending({"started_at": started, "ended_at": _now(), "exit_code": 1, "error": f"hub unreachable: {e}"[:300]})
        return config.PROBLEM_EXIT
    n = _flush_pending(base, name, token, opener)
    if n:
        print(f"havnvard checkin: {n} earlier run(s) reported late")
    n = _flush_notices(base, name, token, opener)
    if n:
        print(f"havnvard checkin: {n} notice(s) kept on this computer now left on the hub page")
    print(f"havnvard checkin: {'due' if ans.get('due') else 'not due'} ({ans.get('reason')})")
    if not (run and ans.get("due")):
        return 0
    from .enroll import client_run
    runner = runner or client_run
    rid = _post(f"{base}/api/v1/devices/{name}/run", token, {"action": "start"}, opener)["run_id"]
    try:
        rc = runner()
        err = None
    except BackupError as e:
        rc, err = config.ERROR_EXIT, str(e)
    try:
        _post(f"{base}/api/v1/devices/{name}/run", token, {"action": "end", "run_id": rid, "exit_code": rc,
                                                           "error": err}, opener)
    except (OSError, urllib.error.URLError) as e:
        print(f"havnvard checkin: run finished (exit {rc}) but the hub could not be told ({e})")
    return 0 if rc in (0, 3) else config.PROBLEM_EXIT
