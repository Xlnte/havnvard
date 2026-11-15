"""Device side of schedules (3.3.0, INFRA-576): ask the hub "am I due?", run the backup if so, report the run.

Config (backup.toml): [checkin] url = "http://HUB:8001", token_file = "~/.config/havnvard/checkin.token".
* A 10 s reachability probe comes first: when the hub is down the device does not spend ~15 min in restic retries
  (20261113: three runs burned 15 min each against a powered-off hub). The missed check-in is kept in the state dir
  and reported at the next successful check-in as a MISSED CHECK-IN, never as a failed backup run (F9: it must not
  push the next real backup back).
* Every run that started is reported as ended (F5), whatever happens inside it: when the end report cannot reach the
  hub it is kept and sent at the next check-in; when even the start could not be reported, the whole run is reported
  late with its real times.
* The backup itself is the unchanged `enroll.client_run()` (one backup command line for timer runs and offload).
"""
from __future__ import annotations

import collections
import datetime as dt
import json
import os
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


def _append_line(p: Path, line: str) -> None:
    """Append one line to a queue file under its lock (INFRA-609): a flush that rewrites the file cannot lose it."""
    p.parent.mkdir(parents=True, exist_ok=True)
    with config.file_lock(p):
        with open(p, "a") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def _flush_file(p: Path, handle) -> int:
    """Send every line of queue file P with `handle(line) -> bool` (True = done, False = keep), then remove exactly the done
    lines. INFRA-609: the network work happens WITHOUT the append lock, and the file is re-read under the lock before it
    is rewritten (temp + rename), so a line appended by another process while we were sending is never lost. One flusher
    at a time (a second one waits), so a line is not sent twice by two overlapping check-ins."""
    if not p.is_file():
        return 0
    with config.file_lock(p.with_name(p.name + ".flush")):
        with config.file_lock(p):
            lines = p.read_text().splitlines() if p.is_file() else []
        done = [ln for ln in lines if handle(ln)]
        if done:
            with config.file_lock(p):
                gone = collections.Counter(done)
                keep = []
                for ln in (p.read_text().splitlines() if p.is_file() else []):
                    if gone[ln] > 0:
                        gone[ln] -= 1
                    else:
                        keep.append(ln)
                config.atomic_write_text(p, "".join(x + "\n" for x in keep))
    return len(done)


def _keep_pending(rec: dict) -> None:
    _append_line(_pending_file(), json.dumps(rec))


def _flush_pending(base: str, name: str, token: str, opener) -> int:
    """Send what could not be reported while the hub was down: missed check-ins, run ends, whole runs. The file is
    replaced by the lines still unsent (our own state file, never a backup or a user file); see `_flush_file`."""
    def handle(ln: str) -> bool:
        try:
            rec = json.loads(ln)
            if rec.get("kind") == "end":
                _post(f"{base}/api/v1/devices/{name}/run", token, {k: v for k, v in rec.items() if k != "kind"}
                      | {"action": "end"}, opener)
            else:
                _post(f"{base}/api/v1/devices/{name}/late", token, rec, opener)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 404:                       # the hub has no such open run any more: nothing left to send
                print(f"havnvard checkin: hub no longer has that run open (404); dropped from the queue: {ln[:200]}")
                return True
            return False
        except (OSError, urllib.error.URLError, ValueError):
            return False
    return _flush_file(_pending_file(), handle)


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
        _append_line(p, json.dumps(rec))
    except OSError as e:
        return f"{why}; could not keep it on this computer either ({e})"
    return f"{why}; kept on this computer in {p} and sent at the next check-in"


def _flush_notices(base: str, name: str, token: str, opener) -> int:
    """Our own state file: replaced by the lines still unsent (never a backup or a user file); see `_flush_file`."""
    def handle(ln: str) -> bool:
        try:
            rec = json.loads(ln)
            _post(f"{base}/api/v1/devices/{name}/notice", token,
                  {"kind": rec["kind"], "text": rec["text"] + f"\n\n(recorded on the computer at {rec['at']})"}, opener)
            return True
        except (OSError, urllib.error.URLError, ValueError, KeyError):
            return False
    return _flush_file(_notices_file(), handle)


def checkin(run: bool = False, opener=urllib.request.urlopen, runner=None) -> int:
    """Exit 0 = not due or ran OK, 1 = the run failed or the hub could not be reached (kept for a late report)."""
    from . import __version__
    base, name, token = _settings()
    started = _now()
    try:
        ans = _post(f"{base}/api/v1/devices/{name}/checkin", token, {"client_version": __version__}, opener)
    except (OSError, urllib.error.URLError) as e:
        print(f"havnvard checkin: hub unreachable at {base} ({e}); nothing run, kept as a missed check-in")
        _keep_pending({"kind": "checkin_failed", "at": started, "error": f"hub unreachable: {e}"[:300]})
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
    run_started = _now()
    try:
        rid = _post(f"{base}/api/v1/devices/{name}/run", token, {"action": "start"}, opener)["run_id"]
    except (OSError, urllib.error.URLError, ValueError, KeyError) as e:
        rid = None
        print(f"havnvard checkin: the hub could not be told the run started ({e}); running anyway, reported late")
    rc, err = config.ERROR_EXIT, "the backup stopped on an unexpected error before it could report"
    try:
        rc = runner()
        err = None
    except BackupError as e:
        rc, err = config.ERROR_EXIT, str(e)
    except BaseException as e:
        err = f"{type(e).__name__}: {e}"[:300]
        raise                                       # the end is still reported (finally), then the error goes on
    finally:
        _report_end(base, name, token, rid, rc, err, run_started, opener)
    return 0 if rc in (0, 3) else config.PROBLEM_EXIT


def _report_end(base: str, name: str, token: str, rid, rc: int, err: str | None, started: str, opener) -> None:
    """Never dropped (F5): sent now, or kept and sent at the next check-in."""
    ended = _now()
    if rid is None:
        rec = {"started_at": started, "ended_at": ended, "exit_code": rc, "error": err}
        url = f"{base}/api/v1/devices/{name}/late"
        body = rec
    else:
        rec = {"kind": "end", "run_id": rid, "exit_code": rc, "error": err, "ended_at": ended}
        url = f"{base}/api/v1/devices/{name}/run"
        body = {"action": "end", "run_id": rid, "exit_code": rc, "error": err, "ended_at": ended}
    try:
        _post(url, token, body, opener)
    except (OSError, urllib.error.URLError, ValueError) as e:
        _keep_pending(rec)
        print(f"havnvard checkin: run finished (exit {rc}) but the hub could not be told ({e}); kept in "
              f"{_pending_file()} and sent at the next check-in")
