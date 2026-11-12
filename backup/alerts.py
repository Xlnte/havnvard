"""Alerting. Two ways to deliver, tried in order; no Telegram or vendor code lives here.

1. alertlib, if it can be imported (path: HAVNVARD_ALERTLIB_PATH, or [alerts] alertlib_path in backup.toml).
   alertlib.fire() dedups and never raises.
2. An alert command from backup.toml, for any machine without alertlib:

       [alerts]
       command = ["/usr/local/bin/notify-me"]      # any program: ntfy, mail, a webhook script ...

   It runs with HAVNVARD_ALERT_KEY and HAVNVARD_ALERT_TEXT in its environment (and the text on stdin); exit 0 means
   delivered. HavnVard keeps a per-key cooldown for it in the state dir, so a stuck problem alerts once per cooldown.

If neither is available the alert could NOT be raised, and fire() says so loudly (returns False) instead of looking
like a delivered alert. Callers fold that into their exit code and output.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
import time

from . import config

SOURCE = "havnvard-backup"
COMMAND_TIMEOUT_S = 60


def _load():
    path = os.environ.get("HAVNVARD_ALERTLIB_PATH") or (config.load().get("alerts") or {}).get("alertlib_path")
    if path and path not in sys.path:
        sys.path.append(path)   # append, never insert(0): path-first shadowing is a known defect class
    return importlib.import_module("alertlib")


def _command() -> list[str]:
    cmd = (config.load().get("alerts") or {}).get("command") or []
    if isinstance(cmd, str):
        cmd = [cmd]
    return [str(c) for c in cmd]


def _cooldown_file(key: str):
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)
    return config.state_dir() / "alerts" / f"{safe}.last"


def _fire_command(cmd: list[str], key: str, text: str, cooldown_sec: int) -> tuple[bool, str]:
    stamp = _cooldown_file(key)
    try:
        if stamp.exists() and time.time() - stamp.stat().st_mtime < cooldown_sec:
            return True, "suppressed by cooldown"
    except OSError:
        pass
    env = dict(os.environ, HAVNVARD_ALERT_KEY=key, HAVNVARD_ALERT_TEXT=text, HAVNVARD_ALERT_SOURCE=SOURCE)
    try:
        r = subprocess.run(cmd, input=text, text=True, env=env, capture_output=True, timeout=COMMAND_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"alert command failed to run ({type(e).__name__}: {e})"
    if r.returncode != 0:
        return False, f"alert command exit {r.returncode}: {(r.stderr or r.stdout).strip()[:200]}"
    try:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.touch()
    except OSError as e:
        print(f"warning: cannot record alert cooldown {stamp}: {e}", file=sys.stderr)
    return True, "sent by alert command"


def fire(key: str, text: str, cooldown_sec: int = 6 * 3600) -> tuple[bool, str]:
    """(delivered_or_deduped, detail). False means the alert could NOT be raised at all."""
    try:
        lib = _load()
    except ImportError as e:
        cmd = _command()
        if cmd:
            return _fire_command(cmd, key, text, cooldown_sec)
        return False, f"alertlib not importable ({e}) and no [alerts] command in backup.toml"
    try:
        sent = lib.fire(key, text, cooldown_sec, SOURCE)
    except Exception as e:  # noqa: BLE001  boundary: report, never hide
        return False, f"alertlib.fire raised {type(e).__name__}: {e}"
    return True, "sent" if sent else "suppressed by alertlib cooldown"


def resolve(key: str) -> None:
    try:
        lib = _load()
    except ImportError:
        try:
            _cooldown_file(key).unlink(missing_ok=True)   # next problem alerts at once
        except OSError as e:
            print(f"warning: cannot clear alert cooldown for {key}: {e}", file=sys.stderr)
        return
    try:
        lib.resolve(key)
    except Exception as e:  # noqa: BLE001
        print(f"warning: alertlib.resolve({key}) failed: {e}", file=sys.stderr)
