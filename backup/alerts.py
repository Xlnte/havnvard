"""Alerting goes through the shared alertlib (/srv/alertlib); no Telegram code lives here.

alertlib.fire() is deduped and never raises. This module adds the part alertlib cannot do
for us: if alertlib itself is missing, say so loudly (return False) instead of looking like
a delivered alert. Callers fold that into their exit code and output.
"""
from __future__ import annotations

import importlib
import os
import sys

DEFAULT_PATH = "/srv/alertlib"
SOURCE = "havnvard-backup"


def _load():
    path = os.environ.get("HAVNVARD_ALERTLIB_PATH", DEFAULT_PATH)
    if path not in sys.path:
        sys.path.insert(0, path)
    return importlib.import_module("alertlib")


def fire(key: str, text: str, cooldown_sec: int = 6 * 3600) -> tuple[bool, str]:
    """(delivered_or_deduped, detail). False means the alert could NOT be raised at all."""
    try:
        lib = _load()
    except ImportError as e:
        return False, f"alertlib not importable ({e})"
    try:
        sent = lib.fire(key, text, cooldown_sec, SOURCE)
    except Exception as e:  # noqa: BLE001  boundary: report, never hide
        return False, f"alertlib.fire raised {type(e).__name__}: {e}"
    return True, "sent" if sent else "suppressed by alertlib cooldown"


def resolve(key: str) -> None:
    try:
        _load().resolve(key)
    except Exception as e:  # noqa: BLE001
        print(f"warning: alertlib.resolve({key}) failed: {e}", file=sys.stderr)
