from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import dataclass
from typing import Protocol


class AlertSink(Protocol):
    def send(self, event_type: str, severity: str, payload: dict) -> None: ...


@dataclass
class NullAlertSink:
    def send(self, event_type: str, severity: str, payload: dict) -> None:
        return None


@dataclass
class CommandAlertSink:
    command: str

    def send(self, event_type: str, severity: str, payload: dict) -> None:
        # INFRA-140 (20260828): same datetime-in-payload gap as repository.py's
        # reserve_alert() -- payload can carry SLA timestamps, add default=str.
        body = json.dumps({"event_type": event_type, "severity": severity, "payload": payload},
                           sort_keys=True, default=str)
        subprocess.run(shlex.split(self.command), input=body, text=True, check=True, timeout=30)


def fingerprint(event_type: str, host: str, path: str | None, discriminator: str) -> str:
    raw = "\0".join([event_type, host, path or "", discriminator])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
