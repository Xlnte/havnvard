from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Callable


@dataclass
class WaitingRoomGate:
    acquire_command: str | None
    release_command: str | None

    def acquire(
        self,
        run_id: str,
        host: str,
        tier: str,
        *,
        max_wait_seconds: int = 1800,
        retry_seconds: int = 30,
        on_wait: Callable[[int], None] | None = None,
    ) -> bool:
        if not self.acquire_command:
            return True
        payload = json.dumps({"run_id": run_id, "host": host, "tier": tier, "priority": "P3"})
        started = time.monotonic()
        while True:
            result = subprocess.run(
                shlex.split(self.acquire_command), input=payload, text=True, timeout=30, check=False
            )
            if result.returncode == 0:
                return True
            elapsed = int(time.monotonic() - started)
            if on_wait:
                on_wait(elapsed)
            if elapsed >= max_wait_seconds:
                return False
            time.sleep(min(retry_seconds, max(0, max_wait_seconds - elapsed)))

    def release(self, run_id: str, host: str, tier: str) -> None:
        if not self.release_command:
            return
        payload = json.dumps({"run_id": run_id, "host": host, "tier": tier, "priority": "P3"})
        subprocess.run(
            shlex.split(self.release_command), input=payload, text=True, timeout=30, check=False
        )
