"""Read a root-owned credential file (INFRA-633; same rule as INFRA-540 in crosshost_verify.py).

Read the file directly when this process may (running as root, or in the file's group). Only a PermissionError falls back to
`sudo cat`; a missing file raises FileNotFoundError and is NOT retried via sudo. The contents are never logged by this module.
"""
from __future__ import annotations

import subprocess


def read_token_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        return subprocess.run(["sudo", "cat", path], capture_output=True, text=True, check=True).stdout
