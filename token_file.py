"""Read a root-owned credential file (INFRA-633; same rule as INFRA-540; INFRA-637 made it the one helper).

Read the file directly when this process may (running as root, or in the file's group). Only a PermissionError falls back to
`sudo -n cat` (-n: fail at once instead of waiting for a password prompt on a service with no terminal); a missing file raises
FileNotFoundError and is NOT retried via sudo. If the sudo fallback fails (no passwordless sudo, file unreadable, timeout) a
TokenReadError names the file and the exit code only. The contents, and sudo's own stderr, are never put in a message or a log.
"""
from __future__ import annotations

import subprocess

SUDO_TIMEOUT_SEC = 30


class TokenReadError(RuntimeError):
    """The credential file could not be read, directly or with `sudo -n cat`. The message never carries file content."""


def read_token_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        pass
    try:
        return subprocess.run(
            ["sudo", "-n", "cat", path], capture_output=True, text=True, check=True,
            stdin=subprocess.DEVNULL, timeout=SUDO_TIMEOUT_SEC,
        ).stdout
    except subprocess.CalledProcessError as e:
        raise TokenReadError(
            f"cannot read credential file {path}: not readable by this user and `sudo -n cat` failed (exit {e.returncode}); "
            f"run as root or grant passwordless sudo for cat on that file"
        ) from None
    except subprocess.TimeoutExpired:
        raise TokenReadError(f"cannot read credential file {path}: `sudo -n cat` timed out after {SUDO_TIMEOUT_SEC}s") from None
    except FileNotFoundError:
        raise TokenReadError(f"cannot read credential file {path}: not readable by this user and sudo is not installed") from None
