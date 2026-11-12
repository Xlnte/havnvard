from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from .config import BackupError, config_dir


def which(name: str, env_var: str) -> str:
    p = os.environ.get(env_var) or shutil.which(name)
    if not p:
        raise BackupError(f"{name} not found on PATH (set {env_var} to override)")
    return p


def restic_bin() -> str:
    return which("restic", "HAVNVARD_RESTIC")


def rclone_bin() -> str:
    return which("rclone", "HAVNVARD_RCLONE")


def run(cmd: list[str], env: dict | None = None, timeout: float | None = None,
        input_text: str | None = None) -> subprocess.CompletedProcess:
    """subprocess.run that turns 'could not start' and 'timed out' into BackupError."""
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        return subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=timeout, input=input_text)
    except subprocess.TimeoutExpired as ex:
        raise BackupError(f"timed out after {timeout}s: {' '.join(cmd[:3])}") from ex
    except OSError as ex:
        raise BackupError(f"cannot run {cmd[0]}: {ex}") from ex


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def new_secret_file(path: Path) -> bool:
    """Create a random secret file (mode 600) and return True. If it exists, leave it alone
    and return False: re-enrolling must never replace a password that protects existing data.
    The secret is never printed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_urlsafe(32) + "\n")
    return True


def read_secret(path: Path) -> str:
    try:
        v = path.read_text().strip()
    except OSError as e:
        raise BackupError(f"cannot read secret file {path}: {e}") from e
    if not v:
        raise BackupError(f"secret file {path} is empty")
    return v


def systemd_arg(s: str) -> str:
    if any(c.isspace() or c in '"\\' for c in s):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def hub_password_dir() -> Path:
    return config_dir() / "hub-passwords"


def now() -> float:
    return time.time()
