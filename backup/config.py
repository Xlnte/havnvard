"""Config and secret paths (GHY-38): everything under ~/.config/havnvard/.

backup.toml  non-secret settings        restic.pass  restic repo password (600)
rest.pass    hub (rest-server) login password (600)
hub-passwords/DEVICE.pass  hub-side copies of device repo passwords, for catalog and hub-side drills (600); never accepted for deletion (prune/forget-* need --owner-key); nas-copy needs none
"""
from __future__ import annotations

import contextlib
import os
import re
import secrets
import tomllib
from pathlib import Path

PROBLEM_EXIT = 1   # a check ran and found a problem
ERROR_EXIT = 2     # the tool could not do what was asked (never a silent success)


class BackupError(Exception):
    """A failure the caller must see; the CLI turns it into exit code 2."""


# INFRA-626: ONE computer-name rule for the client (`enroll`) and the hub (`add_device`): starts with a letter or digit,
# then letters, digits, . _ - ; 1-63 characters. LEGACY_DEVICE_NAME_PATTERN is only what the device API route still
# accepts, so a computer registered under 3.3.0-3.3.5 (a name like "-pc" or 64 characters) keeps checking in.
DEVICE_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}"
DEVICE_NAME_RE = re.compile(rf"^{DEVICE_NAME_PATTERN}$")
LEGACY_DEVICE_NAME_PATTERN = r"[A-Za-z0-9._-]{1,64}"


@contextlib.contextmanager
def file_lock(path: Path):
    """An exclusive advisory lock (flock) on a sibling `.lock` file, so two processes never read-then-rewrite the same
    state file at once (INFRA-609, INFRA-613). The lock file is ours, 600, and never a symlink we would follow."""
    import fcntl
    lk = path.with_name(f".{path.name}.lock")
    fd = os.open(lk, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)                                     # closing releases the lock


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Write PATH whole or not at all (INFRA-614): a private temp file in the same directory, fsynced, then renamed over
    PATH. A crash at any point leaves the old file or the new one, never an empty or half-written one."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic write of HavnVard's own state file (allowlisted in test_crosshost_verify)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)  # our own temp file, never a user file (allowlisted in test_crosshost_verify)
        raise


def config_dir() -> Path:
    return Path(os.environ.get("HAVNVARD_CONFIG_DIR") or Path.home() / ".config" / "havnvard")


def state_dir() -> Path:
    return Path(os.environ.get("HAVNVARD_STATE_DIR") or Path.home() / ".local" / "state" / "havnvard")


def config_path() -> Path:
    return config_dir() / "backup.toml"


def load() -> dict:
    p = config_path()
    if not p.exists():
        return {}
    try:
        with open(p, "rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise BackupError(f"cannot read {p}: {e}") from e


def _val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, list):
        return "[" + ", ".join(_val(x) for x in v) + "]"
    raise BackupError(f"unsupported config value {v!r}")


def _dump(d: dict, prefix: str = "") -> str:
    out = []
    scalars = {k: v for k, v in d.items() if not isinstance(v, dict)}
    tables = {k: v for k, v in d.items() if isinstance(v, dict)}
    if prefix and scalars:
        out.append(f"[{prefix}]")
    for k, v in scalars.items():
        out.append(f"{k} = {_val(v)}")
    if scalars:
        out.append("")
    for k, v in tables.items():
        out.append(_dump(v, f"{prefix}.{k}" if prefix else k))
    return "\n".join(out)


def save(cfg: dict) -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    p = config_path()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# HavnVard Backup settings. No secrets here; passwords are separate 600 files.\n")
        f.write(_dump(cfg).rstrip() + "\n")
    os.chmod(p, 0o600)
    return p


def update(section: str, values: dict) -> dict:
    cfg = load()
    cfg.setdefault(section, {}).update(values)
    save(cfg)
    return cfg
