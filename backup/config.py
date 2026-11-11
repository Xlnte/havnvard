"""Config and secret paths (GHY-38): everything under ~/.config/havnvard/.

backup.toml  non-secret settings        restic.pass  restic repo password (600)
rest.pass    hub (rest-server) login password (600)
hub-passwords/DEVICE.pass  hub-side copies of device repo passwords, for prune and hub-side drills (600); nas-copy needs none
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

PROBLEM_EXIT = 1   # a check ran and found a problem
ERROR_EXIT = 2     # the tool could not do what was asked (never a silent success)


class BackupError(Exception):
    """A failure the caller must see; the CLI turns it into exit code 2."""


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
