"""Site settings for the HavnVard inventory tools (scan, dedup, verify, report, UI).

One place for everything that differs between installations: the database, the host names, the NAS. Before 3.0.0
every tool carried its own copy of these (8 copies of the database lookup alone); they now all read this module.

Where the settings come from, first found wins:
  1. the file named by $HAVNVARD_SITE
  2. /etc/havnvard/site.toml         (system-wide; what root-run scans and timers use)
  3. ~/.config/havnvard/site.toml    (per user)
Without any file the defaults below apply, which suit a single machine with a local Postgres.

Example (see config/site.example.toml):

    [database]
    env_file = "/etc/havnvard/havnvard.env"   # a file holding POSTGRES_URL=...; never put the password in site.toml
    fallback_url = "postgresql://havnvard@127.0.0.1:5432/havnvard"

    [hosts]
    local = "server-1"          # the name this machine's rows carry in the inventory
    nas = "nas-1"               # the NAS host name (rows of NAS shares)
    sources = ["server-1", "laptop-1"]   # machines whose files need a backup (the NAS is the target)

    [nas]
    ssh_target = "backup@nas-1.example"
    share_base = "/share/CACHEDEV1_DATA"     # QNAP default volume
    admin_token_file = "/etc/havnvard/nas_admin.env"
    backup_token_file = "/etc/havnvard/nas_backup.env"

    [ui]
    public_url = "http://127.0.0.1:9108"
    dashboard_url = ""

Secrets never live in this file: it names files that hold them.
"""
from __future__ import annotations

import os
import socket
import tomllib
from functools import lru_cache
from pathlib import Path

DEFAULT_FALLBACK_URL = "postgresql://havnvard@127.0.0.1:5432/havnvard"


class SiteConfigError(Exception):
    """The site file exists but cannot be read: never fall back silently to defaults."""


def site_paths() -> list[Path]:
    env = os.environ.get("HAVNVARD_SITE")
    if env:
        return [Path(env)]
    return [Path("/etc/havnvard/site.toml"), Path.home() / ".config" / "havnvard" / "site.toml"]


@lru_cache(maxsize=1)
def site() -> dict:
    for p in site_paths():
        if p.exists():
            try:
                with open(p, "rb") as f:
                    data = tomllib.load(f)
            except (OSError, tomllib.TOMLDecodeError) as e:
                raise SiteConfigError(f"cannot read HavnVard site file {p}: {e}") from e
            data.setdefault("_path", str(p))
            _validate(data, p)
            return data
    if os.environ.get("HAVNVARD_SITE"):
        raise SiteConfigError(f"HAVNVARD_SITE points at a missing file: {os.environ['HAVNVARD_SITE']}")
    return {}


def _validate(data: dict, path) -> None:
    """Fail loudly on a mistyped site file: a string where a list belongs would otherwise turn into one-letter host
    names and make every host-filtered query return nothing, which looks like success (review F1)."""
    def bad(key, want):
        raise SiteConfigError(f"site file {path}: {key} must be {want}")
    for name, v in data.items():
        if name != "_path" and not isinstance(v, dict):
            bad(f"[{name}]", "a table")
    hosts = data.get("hosts") or {}
    for k in ("local", "nas"):
        if k in hosts and not (isinstance(hosts[k], str) and hosts[k].strip()):
            bad(f"[hosts] {k}", "a non-empty string")
    for k in ("sources", "all"):
        if k in hosts and not (isinstance(hosts[k], list) and hosts[k]
                               and all(isinstance(x, str) and x.strip() for x in hosts[k])):
            bad(f"[hosts] {k}", "a non-empty list of strings")
    for name, a in (data.get("agents") or {}).items():
        if not isinstance(a, dict):
            bad(f"[agents.{name}]", "a table")
    def str_list(sec, key):
        v = (data.get(sec) or {}).get(key)
        if v is not None and not (isinstance(v, list) and all(isinstance(x, str) and x.strip() for x in v)):
            bad(f"[{sec}] {key}", "a list of strings")
    for sec, key in (("scan", "extra_excludes"), ("load_bearing", "crontab_users"), ("report", "slow_shares"),
                     ("nas", "dedup_excludes"), ("legacy_restic", "file_list_names")):
        str_list(sec, key)       # review N2: a string here would split into one-letter entries
    ap = (data.get("report") or {}).get("app_prefixes")
    if ap is not None and not (isinstance(ap, list) and all(isinstance(x, list) and len(x) == 2
                                                             and all(isinstance(y, str) for y in x) for x in ap)):
        bad("[report] app_prefixes", "a list of [prefix, label] pairs")
    db = data.get("database") or {}
    for k in ("env_file", "fallback_url"):
        if k in db and not isinstance(db[k], str):
            bad(f"[database] {k}", "a string")


def section(name: str) -> dict:
    v = site().get(name) or {}
    return v if isinstance(v, dict) else {}


# ---- database --------------------------------------------------------------------------------------------------

def env_file() -> str | None:
    return os.environ.get("HAVNVARD_ENV_FILE") or section("database").get("env_file") or None


def read_env_value(path: str | None, key: str) -> str | None:
    """KEY=value from a dotenv-style file. None when no file is configured or the key is absent. A file that IS
    configured but cannot be read raises SiteConfigError (review F2): falling back silently would hide the real cause
    (wrong owner, missing file) behind "not set" or a different database. The message never includes file contents."""
    if not path:
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError as e:
        raise SiteConfigError(f"cannot read env file {path}: {type(e).__name__}: {e.strerror or e}") from e
    return None


def get_dsn() -> str:
    """POSTGRES_URL from the environment, else from the site's env_file, else the site's fallback URL."""
    return (
        os.environ.get("POSTGRES_URL")
        or read_env_value(env_file(), "POSTGRES_URL")
        or section("database").get("fallback_url")
        or DEFAULT_FALLBACK_URL
    )


def require_dsn() -> str:
    """Like get_dsn() but refuses the built-in fallback: for tools that must not guess a database."""
    dsn = os.environ.get("POSTGRES_URL") or read_env_value(env_file(), "POSTGRES_URL") \
        or section("database").get("fallback_url")
    if not dsn:
        raise SiteConfigError("no database configured: set POSTGRES_URL or [database] env_file in the site file")
    return dsn


def secret_value(key: str) -> str | None:
    """A secret (bot token and the like) from the environment or the site's env_file."""
    return os.environ.get(key) or read_env_value(env_file(), key)


# ---- hosts -----------------------------------------------------------------------------------------------------

def local_host() -> str:
    return section("hosts").get("local") or socket.gethostname()


def nas_host() -> str:
    return section("hosts").get("nas") or "nas"


def source_hosts() -> tuple[str, ...]:
    """Machines whose files need a backup (the NAS is the backup target, not a source)."""
    v = section("hosts").get("sources")
    return tuple(v) if v else (local_host(),)


def all_hosts() -> tuple[str, ...]:
    v = section("hosts").get("all")
    if v:
        return tuple(v)
    out = list(source_hosts())
    if nas_host() not in out:
        out.append(nas_host())
    return tuple(out)


# ---- NAS ------------------------------------------------------------------------------------------------------

def nas(key: str, default: str | None = None) -> str | None:
    return section("nas").get(key, default)


def nas_share_base() -> str:
    return nas("share_base") or "/share/CACHEDEV1_DATA"


# ---- UI ---------------------------------------------------------------------------------------------------------

def ui(key: str, default: str = "") -> str:
    return section("ui").get(key, default)


# ---- remote agent machines (hashed over plain key-based ssh) ---------------------------------------------------
#   [agents.laptop-1]
#   ssh_host = "laptop-1.example"   # name or address
#   ssh_user = "havnvard"
#   ssh_key = "~/.ssh/id_ed25519"
#   scratch_dir = "/tmp/diskaudit_crosshost_scratch"

def agent_hosts() -> tuple[str, ...]:
    return tuple((site().get("agents") or {}).keys())


def agent(name: str) -> dict:
    a = (site().get("agents") or {}).get(name)
    if not isinstance(a, dict):
        raise SiteConfigError(f"no [agents.{name}] section in the site file")
    return {
        "ssh_host": a.get("ssh_host") or name,
        "ssh_user": a.get("ssh_user") or os.environ.get("USER", "havnvard"),
        "ssh_key": os.path.expanduser(a.get("ssh_key") or "~/.ssh/id_ed25519"),
        "scratch_dir": a.get("scratch_dir") or "/tmp/diskaudit_crosshost_scratch",
    }


# ---- alertlib (optional operator-alert library) -----------------------------------------------------------------

def import_alertlib():
    """Import alertlib from $HAVNVARD_ALERTLIB_PATH or [alerts] alertlib_path (appended to sys.path, never first,
    so it cannot shadow an installed package). Raises ImportError when absent: callers report that loudly."""
    import importlib  # noqa: PLC0415
    import sys  # noqa: PLC0415
    path = os.environ.get("HAVNVARD_ALERTLIB_PATH") or section("alerts").get("alertlib_path")
    if path and path not in sys.path:
        sys.path.append(path)
    return importlib.import_module("alertlib")
