from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class HostConfig:
    name: str
    mode: str
    ssh_target: str | None
    scratch_dir: str | None
    # "pubkey" (plain key-based ssh) or "sshpass" (server rejects publickey auth
    # for this account; credentials_file is then authoritative for user@host).
    auth: str = "pubkey"
    credentials_file: str | None = None


VALID_AUTH_MODES = {"pubkey", "sshpass"}


@dataclass(frozen=True)
class PathExclusion:
    """One path prefix the verifier must NOT enqueue (INFRA-281).

    Excluded paths are reported, never silently dropped: see
    Repository.count_excluded_candidates and VerificationService.run, which
    record per-prefix counts on the run row and in the journal. An exclusion is
    a POLICY decision ("we deliberately do not verify here") and is therefore
    kept strictly separate from a read FAILURE ("we tried and could not") --
    only the latter is allowed to make a run non-successful.
    See docs/STANDARDS/SILENT_FAILURE_STANDARD.md.
    """

    prefix: str
    host: str | None = None  # None == applies to every host
    reason: str = ""

    def applies_to(self, host: str) -> bool:
        return self.host is None or self.host == host


# Shipped defaults. Overridable wholesale by INFRA126_EXCLUDE_PATH_PREFIXES so
# the next deprecated home needs a config change, not a code change -- same
# pattern as _default_hosts() above.
DEFAULT_EXCLUSIONS: tuple[PathExclusion, ...] = ()   # 3.0.0: site-specific; set INFRA126_EXCLUDE_PATH_PREFIXES


@dataclass(frozen=True)
class Settings:
    postgres_url: str
    batch_size: int
    enqueue_page_size: int
    lease_seconds: int
    heartbeat_seconds: int
    hash_timeout_seconds: int
    remote_batch_timeout_seconds: int
    remote_poll_seconds: int
    remote_heartbeat_stale_seconds: int
    auto_accept_mutable_score: int
    stabilization_delay_hours: int
    log_dir: str
    hosts: dict[str, HostConfig]
    exclude_path_prefixes: tuple[PathExclusion, ...]
    tg_command: str | None
    plane_command: str | None
    waitingroom_acquire_command: str | None
    waitingroom_release_command: str | None
    waitingroom_max_wait_seconds: int
    waitingroom_retry_seconds: int
    allow_null_integrations: bool


def _default_hosts() -> dict[str, HostConfig]:
    """Without INFRA126_HOSTS_JSON only this machine is verified (3.0.0: remote hosts are site settings).
    A remote entry looks like {"nas-1": {"mode": "remote", "ssh_target": "backup@nas-1", "scratch_dir": "...",
    "auth": "sshpass", "credentials_file": "/etc/havnvard/nas_backup.env"}}; see config/infra126.env.example."""
    name = socket.gethostname()
    return {name: HostConfig(name, "local", None, None)}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1","true","yes","on"}


def _parse_exclusions(raw: str | None) -> tuple[PathExclusion, ...]:
    """Parse INFRA126_EXCLUDE_PATH_PREFIXES.

    Accepted forms (all equivalent in power):
      * JSON array of objects:  [{"host":"server-1","prefix":"/home/olduser/","reason":"..."}]
      * JSON array of strings:  ["server-1:/home/olduser/", "/global/prefix/"]
      * comma/newline list:     server-1:/home/olduser/,/global/prefix/

    An explicitly empty value ("" or "[]") disables exclusions entirely -- that
    is a deliberate operator choice and is distinct from the variable being
    unset, which keeps DEFAULT_EXCLUSIONS.
    """
    if raw is None:
        return DEFAULT_EXCLUSIONS
    text = raw.strip()
    if not text:
        return ()
    entries: list[object]
    if text.startswith("["):
        entries = json.loads(text)
    else:
        entries = [part.strip() for part in text.replace("\n", ",").split(",") if part.strip()]
    parsed: list[PathExclusion] = []
    for entry in entries:
        if isinstance(entry, str):
            host, sep, prefix = entry.partition(":")
            if not sep or host.startswith("/"):
                host, prefix = None, entry
            parsed.append(PathExclusion(prefix=prefix.strip(), host=host, reason="configured via INFRA126_EXCLUDE_PATH_PREFIXES"))
        elif isinstance(entry, dict):
            prefix = str(entry.get("prefix", "")).strip()
            parsed.append(PathExclusion(
                prefix=prefix,
                host=entry.get("host") or None,
                reason=str(entry.get("reason", "configured via INFRA126_EXCLUDE_PATH_PREFIXES")),
            ))
        else:
            raise ValueError(f"INFRA126_EXCLUDE_PATH_PREFIXES: unsupported entry {entry!r}")
    for exclusion in parsed:
        if not exclusion.prefix.startswith("/"):
            raise ValueError(
                f"INFRA126_EXCLUDE_PATH_PREFIXES: prefix {exclusion.prefix!r} must be an absolute path"
            )
        if exclusion.prefix == "/":
            raise ValueError("INFRA126_EXCLUDE_PATH_PREFIXES: refusing to exclude the whole filesystem")
    return tuple(parsed)


def load_settings() -> Settings:
    hosts = _default_hosts()
    raw_hosts = os.getenv("INFRA126_HOSTS_JSON")
    if raw_hosts:
        decoded = json.loads(raw_hosts)
        hosts = {}
        for name, value in decoded.items():
            auth = value.get("auth", "pubkey")
            if auth not in VALID_AUTH_MODES:
                raise ValueError(
                    f"host {name}: unknown auth {auth!r}; expected one of {sorted(VALID_AUTH_MODES)}"
                )
            credentials_file = value.get("credentials_file")
            if auth == "sshpass" and not credentials_file:
                raise ValueError(f"host {name}: auth='sshpass' requires credentials_file")
            hosts[name] = HostConfig(
                name=name,
                mode=value["mode"],
                ssh_target=value.get("ssh_target"),
                scratch_dir=value.get("scratch_dir"),
                auth=auth,
                credentials_file=credentials_file,
            )
    return Settings(
        postgres_url=os.environ["POSTGRES_URL"],
        batch_size=int(os.getenv("INFRA126_BATCH_SIZE", "500")),
        enqueue_page_size=int(os.getenv("INFRA126_ENQUEUE_PAGE_SIZE", "5000")),
        lease_seconds=int(os.getenv("INFRA126_LEASE_SECONDS", "1800")),
        heartbeat_seconds=int(os.getenv("INFRA126_HEARTBEAT_SECONDS", "30")),
        hash_timeout_seconds=int(os.getenv("INFRA126_HASH_TIMEOUT_SECONDS", "1200")),
        remote_batch_timeout_seconds=int(os.getenv("INFRA126_REMOTE_BATCH_TIMEOUT_SECONDS", "1200")),
        remote_poll_seconds=int(os.getenv("INFRA126_REMOTE_POLL_SECONDS", "15")),
        remote_heartbeat_stale_seconds=int(os.getenv("INFRA126_REMOTE_HEARTBEAT_STALE_SECONDS", "300")),
        auto_accept_mutable_score=int(os.getenv("INFRA126_AUTO_ACCEPT_MUTABLE_SCORE", "90")),
        stabilization_delay_hours=int(os.getenv("INFRA126_STABILIZATION_DELAY_HOURS", "24")),
        log_dir=os.getenv("INFRA126_LOG_DIR", "/var/log/havnvard/infra126"),
        hosts=hosts,
        exclude_path_prefixes=_parse_exclusions(os.getenv("INFRA126_EXCLUDE_PATH_PREFIXES")),
        tg_command=os.getenv("INFRA126_TG_COMMAND"),
        plane_command=os.getenv("INFRA126_PLANE_COMMAND"),
        waitingroom_acquire_command=os.getenv("INFRA126_WAITINGROOM_ACQUIRE_COMMAND"),
        waitingroom_release_command=os.getenv("INFRA126_WAITINGROOM_RELEASE_COMMAND"),
        waitingroom_max_wait_seconds=int(os.getenv("INFRA126_WAITINGROOM_MAX_WAIT_SECONDS", "1800")),
        waitingroom_retry_seconds=int(os.getenv("INFRA126_WAITINGROOM_RETRY_SECONDS", "30")),
        allow_null_integrations=_env_bool("INFRA126_ALLOW_NULL_INTEGRATIONS",False),
    )
