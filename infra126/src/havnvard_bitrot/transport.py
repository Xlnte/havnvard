"""Per-host SSH transports for INFRA-126 remote hashing.

Some hosts (nas-1) refuse publickey auth entirely for the backup account
and can only be reached with sshpass + a root-owned credentials file, while
others (agent-1) are plain key-based ssh. This module keeps that difference in
one place so remote.py never builds an ssh/scp argv itself.

The sshpass pattern here is a deliberate port of the proven implementation in
/opt/havnvard/crosshost_verify.py (sudo-cat credential loading and
0600 password-file handling), extended with timeout/check passthrough and an
explicitly closed stdin on every subprocess call.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, config.py must not import this module
    from .config import HostConfig

logger = logging.getLogger(__name__)

_SSH_OPTS_COMMON = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]


def _run(argv: list[str], *, timeout: int, check: bool) -> subprocess.CompletedProcess[str]:
    """Every ssh/scp call closes stdin. A backgrounding ssh that inherits this
    process's stdin never returns until its own timeout fires (observed live
    against agent-1), which is why stdin is DEVNULL everywhere here."""
    return subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=check,
        stdin=subprocess.DEVNULL,
    )


class SshTransport:
    """Interface implemented by every transport. `target` is the connection
    identity actually used on the wire (user@host)."""

    target: str = ""

    def ssh(self, remote_cmd: str, *, timeout: int, check: bool = True, background: bool = False) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def scp_put(self, local_path: str, remote_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def scp_get(self, remote_path: str, local_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def recovery_prefix(self) -> str:
        """Command prefix a human operator can paste to reach this host. Stored
        in the DB alongside the exact PID; never executed by this package."""
        raise NotImplementedError


class PubkeySshTransport(SshTransport):
    def __init__(self, ssh_target: str):
        self.target = ssh_target

    def ssh(self, remote_cmd: str, *, timeout: int, check: bool = True, background: bool = False) -> subprocess.CompletedProcess[str]:
        argv = ["ssh"] + (["-n"] if background else []) + _SSH_OPTS_COMMON + [self.target, remote_cmd]
        return _run(argv, timeout=timeout, check=check)

    def scp_put(self, local_path: str, remote_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        argv = ["scp", "-q"] + _SSH_OPTS_COMMON + [str(local_path), f"{self.target}:{remote_path}"]
        return _run(argv, timeout=timeout, check=True)

    def scp_get(self, remote_path: str, local_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        argv = ["scp", "-q"] + _SSH_OPTS_COMMON + [f"{self.target}:{remote_path}", str(local_path)]
        return _run(argv, timeout=timeout, check=True)

    def recovery_prefix(self) -> str:
        return f"ssh {shlex.quote(self.target)}"


class SshpassSshTransport(SshTransport):
    """For hosts whose SSH server rejects publickey auth for this account.

    The credentials file is authoritative for connection identity: the target
    is `NAS_USER@NAS_HOST` from that file, not whatever ssh_target config says.
    """

    _PUBKEY_OFF = ["-o", "PubkeyAuthentication=no"]

    def __init__(self, credentials_file: str, configured_target: str | None = None):
        if shutil.which("sshpass") is None:
            raise RuntimeError(
                f"auth=sshpass requires the sshpass binary but it was not found on PATH "
                f"(credentials_file={credentials_file})"
            )
        self.credentials_file = credentials_file
        self.configured_target = configured_target
        self.target = configured_target or ""
        self._password: str | None = None

    def _load_credentials(self) -> str:
        """Lazy and cached: the verification poll loop runs every ~15s and must
        not shell out to sudo on every probe."""
        if self._password is not None:
            return self._password
        result = subprocess.run(
            ["sudo", "cat", self.credentials_file],
            capture_output=True,
            text=True,
            check=True,
            stdin=subprocess.DEVNULL,
        )
        user = host = password = None
        for line in result.stdout.splitlines():
            if line.startswith("NAS_USER="):
                user = line.split("=", 1)[1].strip()
            elif line.startswith("NAS_HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("NAS_PASS="):
                password = line.split("=", 1)[1].strip()
        if not user or not host or not password:
            raise RuntimeError(
                f"could not parse NAS_USER/NAS_HOST/NAS_PASS from {self.credentials_file}"
            )
        resolved = f"{user}@{host}"
        if self.configured_target and self.configured_target != resolved:
            logger.warning(
                "INFRA-126 host credentials file %s resolves to %s; configured ssh_target %s is ignored",
                self.credentials_file,
                resolved,
                self.configured_target,
            )
        self.target = resolved
        self._password = password
        return password

    def _with_sshpass(self, argv: list[str], *, timeout: int, check: bool) -> subprocess.CompletedProcess[str]:
        """Never pass the password as a bare -p arg (leaks via `ps aux`) --
        write it to a private 0600 file inside a private temp dir and hand
        sshpass the path. The temp dir (and password file) are removed when the
        context exits, on success or failure."""
        password = self._load_credentials()
        with tempfile.TemporaryDirectory(prefix="infra126-naspw-") as temp_dir:
            pw_path = os.path.join(temp_dir, "pw")
            handle = os.open(pw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as pw_file:
                pw_file.write(password)
            os.chmod(pw_path, 0o600)
            return _run(["sshpass", "-f", pw_path] + argv, timeout=timeout, check=check)

    def ssh(self, remote_cmd: str, *, timeout: int, check: bool = True, background: bool = False) -> subprocess.CompletedProcess[str]:
        self._load_credentials()
        argv = ["ssh"] + (["-n"] if background else []) + _SSH_OPTS_COMMON + self._PUBKEY_OFF + [self.target, remote_cmd]
        return self._with_sshpass(argv, timeout=timeout, check=check)

    def scp_put(self, local_path: str, remote_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        self._load_credentials()
        argv = ["scp", "-q"] + _SSH_OPTS_COMMON + self._PUBKEY_OFF + [str(local_path), f"{self.target}:{remote_path}"]
        return self._with_sshpass(argv, timeout=timeout, check=True)

    def scp_get(self, remote_path: str, local_path: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
        self._load_credentials()
        argv = ["scp", "-q"] + _SSH_OPTS_COMMON + self._PUBKEY_OFF + [f"{self.target}:{remote_path}", str(local_path)]
        return self._with_sshpass(argv, timeout=timeout, check=True)

    def recovery_prefix(self) -> str:
        self._load_credentials()
        return (
            f"sshpass -f <(sudo grep -oP '(?<=^NAS_PASS=).*' {self.credentials_file}) "
            f"ssh -o PubkeyAuthentication=no {shlex.quote(self.target)}"
        )


def build_transport(host: "HostConfig") -> SshTransport:
    auth = getattr(host, "auth", "pubkey")
    if auth == "sshpass":
        if not host.credentials_file:
            raise RuntimeError(f"host {host.name} uses auth=sshpass but has no credentials_file")
        return SshpassSshTransport(host.credentials_file, host.ssh_target)
    if not host.ssh_target:
        raise RuntimeError(f"host {host.name} uses auth=pubkey but has no ssh_target")
    return PubkeySshTransport(host.ssh_target)
