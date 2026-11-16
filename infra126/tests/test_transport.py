from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from havnvard_bitrot.config import HostConfig
from havnvard_bitrot.transport import (
    PubkeySshTransport,
    SshpassSshTransport,
    build_transport,
)

CREDENTIALS_FILE = "/etc/havnvard/nas_backup.env"
CREDENTIALS = "NAS_USER=backup\nNAS_HOST=nas-1.example\nNAS_PASS=hunter2secret\n"
RESOLVED_TARGET = "backup@nas-1.example"


def _install_fake_run(monkeypatch, calls, *, credentials=CREDENTIALS, observed=None):
    """Fake subprocess.run for havnvard_bitrot.transport.

    Records every argv/kwargs pair. Answers `sudo cat` with credential text and
    snapshots the sshpass password file while it is still live so the test can
    assert on its mode/content before cleanup removes it.
    """

    def fake_run(argv, **kwargs):
        argv = list(argv)
        calls.append((argv, dict(kwargs)))
        if argv[:3] == ["sudo", "-n", "cat"]:
            return SimpleNamespace(stdout=credentials, stderr="", returncode=0)
        if argv[0] == "sshpass" and observed is not None:
            pw_path = argv[2]
            observed.append(
                {
                    "path": pw_path,
                    "content": Path(pw_path).read_text(encoding="utf-8"),
                    "mode": stat.S_IMODE(os.stat(pw_path).st_mode),
                }
            )
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr("havnvard_bitrot.transport.subprocess.run", fake_run)


@pytest.fixture(autouse=True)
def _credentials_file_denied(monkeypatch):
    """The credentials file is root-owned: this process gets PermissionError on the direct read (INFRA-637), so the helper
    takes its `sudo -n cat` fallback, which _install_fake_run answers. No real file or sudo is touched."""
    import builtins

    real_open = builtins.open

    def deny(path, *a, **k):
        if str(path) == CREDENTIALS_FILE:
            raise PermissionError(13, "denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", deny)


def _allow_sshpass(monkeypatch):
    monkeypatch.setattr("havnvard_bitrot.transport.shutil.which", lambda _: "/usr/bin/sshpass")


# --------------------------------------------------------------------------
# 1. pubkey transport
# --------------------------------------------------------------------------


def test_pubkey_ssh_builds_plain_ssh_argv_with_devnull_stdin(monkeypatch):
    calls = []
    _install_fake_run(monkeypatch, calls)
    transport = PubkeySshTransport("havnvard@agent-1.example")

    transport.ssh("echo hello", timeout=30)

    argv, kwargs = calls[0]
    assert argv[0] == "ssh"
    assert "-n" not in argv
    assert argv[-2:] == ["havnvard@agent-1.example", "echo hello"]
    assert "StrictHostKeyChecking=accept-new" in argv
    assert "ConnectTimeout=10" in argv
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 30


def test_pubkey_ssh_adds_dash_n_only_when_backgrounding(monkeypatch):
    calls = []
    _install_fake_run(monkeypatch, calls)
    transport = PubkeySshTransport("havnvard@agent-1.example")

    transport.ssh("foreground", timeout=30)
    transport.ssh("background", timeout=60, background=True)

    assert "-n" not in calls[0][0]
    assert calls[1][0][:2] == ["ssh", "-n"]


def test_pubkey_scp_calls_close_stdin(monkeypatch, tmp_path):
    calls = []
    _install_fake_run(monkeypatch, calls)
    transport = PubkeySshTransport("havnvard@agent-1.example")

    transport.scp_put(str(tmp_path / "local"), "/remote/path", timeout=120)
    transport.scp_get("/remote/results", str(tmp_path / "out"), timeout=120)

    put_argv, put_kwargs = calls[0]
    get_argv, get_kwargs = calls[1]
    assert put_argv[:2] == ["scp", "-q"]
    assert put_argv[-1] == "havnvard@agent-1.example:/remote/path"
    assert get_argv[-2] == "havnvard@agent-1.example:/remote/results"
    assert put_kwargs["stdin"] is subprocess.DEVNULL
    assert get_kwargs["stdin"] is subprocess.DEVNULL


def test_pubkey_recovery_prefix_is_plain_ssh():
    assert PubkeySshTransport("havnvard@agent-1").recovery_prefix() == "ssh havnvard@agent-1"


# --------------------------------------------------------------------------
# 2. sshpass transport
# --------------------------------------------------------------------------


def test_sshpass_ssh_argv_disables_pubkey_and_hides_password(monkeypatch):
    calls = []
    observed = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls, observed=observed)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    transport.ssh("echo hello", timeout=30)

    sshpass_calls = [argv for argv, _ in calls if argv[0] == "sshpass"]
    assert len(sshpass_calls) == 1
    argv = sshpass_calls[0]
    assert argv[0] == "sshpass"
    assert argv[1] == "-f"
    assert argv[3] == "ssh"
    assert "-n" not in argv
    assert "PubkeyAuthentication=no" in argv
    assert argv[-2:] == [RESOLVED_TARGET, "echo hello"]
    assert not any("hunter2secret" in part for part in argv)


def test_sshpass_password_file_is_0600_and_removed_after_call(monkeypatch):
    calls = []
    observed = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls, observed=observed)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    transport.ssh("echo hello", timeout=30)

    assert len(observed) == 1
    assert observed[0]["content"] == "hunter2secret"
    assert observed[0]["mode"] == 0o600
    assert not os.path.exists(observed[0]["path"])


def test_sshpass_scp_helpers_wrap_sshpass(monkeypatch, tmp_path):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    transport.scp_put(str(tmp_path / "local"), "/remote/path", timeout=120)
    transport.scp_get("/remote/results", str(tmp_path / "out"), timeout=120)

    sshpass_calls = [argv for argv, _ in calls if argv[0] == "sshpass"]
    assert len(sshpass_calls) == 2
    put_argv, get_argv = sshpass_calls
    assert put_argv[3] == "scp"
    assert "PubkeyAuthentication=no" in put_argv
    assert put_argv[-1] == f"{RESOLVED_TARGET}:/remote/path"
    assert get_argv[-2] == f"{RESOLVED_TARGET}:/remote/results"


def test_sshpass_constructor_fails_fast_without_sshpass_binary(monkeypatch):
    monkeypatch.setattr("havnvard_bitrot.transport.shutil.which", lambda _: None)
    with pytest.raises(RuntimeError, match="sshpass"):
        SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)


def test_sshpass_recovery_prefix_is_sshpass_shaped(monkeypatch):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    prefix = transport.recovery_prefix()

    assert prefix.startswith("sshpass -f")
    assert CREDENTIALS_FILE in prefix
    assert "PubkeyAuthentication=no" in prefix
    assert RESOLVED_TARGET in prefix
    assert "hunter2secret" not in prefix


# --------------------------------------------------------------------------
# 3. credential loading
# --------------------------------------------------------------------------


def test_credentials_are_read_with_sudo_cat_and_parsed(monkeypatch):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    transport.ssh("echo hello", timeout=30)

    assert calls[0][0] == ["sudo", "-n", "cat", CREDENTIALS_FILE]
    assert calls[0][1]["stdin"] is subprocess.DEVNULL
    assert transport.target == RESOLVED_TARGET


@pytest.mark.parametrize(
    "credentials",
    [
        "NAS_HOST=h\nNAS_PASS=p\n",
        "NAS_USER=u\nNAS_PASS=p\n",
        "NAS_USER=u\nNAS_HOST=h\n",
        "",
    ],
)
def test_incomplete_credentials_raise_naming_the_file(monkeypatch, credentials):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls, credentials=credentials)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    with pytest.raises(RuntimeError, match=CREDENTIALS_FILE):
        transport.ssh("echo hello", timeout=30)


def test_configured_target_mismatch_warns_but_still_uses_credentials_file(monkeypatch, caplog):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls)
    transport = SshpassSshTransport(CREDENTIALS_FILE, "someone@stale-host")

    with caplog.at_level("WARNING"):
        transport.ssh("echo hello", timeout=30)

    assert transport.target == RESOLVED_TARGET
    assert any("stale-host" in record.getMessage() for record in caplog.records)


def test_sudo_failure_is_a_clear_error_without_credential_content(monkeypatch):
    """INFRA-637: no passwordless sudo -> `sudo -n` exits 1 at once; the error names the file and never the output."""
    _allow_sshpass(monkeypatch)

    def failing_run(argv, **kwargs):
        raise subprocess.CalledProcessError(1, list(argv), output="NAS_PASS=hunter2secret", stderr="sudo: a password is required")

    monkeypatch.setattr("havnvard_bitrot.transport.subprocess.run", failing_run)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    with pytest.raises(RuntimeError) as err:
        transport.ssh("echo hello", timeout=30)

    assert CREDENTIALS_FILE in str(err.value) and "exit 1" in str(err.value)
    assert "hunter2secret" not in str(err.value) and "password is required" not in str(err.value)
    assert err.value.__cause__ is None


# --------------------------------------------------------------------------
# 4. credential caching
# --------------------------------------------------------------------------


def test_credentials_are_loaded_once_across_multiple_calls(monkeypatch):
    calls = []
    _allow_sshpass(monkeypatch)
    _install_fake_run(monkeypatch, calls)
    transport = SshpassSshTransport(CREDENTIALS_FILE, RESOLVED_TARGET)

    transport.ssh("first", timeout=30)
    transport.ssh("second", timeout=30)

    sudo_calls = [argv for argv, _ in calls if argv[:3] == ["sudo", "-n", "cat"]]
    assert len(sudo_calls) == 1


# --------------------------------------------------------------------------
# 5. factory
# --------------------------------------------------------------------------


def test_build_transport_returns_pubkey_for_default_host():
    host = HostConfig("agent-1", "remote", "havnvard@agent-1", "/var/lib/havnvard/infra126")
    transport = build_transport(host)
    assert isinstance(transport, PubkeySshTransport)
    assert transport.target == "havnvard@agent-1"


def test_build_transport_returns_sshpass_for_sshpass_host(monkeypatch):
    _allow_sshpass(monkeypatch)
    host = HostConfig(
        "nas-1",
        "remote",
        RESOLVED_TARGET,
        "/share/CACHEDEV1_DATA/.diskaudit_scratch/infra126",
        auth="sshpass",
        credentials_file=CREDENTIALS_FILE,
    )
    transport = build_transport(host)
    assert isinstance(transport, SshpassSshTransport)


def test_build_transport_rejects_sshpass_without_credentials_file(monkeypatch):
    _allow_sshpass(monkeypatch)
    host = HostConfig("nas-1", "remote", RESOLVED_TARGET, "/scratch", auth="sshpass")
    with pytest.raises(RuntimeError, match="credentials_file"):
        build_transport(host)


def test_build_transport_rejects_pubkey_without_ssh_target():
    host = HostConfig("nowhere", "remote", None, "/scratch")
    with pytest.raises(RuntimeError, match="ssh_target"):
        build_transport(host)


# --------------------------------------------------------------------------
# 6. which token_file.py the package loads (INFRA-637 review)
# --------------------------------------------------------------------------

CHECKOUT_ROOT = Path(__file__).resolve().parents[2]


def _stray_token_file(tmp_path, tag):
    d = tmp_path / tag
    d.mkdir()
    (d / "token_file.py").write_text(f"def read_token_text(path):\n    return {tag!r}\n", encoding="utf-8")
    return d


def test_token_reader_comes_from_the_checkout_root_not_a_stray_module_on_sys_path(monkeypatch, tmp_path):
    """A token_file.py that happens to be importable (cwd of `python -m`, a stale /srv/diskaudit.bak-* checkout, a
    worktree on PYTHONPATH) must not win over the checkout this package was installed from."""
    import sys

    from havnvard_bitrot import transport

    monkeypatch.delenv("HAVNVARD_HOME", raising=False)
    monkeypatch.syspath_prepend(str(_stray_token_file(tmp_path, "STRAY")))
    monkeypatch.delitem(sys.modules, "token_file", raising=False)
    before = list(sys.path)
    reader = transport._read_token_text()
    assert Path(sys.modules[reader.__module__].__file__).resolve() == CHECKOUT_ROOT / "token_file.py"
    assert sys.path == before  # the lookup does not put the checkout root in front of every later import


def test_havnvard_home_names_the_token_reader_first(monkeypatch, tmp_path):
    import sys

    from havnvard_bitrot import transport

    monkeypatch.setenv("HAVNVARD_HOME", str(_stray_token_file(tmp_path, "HOME")))
    monkeypatch.delitem(sys.modules, "token_file", raising=False)
    assert transport._read_token_text()("/any") == "HOME"
