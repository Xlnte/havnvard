from __future__ import annotations

import json

import pytest

from havnvard_bitrot.config import HostConfig, load_settings

POSTGRES_URL = "postgresql://role:password@127.0.0.1:5432/havnvard"


def _env(monkeypatch, hosts_json: str | None = None) -> None:
    monkeypatch.setenv("POSTGRES_URL", POSTGRES_URL)
    if hosts_json is None:
        monkeypatch.delenv("INFRA126_HOSTS_JSON", raising=False)
    else:
        monkeypatch.setenv("INFRA126_HOSTS_JSON", hosts_json)


def test_host_config_defaults_to_pubkey_auth():
    host = HostConfig("agent-1", "remote", "havnvard@agent-1", "/var/lib/havnvard/infra126")
    assert host.auth == "pubkey"
    assert host.credentials_file is None


def test_default_hosts_is_only_this_machine(monkeypatch):
    """3.0.0: remote hosts are site settings (INFRA126_HOSTS_JSON); unset = verify only the local machine."""
    import socket
    _env(monkeypatch)
    settings = load_settings()
    assert list(settings.hosts) == [socket.gethostname()]
    only = settings.hosts[socket.gethostname()]
    assert only.mode == "local" and only.auth == "pubkey" and only.credentials_file is None


def test_hosts_json_without_auth_defaults_to_pubkey(monkeypatch):
    _env(monkeypatch, json.dumps({
        "agent-1": {"mode": "remote", "ssh_target": "havnvard@agent-1", "scratch_dir": "/var/lib/havnvard/infra126"},
    }))
    host = load_settings().hosts["agent-1"]
    assert host.auth == "pubkey"
    assert host.credentials_file is None


def test_hosts_json_parses_sshpass_auth(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-1": {
            "mode": "remote",
            "ssh_target": "backup@nas-1.example",
            "scratch_dir": "/share/CACHEDEV1_DATA/.diskaudit_scratch/infra126",
            "auth": "sshpass",
            "credentials_file": "/etc/havnvard/nas_backup.env",
        },
    }))
    host = load_settings().hosts["nas-1"]
    assert host.auth == "sshpass"
    assert host.credentials_file == "/etc/havnvard/nas_backup.env"


def test_unknown_auth_value_is_rejected(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-1": {"mode": "remote", "ssh_target": "a@b", "scratch_dir": "/scratch", "auth": "garbage"},
    }))
    with pytest.raises(ValueError, match="auth"):
        load_settings()


def test_sshpass_without_credentials_file_is_rejected(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-1": {"mode": "remote", "ssh_target": "a@b", "scratch_dir": "/scratch", "auth": "sshpass"},
    }))
    with pytest.raises(ValueError, match="credentials_file"):
        load_settings()
