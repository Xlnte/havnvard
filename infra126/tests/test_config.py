from __future__ import annotations

import json

import pytest

from havnvard_bitrot.config import HostConfig, load_settings

POSTGRES_URL = "postgresql://role:password@127.0.0.1:5432/ultra_crm"


def _env(monkeypatch, hosts_json: str | None = None) -> None:
    monkeypatch.setenv("POSTGRES_URL", POSTGRES_URL)
    if hosts_json is None:
        monkeypatch.delenv("INFRA126_HOSTS_JSON", raising=False)
    else:
        monkeypatch.setenv("INFRA126_HOSTS_JSON", hosts_json)


def test_host_config_defaults_to_pubkey_auth():
    host = HostConfig("trigkey", "remote", "parker@trigkey", "/var/lib/havnvard/infra126")
    assert host.auth == "pubkey"
    assert host.credentials_file is None


def test_default_hosts_put_nas_on_sshpass(monkeypatch):
    _env(monkeypatch)
    settings = load_settings()
    nas = settings.hosts["nas-ts453a"]
    assert nas.auth == "sshpass"
    assert nas.credentials_file == "/etc/forge/tokens/nas_backup.env"
    assert settings.hosts["trigkey"].auth == "pubkey"
    assert settings.hosts["trigkey"].credentials_file is None
    assert settings.hosts["spark-20cf"].auth == "pubkey"


def test_hosts_json_without_auth_defaults_to_pubkey(monkeypatch):
    _env(monkeypatch, json.dumps({
        "trigkey": {"mode": "remote", "ssh_target": "parker@trigkey", "scratch_dir": "/var/lib/havnvard/infra126"},
    }))
    host = load_settings().hosts["trigkey"]
    assert host.auth == "pubkey"
    assert host.credentials_file is None


def test_hosts_json_parses_sshpass_auth(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-ts453a": {
            "mode": "remote",
            "ssh_target": "sparkbkup@nas-ts453a.tail5f354b.ts.net",
            "scratch_dir": "/share/CACHEDEV1_DATA/.diskaudit_scratch/infra126",
            "auth": "sshpass",
            "credentials_file": "/etc/forge/tokens/nas_backup.env",
        },
    }))
    host = load_settings().hosts["nas-ts453a"]
    assert host.auth == "sshpass"
    assert host.credentials_file == "/etc/forge/tokens/nas_backup.env"


def test_unknown_auth_value_is_rejected(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-ts453a": {"mode": "remote", "ssh_target": "a@b", "scratch_dir": "/scratch", "auth": "garbage"},
    }))
    with pytest.raises(ValueError, match="auth"):
        load_settings()


def test_sshpass_without_credentials_file_is_rejected(monkeypatch):
    _env(monkeypatch, json.dumps({
        "nas-ts453a": {"mode": "remote", "ssh_target": "a@b", "scratch_dir": "/scratch", "auth": "sshpass"},
    }))
    with pytest.raises(ValueError, match="credentials_file"):
        load_settings()
