"""Config, enrol, hub, client and health paths of the HavnVard Backup package (no live services)."""
from __future__ import annotations

import os
import stat
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, cli, config, enroll, health, hub  # noqa: E402
from backup.config import BackupError  # noqa: E402


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    sent = []
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (sent.append((k, t)) or (True, "sent")))
    monkeypatch.setattr(alerts, "resolve", lambda k: sent.append((k, "RESOLVED")))
    return sent


def test_config_roundtrip_and_mode(tmp_path):
    config.save({"hub": {"address": "h:1"}, "offsite": {"gd": {"rclone_remote": 'a:"b"', "crypt": True}}})
    assert config.load()["offsite"]["gd"] == {"rclone_remote": 'a:"b"', "crypt": True}
    assert stat.S_IMODE(os.stat(config.config_path()).st_mode) == 0o600


def test_enroll_never_overwrites_or_prints_passwords(tmp_path, capsys):
    data = tmp_path / "d"
    data.mkdir()
    out = "\n".join(enroll.enroll("dev1", [str(data)], "generic", None, None, tmp_path / "o"))
    pw = (config.config_dir() / "restic.pass").read_text().strip()
    rest = (config.config_dir() / "rest.pass").read_text().strip()
    assert pw not in out and rest not in out and "{SHA}" in out
    assert stat.S_IMODE(os.stat(config.config_dir() / "restic.pass").st_mode) == 0o600
    out2 = "\n".join(enroll.enroll("dev1", [str(data)], "generic", 100, "01-05", tmp_path / "o"))
    assert (config.config_dir() / "restic.pass").read_text().strip() == pw   # idempotent
    assert "already existed" in out2 and config.load()["device"]["limit_upload_kib"] == 100
    assert (tmp_path / "o" / "havnvard-backup.timer").exists()


@pytest.mark.parametrize("name,paths", [("bad name!", ["."]), ("ok", ["/nonexistent/x"]), ("ok", [])])
def test_enroll_rejects_bad_input(tmp_path, name, paths):
    with pytest.raises(BackupError):
        enroll.enroll(name, paths, "generic", None, None, tmp_path)


def test_quiet_hours():
    assert enroll.in_quiet("08-18", 9) and not enroll.in_quiet("08-18", 18)
    assert enroll.in_quiet("22-06", 23) and enroll.in_quiet("22-06", 3) and not enroll.in_quiet("22-06", 12)
    with pytest.raises(BackupError):
        enroll.parse_quiet("8to9")


def test_hub_set_validation():
    assert hub.hub_set("100.1.2.3") == "100.1.2.3:8000"
    assert config.load()["hub"]["address"] == "100.1.2.3:8000"
    for bad in ("", "a b", "h:99999", "u@h", "http://h"):
        with pytest.raises(BackupError):
            hub.hub_set(bad)


def test_hub_install_renders_and_runs_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(hub, "run", lambda *a, **k: pytest.fail("hub install must not run commands"))
    lines = hub.hub_install(str(tmp_path / "repos"), 8000, "127.0.0.1", tmp_path / "o", "/bin/rest-server")
    svc = (tmp_path / "o" / "restic-hub.service").read_text()
    assert "--append-only --private-repos" in svc and "--listen 127.0.0.1:8000" in svc
    assert any("loopback" in ln or "this machine only" in ln for ln in lines)
    assert config.load()["hub_local"]["repo_root"] == str((tmp_path / "repos").resolve())


def test_diskguard_df_failure_alerts_and_exits_1(tmp_path, env, monkeypatch):
    config.update("hub_local", {"repo_root": str(tmp_path)})
    monkeypatch.setattr(hub, "_free_gb", lambda p: (_ for _ in ()).throw(BackupError("df broke")))
    assert hub.diskguard() == config.PROBLEM_EXIT and env and "df broke" in env[0][1]


def test_diskguard_stops_then_restarts_only_its_own_stop(tmp_path, env, monkeypatch):
    config.update("hub_local", {"repo_root": str(tmp_path)})
    calls = []

    class R:
        returncode = 0

    monkeypatch.setattr(hub, "run", lambda cmd, **k: (calls.append(cmd[2]) or R()))
    monkeypatch.setattr(hub, "_free_gb", lambda p: 50)
    assert hub.diskguard() == 1 and "stop" in calls
    monkeypatch.setattr(hub, "_free_gb", lambda p: 130)
    calls.clear()
    assert hub.diskguard() == 0 and "start" in calls
    calls.clear()
    assert hub.diskguard() == 0 and not calls   # guard no longer owns a stop: it must not start anything


def _stub_restic(tmp_path, monkeypatch):
    bin_ = tmp_path / "restic"
    bin_.write_text('#!/bin/bash\necho "$@" >> "$FAKE_LOG"\ncase "$1" in cat) exit ${FAKE_CAT_RC:-0};; '
                    'init) exit 0;; backup) exit ${FAKE_BACKUP_RC:-0};; esac\n')
    bin_.chmod(0o755)
    monkeypatch.setenv("HAVNVARD_RESTIC", str(bin_))
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "log"))
    return tmp_path / "log"


def _enrolled(tmp_path, quiet=None):
    data = tmp_path / "d"
    data.mkdir(exist_ok=True)
    hub.hub_set("h:1")
    enroll.enroll("dev1", [str(data)], "generic", None, quiet, tmp_path / "o")


def test_client_run_creates_repo_and_passes_rc3_through(tmp_path, monkeypatch):
    log = _stub_restic(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_CAT_RC", "10")
    monkeypatch.setenv("FAKE_BACKUP_RC", "3")
    _enrolled(tmp_path)
    assert enroll.client_run(init=True) == 3
    text = log.read_text()
    assert "init" in text and "--limit-upload 4096" in text and "--host dev1" in text
    assert health.collect()[0][1] is True   # rc 3 still counts as a saved snapshot


def test_client_run_unreachable_hub_is_an_error_not_a_pass(tmp_path, monkeypatch):
    _stub_restic(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_CAT_RC", "1")
    _enrolled(tmp_path)
    with pytest.raises(BackupError):
        enroll.client_run(init=True)
    assert health.collect()[0][1] is False


def test_client_run_quiet_hours_skips_and_unenrolled_errors(tmp_path, monkeypatch):
    log = _stub_restic(tmp_path, monkeypatch)
    with pytest.raises(BackupError):
        enroll.client_run()
    _enrolled(tmp_path, quiet="08-18")
    assert enroll.client_run(hour=10) == 0 and not log.exists()


def _hub_with_repo(tmp_path, age_h):
    root = tmp_path / "hub"
    snap = root / "dev1" / "snapshots"
    snap.mkdir(parents=True)
    (root / "dev1" / "config").write_text("x")
    f = snap / "abc"
    f.write_text("s")
    t = time.time() - age_h * 3600
    os.utime(f, (t, t))
    config.update("hub_local", {"repo_root": str(root)})


def test_health_flags_stale_snapshot_and_alerts(tmp_path, env):
    _hub_with_repo(tmp_path, 30)
    assert health.run_health() == 1
    assert env and env[0][0] == "havnvard-backup-health" and "dev1" in env[0][1]


def test_health_ok_resolves(tmp_path, env):
    _hub_with_repo(tmp_path, 1)
    assert health.run_health() == 0 and env[-1][1] == "RESOLVED"


def test_health_empty_hub_and_nothing_configured_are_not_success(tmp_path):
    with pytest.raises(BackupError):
        health.collect()
    (tmp_path / "hub").mkdir()
    config.update("hub_local", {"repo_root": str(tmp_path / "hub")})
    assert not health.collect()[0][1]   # no repos found is a problem


def test_cli_maps_errors_to_exit_2(capsys):
    assert cli.main(["health"]) == config.ERROR_EXIT
    assert "ERROR" in capsys.readouterr().err


def test_alert_failure_is_visible(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setenv("HAVNVARD_ALERTLIB_PATH", "/nonexistent")
    monkeypatch.setitem(sys.modules, "alertlib", None)
    ok, why = alerts.fire("k", "t")
    assert not ok and "alertlib" in why


def _alert_env(monkeypatch, tmp_path, command):
    monkeypatch.undo()                       # drop the fake fire/resolve; re-isolate config and state
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "acfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "astate"))
    monkeypatch.setenv("HAVNVARD_ALERTLIB_PATH", "/nonexistent")
    monkeypatch.setitem(sys.modules, "alertlib", None)
    if command is not None:
        config.save({"alerts": {"command": command}})


def test_alert_command_used_when_no_alertlib(monkeypatch, tmp_path):
    out = tmp_path / "got.txt"
    _alert_env(monkeypatch, tmp_path, ["sh", "-c", f'printf "%s|%s" "$HAVNVARD_ALERT_KEY" "$HAVNVARD_ALERT_TEXT" >> {out}'])
    ok, why = alerts.fire("hv-key", "hub stale", cooldown_sec=3600)
    assert ok and "alert command" in why
    assert out.read_text() == "hv-key|hub stale"
    ok2, why2 = alerts.fire("hv-key", "hub stale", cooldown_sec=3600)   # inside the cooldown: not sent again
    assert ok2 and "cooldown" in why2 and out.read_text() == "hv-key|hub stale"
    alerts.resolve("hv-key")                                            # resolve clears it: next problem alerts
    assert alerts.fire("hv-key", "again", cooldown_sec=3600)[0] and out.read_text().endswith("hv-key|again")


def test_alert_command_failure_is_visible(monkeypatch, tmp_path):
    _alert_env(monkeypatch, tmp_path, ["sh", "-c", "echo nope >&2; exit 3"])
    ok, why = alerts.fire("k", "t")
    assert not ok and "exit 3" in why and "nope" in why


def test_alert_without_alertlib_or_command_is_visible(monkeypatch, tmp_path):
    _alert_env(monkeypatch, tmp_path, None)
    ok, why = alerts.fire("k", "t")
    assert not ok and "no [alerts] command" in why


def test_excludes_profiles_use_home_placeholder():
    for prof in enroll.PROFILES:
        text = enroll.excludes_text(prof)
        assert "{HOME}" not in text and str(__import__("pathlib").Path.home()) in text


def test_package_version_matches_module_yaml():
    import re as _re
    from backup import __version__
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "module.yaml"), encoding="utf-8") as f:
        m = _re.search(r"^version:\s*([0-9.]+)\s*$", f.read(), _re.M)
    assert m and m.group(1) == __version__


def test_alertlib_path_from_backup_toml(monkeypatch, tmp_path):
    _alert_env(monkeypatch, tmp_path, None)
    monkeypatch.delenv("HAVNVARD_ALERTLIB_PATH")
    monkeypatch.delitem(sys.modules, "alertlib")
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "alertlib.py").write_text("def fire(k, t, c, s):\n    return True\n")
    config.save({"alerts": {"alertlib_path": str(lib)}})
    ok, why = alerts.fire("k", "t")
    assert ok and why == "sent"
