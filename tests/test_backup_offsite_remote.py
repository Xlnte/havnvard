"""3.3.2 (INFRA-547): `health` watches an offsite uploader that runs on ANOTHER machine.

The failure this guards against: the hub moved, the uploader on the desktop kept uploading the retired hub's folder (and
later nothing at all), and `health` on the new hub stayed green because it only knew offsite targets it ran itself.
Every test is local: the "remote" status is produced by a fake command; no ssh, no network, no real hub.
"""
from __future__ import annotations

import json
import os
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, config, health, relay  # noqa: E402

NOW = 1_800_000_000.0
SRC = "agent-1:/srv/hub/restic-hub"


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    sent = []
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (sent.append((k, t)) or (True, "sent")))
    monkeypatch.setattr(alerts, "resolve", lambda k: sent.append((k, "RESOLVED")))
    return sent


def _hub(tmp_path, repos=("dev1", "dev2")):
    root = tmp_path / "hub"
    for r in repos:
        (root / r / "snapshots").mkdir(parents=True)
        (root / r / "config").write_text("x")
        f = root / r / "snapshots" / "abc"
        f.write_text("s")
        os.utime(f, (NOW - 3600, NOW - 3600))
    config.update("hub_local", {"repo_root": str(root)})
    return root


def _status(tmp_path, **over):
    doc = {"source": SRC, "at": NOW - 600, "rc": 0, "flagged": 0, "hold": [],
           "repos": {"dev1": {"ok_at": NOW - 7200}, "dev2": {"ok_at": NOW - 7200}}}
    doc.update(over)
    p = tmp_path / "remote-status.json"
    p.write_text(json.dumps(doc))
    return p


def _target(p, **over):
    spec = {"status_command": ["cat", str(p)], "expect_source": SRC}
    spec.update(over)
    config.update("offsite_remote", {"desk": spec})


def _bad(results):
    return {n: d for n, ok, d in results if not ok}


def test_fresh_remote_uploader_of_this_hub_is_healthy(tmp_path):
    _hub(tmp_path)
    _target(_status(tmp_path))
    res = health.collect(now=NOW)
    assert not _bad(res), _bad(res)
    assert any(n == "offsite desk dev1" for n, _, _ in res)


def test_uploader_reading_the_retired_hub_is_a_problem(tmp_path):
    """INFRA-547 itself: fresh, rc 0, every repo 'uploaded', but from the OLD hub's folder."""
    _hub(tmp_path)
    _target(_status(tmp_path, source="desktop-1:/home/u/restic-hub"))
    bad = _bad(health.collect(now=NOW))
    assert "offsite desk" in bad and "not this hub" in bad["offsite desk"]
    assert "desktop-1:/home/u/restic-hub" in bad["offsite desk"]


def test_unreachable_or_unreadable_status_is_a_problem_never_a_pass(tmp_path):
    _hub(tmp_path)
    _target(tmp_path / "missing.json")
    bad = _bad(health.collect(now=NOW))
    assert "offsite desk" in bad and "status" in bad["offsite desk"]
    p = tmp_path / "junk.json"
    p.write_text("not json")
    _target(p)
    assert "offsite desk" in _bad(health.collect(now=NOW))


def test_status_command_that_cannot_start_is_a_problem(tmp_path):
    _hub(tmp_path)
    _target(tmp_path / "x", status_command=["/nonexistent/havnvard-cmd"])
    assert "offsite desk" in _bad(health.collect(now=NOW))


def test_hub_repo_never_uploaded_or_stale_is_named(tmp_path):
    _hub(tmp_path, repos=("dev1", "dev2", "dev3"))
    _target(_status(tmp_path, repos={"dev1": {"ok_at": NOW - 7200}, "dev2": {"ok_at": NOW - 100 * 3600}}))
    bad = _bad(health.collect(now=NOW))
    assert "offsite desk dev1" not in bad
    assert "100 h" in bad["offsite desk dev2"]
    assert "never" in bad["offsite desk dev3"]


def test_uploader_that_stopped_running_is_a_problem(tmp_path):
    """Per-repo times can look fine right up to the limit; a run that has not happened for > limit is caught on its own."""
    _hub(tmp_path)
    _target(_status(tmp_path, at=NOW - 80 * 3600, repos={"dev1": {"ok_at": NOW - 80 * 3600},
                                                         "dev2": {"ok_at": NOW - 80 * 3600}}))
    bad = _bad(health.collect(now=NOW))
    assert "offsite desk" in bad and "80 h" in bad["offsite desk"]


def test_last_run_failed_or_flagged_is_a_problem(tmp_path):
    _hub(tmp_path)
    _target(_status(tmp_path, rc=2))
    assert "rc 2" in _bad(health.collect(now=NOW))["offsite desk"]
    _target(_status(tmp_path, flagged=3))
    assert "3 flagged" in _bad(health.collect(now=NOW))["offsite desk"]


def test_budget_stop_rc_75_is_not_a_failed_run(tmp_path):
    """rc 75 = the run used its time budget and the next one continues; it is not a failure (review gap)."""
    _hub(tmp_path)
    _target(_status(tmp_path, rc=75))
    assert not _bad(health.collect(now=NOW))


def test_held_repo_is_reported_not_failed(tmp_path):
    _hub(tmp_path, repos=("dev1", "dev2", "big"))
    _target(_status(tmp_path, hold=["big"]))
    res = health.collect(now=NOW)
    assert not _bad(res)
    assert any(n == "offsite desk big" and "held" in d for n, ok, d in res)


def test_stale_hours_follows_offsite_stale_hours(tmp_path):
    _hub(tmp_path)
    config.update("health", {"offsite_stale_hours": 1})
    _target(_status(tmp_path))
    assert "offsite desk dev1" in _bad(health.collect(now=NOW))


def test_expect_source_defaults_to_this_host_and_repo_root(tmp_path, monkeypatch):
    root = _hub(tmp_path)
    monkeypatch.setattr(health.socket, "gethostname", lambda: "agent-1")
    p = _status(tmp_path, source=f"agent-1:{root}")
    config.update("offsite_remote", {"desk": {"status_command": ["cat", str(p)]}})
    assert not _bad(health.collect(now=NOW))


def test_bad_target_config_is_an_error_not_a_pass(tmp_path):
    _hub(tmp_path)
    config.update("offsite_remote", {"desk": {"status_command": "cat x"}})
    bad = _bad(health.collect(now=NOW))
    assert "offsite desk" in bad and "status_command" in bad["offsite desk"]


def test_offsite_problems_raise_their_own_alert_key(tmp_path, env, monkeypatch):
    _hub(tmp_path)
    _target(_status(tmp_path, source="desktop-1:/home/u/restic-hub"))
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.run_health() == 1   # exit code still says "something is wrong"
    fired = [k for k, t in env if t != "RESOLVED"]
    assert health.OFFSITE_KEY == "havnvard-offsite-stale" and fired == [health.OFFSITE_KEY]
    assert "not this hub" in dict(env)[health.OFFSITE_KEY]
    # review fix 3: an offsite-only problem never holds the main key open
    assert (health.ALERT_KEY, "RESOLVED") in env


@pytest.mark.parametrize("as_json", [False, True])
def test_offsite_only_problem_fires_only_the_offsite_key(tmp_path, env, monkeypatch, capsys, as_json):
    _hub(tmp_path)
    _target(_status(tmp_path, repos={"dev1": {"ok_at": NOW - 7200}}))   # dev2 never uploaded
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.run_health(as_json=as_json) == 1
    assert [k for k, t in env if t != "RESOLVED"] == [health.OFFSITE_KEY]
    assert (health.ALERT_KEY, "RESOLVED") in env


@pytest.mark.parametrize("as_json", [False, True])
def test_device_problem_during_offsite_problem_fires_the_main_key(tmp_path, env, monkeypatch, capsys, as_json):
    root = _hub(tmp_path)
    old = root / "dev1" / "snapshots" / "abc"
    os.utime(old, (NOW - 500 * 3600, NOW - 500 * 3600))   # dev1's newest snapshot is very old: a device problem
    _target(_status(tmp_path, repos={"dev1": {"ok_at": NOW - 7200}}))   # and dev2 never uploaded: an offsite problem
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.run_health(as_json=as_json) == 1
    fired = dict((k, t) for k, t in env if t != "RESOLVED")
    assert set(fired) == {health.ALERT_KEY, health.OFFSITE_KEY}
    assert "offsite" not in fired[health.ALERT_KEY]          # the main text carries only the device problem
    assert "never fully uploaded" in fired[health.OFFSITE_KEY]


def test_offsite_key_resolves_when_offsite_is_healthy(tmp_path, env, monkeypatch):
    _hub(tmp_path)
    _target(_status(tmp_path))
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.run_health() == 0
    assert (health.OFFSITE_KEY, "RESOLVED") in env


# ---- relay: the same key on the machine that can alert ---------------------------------------------------------------

def _runner(rc, out):
    return lambda cmd, timeout=None: SimpleNamespace(returncode=rc, stdout=out, stderr="")


def test_relay_fires_offsite_key_for_offsite_checks(env):
    out = json.dumps({"ok": False, "exit_code": 1, "checks": [
        {"name": "snapshot age dev1", "ok": True, "detail": "1 h"},
        {"name": "offsite desk", "ok": False, "detail": "uploads desktop-1:/x, not this hub"}]})
    assert relay.relay("hub", "python3", "havnvard", _runner(1, out)) == 1
    assert f"{health.OFFSITE_KEY}-hub" in [k for k, t in env if t != "RESOLVED"]


def test_relay_offsite_only_problem_resolves_the_main_key(env):
    """Review fix 3: the hub's main key is not held open by an offsite backlog."""
    out = json.dumps({"ok": False, "exit_code": 1, "checks": [
        {"name": "snapshot age dev1", "ok": True, "detail": "1 h"},
        {"name": "offsite desk dev2", "ok": False, "detail": "never fully uploaded"}]})
    assert relay.relay("hub", "python3", "havnvard", _runner(1, out)) == 1
    assert ("havnvard-backup-health-hub", "RESOLVED") in env
    assert [k for k, t in env if t != "RESOLVED"] == [f"{health.OFFSITE_KEY}-hub"]
    assert relay.interpret(1, out) == (True, "")


def test_relay_device_problem_during_offsite_problem_fires_both_keys_separately(env):
    out = json.dumps({"ok": False, "exit_code": 1, "checks": [
        {"name": "snapshot age dev1", "ok": False, "detail": "30 h"},
        {"name": "offsite desk dev2", "ok": False, "detail": "never fully uploaded"}]})
    assert relay.relay("hub", "python3", "havnvard", _runner(1, out)) == 1
    fired = dict((k, t) for k, t in env if t != "RESOLVED")
    assert set(fired) == {"havnvard-backup-health-hub", f"{health.OFFSITE_KEY}-hub"}
    assert "offsite" not in fired["havnvard-backup-health-hub"] and "30 h" in fired["havnvard-backup-health-hub"]


def test_relay_resolves_offsite_key_only_when_offsite_checks_pass(env):
    out = json.dumps({"ok": False, "exit_code": 1, "checks": [
        {"name": "snapshot age dev1", "ok": False, "detail": "30 h"},
        {"name": "offsite desk", "ok": True, "detail": "fine"}]})
    relay.relay("hub", "python3", "havnvard", _runner(1, out))
    assert (f"{health.OFFSITE_KEY}-hub", "RESOLVED") in env


@pytest.mark.parametrize("device_ok", [True, False])
def test_relay_exits_2_when_the_offsite_alert_cannot_be_sent(env, monkeypatch, capsys, device_ok):
    """R2 (re-review 52ed43c): an offsite alert that could not be raised is a relay failure (2), never a plain 1,
    whether or not the main key also has a problem."""
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (False, "no channel") if "offsite" in k else (True, "sent"))
    out = json.dumps({"ok": False, "exit_code": 1, "checks": [
        {"name": "snapshot age dev1", "ok": device_ok, "detail": "1 h" if device_ok else "30 h"},
        {"name": "offsite desk dev2", "ok": False, "detail": "never fully uploaded"}]})
    assert relay.relay("hub", "python3", "havnvard", _runner(1, out)) == config.ERROR_EXIT
    assert f"ALERT NOT SENT ({health.OFFSITE_KEY}-hub)" in capsys.readouterr().out


def test_relay_failure_never_resolves_the_offsite_key(env):
    relay.relay("hub", "python3", "havnvard", _runner(255, ""))
    assert not any(k == f"{health.OFFSITE_KEY}-hub" and v == "RESOLVED" for k, v in env)


def test_wall_clock_is_used_by_default(tmp_path):
    """collect() without now= uses the real clock (guards the default path)."""
    _hub(tmp_path)
    _target(_status(tmp_path, at=time.time(), repos={"dev1": {"ok_at": time.time()}, "dev2": {"ok_at": time.time()}}))
    names = [n for n, _, _ in health.collect()]
    assert "offsite desk" in names
