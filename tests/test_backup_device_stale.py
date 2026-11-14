"""3.3.3 (INFRA-549): `health` checks every backup STREAM of every device, with a per-device limit and alert key.

The failure this guards against: a hub repository holds several streams (restic's host + paths grouping). The 3.3.2
check looked only at the newest snapshot FILE of the whole repository, so one fresh stream (a home-folder backup every
few hours) hid 48 app streams that had stopped 3 to 78 days earlier, and `health` stayed green.
Most tests feed snapshot lists through a fake lister; one test uses real local restic repositories.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, config, health, relay  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import needs_restic, restic  # noqa: E402

NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "restic-cache"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    sent = []
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (sent.append((k, t)) or (True, "sent")))
    monkeypatch.setattr(alerts, "resolve", lambda k: sent.append((k, "RESOLVED")))
    return sent


def _iso(age_h: float) -> str:
    return dt.datetime.fromtimestamp(NOW - age_h * 3600, dt.timezone.utc).isoformat()


def _snap(host, paths, age_h, tags=None):
    return {"hostname": host, "paths": list(paths), "time": _iso(age_h), "tags": tags or []}


def _hub(tmp_path, repos=("dev1", "dev2"), passwords=True):
    root = tmp_path / "hub"
    for r in repos:
        (root / r / "snapshots").mkdir(parents=True)
        (root / r / "config").write_text("x")
        f = root / r / "snapshots" / "abc"
        f.write_text("s")
        os.utime(f, (NOW - 3600, NOW - 3600))   # the newest FILE is always 1 h old: the 3.3.2 check is always green
        if passwords:
            pw = config.config_dir() / "hub-passwords" / f"{r}.pass"
            pw.parent.mkdir(parents=True, exist_ok=True)
            pw.write_text("pw\n")
    config.update("hub_local", {"repo_root": str(root)})
    return root


def _lister(monkeypatch, by_repo: dict):
    """by_repo: repo -> list of snapshots, or an Exception to raise."""
    calls = []

    def fake(repo_dir, repo, h):
        calls.append(repo)
        v = by_repo[repo]
        if isinstance(v, Exception):
            raise v
        return v
    monkeypatch.setattr(health, "_list_snapshots", fake)
    return calls


def _health(**kv):
    cfg = config.load()
    cfg.setdefault("health", {}).update(kv)
    config.save(cfg)


def _bad(results):
    return {n: d for n, ok, d in results if not ok}


# ---------- the check ----------

def test_one_stale_stream_makes_the_device_stale_although_the_newest_file_is_fresh(tmp_path, monkeypatch):
    """INFRA-549 itself: the home stream is 2 h old, an app stream stopped 98 h ago."""
    _hub(tmp_path)
    _lister(monkeypatch, {
        "dev1": [_snap("box", ["/home/u"], 2), _snap("box", ["/srv/app"], 98), _snap("box", ["/srv/app"], 120)],
        "dev2": [_snap("lap", ["/home/u"], 1)]})
    bad = _bad(health.collect(now=NOW))
    assert set(bad) == {"device dev1"}, bad
    assert "1 of 2 stream(s)" in bad["device dev1"] and "/srv/app 98.0 h" in bad["device dev1"]
    assert "limit 26 h" in bad["device dev1"]


def test_fresh_streams_are_healthy_and_replace_the_file_age_check(tmp_path, monkeypatch):
    _hub(tmp_path)
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 2), _snap("box", ["/srv/app"], 20)],
                          "dev2": [_snap("lap", ["/home/u"], 1)]})
    res = health.collect(now=NOW)
    assert not _bad(res), _bad(res)
    names = {n for n, _, _ in res}
    assert {"device dev1", "device dev2"} <= names
    assert not any(n.startswith("snapshot age") for n in names)


def test_missed_backup_on_a_one_stream_device_is_stale(tmp_path, monkeypatch):
    _hub(tmp_path)
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 2)], "dev2": [_snap("lap", ["/home/u"], 30)]})
    bad = _bad(health.collect(now=NOW))
    assert set(bad) == {"device dev2"}
    assert "30.0 h" in bad["device dev2"]


def test_per_device_limit_overrides_the_default(tmp_path, monkeypatch):
    _hub(tmp_path)
    config.update("health", {"devices": {"dev2": {"stale_hours": 48}}})
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 30)], "dev2": [_snap("lap", ["/home/u"], 30)]})
    bad = _bad(health.collect(now=NOW))
    assert set(bad) == {"device dev1"}
    _health(stale_hours=12)
    bad = _bad(health.collect(now=NOW))
    assert "limit 12 h" in bad["device dev1"]


def test_retired_streams_are_reported_not_failed(tmp_path, monkeypatch):
    _hub(tmp_path)
    config.update("health", {"devices": {"dev1": {"retired_streams": ["box|/srv/old"]}}})
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 2), _snap("box", ["/srv/old"], 1800)],
                          "dev2": [_snap("lap", ["/home/u"], 1)]})
    res = health.collect(now=NOW)
    assert not _bad(res), _bad(res)
    assert "1 retired" in dict((n, d) for n, _, d in res)["device dev1"]


def test_a_device_whose_every_stream_is_retired_is_a_problem(tmp_path, monkeypatch):
    _hub(tmp_path, repos=("dev1",))
    config.update("health", {"devices": {"dev1": {"retired_streams": ["box|/home/u"]}}})
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 2)]})
    bad = _bad(health.collect(now=NOW))
    assert "every stream" in bad["device dev1"]


def test_catalog_snapshots_are_not_backups(tmp_path, monkeypatch):
    """The hub writes a catalog snapshot into every repo each run: it must never make a stopped device look fresh."""
    _hub(tmp_path, repos=("dev1",))
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 40),
                                   _snap("hub", ["/cat"], 0.1, tags=["havnvard-catalog"])]})
    bad = _bad(health.collect(now=NOW))
    assert set(bad) == {"device dev1"} and "40.0 h" in bad["device dev1"]


def test_unreadable_repository_is_its_own_loud_problem_never_a_healthy_device(tmp_path, monkeypatch):
    """Fail-open rule: a read failure is never 'no stale devices'. It is a `stream check` problem (main key), the
    device key is not touched, and the 3.3.2 file-age check still runs so a stopped device is still caught."""
    _hub(tmp_path)
    _lister(monkeypatch, {"dev1": BackupError("restic snapshots failed rc=1: wrong password"),
                          "dev2": [_snap("lap", ["/home/u"], 1)]})
    res = health.collect(now=NOW)
    bad = _bad(res)
    assert "stream check dev1" in bad and "wrong password" in bad["stream check dev1"]
    names = {n for n, _, _ in res}
    assert "device dev1" not in names            # no verdict either way: the device key stays as it was
    assert "snapshot age dev1" in names          # fallback still runs


def test_empty_repository_is_a_problem(tmp_path, monkeypatch):
    _hub(tmp_path, repos=("dev1",))
    _lister(monkeypatch, {"dev1": []})
    bad = _bad(health.collect(now=NOW))
    assert "no backups" in bad["device dev1"]


def test_auto_mode_without_a_hub_password_keeps_the_file_age_check(tmp_path, monkeypatch):
    """Default `check_streams = "auto"`: a hub with no hub-side passwords behaves as 3.3.2 did, and says so."""
    _hub(tmp_path, passwords=False)
    calls = _lister(monkeypatch, {})
    res = health.collect(now=NOW)
    assert calls == []
    assert not _bad(res), _bad(res)
    d = dict((n, d) for n, _, d in res)
    assert "snapshot age dev1" in d and "per-stream check off" in d["snapshot age dev1"]


def test_check_streams_true_without_a_password_is_a_problem(tmp_path, monkeypatch):
    _hub(tmp_path, passwords=False)
    _health(check_streams=True)
    _lister(monkeypatch, {})
    bad = _bad(health.collect(now=NOW))
    assert "stream check dev1" in bad and "hub-side password" in bad["stream check dev1"]


def test_check_streams_false_turns_it_off(tmp_path, monkeypatch):
    _hub(tmp_path)
    _health(check_streams=False)
    calls = _lister(monkeypatch, {})
    res = health.collect(now=NOW)
    assert calls == [] and not _bad(res)


def test_archive_repos_are_not_stream_checked(tmp_path, monkeypatch):
    _hub(tmp_path, repos=("dev1", "old"))
    _health(archive_repos=["old"])
    calls = _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 1)]})
    res = health.collect(now=NOW)
    assert calls == ["dev1"] and not _bad(res)


def test_device_config_for_an_unknown_repo_is_a_problem(tmp_path, monkeypatch):
    """A typo (dev-1 for dev1) would otherwise silently leave the real device on the default limit."""
    _hub(tmp_path)
    config.update("health", {"devices": {"dev-1": {"stale_hours": 48}}})
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 1)], "dev2": [_snap("lap", ["/home/u"], 1)]})
    bad = _bad(health.collect(now=NOW))
    assert "health config" in bad and "dev-1" in bad["health config"]


@pytest.mark.parametrize("bad_cfg", [{"dev1": {"stale_hours": "soon"}}, {"dev1": {"stale_hours": 0}},
                                     {"dev1": {"retired_streams": "box|/srv/old"}}, {"dev1": "48"}])
def test_bad_device_config_is_a_loud_problem(tmp_path, monkeypatch, bad_cfg):
    _hub(tmp_path, repos=("dev1",))
    config.update("health", {"devices": bad_cfg})
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 1)]})
    bad = _bad(health.collect(now=NOW))
    assert "stream check dev1" in bad or "health config" in bad, bad


# ---------- alerts: once per state change, own key per device ----------

@pytest.fixture
def frozen(monkeypatch):
    """run_health() reads the clock itself; pin it to NOW for the fake snapshot times."""
    monkeypatch.setattr(health.time, "time", lambda: NOW)

def _keys(sent):
    return [(k, t == "RESOLVED") for k, t in sent]


def test_health_fires_only_the_stale_devices_key_and_resolves_the_others(tmp_path, monkeypatch, env, frozen):
    _hub(tmp_path)
    _lister(monkeypatch, {"dev1": [_snap("box", ["/srv/app"], 98)], "dev2": [_snap("lap", ["/home/u"], 1)]})
    assert health.run_health(send_alerts=True) == config.PROBLEM_EXIT
    k = _keys(env)
    assert ("havnvard-device-stale-dev1", False) in k
    assert ("havnvard-device-stale-dev2", True) in k
    assert ("havnvard-backup-health", True) in k          # a stale device never holds the main key open
    assert ("havnvard-backup-health", False) not in k


def test_health_json_path_alerts_the_same_way(tmp_path, monkeypatch, env, frozen, capsys):
    _hub(tmp_path)
    _lister(monkeypatch, {"dev1": [_snap("box", ["/srv/app"], 98)], "dev2": [_snap("lap", ["/home/u"], 1)]})
    assert health.run_health(send_alerts=True, as_json=True) == config.PROBLEM_EXIT
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is False and any(c["name"] == "device dev1" and not c["ok"] for c in doc["checks"])
    k = _keys(env)
    assert ("havnvard-device-stale-dev1", False) in k and ("havnvard-backup-health", True) in k


def test_fresh_snapshot_resolves_the_device_key(tmp_path, monkeypatch, env, frozen):
    _hub(tmp_path, repos=("dev1",))
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 30)]})
    health.run_health(send_alerts=True)
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 30), _snap("box", ["/home/u"], 0.2)]})
    env.clear()
    assert health.run_health(send_alerts=True) == 0
    assert ("havnvard-device-stale-dev1", True) in _keys(env)


def test_unreadable_repo_leaves_the_device_key_alone_and_alerts_on_the_main_key(tmp_path, monkeypatch, env, frozen):
    _hub(tmp_path, repos=("dev1",))
    _lister(monkeypatch, {"dev1": BackupError("restic not found on PATH")})
    assert health.run_health(send_alerts=True) == config.PROBLEM_EXIT
    k = _keys(env)
    assert not any(key.startswith("havnvard-device-stale") for key, _ in k), k
    assert ("havnvard-backup-health", False) in k
    assert "restic not found" in dict(env)["havnvard-backup-health"]


def test_unsent_device_alert_is_loud(tmp_path, monkeypatch, frozen, capsys):
    _hub(tmp_path, repos=("dev1",))
    _lister(monkeypatch, {"dev1": [_snap("box", ["/home/u"], 30)]})
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (False, "alertlib not importable"))
    health.run_health(send_alerts=True)
    out = capsys.readouterr()
    assert "ALERT NOT SENT (havnvard-device-stale-dev1)" in out.out + out.err


# ---------- health-relay ----------

def _doc(checks):
    ok = all(c["ok"] for c in checks)
    return json.dumps({"ok": ok, "exit_code": 0 if ok else 1, "checks": checks}), (0 if ok else 1)


def _runner(stdout, rc, stderr=""):
    return lambda cmd, timeout=None: SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def test_relay_fires_and_resolves_per_device_keys_and_keeps_the_main_key_clear(env):
    out, rc = _doc([{"name": "device dev1", "ok": False, "detail": "1 of 9 stream(s) older than 26 h"},
                    {"name": "device dev2", "ok": True, "detail": "1 stream(s)"},
                    {"name": "hub free space", "ok": True, "detail": "x"}])
    assert relay.relay("hub-1", "python3", "/opt/hv", runner=_runner(out, rc)) == config.PROBLEM_EXIT
    k = _keys(env)
    assert ("havnvard-device-stale-dev1", False) in k and ("havnvard-device-stale-dev2", True) in k
    assert ("havnvard-backup-health-hub-1", True) in k
    assert ("havnvard-backup-health-hub-1", False) not in k
    assert "1 of 9 stream" in dict(env)["havnvard-device-stale-dev1"]


def test_relay_all_devices_fresh_exits_0(env):
    out, rc = _doc([{"name": "device dev1", "ok": True, "detail": "ok"}])
    assert relay.relay("hub-1", "python3", "/opt/hv", runner=_runner(out, rc)) == 0
    assert ("havnvard-device-stale-dev1", True) in _keys(env)


def test_failed_relay_never_resolves_a_device_key(env):
    rc = relay.relay("hub-1", "python3", "/opt/hv", runner=_runner("", 255, "ssh: connect refused"))
    assert rc == config.ERROR_EXIT
    assert not any(k.startswith("havnvard-device-stale") for k, _ in _keys(env))
    assert ("havnvard-backup-health-hub-1", False) in _keys(env)


def test_relay_device_alert_not_sent_is_a_relay_failure(monkeypatch):
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (False, "no alertlib"))
    monkeypatch.setattr(alerts, "resolve", lambda k: None)
    out, rc = _doc([{"name": "device dev1", "ok": False, "detail": "stale"}])
    assert relay.relay("hub-1", "python3", "/opt/hv", runner=_runner(out, rc)) == config.ERROR_EXIT


def test_relay_stream_read_failure_goes_to_the_main_key(env):
    out, rc = _doc([{"name": "stream check dev1", "ok": False, "detail": "cannot read the backups: x"},
                    {"name": "snapshot age dev1", "ok": True, "detail": "1.0 h"}])
    assert relay.relay("hub-1", "python3", "/opt/hv", runner=_runner(out, rc)) == config.PROBLEM_EXIT
    k = _keys(env)
    assert ("havnvard-backup-health-hub-1", False) in k
    assert not any(key.startswith("havnvard-device-stale") for key, _ in k)


def test_relay_units_allow_time_for_the_stream_check(tmp_path):
    paths = relay.render_units(tmp_path, "hub-1", "python3", "/opt/hv")
    svc = next(p for p in paths if p.suffix == ".service").read_text()
    assert "TimeoutStartSec=6m" in svc


# ---------- real restic ----------

@needs_restic
def test_real_restic_repo_with_a_stopped_stream(tmp_path, monkeypatch):
    """End to end through the real lister: two streams in one repo, one backed up 'long ago' (restic --time)."""
    root = _hub(tmp_path, repos=())
    repo, pw = root / "dev1", config.config_dir() / "hub-passwords" / "dev1.pass"
    pw.parent.mkdir(parents=True, exist_ok=True)
    pw.write_text("test-password\n")
    a, b = tmp_path / "home", tmp_path / "app"
    for d in (a, b):
        d.mkdir()
        (d / "f.txt").write_text("x")
    restic(repo, pw, "init")
    restic(repo, pw, "backup", "--host", "box", str(a))
    old = dt.datetime.now() - dt.timedelta(hours=60)
    restic(repo, pw, "backup", "--host", "box", "--time", old.strftime("%Y-%m-%d %H:%M:%S"), str(b))
    _health(check_streams=True)
    bad = _bad(health.collect())
    assert set(bad) == {"device dev1"}, bad
    assert str(b) in bad["device dev1"] and "1 of 2 stream(s)" in bad["device dev1"]
