"""HavnVard Backup 2.1: coverage-sync matching, not-backed-up report, health JSON + relay, check-timers.
No Postgres, no systemctl, no ssh: a fake DB connection, injected runners."""
from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, cli, config, coverage, health, nobackup, relay, timers  # noqa: E402
from backup.config import BackupError  # noqa: E402


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    sent = []
    monkeypatch.setattr(alerts, "fire", lambda k, t, c=0: (sent.append(("fire", k, t)) or (True, "sent")))
    monkeypatch.setattr(alerts, "resolve", lambda k: sent.append(("resolve", k)))
    return sent


# ---- coverage-sync -------------------------------------------------------------------------------------------
LS = [json.dumps({"struct_type": "snapshot", "short_id": "abc123"}),
      json.dumps({"struct_type": "node", "type": "file", "path": "/d/a", "size": 10, "mtime": "2026-11-01T10:00:00.123456789Z"}),
      json.dumps({"struct_type": "node", "type": "dir", "path": "/d"}),
      json.dumps({"struct_type": "node", "type": "file", "path": "/d/b", "size": 5, "mtime": "2026-11-01T10:00:00Z"})]


def test_parse_ls_json_files_only():
    snap, files = coverage.parse_ls_json(LS)
    assert snap == "abc123" and set(files) == {"/d/a", "/d/b"} and files["/d/a"] == (10, files["/d/b"][1])


def test_parse_ls_json_bad_node_is_an_error():
    with pytest.raises(BackupError):
        coverage.parse_ls_json([json.dumps({"struct_type": "node", "type": "file", "path": "/x"})])
    with pytest.raises(BackupError):
        coverage.parse_ls_json(["not json"])


def test_match_listing_requires_path_size_mtime():
    _, listing = coverage.parse_ls_json(LS)
    t = listing["/d/a"][1]
    cands = [("/d/a", 10, t), ("/d/b", 6, t), ("/d/b", 5, t + 60), ("/d/c", 10, t), ("/d/a", None, t), ("/d/a", 10, None)]
    assert coverage.match_listing(cands, listing) == ["/d/a"]


class FakeCur:
    def __init__(self, conn): self.c = conn
    def execute(self, sql, params=None): self.c.log.append(("execute", sql, params)); self.rows = list(self.c.rows)
    def fetchmany(self, n): r, self.rows = self.rows[:n], self.rows[n:]; return r
    def executemany(self, sql, seq): self.c.log.append(("executemany", sql, list(seq)))


class FakeConn:
    def __init__(self, rows): self.rows, self.log = rows, []
    def cursor(self): return FakeCur(self)
    def commit(self): self.log.append(("commit",))
    def rollback(self): self.log.append(("rollback",))


def test_sync_coverage_updates_only_matches_and_commits():
    _, listing = coverage.parse_ls_json(LS)
    t = listing["/d/a"][1]
    conn = FakeConn([("/d/a", 10, t), ("/d/zzz", 1, t)])
    assert coverage.sync_coverage(conn, "server-1", "abc123", listing) == 1
    upd = [x for x in conn.log if x[0] == "executemany"][0]
    assert [p[4] for p in upd[2]] == ["/d/a"] and "BACKED_UP_UNVERIFIED" in upd[1] and "'BACKED_UP_VERIFIED'" not in upd[1] and conn.log[-1] == ("commit",)


def test_sync_coverage_dry_run_writes_nothing():
    _, listing = coverage.parse_ls_json(LS)
    conn = FakeConn([("/d/a", 10, listing["/d/a"][1])])
    assert coverage.sync_coverage(conn, "h", "s", listing, dry_run=True) == 1
    assert not [x for x in conn.log if x[0] == "executemany"] and conn.log[-1] == ("rollback",)


# ---- not-backed-up -------------------------------------------------------------------------------------------
def test_not_backed_up_query_text_and_params():
    (_, tsql, tp), (_, gsql, gp) = nobackup.build_queries("hub-1", "type", 7)
    assert tp == ("hub-1", "hub-1") and gp == ("hub-1", "hub-1", 7)
    assert "NOT_BACKED_UP" in tsql and "DISTINCT ON (host, inode)" in gsql and "LIMIT %s" in gsql and "lower(substring" in gsql
    assert nobackup.build_queries(None, "folder", 5)[1][2] == (5,)
    for bad in (("x", 5), ("type", 0)):
        with pytest.raises(BackupError):
            nobackup.build_queries(None, *bad)


def test_not_backed_up_format():
    txt = nobackup.format_report([("hub-1", 3, 2_500_000_000)], [("/home/p/vids", 2, 2_000_000_000)], "folder", "hub-1")
    assert "2.50" in txt and "/home/p/vids" in txt and "folder" in txt
    assert "No NOT_BACKED_UP rows" in nobackup.format_report([], [], "type", None)


# ---- health --json and relay ---------------------------------------------------------------------------------
def test_health_json_ok_and_problem(capsys, monkeypatch):
    monkeypatch.setattr(health, "collect", lambda: [("a", True, "fine"), ("b", False, "stale")])
    assert cli.main(["health", "--json", "--no-alert"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc == {"ok": False, "exit_code": 1, "checks": [{"name": "a", "ok": True, "detail": "fine"},
                                                           {"name": "b", "ok": False, "detail": "stale"}]}


def test_health_json_unconfigured_is_exit_2(capsys):
    assert cli.main(["health", "--json", "--no-alert"]) == 2
    assert "error" in json.loads(capsys.readouterr().out)


def _runner(rc, out="", err=""):
    return lambda cmd, timeout=None: SimpleNamespace(returncode=rc, stdout=out, stderr=err)


GOOD = json.dumps({"ok": True, "exit_code": 0, "checks": [{"name": "a", "ok": True, "detail": "x"}]})
BAD = json.dumps({"ok": False, "exit_code": 1, "checks": [{"name": "snapshot age d", "ok": False, "detail": "30 h"}]})


def test_relay_healthy_resolves(env):
    assert relay.relay("hub", "python3", "havnvard", _runner(0, "banner\n" + GOOD)) == 0
    assert env == [("resolve", "havnvard-backup-health-hub")]


def test_relay_hub_problem_alerts_exit_1(env):
    assert relay.relay("hub", "python3", "havnvard", _runner(1, BAD)) == 1
    assert env[0][0] == "fire" and "snapshot age d" in env[0][2]


@pytest.mark.parametrize("rc,out", [(255, ""), (0, "garbage"), (0, ""), (0, BAD), (2, json.dumps({"ok": False, "error": "no cfg", "checks": []}))])
def test_relay_failures_are_alerts_never_silent(env, rc, out):
    code = relay.relay("hub", "python3", "havnvard", _runner(rc, out, "Connection refused"))
    assert code == 2 and env and env[0][0] == "fire"


def test_relay_remote_command_is_quoted():
    assert relay.remote_command("py thon", "a b") == "cd 'a b' && 'py thon' -m backup health --json --no-alert"


def test_relay_units_render(tmp_path):
    ps = relay.render_units(tmp_path, "hub-1", "/usr/bin/python3", "/home/p/havnvard")
    svc = (tmp_path / "havnvard-health-relay.service").read_text()
    assert "health-relay --ssh hub-1" in svc and "SuccessExitStatus=1" in svc and len(ps) == 2
    assert "OnCalendar=hourly" in (tmp_path / "havnvard-health-relay.timer").read_text()


# ---- check-timers --------------------------------------------------------------------------------------------
def test_check_timers_flags_missing_script_and_source():
    units = {"havnvard-restic-gone.service": "[Service]\nWorkingDirectory=/srv/gone\nExecStart=/srv/gone/run.sh\n",
             "havnvard-restic-ok.service": "[Service]\nExecStart=/bin/bash /srv/ok/run.sh\n"}
    calls = []

    def runner(cmd):
        calls.append(cmd)
        if "list-timers" in cmd:
            return 0, ("Mon x havnvard-restic-gone.timer havnvard-restic-gone.service\n"
                       "Mon y havnvard-restic-ok.timer havnvard-restic-ok.service\n") if "--user" not in cmd else ""
        return 0, units[cmd[-1]]
    files = {"/srv/ok/run.sh": "export BACKUP_SRC=/srv/ok-data\n"}
    f = timers.check_timers(runner, exists=lambda p: p in files or p == "/bin/bash", read=lambda p: files[p])
    assert {(t, w.split(" ")[0]) for t, w, _ in f} == {("havnvard-restic-gone.timer", "WorkingDirectory"),
                                                      ("havnvard-restic-gone.timer", "ExecStart")} | \
        {("havnvard-restic-ok.timer", "backup")}
    assert all(c[0] == "systemctl" and ("cat" in c or "list-timers" in c) for c in calls)


def test_check_timers_systemctl_failure_is_an_error():
    with pytest.raises(BackupError):
        timers.check_timers(lambda c: (1, ""))
