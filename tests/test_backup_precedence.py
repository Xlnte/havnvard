"""HavnVard 3.3.13 (INFRA-644): a pullback takes precedence over other backup jobs, and is tested by a drill.

Spec: runbooks/20261116-havnvard-pullback-precedence/20261116_SPEC_PULLBACK_PRECEDENCE.md v1.0, section 4. Each test
names the acceptance criterion it proves (C1 ... C11). Local restic repositories in tmp dirs only: no hub, no device,
no network, no database. A real exclusive lock is held with `restic key passwd` waiting on stdin (it takes an exclusive
lock, then reads the new password; closing stdin makes it fail with nothing changed). Waits the spec gives in minutes
are scaled to seconds through the module's constants; the logic is the same.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import (accounts, alerts, archive, catalog, config, health, precedence, prune,  # noqa: E402
                    pullback_drill, relay)
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import needs_restic, restic  # noqa: E402

REPO_DIR = Path(__file__).resolve().parent.parent
LOCK_NAME = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture
def hub(tmp_path, monkeypatch):
    """A hub with one device repository `dev1` (hub-side password), the owner's own key copy, and a test folder."""
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    fired: list[tuple[str, str]] = []
    resolved: list[str] = []
    monkeypatch.setattr(alerts, "fire", lambda key, text, *a, **k: (fired.append((key, text)) or (True, "sent")))
    monkeypatch.setattr(alerts, "resolve", lambda key: resolved.append(key))
    monkeypatch.setattr(precedence, "POLL_S", 0.2)
    (tmp_path / "cfg").mkdir()
    root, pdir = tmp_path / "hub", tmp_path / "cfg" / "hub-passwords"
    pdir.mkdir()
    repo, pw = root / "dev1", pdir / "dev1.pass"
    pw.write_text("test-password\n")
    restic(repo, pw, "init")
    owner = tmp_path / "owner.pass"
    owner.write_text("test-password\n")
    config.save({"hub_local": {"repo_root": str(root)}})
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    monkeypatch.setattr(archive, "device_env", lambda: (env, {"name": "dev1", "paths": []}))
    data = tmp_path / "hvtest"
    for sub in ("a", "b"):
        (data / sub).mkdir(parents=True)
        for i in range(6):
            (data / sub / f"f{i}.bin").write_bytes(os.urandom(500 + i) + sub.encode())
    restic(repo, pw, "backup", str(data))
    return {"tmp": tmp_path, "repo": repo, "pw": pw, "owner": owner, "data": data, "env": env, "root": root,
            "fired": fired, "resolved": resolved}


def _snap(h):
    """The newest DATA snapshot (catalog copies and the drill marker are not data)."""
    return catalog.data_snapshots(json.loads(restic(h["repo"], h["pw"], "snapshots", "--json", "--no-lock")))[-1]


def _locks(repo: Path) -> list[str]:
    d = repo / "locks"
    return sorted(n for n in os.listdir(d) if LOCK_NAME.match(n)) if d.is_dir() else []


def hold_exclusive(h) -> subprocess.Popen:
    """A real live exclusive restic lock on dev1, held until the returned process's stdin is closed."""
    p = subprocess.Popen(["restic", "key", "passwd"], env={**os.environ, **h["env"]}, stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(400):
        if _locks(h["repo"]):
            return p
        time.sleep(0.05)
    p.kill()
    raise AssertionError("restic key passwd did not take its lock")


def release(p: subprocess.Popen) -> None:
    p.stdin.close()
    p.wait(timeout=30)


def release_once_waiting(holder: subprocess.Popen) -> threading.Thread:
    """Release the held lock only after the pullback has really met it (its `pullback.lock_met` log line), plus 1 s,
    so a slow machine can never let the pullback start after the lock is already gone (no fixed timer)."""
    def go():
        wait_for(lambda: precedence.log_path().is_file() and "pullback.lock_met" in precedence.log_path().read_text(),
                 120)
        time.sleep(1.0)
        release(holder)
    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t


def fake_job(repo: str, job: str, pid: int, who: str = "hubowner", started: float | None = None) -> Path:
    d = precedence.jobs_dir(repo)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{precedence.host()}-{pid}.json"
    p.write_text(json.dumps({"job": job, "user": who, "host": precedence.host(), "pid": pid,
                             "started_at": started or time.time(), "what": "test"}))
    return p


def _lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.strip()]


def _cli_env():
    return {**os.environ, "PYTHONPATH": str(REPO_DIR)}


def slow_restic(tmp: Path, seconds: float) -> Path:
    w = tmp / "restic-slow.sh"
    w.write_text(f'#!/bin/sh\nif [ "$1" = dump ]; then sleep {seconds}; fi\nexec restic "$@"\n')
    w.chmod(0o755)
    return w


def wait_for(cond, timeout=30.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return False


# ---------- C1: pullback + catalog at once ----------

@needs_restic
def test_c1_catalog_tag_defers_during_pullback_and_catches_up(hub, capsys):
    """C1 (forced): the catalog's exclusive name tag runs while a pullback is live: deferred, 0 FAILED, caught up next run."""
    snap = _snap(hub)
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    runs = []
    rc = archive.pullback(paths=[str(hub["data"])], snapshot=snap["id"][:8], target=str(tgt),
                          on_start=lambda it: runs.append(catalog.catalog_run()))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "STATUS: DONE 12/12" in out and "FAILED" not in out.replace("0 FAILED", "")
    assert "DEFERRED name tag" in out and runs == [0]
    lines = precedence.open_deferrals(job="catalog", repo="dev1")
    assert len(lines) == 1 and lines[0]["pullback_ended_at"]                 # the pullback's end was recorded
    assert not any(catalog.NAME_RE.match(t) for t in _snap(hub).get("tags") or [])   # not tagged during the pullback
    assert catalog.catalog_run() == 0                                        # next run: catches up
    out = capsys.readouterr().out
    assert "caught up" in out and "done now" in out
    assert precedence.open_deferrals() == []
    done = [json.loads(ln) for ln in precedence.deferred_path().read_text().splitlines()]
    assert done[0]["done_at"] and done[0]["tag"] in (_snap(hub).get("tags") or [])
    log = precedence.log_path().read_text()
    assert '"action": "yield.deferred"' in log and '"action": "yield.caught_up"' in log


@needs_restic
def test_c1_c9_pullback_waits_out_a_catalog_tag_already_in_flight(hub, capsys):
    """C1 / C9 / 3.3: the catalog's tag already holds the exclusive lock when the pullback starts: the pullback names it,
    retries (up to 2 min), gets the lock and finishes with 0 FAILED."""
    snap = _snap(hub)
    holder = hold_exclusive(hub)
    fake_job("dev1", "catalog", holder.pid, started=time.time() - 3)
    release_once_waiting(holder)
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    rc = archive.pullback(paths=[str(hub["data"] / "a")], snapshot=snap["id"][:8], target=str(tgt))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "STATUS: WAITING for the hub catalog's name tag hubowner started at" in out
    assert "retrying for up to 2 min" in out and re.search(r"GOT THE LOCK after \d+s", out)
    assert _lines(out)[-1] == "STATUS: DONE 6/6"


# ---------- C2: prune / forget / key removal refuse while a pullback is live ----------

@needs_restic
def test_c2_prune_forget_and_key_removal_refuse_while_pullback_live(hub, capsys):
    before = restic(hub["repo"], hub["pw"], "snapshots", "--json")
    with precedence.announce("dev1", "test pullback"):
        with pytest.raises(precedence.PullbackLive, match="nothing was changed; run the backup delete again"):
            prune.prune("dev1", {"keep_daily": 1}, str(hub["owner"]), confirm="x")
        with pytest.raises(precedence.PullbackLive, match="a pullback for .* running since .*nothing was changed"):
            archive.forget_dated("dev1", "2099-01-01", str(hub["owner"]), confirm="x")
        with pytest.raises(precedence.PullbackLive, match="nothing was changed"):   # pullback began during the prompt
            prune.delete_snapshots("restic", hub["env"], "dev1", [_snap(hub)], "TEST", "DELETE FROM dev1 1 SNAPSHOTS TEST")

        class Accts:
            def store_key_matches(self, k): return True
            def _log(self, *a, **k): raise AssertionError("nothing may be logged as done")
        with pytest.raises(precedence.PullbackLive, match="nothing was changed; run the key removal again"):
            accounts.revoke_device_keys("restic", str(hub["repo"]), "store", Accts(), "dev1")
    assert restic(hub["repo"], hub["pw"], "snapshots", "--json") == before                  # nothing changed
    assert '"action": "yield.refused"' in precedence.log_path().read_text()


# ---------- C3: a stale lock is unlocked (stale only), audited ----------

@needs_restic
def test_c3_stale_lock_of_dead_process_is_unlocked_and_audited(hub, capsys):
    accounts.Accounts()                                      # this hub has an audit log
    holder = hold_exclusive(hub)
    os.kill(holder.pid, signal.SIGKILL)
    holder.wait()
    assert len(_locks(hub["repo"])) == 1                     # the dead process's lock is left behind
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    rc = archive.pullback(paths=[str(hub["data"] / "b")], snapshot=_snap(hub)["id"][:8], target=str(tgt))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert f"STALE LOCK on dev1: a lock left by process {holder.pid}" in out and "removes stale locks only" in out
    assert _locks(hub["repo"]) == []
    assert '"action": "pullback.stale_unlock"' in precedence.log_path().read_text()
    rows = [r for r in accounts.Accounts().audit_rows() if r["action"] == "pullback.stale_unlock"]
    assert len(rows) == 1 and rows[0]["target"] == "dev1"


# ---------- C4 / C9 / C9c: a foreign live lock held too long ----------

@needs_restic
def test_c4_c9_c9c_foreign_live_lock_gives_up_names_holder_and_removes_nothing(hub, capsys, monkeypatch):
    """C4: held longer than the wait (10 min, scaled to 3 s): FAILED with the holder named, exit 1, no lock removed.
    C9: the waiting lines name who holds it and since when, and what the person can do. C9c: after the notice time
    (2 min, scaled to 1 s) ONE hub notice names the holder."""
    monkeypatch.setattr(precedence, "OTHER_WAIT_S", 3)
    monkeypatch.setattr(precedence, "NOTICE_AFTER_S", 1)
    monkeypatch.setattr(precedence, "LINE_EVERY_S", 1)
    notices = []
    snap = _snap(hub)
    holder = hold_exclusive(hub)
    try:
        lock_before = _locks(hub["repo"])
        tgt = hub["tmp"] / "back"
        tgt.mkdir()
        rc = archive.pullback(paths=[str(hub["data"] / "a" / "f1.bin"), str(hub["data"] / "b" / "f2.bin")],
                              snapshot=snap["id"][:8], target=str(tgt),
                              hub_notice=lambda kind, text: notices.append((kind, text)) or "sent")
        out = capsys.readouterr().out
        assert _locks(hub["repo"]) == lock_before                                   # never removes a live lock
    finally:
        release(holder)
    assert rc == config.PROBLEM_EXIT
    who = f"a restic lock held by process {holder.pid} of user"
    assert f"STATUS: WAITING for {who}" in out and "since 20" in out
    assert "still waiting for" in out and "press Ctrl-C and run the same pullback again later" in out
    assert "ask the hub owner" in out
    assert re.search(r"GAVE UP after \d+s waiting for " + re.escape(who), out)
    assert "FAILED" in out and "no lock was removed" in out
    assert len(notices) == 1 and notices[0][0] == "pullback_waiting" and who in notices[0][1]
    assert _lines(out)[-1].startswith("STATUS: NOT DONE 0/2, 2 FAILED (listed above): run the same pullback again")


@needs_restic
def test_c9_waiting_line_names_a_running_prune_and_who_started_it(hub, capsys, monkeypatch):
    holder = hold_exclusive(hub)
    fake_job("dev1", "prune", holder.pid, who="hubowner", started=time.time() - 60)
    sid = _snap(hub)["id"][:8]
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    release_once_waiting(holder)
    assert archive.pullback(paths=[str(hub["data"] / "a")], snapshot=sid, target=str(tgt)) == 0
    out = capsys.readouterr().out
    assert "WAITING for the backup delete hubowner started at" in out and f"on {precedence.host()}" in out
    assert "retrying for up to 10 min" in out and "to stop that job now, ask the hub owner" in out
    assert "GOT THE LOCK" in out


# ---------- C5: honest summary ----------

@needs_restic
def test_c5_summary_never_counts_a_failed_file_restored(hub, capsys, monkeypatch):
    """C5 (with test_lock_refused_dump_is_not_counted_restored_infra645): 1 FAILED of N says N-1 restored, 1 FAILED."""
    monkeypatch.setattr(precedence, "OTHER_WAIT_S", 0.5)
    bad = str(hub["data"] / "a" / "f3.bin")
    w = hub["tmp"] / "restic-locked.sh"
    w.write_text('#!/bin/sh\nfor a in "$@"; do if [ "$a" = "%s" ] && [ "$1" = dump ]; then echo "unable to create '
                 'lock in backend: repository is already locked exclusively by PID 1 on elsewhere by someone (UID 1, '
                 'GID 1)" >&2; exit 11; fi; done\nexec restic "$@"\n' % bad)
    w.chmod(0o755)
    monkeypatch.setenv("HAVNVARD_RESTIC", str(w))
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    files = [str(hub["data"] / "a" / f"f{i}.bin") for i in range(6)]
    assert archive.pullback(paths=files, snapshot=_snap(hub)["id"][:8], target=str(tgt),
                            hub_notice=lambda *a: "sent") == config.PROBLEM_EXIT
    out = capsys.readouterr().out
    assert "pullback: 5 restored, 1 FAILED (listed below)" in out and "6 restored" not in out
    assert "5/6 files accounted for" in out and not (tgt / bad.lstrip("/")).exists()     # no empty PARTIAL copy
    assert _lines(out)[-1].startswith("STATUS: NOT DONE 5/6, 1 FAILED")


# ---------- C6 / C9a: the intent file on every kind of exit ----------

def test_c6_intent_removed_on_normal_exit_and_on_exception(hub):
    with precedence.announce("dev1", "t") as it:
        assert it.path.is_file() and json.loads(it.path.read_text())["pid"] == os.getpid()
        assert precedence.read_intents("dev1")[0][0]["id"] == it.id
    assert not it.path.exists()
    with pytest.raises(RuntimeError), precedence.announce("dev1", "t") as it2:
        raise RuntimeError("boom")
    assert not it2.path.exists()


def test_c6_heartbeat_refreshes_the_intent(hub, monkeypatch):
    monkeypatch.setattr(precedence, "HEARTBEAT_S", 0.1)
    with precedence.announce("dev1", "t") as it:
        first = json.loads(it.path.read_text())["heartbeat_at"]
        assert wait_for(lambda: json.loads(it.path.read_text())["heartbeat_at"] > first, 5)


@needs_restic
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_c6_intent_removed_on_ctrl_c_and_sigterm(hub, sig):
    w = slow_restic(hub["tmp"], 30)
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    p = subprocess.Popen([sys.executable, "-m", "backup", "pullback", "--from", "dev1", "--snapshot",
                          _snap(hub)["id"][:8], str(hub["data"] / "a" / "f0.bin"), "--target", str(tgt)],
                         cwd=str(REPO_DIR), env={**_cli_env(), "HAVNVARD_RESTIC": str(w)},
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    assert wait_for(lambda: list(precedence.intent_dir("dev1").glob("*.json")), 30)
    time.sleep(1.0)                                          # inside the slow `restic dump`
    os.killpg(p.pid, sig)                                    # Ctrl-C reaches the whole foreground group
    out, err = p.communicate(timeout=60)
    assert p.returncode != 0
    assert list(precedence.intent_dir("dev1").glob("*.json")) == []
    assert out.splitlines()[0] == "STATUS: RUNNING" and out.splitlines()[-1].startswith("STATUS: NOT DONE")


@needs_restic
def test_c6_c9a_hard_kill_leaves_a_stale_intent_that_blocks_nothing(hub, capsys):
    """C6 (crash) and C9a: after kill -9 the intent file stays, is stale at once (its process is gone), and the next
    catalog run removes it (logged) and tags as usual: nothing is deferred."""
    w = slow_restic(hub["tmp"], 30)
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    p = subprocess.Popen([sys.executable, "-m", "backup", "pullback", "--from", "dev1", "--snapshot",
                          _snap(hub)["id"][:8], str(hub["data"] / "a" / "f0.bin"), "--target", str(tgt)],
                         cwd=str(REPO_DIR), env={**_cli_env(), "HAVNVARD_RESTIC": str(w)},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    assert wait_for(lambda: list(precedence.intent_dir("dev1").glob("*.json")), 30)
    os.killpg(p.pid, signal.SIGKILL)                         # power loss: the pullback and its children die at once
    p.wait()
    left = list(precedence.intent_dir("dev1").glob("*.json"))
    assert len(left) == 1
    assert catalog.catalog_run() == 0
    out = capsys.readouterr().out
    assert "DEFERRED" not in out and precedence.open_deferrals() == []
    assert not left[0].exists()
    log = precedence.log_path().read_text()
    assert '"action": "intent.stale_removed"' in log and f"process {p.pid} is gone" in log


def test_c6_stale_rules_heartbeat_age_other_boot_and_unreadable(hub, monkeypatch):
    d = precedence.intent_dir("dev1")
    d.mkdir(parents=True)
    now = time.time()
    base = {"pid": os.getpid(), "user": "u", "started_at": now - 900, "what": "t", "id": "x"}
    (d / "old.json").write_text(json.dumps({**base, "host": "elsewhere", "heartbeat_at": now - 301}))
    (d / "reboot.json").write_text(json.dumps({**base, "host": precedence.host(), "heartbeat_at": now,
                                               "boot_id": "another-boot"}))
    (d / "fresh.json").write_text(json.dumps({**base, "host": "elsewhere", "heartbeat_at": now - 20}))
    (d / "half.json").write_text('{"pid": 12')                                    # mid-write: live for 5 min
    (d / "oldhalf.json").write_text('{"pid": 12')
    os.utime(d / "oldhalf.json", (now - 400, now - 400))
    monkeypatch.setattr(precedence, "boot_id", lambda: "this-boot")
    live, unread = precedence.read_intents("dev1", now)
    assert sorted(Path(i["path"]).name for i in live) == ["fresh.json", "half.json"] and unread == 1
    assert sorted(p.name for p in d.iterdir()) == ["fresh.json", "half.json"]     # stale ones removed (logged)
    log = precedence.log_path().read_text()
    assert "heartbeat 301 s old" in log and "the computer restarted since" in log and "unreadable for over" in log


# ---------- C7 / C9d: overdue deferrals ----------

def _deferral_after_ended_pullback(ended: float):
    precedence.defer("catalog", "dev1", "abc12345", "20261116_DEV1_000001",
                     {"id": "h-1-1", "user": "u", "started_at": ended - 60, "heartbeat_at": ended - 30})
    precedence.note_pullback_end("h-1-1", ended)


def test_c7_c9d_deferral_older_than_3h_is_a_health_problem_and_alerts_then_resolves(hub):
    now = time.time()
    _deferral_after_ended_pullback(now - 3 * 3600 - 60)                  # no catalog run since: overdue (75 min rule)
    res = dict((n, (ok, d)) for n, ok, d in health.collect(now))
    assert res[health.YIELD_CHECK][0] is False and "no catalog run has started" in res[health.YIELD_CHECK][1]
    assert "python -m backup catalog run" in res[health.YIELD_CHECK][1]
    assert health.run_health(send_alerts=True) == config.PROBLEM_EXIT
    assert any(k == health.YIELD_KEY for k, _ in hub["fired"])
    assert not any(k == health.ALERT_KEY for k, _ in hub["fired"]), "the main key is not raised for it"
    precedence.mark_done(lambda o: True, "test catch-up")
    hub["resolved"].clear()
    health.run_health(send_alerts=True)
    assert health.YIELD_KEY in hub["resolved"]
    assert dict((n, ok) for n, ok, _ in health.collect())[health.YIELD_CHECK] is True


def test_c9d_overdue_follows_the_real_catalog_run(hub):
    now = time.time()
    end = now - 3600
    _deferral_after_ended_pullback(end)
    # a catalog run started after the pullback ended and finished 10 min ago: not overdue yet (15 min after it)
    t = precedence.record_catalog_start(end + 300)
    precedence.record_catalog_finish(t, now - 600)
    assert precedence.overdue(now)[0] == []
    # 16 min after that run finished: overdue
    late, n = precedence.overdue(now + 360)
    assert n == 1 and len(late) == 1 and "without catching it up" in late[0][1]
    # a run that started before the pullback ended does not count; none after for 75 min -> overdue
    precedence.runs_path().write_text(json.dumps([{"started_at": end - 10, "finished_at": end + 1000}]))
    assert precedence.overdue(end + 74 * 60)[0] == []
    assert len(precedence.overdue(end + 76 * 60)[0]) == 1
    # a slow catalog run (started, not finished within 75 min) does not alert early ...
    precedence.runs_path().write_text(json.dumps([{"started_at": end + 60, "finished_at": None}]))
    assert precedence.overdue(end + 70 * 60)[0] == []
    # ... a stopped one does
    assert "has not finished" in precedence.overdue(end + 80 * 60)[0][0][1]
    # while that pullback is still live, nothing is overdue
    precedence.deferred_path().write_text("")
    with precedence.announce("dev1", "t") as it:
        precedence.defer("catalog", "dev1", "s", "T", precedence.read_intents("dev1")[0][0])
        assert precedence.overdue(time.time() + 2 * 3600)[0] == []      # live and under 3 h (over 3 h: F4)
    assert precedence.open_deferrals()[0]["pullback_ended_at"]
    assert it.closed


def test_c9d_relay_raises_and_resolves_yield_and_drill_keys(hub):
    doc = {"ok": False, "exit_code": 1, "checks": [
        {"name": "yield-overdue", "ok": False, "detail": "late"},
        {"name": "pullback-drill", "ok": True, "detail": "passed"},
        {"name": "hub free space", "ok": True, "detail": "x"}]}

    class R:
        returncode, stdout, stderr = 1, json.dumps(doc), ""
    rc = relay.relay("hubhost", "python3", "havnvard", runner=lambda *a, **k: R())
    keys = [k for k, _ in hub["fired"]]
    assert "havnvard-yield-overdue-hubhost" in keys and "havnvard-backup-health-hubhost" not in keys
    assert "havnvard-pullback-drill-hubhost" in hub["resolved"]
    assert rc == config.PROBLEM_EXIT


def test_deferred_done_lines_trimmed_after_30_days(hub):
    _deferral_after_ended_pullback(time.time())
    precedence.mark_done(lambda o: True, "x", now=time.time() - 31 * 86400)
    precedence.defer("catalog", "dev1", "b", "T2", {"id": "z", "user": "u", "started_at": 1, "heartbeat_at": 1})
    lines = precedence.deferred_path().read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["tag"] == "T2"


# ---------- C9e: STATUS first and last ----------

@needs_restic
def test_c9e_status_is_the_first_and_last_line(hub, capsys):
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    assert archive.pullback(paths=[str(hub["data"] / "b")], snapshot=_snap(hub)["id"][:8], target=str(tgt)) == 0
    out = _lines(capsys.readouterr().out)
    assert out[0] == "STATUS: RUNNING" and out[-1] == "STATUS: DONE 6/6"
    with pytest.raises(BackupError):
        archive.pullback(paths=[str(hub["data"] / "nope")], snapshot=_snap(hub)["id"][:8], target=str(tgt))
    out = _lines(capsys.readouterr().out)
    assert out[0] == "STATUS: RUNNING" and out[-1].startswith("STATUS: NOT DONE (not in snapshot")
    assert "run the same pullback again; files already back are left alone" in out[-1]
    assert list(precedence.intent_dir("dev1").glob("*.json")) == []


# ---------- C8 / C9b / C10 / C11: the drill ----------

def _hashes(h) -> Path:
    f = h["tmp"] / "set.sha256"
    f.write_text("".join(f"{__import__('hashlib').sha256(p.read_bytes()).hexdigest()}  {p}\n"
                         for p in sorted(h["data"].rglob("*.bin"))))
    return f


@needs_restic
def test_c8_c9b_c10_c11_drill_passes_on_a_hub(hub, capsys):
    data_before = [s["id"] for s in catalog.data_snapshots(catalog.snapshots("restic", hub["env"]))]
    rc = pullback_drill.pullback_drill("dev1", "hv-test", hashes=str(_hashes(hub)))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "drill: 12/12 restored, contention: yielded+caught up, 0 FAILED" in out                   # C10
    assert "deferred 1, caught up 1/1" in out                                                        # C9b
    assert "20/20 parallel pullbacks exit 0" in out and "20/20 intent files written and removed" in out   # C8
    assert "0 intent file(s) read half-written" in out and "0 wrong 'free' answer(s) of 50 checks" in out
    assert "intent folder: empty at the end" in out
    assert "not covered by this drill: a pullback over the network" in out
    assert re.search(r"(\d+)/\1 checks passed", out)
    line = [json.loads(ln) for ln in precedence.deferred_path().read_text().splitlines()
            if json.loads(ln)["job"] == "pullback-drill"]
    assert len(line) == 1 and line[0]["done_at"]                                                     # C9b
    marker = pullback_drill._marker("restic", hub["env"])
    assert line[0]["tag"] in marker["tags"]
    assert os.stat(hub["repo"] / "snapshots" / marker["id"]).st_mtime == 0       # never makes the device look fresh
    # C11: the drill deleted nothing; the marker is not a data backup
    assert [s["id"] for s in catalog.data_snapshots(catalog.snapshots("restic", hub["env"]))] == data_before
    assert pullback_drill.KEY in hub["resolved"]
    assert json.loads(pullback_drill.result_path().read_text())["ok"] is True
    assert dict((n, ok) for n, ok, _ in health.collect())[health.DRILL_CHECK] is True
    # a second drill reuses the marker (one marker snapshot, never more)
    assert pullback_drill.pullback_drill("dev1", "hv-test", parallel=3, checks=10) == 0
    assert len([s for s in catalog.snapshots("restic", hub["env"]) if catalog.DRILL_TAG in (s.get("tags") or [])]) == 1


@needs_restic
def test_c10_drill_with_a_broken_or_missing_test_set_or_hub_fails_and_alerts(hub, capsys):
    f = _hashes(hub)
    f.write_text(f.read_text().replace(f.read_text()[:4], "0000", 1))          # one wrong SHA-256
    assert pullback_drill.pullback_drill("dev1", "hv-test", hashes=str(f), parallel=2, checks=5) == config.PROBLEM_EXIT
    out = capsys.readouterr().out
    assert "FAILED SHA-256: 11/12" in out and "pullback-drill dev1/hv-test: FAILED" in out
    assert any(k == pullback_drill.KEY for k, _ in hub["fired"])
    assert dict((n, ok) for n, ok, _ in health.collect())[health.DRILL_CHECK] is False
    hub["fired"].clear()
    assert pullback_drill.pullback_drill("dev1", "no-such-set") == config.PROBLEM_EXIT                 # missing set
    assert "test set no-such-set of dev1 is missing" in capsys.readouterr().out
    assert any(k == pullback_drill.KEY for k, _ in hub["fired"])
    hub["fired"].clear()
    os.rename(hub["repo"] / "config", hub["repo"] / "config.away")                                   # hub repo down
    try:
        assert pullback_drill.pullback_drill("dev1", "hv-test") == config.PROBLEM_EXIT
    finally:
        os.rename(hub["repo"] / "config.away", hub["repo"] / "config")
    assert "drill could not run" in capsys.readouterr().out and hub["fired"]


def test_c10_drill_timer_is_rendered_not_installed(tmp_path):
    paths = pullback_drill.render_units(tmp_path, "dev1", "hv-test")
    timer = (tmp_path / "havnvard-pullback-drill.timer").read_text()
    svc = (tmp_path / "havnvard-pullback-drill.service").read_text()
    assert "OnCalendar=Sun *-*-* 03:30:00" in timer and "pullback-drill --from dev1 --set hv-test" in svc
    assert len(paths) == 2
    r = subprocess.run([sys.executable, "-m", "backup", "pullback-drill", "--from", "dev1", "--set", "s",
                        "--render-units", str(tmp_path / "u")], cwd=str(REPO_DIR), env=_cli_env(),
                       capture_output=True, text=True)
    assert r.returncode == 0 and "NOT installed or enabled" in r.stdout


def test_c11_never_delete_unlock_is_stale_only_and_no_forget_in_new_code():
    src = {p.name: p.read_text() for p in (REPO_DIR / "backup").glob("*.py")}
    assert not any(re.search(r"""["']--remove-all["']""", t) for t in src.values())   # never passed to restic
    assert '[self.restic, "unlock"]' in src["precedence.py"]
    for name in ("precedence.py", "pullback_drill.py"):
        assert not re.search(r'"(forget|prune)"\s*[,\]]', src[name].replace('"prune": "backup delete"', "")
                             .replace('"forget": "backup delete"', "")), name


def test_c4_after_giving_up_the_same_lock_fails_fast(hub, monkeypatch):
    """C4: once a pullback gave up on a holder, later files under the same lock are FAILED at once, not waited 10 min each."""
    monkeypatch.setattr(precedence, "OTHER_WAIT_S", 0.5)
    err = ("unable to create lock in backend: repository is already locked exclusively by PID 4711 on elsewhere by x "
           "(UID 1, GID 1)\nlock was created at 2026-11-16 12:00:00 (1s ago)\nstorage ID 1a2b3c4d")
    calls = []

    def fn():
        calls.append(1)
        raise precedence.Locked(err)
    g = precedence.LockGate("restic", {}, "dev1", notice=lambda *a: "sent", out=lambda *a: None)
    with pytest.raises(BackupError, match="GAVE UP"):
        g.run(fn, ["/a"])
    n = len(calls)
    t = time.time()
    with pytest.raises(BackupError, match="not tried: still locked by .*process 4711"):
        g.run(fn, ["/b"])
    assert len(calls) == n + 1 and time.time() - t < 0.5


def test_lock_message_parsing():
    err = ("repo already locked, waiting up to 0s for the lock\nunable to create lock in backend: repository is already "
           "locked exclusively by PID 4711 on hub-1 by someone (UID 1000, GID 1000)\nlock was created at "
           "2026-11-16 12:45:16 (1m2.5s ago)\nstorage ID 1a2b3c4d\nthe `unlock` command can be used to remove stale locks")
    lk = precedence.parse_lock(err)
    assert lk == {"pid": 4711, "host": "hub-1", "user": "someone", "exclusive": True, "created": "2026-11-16 12:45:16",
                  "age_s": pytest.approx(62.5), "sid": "1a2b3c4d"}
    assert precedence.lock_conflict(err) and not precedence.lock_conflict("unable to create lock: permission denied")
    assert precedence.parse_lock("nothing") is None
    as_json = json.dumps({"message_type": "exit_error", "code": 11, "message": err.split("\n", 1)[1]})
    assert precedence.parse_lock(as_json)["sid"] == "1a2b3c4d"            # `restic ... --json` prints errors as JSON
    g = precedence.LockGate("restic", {}, "dev1")
    assert g.classify({**lk, "age_s": 31 * 60})[0] == "stale"
    assert g.classify(lk)[0] == "foreign"
    assert g.classify(None)[0] == "foreign"
    assert g.classify({**lk, "host": precedence.host(), "pid": 2 ** 22 + 12345})[0] == "stale"


# ---------- fix wave after the independent review (F1-F7, L4, L5, L11) ----------

def _drill_ok(h, **kw):
    return pullback_drill.pullback_drill("dev1", "hv-test", hashes=str(_hashes(h)), parallel=3, checks=10, **kw)


@needs_restic
def test_f1_drill_lock_leg_meets_a_real_held_lock_and_gets_it(hub, capsys):
    """F1: the drill puts a REAL exclusive restic lock (its own tag, paused) in the pullback's way; LockGate must name
    it and get it with 0 FAILED."""
    assert _drill_ok(hub) == 0
    out = capsys.readouterr().out
    assert re.search(r"OK     lock gate: lock gate exercised: GOT THE LOCK after \d+s \(holder: the pullback drill's tag "
                     r"step .* started at", out), out
    assert "STATUS: WAITING for the pullback drill's tag step" in out
    marker = pullback_drill._marker("restic", hub["env"])
    assert any(t.startswith("havnvard-drill-lock-") for t in marker["tags"])      # the held tag step did finish
    assert _locks(hub["repo"]) == []                                              # and nothing is left holding a lock


@needs_restic
def test_f1_drill_lock_leg_not_exercised_is_a_failed_drill(hub, capsys, monkeypatch):
    monkeypatch.setattr(pullback_drill, "_lock_files", lambda d: set())          # the lock is never seen in the way
    assert _drill_ok(hub) == config.PROBLEM_EXIT
    out = capsys.readouterr().out
    assert "FAILED lock gate: lock gate NOT exercised" in out and "pullback-drill dev1/hv-test: FAILED" in out


@pytest.mark.parametrize("exc", [ValueError("bad restic json"), SystemExit(143), KeyboardInterrupt()])
def test_f2_a_crashed_or_killed_drill_is_recorded_failed_and_alerts(hub, monkeypatch, capsys, exc):
    pullback_drill.result_path().parent.mkdir(parents=True, exist_ok=True)
    pullback_drill.result_path().write_text(json.dumps({"ok": True, "at": precedence.iso(time.time()),
                                                        "summary": "last week PASSED"}))

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(pullback_drill, "_drill", boom)
    if isinstance(exc, (SystemExit, KeyboardInterrupt)):
        with pytest.raises(type(exc)):
            pullback_drill.pullback_drill("dev1", "hv-test")
    else:
        assert pullback_drill.pullback_drill("dev1", "hv-test") == config.PROBLEM_EXIT
    res = json.loads(pullback_drill.result_path().read_text())
    assert res["ok"] is False and f"drill crashed: {type(exc).__name__}" in res["summary"]
    assert any(k == pullback_drill.KEY for k, _ in hub["fired"])
    assert dict((n, ok) for n, ok, _ in health.collect())[health.DRILL_CHECK] is False


@needs_restic
def test_f3_drill_failing_after_its_deferral_still_catches_up_and_raises_no_yield_alert(hub, monkeypatch, capsys):
    def broken(*a, **k):
        raise BackupError("concurrency case broke")
    monkeypatch.setattr(pullback_drill, "_concurrency_case", broken)
    assert _drill_ok(hub) == config.PROBLEM_EXIT
    assert [o for o in precedence.open_deferrals() if o["job"] == "pullback-drill"] == []          # caught up anyway
    res = dict((n, (ok, d)) for n, ok, d in health.collect(time.time() + 5 * 3600))
    assert res[health.YIELD_CHECK][0] is True and res[health.DRILL_CHECK][0] is False


def test_f3_drill_deferrals_are_not_judged_by_the_catalog_overdue_rule(hub):
    precedence.defer("pullback-drill", "dev1", "m", "havnvard-drill-x",
                     {"id": "gone", "user": "u", "started_at": 1, "heartbeat_at": 1})
    assert precedence.overdue(time.time() + 10 * 3600) == ([], 0)


def test_f4_a_live_pullback_deferring_for_over_3h_is_overdue(hub):
    with precedence.announce("dev1", "hung pullback"):
        line = precedence.defer("catalog", "dev1", "s", "T1", precedence.read_intents("dev1")[0][0])
        assert precedence.overdue(line["deferred_at"] + 3 * 3600 - 60)[0] == []
        late, n = precedence.overdue(line["deferred_at"] + 3 * 3600 + 1)
        assert n == 1 and len(late) == 1 and "deferred for over 3 h; check intent/" in late[0][1]
        assert f"(pid {os.getpid()})" in late[0][1]


@needs_restic
def test_f5_waiting_notice_reaches_the_hub_page_on_a_hub(hub, capsys, monkeypatch):
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    a = accounts.Accounts()
    adm = a.register("boss@example.com", "correct horse battery staple 1", setup_code=a.new_setup_code(), company="Acme")
    a.add_device(adm["account_id"], "dev1")
    monkeypatch.setattr(precedence, "OTHER_WAIT_S", 2)
    monkeypatch.setattr(precedence, "NOTICE_AFTER_S", 0.5)
    sid = _snap(hub)["id"][:8]
    holder = hold_exclusive(hub)
    try:
        tgt = hub["tmp"] / "back"
        tgt.mkdir()
        assert archive.pullback(paths=[str(hub["data"] / "a")], snapshot=sid, target=str(tgt)) == config.PROBLEM_EXIT
    finally:
        release(holder)
    out = capsys.readouterr().out
    notes = [n for n in a.open_notices(adm["account_id"]) if n["kind"] == "pullback_waiting"]
    assert len(notes) == 1 and notes[0]["device"] == "dev1" and f"process {holder.pid}" in notes[0]["text"]
    assert "notice for the hub owner: left on the hub page" in out


def test_f5_hub_without_a_hub_page_says_the_notice_was_not_left(hub):
    sent = precedence.leave_notice_for("dev1")("pullback_waiting", "x")
    assert sent.startswith("NOT left: this hub has no hub page")


@needs_restic
def test_f6_a_folder_that_could_not_be_listed_is_never_accounted_for(hub, capsys, monkeypatch):
    monkeypatch.setattr(precedence, "OTHER_WAIT_S", 0.5)
    old = _snap(hub)
    gone = hub["data"] / "b" / "f0.bin"
    keep = gone.read_bytes()
    gone.unlink()
    restic(hub["repo"], hub["pw"], "backup", str(hub["data"]))                # newer backup without b/f0.bin
    gone.write_bytes(keep)
    w = hub["tmp"] / "restic-ls-locked.sh"
    w.write_text('#!/bin/sh\nif [ "$1" = ls ] && [ "$2" = --json ] && [ "$3" = --recursive ] && [ "$4" = "%s" ]; then '
                 'echo "unable to create lock in backend: repository is already locked exclusively by PID 1 on '
                 'elsewhere by someone (UID 1, GID 1)" >&2; exit 11; fi\nexec restic "$@"\n' % old["id"])
    w.chmod(0o755)
    monkeypatch.setenv("HAVNVARD_RESTIC", str(w))
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    rc = archive.pullback(paths=[str(hub["data"] / "a" / "f1.bin"), str(gone)], target=str(tgt),
                          hub_notice=lambda *a: "sent")
    out = capsys.readouterr().out
    assert rc == config.PROBLEM_EXIT
    assert "1 folder(s) could not be listed (file count unknown, listed below)" in out
    assert "1/1 listed files accounted for, 1 folder(s) NOT listed" in out and "1/1 files accounted for" not in out
    assert f"NOT LISTED {gone}" in out
    assert _lines(out)[-1].startswith("STATUS: NOT DONE 1/1 listed files, 0 FAILED, 1 folder(s) not listed")


def test_f7_readme_and_runbook_state_the_precedence_limit():
    for f in ("README.md", "RUNBOOK.md"):
        t = " ".join((REPO_DIR / f).read_text().replace("**", "").split())
        assert "on the hub" in t and ("as the hub user" in t) and "another computer" in t, f


def test_l4_an_old_drill_result_is_a_problem(hub):
    pullback_drill.result_path().parent.mkdir(parents=True, exist_ok=True)
    at = time.time() - 9 * 86400
    pullback_drill.result_path().write_text(json.dumps({"ok": True, "at": precedence.iso(at), "summary": "passed"}))
    ok, d = {n: (o, dd) for n, o, dd in health.collect()}[health.DRILL_CHECK]
    assert ok is False and "no pullback drill since" in d
    pullback_drill.result_path().write_text(json.dumps({"ok": True, "at": precedence.iso(time.time() - 86400),
                                                        "summary": "passed"}))
    assert {n: o for n, o, _ in health.collect()}[health.DRILL_CHECK] is True


def test_l5_a_crashed_catalog_run_is_recorded_failed_and_a_history_write_error_does_not_stop_it(hub, monkeypatch):
    def crash(*a, **k):
        raise BackupError("boom")
    monkeypatch.setattr(catalog, "_catalog_run", crash)
    with pytest.raises(BackupError):
        catalog.catalog_run()
    r = precedence.catalog_runs()[-1]
    assert r["finished_at"] and r["failed"] is True
    monkeypatch.setattr(catalog, "_catalog_run", lambda *a, **k: 0)

    def full(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(precedence, "record_catalog_start", full)
    assert catalog.catalog_run() == 0


def test_l11_drill_marker_ids_are_skipped_by_the_file_age_check(hub):
    root = hub["tmp"] / "hub2"
    repo = root / "dev9"
    (repo / "snapshots").mkdir(parents=True)
    (repo / "config").write_text("x")
    old = repo / "snapshots" / ("a" * 64)
    old.write_text("x")
    os.utime(old, (time.time() - 40 * 3600, time.time() - 40 * 3600))
    (repo / "snapshots" / ("b" * 64)).write_text("x")                     # a marker whose time was not yet pinned
    config.save({"hub_local": {"repo_root": str(root)}})
    assert {n: o for n, o, _ in health.collect()}["snapshot age dev9"] is True     # fooled without the skip
    pullback_drill._remember("dev9", "b" * 64)
    assert {n: o for n, o, _ in health.collect()}["snapshot age dev9"] is False


def _gone(pid: int) -> bool:
    try:
        st = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    return st[st.rfind(")") + 2] in "ZX"                     # dead, waiting only to be reaped


@needs_restic
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux only")
def test_f1_kill_9_of_the_drill_kills_its_paused_tag_and_lockgate_unlocks_its_dead_lock(hub, capsys):
    """F1 follow-up: the drill's paused `restic tag` dies with the drill (PR_SET_PDEATHSIG), even on kill -9, so it can
    never hold a live repository's exclusive lock. It does leave a DEAD exclusive lock: restic itself does not ignore
    it (every new job fails rc 11 until `restic unlock`); LockGate treats it as stale at once and unlocks it, and the
    next catalog run or drill clears it too (re-review R1, test_r1_*)."""
    script = ("import sys, tempfile, time\nfrom pathlib import Path\nfrom backup import pullback_drill as d\n"
              "env = {'RESTIC_REPOSITORY': sys.argv[1], 'RESTIC_PASSWORD_FILE': sys.argv[2]}\n"
              "m = d.ensure_marker('restic', env)\n"
              "with tempfile.TemporaryFile() as e:\n"
              "    p, held = d.hold_tag('restic', env, m['id'], 'havnvard-drill-lock-killtest', Path(sys.argv[1]) / 'locks', e)\n"
              "    print(p.pid, held, flush=True)\n"
              "    time.sleep(120)\n")
    drill = subprocess.Popen([sys.executable, "-c", script, str(hub["repo"]), str(hub["pw"])], cwd=str(REPO_DIR),
                             env=_cli_env(), stdout=subprocess.PIPE, text=True)
    pid_s, held = drill.stdout.readline().split()
    tag_pid = int(pid_s)
    assert held == "True" and not _gone(tag_pid) and len(_locks(hub["repo"])) == 1
    os.kill(drill.pid, signal.SIGKILL)
    drill.wait()
    assert wait_for(lambda: _gone(tag_pid), 5), "the paused restic tag outlived the killed drill"
    assert len(_locks(hub["repo"])) == 1                     # its lock file is left behind ...
    tgt = hub["tmp"] / "back"
    tgt.mkdir()
    rc = archive.pullback(paths=[str(hub["data"] / "a")], snapshot=_snap(hub)["id"][:8], target=str(tgt))
    out = capsys.readouterr().out
    assert rc == 0, out                                      # ... and is stale at once: unlocked, pullback completes
    assert f"STALE LOCK on dev1: a lock left by process {tag_pid}" in out and _locks(hub["repo"]) == []



# ---------- re-review R1-R4 (3.3.14) ----------

def _dead_lock(h) -> int:
    holder = hold_exclusive(h)
    os.kill(holder.pid, signal.SIGKILL)
    holder.wait()
    assert len(_locks(h["repo"])) == 1
    return holder.pid


@needs_restic
def test_r1_catalog_run_clears_a_dead_exclusive_lock_from_this_host_first(hub, capsys, monkeypatch):
    pid = _dead_lock(hub)
    real = catalog.run
    monkeypatch.setattr(catalog, "run", lambda cmd, **k: real([("5s" if c == "30m" else c) for c in cmd], **k))
    accounts.Accounts()
    assert catalog.catalog_run() == 0, capsys.readouterr().out
    out = capsys.readouterr().out
    assert "dead exclusive lock(s) on dev1 from this host" in out and f"pid {pid}" in out
    assert _locks(hub["repo"]) == []
    rows = [r for r in accounts.Accounts().audit_rows() if r["action"] == "job.stale_unlock"]
    assert len(rows) == 1 and '"job": "catalog"' in rows[0]["detail"]


@needs_restic
def test_r1_drill_start_clears_a_dead_exclusive_lock(hub, capsys, monkeypatch):
    _dead_lock(hub)

    def stop(*a, **k):
        raise BackupError("stop after the lock check")
    monkeypatch.setattr(pullback_drill, "pin_all_markers", stop)
    assert pullback_drill.pullback_drill("dev1", "hv-test", hashes=str(_hashes(hub))) == config.PROBLEM_EXIT
    assert _locks(hub["repo"]) == []
    assert '"job": "pullback-drill"' in precedence.log_path().read_text()


@needs_restic
def test_r1_live_other_user_and_other_host_locks_are_never_unlocked(hub, monkeypatch):
    holder = hold_exclusive(hub)
    try:
        assert precedence.clear_dead_locks("restic", hub["env"], "dev1", "catalog") == 0
        assert len(_locks(hub["repo"])) == 1                                   # a live lock stays
    finally:
        release(holder)
    calls = []
    monkeypatch.setattr(precedence, "lock_records", lambda r, e: [
        {"id": "a" * 64, "exclusive": True, "hostname": "elsewhere", "pid": 2 ** 22 + 7, "username": "x"},
        {"id": "b" * 64, "exclusive": True, "hostname": precedence.host(), "pid": 1, "username": "root"},  # alive, EPERM
        {"id": "c" * 64, "exclusive": False, "hostname": precedence.host(), "pid": 2 ** 22 + 7, "username": "x"}])
    import backup.util as util
    monkeypatch.setattr(util, "run", lambda *a, **k: calls.append(a) or None)
    assert precedence.clear_dead_locks("restic", hub["env"], "dev1", "catalog") == 0 and calls == []


@needs_restic
def test_r3_drill_pins_and_records_every_marker_snapshot(hub, capsys):
    f = hub["tmp"] / "m.txt"
    for body in ("one", "two"):                                             # two markers: one left by a killed tag
        f.write_text(body)
        restic(hub["repo"], hub["pw"], "backup", "--host", "havnvard-drill", "--tag", catalog.DRILL_TAG, str(f))
    ids = [s["id"] for s in catalog.snapshots("restic", hub["env"]) if catalog.DRILL_TAG in (s.get("tags") or [])]
    oldest = sorted(catalog.snapshots("restic", hub["env"]), key=lambda s: s["time"])
    oldest = [s["id"] for s in oldest if s["id"] in ids][0]
    assert pullback_drill.pullback_drill("dev1", "hv-test", hashes=str(_hashes(hub)), parallel=2, checks=5) == 0
    assert oldest in pullback_drill.marker_ids()
    assert os.stat(hub["repo"] / "snapshots" / oldest).st_mtime == 0


@needs_restic
def test_r2_hold_tag_never_pauses_on_a_lock_that_is_not_its_own_exclusive_lock(hub, monkeypatch):
    m = pullback_drill.ensure_marker("restic", hub["env"])
    monkeypatch.setattr(pullback_drill, "_is_our_exclusive", lambda *a: False)
    import tempfile
    with tempfile.TemporaryFile() as e:
        p, held = pullback_drill.hold_tag("restic", hub["env"], m["id"], "havnvard-drill-lock-r2", hub["repo"] / "locks", e)
        try:
            assert held is False
            assert p.wait(timeout=60) == 0                                    # never left paused; the tag finished
        finally:
            pullback_drill._resume(p)
            p.wait(timeout=60)


# ---------- review N1 / N2 (3.3.14) ----------

def _state(pid: int) -> str:
    try:
        st = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return "gone"
    return st[st.rfind(")") + 2]


@needs_restic
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc and PR_SET_PDEATHSIG are Linux only")
def test_n1_a_failing_ownership_check_never_leaves_the_tag_paused(hub, monkeypatch):
    m = pullback_drill.ensure_marker("restic", hub["env"])
    seen = []

    def boom(restic, env, lid, pid):
        seen.append(pid)
        raise BackupError("timed out after 60s: restic cat lock")
    monkeypatch.setattr(pullback_drill, "_is_our_exclusive", boom)
    import tempfile
    with tempfile.TemporaryFile() as e, pytest.raises(BackupError, match="timed out"):
        pullback_drill.hold_tag("restic", hub["env"], m["id"], "havnvard-drill-lock-n1", hub["repo"] / "locks", e)
    pid = seen[0]
    try:
        time.sleep(0.3)
        assert _state(pid) != "T", "the tag was left stopped holding the exclusive lock"
        assert wait_for(lambda: _state(pid) in ("gone", "Z"), 60)         # it ran on and finished
    finally:
        with __import__("contextlib").suppress(ProcessLookupError):
            os.kill(pid, signal.SIGCONT)


@needs_restic
def test_n2_hourly_catalog_run_pins_and_records_drill_markers(hub):
    f = hub["tmp"] / "m.txt"
    f.write_text("marker left by a killed tag")
    restic(hub["repo"], hub["pw"], "backup", "--host", "havnvard-drill", "--tag", catalog.DRILL_TAG, str(f))
    mid = [s["id"] for s in catalog.snapshots("restic", hub["env"]) if catalog.DRILL_TAG in (s.get("tags") or [])][0]
    assert os.stat(hub["repo"] / "snapshots" / mid).st_mtime > 0
    assert catalog.catalog_run() == 0
    assert mid in pullback_drill.marker_ids()
    assert os.stat(hub["repo"] / "snapshots" / mid).st_mtime == 0
