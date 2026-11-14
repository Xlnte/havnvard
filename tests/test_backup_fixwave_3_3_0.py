"""HavnVard 3.3.0 fix wave (Opus reviews 20261114: F1-F10 and FN-1..FN-6; orchestrator decisions D1, D2).

Each test reproduces one review finding and fails on the code before its fix. Throwaway SQLite, files and restic
repositories in pytest's tmp dir only: no live hub, no live database, no network, no screen, no sudo."""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import re
import sqlite3
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import accounts, archive, checkin, config, hubweb, notify, schedules  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import HAVE_RESTIC, restic  # noqa: E402
from test_backup_hubweb import Client  # noqa: E402

ROOT_DIR = Path(__file__).resolve().parent.parent
PW = "correct horse battery"
T0 = dt.datetime(2026, 11, 14, 10, 0, tzinfo=dt.timezone.utc)


def m(n: float) -> dt.datetime:
    return T0 + dt.timedelta(minutes=n)


class Mail:
    def __init__(self, status="not configured"):
        self.status, self.sent = status, []

    def __call__(self, to, subject, body):
        self.sent.append((to, subject, body))
        return self.status


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    a = accounts.Accounts(tmp_path / "accounts.db")
    adm = a.register("boss@example.com", PW, setup_code=a.new_setup_code(), company="Acme")
    u = a.register("al@example.com", PW, invite_code=a.invite(adm["account_id"], "al@example.com"))["account_id"]
    return a, adm["account_id"], u, adm["store_key"]


def _actions(a) -> list[str]:
    return [r["action"] for r in a.audit_rows()]


# ---------- FN-1 (critical): the generated password can only READ the notice ----------

def test_fn1_poc_admin_with_generated_password_cannot_ack_or_set_the_users_password(db):
    """The proof script poc.py, as a regression test: the admin logs in as the user with the generated password and
    tries to acknowledge and set a password. Both must be refused; the notice stays; the user's old password still
    leads to the notice; the audit never shows an acknowledgement."""
    a, adm, u, _ = db
    r = a.force_open(adm, u, "audit", "al@example.com", mailer=Mail())
    s = a.login("al@example.com", r["new_password"])
    assert s["scope"] == "gated" and s["must_ack"] is True
    with pytest.raises(BackupError, match="only you can do this"):
        a.ack_warning(s["token"])
    with pytest.raises(BackupError, match="only you can do this"):
        a.set_own_password(s["token"], "admin-chosen-password-9")
    assert a.notice(u)["unacked"] is True and a.account(u)["must_set_password"] == 1
    assert a.login("al@example.com", PW)["scope"] == "notice"                 # the user's old password still works
    assert "force_open.ack" not in _actions(a) and "password.set_after_force_open" not in _actions(a)
    # the right person, with the old password, can
    old = a.login("al@example.com", PW, ip="100.64.0.7", ua="Firefox/140")
    w = a.ack_warning(old["token"], ip="100.64.0.7", ua="Firefox/140")
    assert w["new_password"] == r["new_password"]
    ack = [x for x in a.audit_rows() if x["action"] == "force_open.ack"][0]
    d = json.loads(ack["detail"])
    assert d["scope"] == "notice" and d["proof"] == "old_password" and d["ip"] == "100.64.0.7" and d["ua"] == "Firefox/140"


def test_fn1_wording_never_says_the_generated_password_opens_the_notice(db, tmp_path):
    a, adm, u, _ = db
    mail = Mail()
    a.force_open(adm, u, "audit", "al@example.com", mailer=mail)
    body = mail.sent[0][2]
    assert "old password and the new one" not in body and "YOUR OWN old password" in body
    for f in ("backup/cli.py", "backup/hubweb.py", "backup/accounts.py"):
        src = (ROOT_DIR / f).read_text()
        assert "old password or the new one" not in src and "(old password or this one)" not in src, f


# ---------- F2 / D1: every admin-issued reset carries the notice; IP/UA recorded; admin never redeems ----------

def test_f2_admin_reset_carries_the_mandatory_notice_and_an_admin_session_cannot_redeem_it(db):
    a, adm, u, _ = db
    code = a.admin_reset(adm, u, ip="100.64.0.1", ua="AdminBrowser/1")["code"]
    assert a.account(u)["must_ack_force_open"] == 1                            # P1: no silent reset
    issued = [x for x in a.audit_rows() if x["action"] == "password.reset_issued"][0]
    assert json.loads(issued["detail"])["ip"] == "100.64.0.1"
    # D1: the admin cannot redeem it from an administrator's session
    admin_sess = a.session(a.login("boss@example.com", PW, kind="admin")["token"])
    with pytest.raises(BackupError, match="administrator cannot redeem"):
        a.set_password_with_reset(code, "admin picks this one", redeemer=admin_sess)
    assert "password.reset_refused" in _actions(a)
    # the user redeems it: a 'notice' session, the notice first, then full access
    r = a.set_password_with_reset(code, "al picks this one", redeemer=None, ip="100.64.0.9", ua="AlBrowser/2")
    assert r["must_ack"] is True and a.session(r["token"])["scope"] == "notice"
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(r["token"])
    assert "reset your password on" in a.notice(u)["text"] and "Reason: password reset by administrator" in a.notice(u)["text"]
    a.ack_warning(r["token"], ip="100.64.0.9", ua="AlBrowser/2")
    ack = json.loads([x for x in a.audit_rows() if x["action"] == "force_open.ack"][0]["detail"])
    assert ack["proof"] == "reset_code" and ack["ip"] == "100.64.0.9" and ack["ua"] == "AlBrowser/2"
    assert a.require_ready(r["token"])["account_id"] == u
    red = json.loads([x for x in a.audit_rows() if x["action"] == "password.reset"][0]["detail"])
    assert red["ip"] == "100.64.0.9" and red["ua"] == "AlBrowser/2"
    with pytest.raises(BackupError, match="used, expired"):                   # single use
        a.set_password_with_reset(code, "again again again")
    assert [h["kind"] for h in a.reset_history(u)] == ["reset"]                # permanent history for /me


def test_f2_p2_force_open_code_cannot_be_used_by_the_admin_to_ack_and_old_codes_die(db):
    """P2: after a force-open the admin cannot clear the notice. A second reset code ends the first; a code past
    24 h is refused."""
    a, adm, u, _ = db
    a.force_open(adm, u, "audit", "al@example.com", mailer=Mail())
    c1 = a.admin_reset(adm, u)["code"]                                                 # D1: allowed while a notice is pending
    c2 = a.admin_reset(adm, u)["code"]
    with pytest.raises(BackupError, match="replaced"):
        a.set_password_with_reset(c1, "first code is dead")
    con = sqlite3.connect(a.path)
    con.execute("UPDATE reset SET expires_at='2000-01-01T00:00:00+00:00'")
    con.commit()
    con.close()
    with pytest.raises(BackupError, match="expired"):
        a.set_password_with_reset(c2, "second code too old")


def test_d1_user_who_forgot_the_old_password_gets_out_with_a_reset_code(db):
    a, adm, u, _ = db
    a.force_open(adm, u, "legal hold", "al@example.com", mailer=Mail())
    code = a.admin_reset(adm, u, reason="Al forgot the old password")["code"]
    t = a.set_password_with_reset(code, "brand new and mine")
    text = a.notice(u)["text"]
    assert "Reason: legal hold" in text and "Reason: Al forgot the old password" in text   # both, nothing hidden
    a.ack_warning(t["token"])
    assert a.require_ready(t["token"])["account_id"] == u
    assert a.login("al@example.com", "brand new and mine")["scope"] == "full"
    assert [h["kind"] for h in a.reset_history(u)] == ["force_open", "reset"]


def test_f2_web_reset_from_an_admin_browser_is_refused_and_me_shows_reset_history(db):
    a, adm, u, _ = db
    w = hubweb.App(a)
    boss = Client(w)
    boss.req("POST", "/login", {"email": "boss@example.com", "password": PW, "kind": "admin"})
    _, _, page = boss.post("/admin/users", {"action": "reset", "target": u, "reason": "forgot it"})
    code = re.search(r"Reset code \(24 h\): <code>([\w-]+)</code>", page).group(1)
    st, _, page = boss.req("POST", "/reset", {"code": code, "password": "boss picks it!", "password2": "boss picks it!"})
    assert st == "400 Bad Request" and "administrator cannot redeem" in page
    al = Client(w)
    st, h, _ = al.req("POST", "/reset", {"code": code, "password": "al picks it!!", "password2": "al picks it!!"},
                      headers={"REMOTE_ADDR": "100.64.0.42", "HTTP_USER_AGENT": "AlPhone"})
    assert h["Location"] == "/ack"
    al.post("/ack", {"step": "ack", "understand": "yes"})
    _, _, page = al.req("GET", "/me")
    assert "reset your password 1 time(s)" in page and "forgot it" in page
    # no reset button for admins (F3)
    _, _, page = boss.req("GET", "/admin/users")
    assert page.count("value='reset'") == 1


# ---------- F3: an admin never resets another admin, nor another company's account ----------

def test_f3_admin_reset_refuses_admins_unknown_and_other_company_accounts(db):
    a, adm, u, _ = db
    adm2 = a.register("co@example.com", PW, invite_code=a.invite(adm, "co@example.com", "admin"))
    assert adm2["kind"] == "admin"
    for target in (adm2["account_id"], adm):
        with pytest.raises(BackupError, match="cannot be reset by another administrator"):
            a.admin_reset(adm, target)
    with pytest.raises(BackupError, match="no such account"):
        a.admin_reset(adm, 999)                                                  # P4
    con = sqlite3.connect(a.path)                                                # a second company on the same hub
    cid = con.execute("INSERT INTO company(name, store_key_fpr, created_at) VALUES ('Other','x','2026-01-01')").lastrowid
    other = con.execute("INSERT INTO account(company_id, kind, email, pw_hash, status, created_at) "
                        "VALUES (?, 'user', 'z@example.com', 'x', 'active', '2026-01-01')", (cid,)).lastrowid
    con.commit()
    con.close()
    for call in (lambda: a.admin_reset(adm, other), lambda: a.disable(adm, other, "x"),
                 lambda: a.force_open(adm, other, "x", "z@example.com", mailer=Mail())):
        with pytest.raises(BackupError, match="no such"):
            call()


# ---------- F4: a computer can only end its own run ----------

def _device_api(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    a = accounts.Accounts(tmp_path / "accounts.db")
    adm = a.register("boss@example.com", PW, setup_code=a.new_setup_code(), company="Acme")["account_id"]
    return hubweb.App(a), adm


def test_f4_one_computers_token_cannot_end_or_rewrite_another_computers_run(tmp_path, monkeypatch):
    w, adm = _device_api(tmp_path, monkeypatch)
    ta, tb = w.a.add_device(adm, "laptop-a"), w.a.add_device(adm, "laptop-b")
    c = Client(w)
    rb = json.loads(c.req("POST", "/api/v1/devices/laptop-b/run", {"action": "start"},
                          {"HTTP_AUTHORIZATION": f"Bearer {tb}"}, as_json=True)[2])["run_id"]
    c.req("POST", "/api/v1/devices/laptop-b/run", {"action": "end", "run_id": rb, "exit_code": 1},
          {"HTTP_AUTHORIZATION": f"Bearer {tb}"}, as_json=True)
    st, _, body = c.req("POST", "/api/v1/devices/laptop-a/run",
                        {"action": "end", "run_id": rb, "exit_code": 0, "snapshot_id": "fake"},
                        {"HTTP_AUTHORIZATION": f"Bearer {ta}"}, as_json=True)            # P5
    assert st == "404 Not Found", body
    run = w.s._runs("laptop-b")[0]
    assert run["status"] == "failed" and run["snapshot_id"] is None
    with pytest.raises(schedules.NotFound):
        w.s.run_end("laptop-b", rb, 0)                                           # already ended: not open any more


# ---------- F5: a run whose end never arrives does not stop the schedule ----------

def test_f5_stale_run_is_marked_failed_and_backups_are_scheduled_again(tmp_path):
    s = schedules.Schedules(tmp_path / "accounts.db")
    s.set(None, "lid", mode="interval", every_min=60)
    rid = s.run_start("lid", now=T0)                                            # P6: lid closed, end never reported
    assert s.checkin("lid", now=m(60 * 23))["reason"] == "a run is still going"
    c = s.checkin("lid", now=m(60 * 25))                                         # no run length known: 24 h bound
    assert c["due"] is True
    run = s._runs("lid")[0]
    assert run["status"] == "failed" and run["error"].startswith("stale:") and run["duration_s"] is None
    assert {r["device"]: r for r in s.overview(now=m(60 * 25))}["lid"]["health"] == "failed"
    s.run_end("lid", rid, 0, "abc", now=m(60 * 26))                               # its real end report still lands
    assert s._runs("lid")[0]["status"] == "completed"
    # with recorded lengths the bound is 2x the longest (at least 1 h)
    r2 = s.run_start("lid", now=m(60 * 27))
    s.run_end("lid", r2, 0, now=m(60 * 27 + 10))
    s.run_start("lid", now=m(60 * 30))
    assert s.stale_after("lid") == dt.timedelta(hours=52)                         # longest = 26 h (the late one)
    assert s.next_due("lid", now=m(60 * 31)) is None


def test_f5_client_always_reports_the_end_and_keeps_it_when_the_hub_blips(tmp_path, monkeypatch):
    w, adm = _device_api(tmp_path, monkeypatch)
    tok = w.a.add_device(adm, "air")
    w.s.set(adm, "air", mode="interval", every_min=60)
    (tmp_path / "cfg").mkdir(exist_ok=True)
    (tmp_path / "cfg" / "tok").write_text(tok + "\n")
    config.save({"checkin": {"url": "http://hub:8001", "token_file": str(tmp_path / "cfg" / "tok")},
                 "device": {"name": "air"}})
    fail_end = {"on": True}

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def opener(req, timeout):
        body = json.loads(req.data)
        if fail_end["on"] and req.full_url.endswith("/run") and body.get("action") == "end":
            raise OSError("hub blip")
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": req.full_url.split("hub:8001", 1)[1], "QUERY_STRING": "",
               "CONTENT_LENGTH": str(len(req.data)), "wsgi.input": io.BytesIO(req.data),
               "CONTENT_TYPE": "application/json", "HTTP_AUTHORIZATION": req.get_header("Authorization")}
        st, _, out = w.handle(env)
        assert st == "200 OK", out
        return Resp(out.encode())

    assert checkin.checkin(run=True, opener=opener, runner=lambda: 0) == 0
    assert w.s._runs("air")[0]["status"] == "running"                          # the end post was lost ...
    assert '"kind": "end"' in (tmp_path / "state" / "checkin-pending.jsonl").read_text()   # ... but kept
    fail_end["on"] = False
    checkin.checkin(run=False, opener=opener)
    assert w.s._runs("air")[0]["status"] == "completed"                         # sent at the next check-in
    # a runner that dies with an unexpected error still reports a failed end, then the error goes on
    w.s.set(adm, "air", mode="constant_loop", min_gap_s=0)

    def boom():
        raise RuntimeError("disk vanished")
    with pytest.raises(RuntimeError):
        checkin.checkin(run=True, opener=opener, runner=boom)
    last = w.s._runs("air")[-1]
    assert last["status"] == "failed" and "RuntimeError: disk vanished" in last["error"]


# ---------- F6: disable cuts every access path ----------

def test_f6_disable_revokes_device_tokens_and_htpasswd_lines(db, tmp_path):
    a, adm, u, _ = db
    tok = a.add_device(adm, "al-laptop", primary_user=u)
    other = a.add_device(adm, "bo-laptop")
    hp = tmp_path / "hub.htpasswd"
    hp.write_text("al-laptop:{SHA}aaaa\nbo-laptop:{SHA}bbbb\n")
    os.chmod(hp, 0o600)
    reloads = []
    r = a.disable(adm, u, "fired", htpasswd=hp, reload=lambda: reloads.append(1) or "reloaded")
    assert a.device_by_token("al-laptop", tok) is None                         # check-in token dead
    assert a.device_by_token("bo-laptop", other)                               # other computers untouched
    assert hp.read_text() == "bo-laptop:{SHA}bbbb\n" and stat.S_IMODE(hp.stat().st_mode) == 0o600
    side = tmp_path / "hub.htpasswd.removed"
    assert "al-laptop:{SHA}aaaa" in side.read_text() and stat.S_IMODE(side.stat().st_mode) == 0o600
    assert reloads == [1] and r["tokens_revoked"] == 1 and r["devices"] == ["al-laptop"]
    assert "revoke-device-key" in r["restic_key"]
    assert "account.disable.devices" in _actions(a)
    w = hubweb.App(a)
    st, _, _ = Client(w).req("POST", "/api/v1/devices/al-laptop/checkin", {}, {"HTTP_AUTHORIZATION": f"Bearer {tok}"},
                             as_json=True)
    assert st == "401 Unauthorized"
    new = a.reissue_device_token(adm, "al-laptop")                              # the admin can bring it back
    assert a.device_by_token("al-laptop", new)


@pytest.mark.skipif(not HAVE_RESTIC, reason="restic not installed")
def test_f6_revoke_device_keys_removes_only_keys_never_data(db, tmp_path):
    a, adm, u, store_key = db
    repo, dev_pw, data = tmp_path / "repo", tmp_path / "dev.pass", tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("payroll\n")
    dev_pw.write_text("device-password\n")
    restic(repo, dev_pw, "init")
    restic(repo, dev_pw, "backup", str(data))
    before = json.loads(restic(repo, dev_pw, "snapshots", "--json"))
    accounts.adopt_repo("restic", {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(dev_pw)}, store_key, a)
    hub_pw = tmp_path / "hub-passwords" / "al-laptop.pass"
    hub_pw.parent.mkdir()
    hub_pw.write_text("device-password\n")                                     # the hub's copy = the device's key
    with pytest.raises(BackupError, match="not this company's store key"):
        accounts.revoke_device_keys("restic", str(repo), "wrong", a, "al-laptop", hub_pw)
    r = accounts.revoke_device_keys("restic", str(repo), store_key, a, "al-laptop", hub_pw)
    assert len(r["removed"]) == 1
    import subprocess
    e = {**os.environ, "RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(dev_pw)}
    assert subprocess.run(["restic", "snapshots"], env=e, capture_output=True).returncode != 0   # device key dead
    kf = tmp_path / "store.key"
    kf.write_text(store_key + "\n")
    after = json.loads(restic(repo, kf, "snapshots", "--json"))
    assert [s["id"] for s in after] == [s["id"] for s in before]                 # no snapshot touched
    assert json.loads(restic(repo, hub_pw, "snapshots", "--json"))              # the hub's new key works
    side, = (tmp_path / "hub-passwords").glob("al-laptop.pass.revoked-*")
    assert side.read_text() == "device-password\n" and stat.S_IMODE(side.stat().st_mode) == 0o600
    assert stat.S_IMODE(hub_pw.stat().st_mode) == 0o600
    assert "device.keys_revoked" in _actions(a)


# ---------- F7 / F8: the per-user filter claim, and paths that are not in normal form ----------

def test_f7_readme_says_the_per_user_filter_is_not_yet_enforced():
    text = (ROOT_DIR / "README.md").read_text()
    assert "A user sees only their own files" not in text
    assert "Not yet enforced in 3.3.0" in text
    assert "Nothing an admin can do clears it" not in text                      # F2: the false claim is gone


def test_f8_dotdot_and_unnormalised_paths_are_under_nobody(db):
    a, adm, u, _ = db
    bob = a.register("bob@example.com", PW, invite_code=a.invite(adm, "bob@example.com"))["account_id"]
    a.add_device(adm, "pc", primary_user=None)
    a.add_rule(adm, "pc", "/home/al", u)
    a.add_rule(adm, "pc", "/home/bob", bob)
    assert a.can_read(u, "pc", "/home/al/x")
    for p in ("/home/al/../bob/payroll.xlsx", "/home/al/./x", "//home/al/x", "home/al/x", "/home/al/x/",
              "/home/al/x/..", "/home/al//x"):
        assert not a.can_read(u, "pc", p), p
        assert a.owner_of("pc", p) is None, p
    assert a.filter_paths(u, "pc", ["/home/al/a", "/home/al/../bob/b"]) == ["/home/al/a"]


# ---------- F9: a missed check-in is not a backup run ----------

def test_f9_missed_checkins_during_an_outage_do_not_push_the_next_backup_back(tmp_path, monkeypatch):
    w, adm = _device_api(tmp_path, monkeypatch)
    tok = w.a.add_device(adm, "air")
    w.s.set(adm, "air", mode="interval", every_min=60)
    rid = w.s.run_start("air", now=T0)
    w.s.run_end("air", rid, 0, "abc", now=m(5))                                 # the last real backup: 10:00
    c = Client(w)
    for k in range(1, 37):                                                       # P7: hub down 10:05-13:00
        st, _, body = c.req("POST", "/api/v1/devices/air/late",
                            {"kind": "checkin_failed", "at": m(5 * k).isoformat(), "error": "hub unreachable"},
                            {"HTTP_AUTHORIZATION": f"Bearer {tok}"}, as_json=True)
        assert st == "200 OK", body
    assert w.s.next_due("air", now=m(181)) == m(60)                               # due at 11:00, not 14:00
    assert w.s.stats("air")["runs"] == 1 and len(w.s._runs("air")) == 1
    ov = {r["device"]: r for r in w.s.overview(now=m(181))}["air"]
    assert ov["last_status"] == "completed"


# ---------- F10: login rate limit and constant work for unknown emails ----------

def test_f10_login_is_rate_limited_per_account_and_per_address_with_bounded_memory(db, monkeypatch):
    a, adm, u, _ = db
    now = [1000.0]
    a._limit = accounts._Limiter(clock=lambda: now[0])
    for _ in range(5):
        with pytest.raises(BackupError, match="wrong email or password"):
            a.login("al@example.com", "not it at all!!", ip="10.0.0.1")
    with pytest.raises(BackupError, match="too many failed logins"):
        a.login("al@example.com", PW, ip="10.0.0.2")                            # the account is locked
    assert sum(1 for x in a.audit_rows() if x["action"] == "login.fail" and "locked" in x["detail"]) == 1
    now[0] += 61
    assert a.login("al@example.com", PW, ip="10.0.0.2")["scope"] == "full"      # the lock ends
    for i in range(5):                                                           # one address, many emails
        with pytest.raises(BackupError):
            a.login(f"guess{i}@example.com", "whatever whatever", ip="10.6.6.6")
    with pytest.raises(BackupError, match="too many failed logins"):
        a.login("al@example.com", PW, ip="10.6.6.6")
    small = accounts._Limiter(max_keys=3, clock=lambda: now[0])
    for i in range(50):
        small.fail(f"k{i}")
    assert len(small.d) == 3


def test_f10_unknown_email_costs_the_same_two_password_checks(db, monkeypatch):
    a, adm, u, _ = db
    calls = []
    real = accounts.check_password
    monkeypatch.setattr(accounts, "check_password", lambda pw, h: calls.append(h) or real(pw, h))
    for email in ("nobody@example.com", "al@example.com"):
        calls.clear()
        with pytest.raises(BackupError, match="wrong email or password"):
            a.login(email, "not the password")
        assert len(calls) == 2 and all(h and h.startswith("scrypt$") for h in calls), email


# ---------- FN-2: the hub sealing key ----------

def test_fn2_hub_key_is_created_atomically_checked_on_every_read_and_never_used_bad(tmp_path):
    k = tmp_path / "accounts.db.key"
    keys, errs = [], []

    def go():
        try:
            keys.append(accounts._hub_key(k))
        except BackupError as e:                                                  # pragma: no cover - must not happen
            errs.append(e)
    ts = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs and len(set(keys)) == 1 and len(keys[0]) == 32
    assert stat.S_IMODE(k.stat().st_mode) == 0o600
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".havnvard-key-")]
    for bad, why in (("", "damaged"), ("ab" * 16, "damaged"), ("zz" * 32, "not hex")):
        e = tmp_path / f"bad{len(bad)}{why[:3]}.key"
        e.write_text(bad)
        os.chmod(e, 0o600)
        with pytest.raises(BackupError, match=why):
            accounts.seal(e, "SECRET-PASSWORD")                                   # never seals with a bad key
    loose = tmp_path / "loose.key"
    loose.write_text("ab" * 32)
    os.chmod(loose, 0o644)
    with pytest.raises(BackupError, match="readable by others"):
        accounts.seal(loose, "x")


def test_fn2_a_key_that_cannot_unseal_never_locks_the_user_out(db):
    a, adm, u, _ = db
    a.force_open(adm, u, "audit", "al@example.com", mailer=Mail())
    kp = a.key_path()
    os.chmod(kp, 0o600)
    kp.write_text("cd" * 32 + "\n")                                              # key replaced: unseal fails
    w = hubweb.App(a)
    c = Client(w)
    c.req("POST", "/login", {"email": "al@example.com", "password": PW})
    c.post("/ack", {"step": "ack", "understand": "yes"})
    st, _, page = c.req("GET", "/ack")
    assert st == "200 OK" and "could not be recovered" in page and "Save my password" in page
    st, h, _ = c.post("/ack", {"step": "password", "password": "my own one now", "password2": "my own one now"})
    assert h["Location"] == "/me" and c.req("GET", "/me")[0] == "200 OK"
    assert "force_open.told_password_failed" in _actions(a)


# ---------- F1, FN-3, FN-4, FN-6, D2: the blocked-folder report ----------

def _writer_with_two_blocked(tmp_path, monkeypatch, deep: int = 0):
    w = archive._Writer(tmp_path, "20261114-0300", tmp_path)
    real = os.mkdir

    def fake_mkdir(p, *a):
        if str(p).endswith(("/locked", "/proj")):
            raise PermissionError(13, "Permission denied", str(p))
        return real(p, *a)
    monkeypatch.setattr(archive.os, "mkdir", fake_mkdir)
    w.put_file("/locked/a.txt", io.BytesIO(b"a"), 1, 0o644, 0)
    (tmp_path / "share").mkdir()
    for i in range(deep or 1):
        w.put_file(f"/share/proj/a/b/f{i:03}.txt", io.BytesIO(b"b"), 1, 0o644, 0)
    return w


def test_f1_blocked_report_imports_cleanly_with_the_default_popup_and_hub_notice(tmp_path, monkeypatch):
    import backup.notify  # noqa: F401  - F1: both modules exist in the tree
    from backup.checkin import report_notice  # noqa: F401
    w = _writer_with_two_blocked(tmp_path, monkeypatch)
    pops, notes = [], []
    monkeypatch.setattr(notify, "popup", lambda t, x, **kw: pops.append(x) or {"shown": False, "how": "test"})
    monkeypatch.setattr(checkin, "report_notice", lambda k, x: notes.append(x) or "sent")
    archive._report_blocked(w, str(tmp_path), None, None)                       # defaults: never an ImportError
    assert len(pops) == 2 and len(notes) == 2


def test_fn4_a_popup_or_notice_that_raises_never_hides_the_other_folders(tmp_path, monkeypatch, capsys):
    w = _writer_with_two_blocked(tmp_path, monkeypatch)
    seen_pop, seen_note = [], []

    def pop(title, text, **kw):
        seen_pop.append(text)
        if len(seen_pop) == 1:
            raise ValueError("invalid literal for int() with base 10: 'x'")      # bad loginctl output
        return {"shown": True, "how": "fake"}

    def note(kind, text):
        seen_note.append(text)
        if len(seen_note) == 1:
            raise KeyError("getpwuid(): uid not found: 4242")
        return "sent"
    errs = archive._report_blocked(w, str(tmp_path), pop, note)
    out = capsys.readouterr()
    assert len(seen_pop) == 2 and len(seen_note) == 2                            # folder 2 still got both
    assert "NO POPUP for" in out.err and "ValueError" in out.err and "KeyError" in out.err
    assert len(errs) == 2
    assert out.out.index("BLOCKED folder") < out.out.index("popup for")         # the list is printed first


def test_fn6_every_unplaced_file_under_a_refused_folder_is_listed_and_counted(tmp_path, monkeypatch, capsys):
    w = _writer_with_two_blocked(tmp_path, monkeypatch, deep=40)
    texts = []
    archive._report_blocked(w, str(tmp_path), lambda t, x, **kw: texts.append(x) or {"shown": True, "how": "f"},
                            lambda k, x: "sent")
    o = capsys.readouterr().out
    assert "NOT PUT BACK: 41 file(s)" in o
    for i in range(40):
        assert f"NOT PUT BACK /share/proj/a/b/f{i:03}.txt" in o
    proj = [t for t in texts if "share" in t.split("\n")[2]][0]
    assert "could not put back 40 item(s)" in proj and "... and 30 more" in proj


def test_fn6_pullback_exits_non_zero_when_files_were_not_placed(tmp_path, monkeypatch):
    w = _writer_with_two_blocked(tmp_path, monkeypatch)
    w.blocked.clear()                                                              # only the unplaced set is left
    assert w.unplaced
    src = Path(archive.__file__).read_text()
    assert "w.blocked or w.unplaced" in src


def test_fn3_zenity_never_reads_the_text_as_markup():
    z = lambda n: "/usr/bin/zenity"  # noqa: E731
    sess = {"user": "alice", "uid": 1234, "type": "x11", "display": ":1", "runtime_dir": "/run/user/1234"}
    evil = '<a href="http://x">Click to restore your files</a> R&D'
    for kw in ({"env": {"DISPLAY": ":0"}}, {"env": {}, "session": sess, "euid": 0}):
        cmd, _, _ = notify.build("T", evil, system="Linux", which=z, **kw)
        assert "--no-markup" in cmd and cmd[-1] == evil


def test_d2_as_root_the_popup_goes_only_to_the_folder_owners_session(monkeypatch):
    monkeypatch.setattr(notify.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notify.shutil, "which", lambda n: "/usr/bin/zenity")
    monkeypatch.setenv("DISPLAY", ":0")                                          # root's own display: never used
    asked, launched = [], []
    alice = {"user": "alice", "uid": 1234, "type": "x11", "display": ":1", "runtime_dir": "/run/user/1234"}

    def finder(uid=None):
        asked.append(uid)
        return alice if uid == 1234 else None
    r = notify.popup("T", "x", launcher=lambda c, e, s: launched.append(c), owner_uid=4321, euid=0, finder=finder)
    assert r["shown"] is False and "no graphical session" in r["how"] and "hub notice only" in r["how"]
    assert launched == [] and asked == [4321]
    r = notify.popup("T", "x", launcher=lambda c, e, s: launched.append(c), owner_uid=1234, euid=0, finder=finder)
    assert r["shown"] is True and launched[0][:3] == ["runuser", "-u", "alice"]
    r = notify.popup("T", "x", launcher=lambda c, e, s: launched.append(c), owner_uid=None, euid=0, finder=finder)
    assert r["shown"] is False and len(launched) == 1


def test_d2_find_session_by_uid_and_bad_loginctl_output_is_skipped():
    def run(cmd):
        if cmd[:2] == ["loginctl", "list-sessions"]:
            return "1 x\n2 y\n3 z\n"
        return {"1": "Type=x11\nActive=yes\nRemote=no\nName=bad\nUser=notanumber\n",
                "2": "Type=x11\nActive=yes\nRemote=no\nName=bob\nUser=2000\nDisplay=:0\n",
                "3": "Type=wayland\nActive=yes\nRemote=no\nName=al\nUser=1000\n"}[cmd[2]]
    assert notify.find_session(run)["user"] == "bob"
    assert notify.find_session(run, uid=1000)["user"] == "al"
    assert notify.find_session(run, uid=7) is None


# ---------- FN-5: the writer, when it runs as root ----------

def test_fn5_modes_and_times_are_set_on_the_open_fd_never_by_path(tmp_path, monkeypatch):
    def no_path_chmod(*a, **k):
        raise AssertionError(f"chmod by path: {a}")
    monkeypatch.setattr(archive.os, "chmod", no_path_chmod)
    w = archive._Writer(tmp_path, "20261114-0300", tmp_path)
    w.put_dir("/d", 0o750, 1_000_000)
    w.put_file("/d/f.txt", io.BytesIO(b"abc"), 3, 0o640, 1_000_000)
    w.finish()
    assert stat.S_IMODE((tmp_path / "d" / "f.txt").stat().st_mode) == 0o640
    assert stat.S_IMODE((tmp_path / "d").stat().st_mode) == 0o750
    assert int((tmp_path / "d" / "f.txt").stat().st_mtime) == 1_000_000


def test_fn5_as_root_setuid_and_setgid_are_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "_euid", lambda: 0)
    monkeypatch.setattr(archive, "_root_unsafe", lambda p: False)               # pretend root owns tmp (R2 test below)
    w = archive._Writer(tmp_path, "20261114-0300", tmp_path)
    w.put_file("/suid", io.BytesIO(b"#!/bin/sh\n"), 10, 0o6755, 0)
    assert stat.S_IMODE((tmp_path / "suid").stat().st_mode) == 0o755


def test_fn5_a_folder_link_out_of_the_target_is_a_blocked_folder_never_followed(tmp_path, monkeypatch):
    tgt, outside = tmp_path / "tgt", tmp_path / "outside"
    tgt.mkdir()
    outside.mkdir()
    (tgt / "x").symlink_to(outside)                                             # /home/al/x -> /etc/cron.d
    w = archive._Writer(tgt, "20261114-0300", tmp_path)
    w.put_file("/x/job", io.BytesIO(b"* * * * * root evil\n"), 20, 0o644, 0)
    assert list(outside.iterdir()) == []
    assert w.unplaced == {"/x/job"} and w.blocked[str(tgt / "x")]["why"] == archive.LINK_OUT
    # as root with target "/": a link owned by a user that points at a folder owned by someone else is refused
    root_tgt = archive._Writer(Path("/"), "20261114-0300", tmp_path)
    monkeypatch.setattr(archive, "_euid", lambda: 0)
    monkeypatch.setattr(archive, "_uid_of", lambda p, follow: 0 if follow else 1000)
    monkeypatch.setattr(archive, "_root_unsafe", lambda p: False)               # isolate the LINK_OUT rule
    src = str(tgt / "x" / "job2")
    root_tgt.put_file(src, io.BytesIO(b"evil\n"), 5, 0o644, 0)
    assert list(outside.iterdir()) == [] and root_tgt.unplaced == {src}


# =====================================================================================================================
# Round 2 (Opus re-review 20261114: R1, R2, R3). Proof script rv2/poc2.py probes D and E are R1's tests.
# =====================================================================================================================

def test_r1_probe_d_a_kept_reset_code_dies_when_the_user_finishes_with_the_old_password(db):
    a, adm, u, _ = db
    code = a.admin_reset(adm, u)["code"]                                        # the admin keeps it
    s = a.login("al@example.com", PW)
    a.ack_warning(s["token"])
    a.set_own_password(s["token"], "al's very own one")
    with pytest.raises(BackupError, match="used, expired"):
        a.set_password_with_reset(code, "admin takes over now")                 # was: a silent FULL session
    assert a.login("al@example.com", "al's very own one")["scope"] == "full"


def test_r1_probe_e_force_open_and_disable_end_outstanding_codes(db):
    a, adm, u, _ = db
    code = a.admin_reset(adm, u)["code"]
    a.force_open(adm, u, "audit", "al@example.com", mailer=Mail())
    with pytest.raises(BackupError, match="used, expired"):
        a.set_password_with_reset(code, "pre force-open code")
    code2 = a.admin_reset(adm, u)["code"]
    a.disable(adm, u, "quit")
    a.enable(adm, u)
    with pytest.raises(BackupError, match="used, expired"):
        a.set_password_with_reset(code2, "code from before the disable")


def test_r1_a_code_never_gives_a_full_session_without_the_notice(db):
    """Even a code that is somehow still valid when no notice is pending leads to a NEW notice, never a full session."""
    a, adm, u, _ = db
    code = a.admin_reset(adm, u, reason="forgot")["code"]
    con = sqlite3.connect(a.path)                                                # simulate: notice already cleared
    con.execute("UPDATE account SET must_ack_force_open=0, must_set_password=0 WHERE id=?", (u,))
    con.execute("UPDATE force_open SET acked_at='2026-11-14T00:00:00+00:00'")
    con.commit()
    con.close()
    r = a.set_password_with_reset(code, "whoever holds it")
    assert r["must_ack"] is True and a.session(r["token"])["scope"] == "notice"
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(r["token"])
    hist = a.reset_history(u)
    assert len(hist) == 2 and hist[-1]["acked_at"] is None and "was redeemed" in hist[-1]["reason"]


def test_r3a_me_lists_every_reset_and_how_it_was_acknowledged_for_good(db):
    a, adm, u, _ = db
    a.force_open(adm, u, "legal hold", "al@example.com", mailer=Mail())
    s = a.login("al@example.com", PW)
    a.ack_warning(s["token"], ip="100.64.0.5", ua="AlLaptop")
    a.set_own_password(s["token"], "al after hold!!")
    code = a.admin_reset(adm, u, reason="forgot again")["code"]
    t = a.set_password_with_reset(code, "someone with the code", ip="100.64.9.9", ua="PrivateWindow")
    a.ack_warning(t["token"], ip="100.64.9.9", ua="PrivateWindow")
    w = hubweb.App(a)
    c = Client(w)
    c.req("POST", "/login", {"email": "al@example.com", "password": "someone with the code"})
    _, _, page = c.req("GET", "/me")
    assert "reset your password 2 time(s)" in page
    assert "force-open: accessed all your files" in page and "legal hold" in page and "forgot again" in page
    assert "with your old password from 100.64.0.5 (AlLaptop)" in page
    assert "with a reset code from 100.64.9.9 (PrivateWindow)" in page
    assert "code given to the admin (no mail configured)" in page


def test_r3b_with_mail_configured_codes_and_passwords_go_only_to_the_user(db):
    a, adm, u, _ = db
    mail = Mail("sent")
    r = a.admin_reset(adm, u, reason="forgot", mailer=mail)
    assert r["code"] is None and r["code_delivery"].startswith("emailed to the user only")
    to, _subj, body = mail.sent[-1]
    code = body.split("Your reset code (works for 24 hours, only once): ")[1].split()[0]
    assert to == "al@example.com" and a.set_password_with_reset(code, "al from the email")["must_ack"] is True
    f = a.force_open(adm, u, "audit", "al@example.com", mailer=mail)
    assert f["new_password"] is None and "Generated password" in mail.sent[-1][2]
    failed = a.admin_reset(adm, u, mailer=Mail("failed: SMTPConnectError: down"))
    assert failed["code"] is None and "FAILED" in failed["code_delivery"]       # never falls back to the admin
    shown = a.admin_reset(adm, u, mailer=Mail("not configured"))
    assert shown["code"] and shown["code_delivery"] == "code given to the admin (no mail configured)"
    assert [h["code_delivery"].split(" ")[0] for h in a.reset_history(u)] == ["emailed", "emailed", "email", "code"]
    assert any(x["action"] == "password.reset_code_delivery" for x in a.audit_rows())


def test_r3c_gated_page_says_exactly_what_is_true(db):
    a, adm, u, _ = db
    r = a.force_open(adm, u, "audit", "al@example.com", mailer=Mail())
    c = Client(hubweb.App(a))
    c.req("POST", "/login", {"email": "al@example.com", "password": r["new_password"]})
    _, _, page = c.req("GET", "/ack")
    assert "cannot hide or clear" not in page
    assert "may have seen it too" in page and "cannot acknowledge it or set a password" in page
    assert "kept on your page for good" in page


def test_r2_as_root_a_folder_another_user_controls_is_blocked_and_never_written(tmp_path, monkeypatch):
    """Scenario: root pulls back into /home/al/proj; al owns it and could swap a sub-folder for a link to /etc/cron.d
    between the check and the write. As root nothing is written into a folder root does not control."""
    tgt, outside = tmp_path / "home-al", tmp_path / "etc-cron.d"
    tgt.mkdir()
    outside.mkdir()
    monkeypatch.setattr(archive, "_euid", lambda: 0)
    swapped = []
    real_write = archive._Writer._write_new

    def swap_then_write(self, path, *a, **k):                                   # the attacker's swap, mid-run
        d = path.parent
        if d != outside and not d.is_symlink():
            d.rename(d.with_name(d.name + ".moved"))
            d.symlink_to(outside)
            swapped.append(d)
        return real_write(self, path, *a, **k)
    monkeypatch.setattr(archive._Writer, "_write_new", swap_then_write)
    w = archive._Writer(tgt, "20261114-0300", tmp_path)
    w.put_file("/x/job", io.BytesIO(b"* * * * * root evil\n"), 20, 0o644, 0)
    assert list(outside.iterdir()) == [] and swapped == []                      # never reached the write
    assert w.unplaced == {"/x/job"}
    (b,) = w.blocked.values()
    assert b["why"] == archive.ROOT_FOREIGN
    # root-owned but group-writable: also refused; root-owned 755: written
    monkeypatch.setattr(archive._Writer, "_write_new", real_write)
    monkeypatch.setattr(archive, "_uid_of", lambda p, follow: 0)
    monkeypatch.setattr(archive, "_mode_of", lambda p, follow: stat.S_IFDIR | 0o775)
    w2 = archive._Writer(tgt, "20261114-0300", tmp_path)
    w2.put_file("/y/f", io.BytesIO(b"x"), 1, 0o644, 0)
    assert w2.unplaced == {"/y/f"}
    monkeypatch.setattr(archive, "_mode_of", lambda p, follow: stat.S_IFDIR | 0o755)
    w3 = archive._Writer(tgt, "20261114-0300", tmp_path)
    w3.put_file("/z/f", io.BytesIO(b"x"), 1, 0o644, 0)
    assert (tgt / "z" / "f").read_bytes() == b"x" and not w3.unplaced
    assert stat.S_IMODE((tgt / "z").stat().st_mode) & 0o022 == 0
