"""HavnVard 3.3.6 regression tests, one per Plane item (INFRA-626, 612, 613, 614, 609, 610, 605, 606, 596, 595, 585). Each
fails on the 3.3.5 base (8b60a2a) and passes now. Throwaway SQLite in tmp dirs, in-process WSGI, fake SMTP and fake restic;
no network, never the live hub."""
from __future__ import annotations

import io
import json
import logging
import os
import stat
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import accounts, checkin, config, enroll, hubweb, mail, schedules  # noqa: E402
from backup.config import BackupError  # noqa: E402
from test_backup_hubweb import PW, Client, app  # noqa: E402,F401  (fixtures)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _admin(w, code, email="boss@example.com"):
    c = Client(w)
    st, _, _ = c.req("POST", "/register", {"email": email, "password": PW, "password2": PW, "setup_code": code,
                                           "company": "Acme"})
    assert st == "200 OK"
    return c, w.a.list_accounts(kind="admin")[0]["id"]


# ---- INFRA-626: web error counters visible, TypeError/AttributeError = logged 500 with traceback, one device-name rule ----
def test_626_counters_on_healthz_and_status_page_and_bugs_are_500_with_traceback(app, monkeypatch, caplog):  # noqa: F811
    w, code = app
    adm, _ = _admin(w, code)

    def boom(*a, **k):
        raise AttributeError("'NoneType' object has no attribute 'x'")
    monkeypatch.setattr(w, "me", boom)
    with caplog.at_level(logging.WARNING, logger="havnvard.hubweb"):
        st, _, page = adm.req("GET", "/me")
    assert st == "500 Internal Server Error", st                      # a bug, not the caller's mistake
    assert "AttributeError" not in page and "Traceback" not in page   # nothing from the exception reaches the browser
    assert "Traceback (most recent call last)" in caplog.text         # but the server log has the full traceback
    st, _, body = Client(w).req("GET", "/healthz")
    h = json.loads(body)
    assert st == "200 OK" and h["errors"]["internal"] == 1 and h["ok"] is False and "mail" in h
    _, _, page = adm.req("GET", "/admin/schedules")
    assert "1 internal error(s)" in page                              # on the hub status page


def test_626_health_check_reads_healthz(app, monkeypatch):  # noqa: F811
    from backup import health
    w, code = app
    body = json.dumps(w.status()).encode()

    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: R(body))
    name, ok, msg = health._hub_web_check("http://127.0.0.1:8001")
    assert name == "hub web" and ok is True and "0 internal" in msg
    w.errors["internal"] = 3
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: R(json.dumps(w.status()).encode()))
    assert health._hub_web_check("http://x")[1] is False


def test_626_one_device_name_rule_for_enroll_and_hub(app):  # noqa: F811
    w, code = app
    _, aid = _admin(w, code)
    assert enroll.NAME_RE is config.DEVICE_NAME_RE
    for name in ("-pc", "x" * 64, ".hidden"):
        assert not enroll.NAME_RE.match(name)
        with pytest.raises(BackupError, match="computer name"):
            w.a.add_device(aid, name)
    for name in ("pc-1", "A", "x" * 63):
        assert enroll.NAME_RE.match(name)
        w.a.add_device(aid, name)


# ---- INFRA-612 (S2): login limiter behind a proxy ----
def test_612_one_persons_typos_do_not_lock_others_behind_the_same_proxy_address(app):  # noqa: F811
    w, code = app
    _admin(w, code)
    a = w.a
    a.invite(a.list_accounts(kind="admin")[0]["id"], "al@example.com")
    for _ in range(accounts.LOGIN_MAX_FAILS + 2):
        with pytest.raises(BackupError):
            a.login("mallory@example.com", "wrong password", ip="10.0.0.2")       # the proxy's address for everyone
    with pytest.raises(BackupError, match="too many"):
        a.login("mallory@example.com", "wrong password", ip="10.0.0.2")            # that pair is locked ...
    r = a.login("boss@example.com", PW, kind="admin", ip="10.0.0.2")               # ... but the admin behind the same address is not
    assert r["kind"] == "admin"


def test_612_global_cap_stops_many_pairs(app, monkeypatch):  # noqa: F811
    w, code = app
    _admin(w, code)
    monkeypatch.setattr(w.a, "_global", accounts._Limiter(max_fails=6, lock=60.0))
    for i in range(6):
        with pytest.raises(BackupError):
            w.a.login(f"u{i}@example.com", "wrong password", ip=f"10.0.0.{i}")
    with pytest.raises(BackupError, match="too many"):
        w.a.login("boss@example.com", PW, kind="admin", ip="10.9.9.9")


def test_612_forwarded_for_is_trusted_only_from_a_configured_proxy(monkeypatch):
    env = {"REMOTE_ADDR": "10.0.0.2", "HTTP_X_FORWARDED_FOR": "6.6.6.6, 100.64.0.9"}
    monkeypatch.delenv("HAVNVARD_TRUSTED_PROXIES", raising=False)
    assert hubweb.client_address(env) == "10.0.0.2"                      # no proxy configured: the header is ignored
    monkeypatch.setenv("HAVNVARD_TRUSTED_PROXIES", "10.0.0.2")
    assert hubweb.client_address(env) == "100.64.0.9"                    # right-most entry that is not a proxy
    assert hubweb.client_address({**env, "REMOTE_ADDR": "9.9.9.9"}) == "9.9.9.9"   # not from the proxy: ignored


# ---- INFRA-613 (S3): cut_htpasswd lock + symlink ----
def test_613_cut_htpasswd_refuses_a_symlink_and_leaves_the_target_alone(tmp_path):
    real = tmp_path / "real.htpasswd"
    real.write_text("pc1:hash1\npc2:hash2\n")
    link = tmp_path / "hub.htpasswd"
    link.symlink_to(real)
    status, removed = accounts.cut_htpasswd(link, ["pc1"])
    assert removed == [] and "REFUSED" in status
    assert real.read_text() == "pc1:hash1\npc2:hash2\n" and link.is_symlink()


def test_613_cut_htpasswd_waits_for_the_lock(tmp_path):
    f = tmp_path / "hub.htpasswd"
    f.write_text("pc1:h1\npc2:h2\n")
    done = threading.Event()
    with config.file_lock(f):
        t = threading.Thread(target=lambda: (accounts.cut_htpasswd(f, ["pc1"]), done.set()))
        t.start()
        assert not done.wait(0.5), "cut_htpasswd ran while another writer held the lock"
    t.join(5)
    assert done.is_set() and f.read_text() == "pc2:h2\n"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


# ---- INFRA-614 (S4): revoke_device_keys crash mid-write ----
def test_614_hub_password_file_survives_a_crash_while_writing_the_new_key(app, tmp_path, monkeypatch):  # noqa: F811
    w, code = app
    adm, _ = _admin(w, code)
    store = "STORE-KEY-123"
    fpr = accounts._h(store)
    with w.a._tx() as con:
        con.execute("UPDATE company SET store_key_fpr=?", (fpr,))
        con.execute("COMMIT")
    hub_pass = tmp_path / "pc1.pass"
    hub_pass.write_text("OLD-HUB-PASSWORD\n")
    state = {"armed": False, "new": None}

    class Done:
        def __init__(self, out="", rc=0):
            self.stdout, self.stderr, self.returncode = out, "", rc

    def fake_run(cmd, env=None, **kw):
        if "list" in cmd:
            keys = [{"id": "aaaaaaaa11", "current": True, "hostName": "havnvard-store"},
                    {"id": "bbbbbbbb22", "current": False, "hostName": "pc1"}]
            return Done(json.dumps(keys))
        if "add" in cmd:
            state["new"] = open(cmd[cmd.index("--new-password-file") + 1]).read()
            state["armed"] = True
        return Done()
    import backup.util as util
    monkeypatch.setattr(util, "run", fake_run)
    real_fdopen = os.fdopen

    class Crashing:
        def __init__(self, f):
            self.f = f

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.f.close()
            return False

        def write(self, text):
            if state["armed"] and text == state["new"]:
                raise OSError("simulated crash while writing the hub key")
            return self.f.write(text)

        def __getattr__(self, n):
            return getattr(self.f, n)
    monkeypatch.setattr(os, "fdopen", lambda fd, *a, **k: Crashing(real_fdopen(fd, *a, **k)))
    with pytest.raises(OSError, match="simulated crash"):
        accounts.revoke_device_keys("restic", "/nonexistent/repo", store, w.a, "pc1", hub_pass)
    assert hub_pass.read_text() == "OLD-HUB-PASSWORD\n"                  # never empty, never half-written


# ---- INFRA-609 (FL-7): the queue-file rewrite must not lose a line appended meanwhile ----
@pytest.mark.parametrize("which", ["pending", "notices"])
def test_609_a_line_appended_during_a_flush_is_not_lost(tmp_path, monkeypatch, which):
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path))
    if which == "pending":
        checkin._keep_pending({"kind": "end", "run_id": 1, "exit_code": 0, "error": None, "ended_at": "t"})
        flush, newline = checkin._flush_pending, lambda: checkin._keep_pending({"kind": "checkin_failed", "at": "t2"})
        path = checkin._pending_file()
    else:
        checkin._keep_notice({"kind": "k", "text": "first", "at": "t"}, "why")
        flush, newline = checkin._flush_notices, lambda: checkin._keep_notice({"kind": "k", "text": "second", "at": "t2"}, "why")
        path = checkin._notices_file()
    calls = []

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout=0):
        calls.append(req.full_url)
        if len(calls) == 1:
            newline()                                                    # another process appends while we are sending
        return Resp(b"{}")
    assert flush("http://hub", "pc1", "tok", opener) == 1
    left = path.read_text().splitlines()
    assert len(left) == 1 and ("checkin_failed" in left[0] or "second" in left[0]), left


# ---- INFRA-610 (FL-8): hub notices capped per device ----
def test_610_notices_per_device_are_capped(app):  # noqa: F811
    w, code = app
    _, aid = _admin(w, code)
    tok = w.a.add_device(aid, "pc1")
    assert tok
    for i in range(accounts.NOTICE_CAP_PER_DEVICE):
        w.a.add_notice("pc1", "k", f"n{i}")
    with pytest.raises(BackupError, match="open notices"):
        w.a.add_notice("pc1", "k", "one too many")
    assert w.a.notices_refused == 1
    assert any(r["action"] == "notice.refused" for r in w.a.audit_rows())
    # over the API the device gets a JSON 400 and keeps the notice on its side
    st, _, body = Client(w).req("POST", "/api/v1/devices/pc1/notice", {"kind": "k", "text": "x"},
                                {"HTTP_AUTHORIZATION": f"Bearer {tok}"}, as_json=True)
    assert st == "400 Bad Request" and "open notices" in json.loads(body)["error"]
    assert w.a.verify_audit()[0]


# ---- INFRA-605 (FL-3): SMTP AUTH only over TLS; strict booleans ----
class FakeSMTP:
    log: list = []

    def __init__(self, host, port, timeout=0, **kw):
        FakeSMTP.log.append(("connect", port))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSMTP.log.append(("starttls",))

    def login(self, u, p):
        FakeSMTP.log.append(("login", u))

    def send_message(self, msg):
        FakeSMTP.log.append(("send",))


def _cfg(tmp_path, **m):
    pw = tmp_path / "smtp.pass"
    pw.write_text("secret\n")
    return {"mail": {"host": "smtp.example.com", "from": "h@example.com", "user": "hub", "password_file": str(pw), **m}}


@pytest.mark.parametrize("m", [{"starttls": "false"}, {"starttls": False, "port": 25}, {"ssl": "false", "starttls": "no"}])
def test_605_no_login_in_cleartext(tmp_path, m):
    FakeSMTP.log = []
    st = mail.send("a@example.com", "s", "b", cfg=_cfg(tmp_path, **m), smtp=FakeSMTP)
    assert st.startswith("failed") and "cleartext" in st
    assert not any(e[0] in ("login", "send") for e in FakeSMTP.log)


def test_605_garbage_boolean_is_a_config_error_and_tls_paths_still_work(tmp_path):
    assert mail.send("a@example.com", "s", "b", cfg=_cfg(tmp_path, starttls="maybe"), smtp=FakeSMTP).startswith("failed")
    FakeSMTP.log = []
    assert mail.send("a@example.com", "s", "b", cfg=_cfg(tmp_path, starttls="true"), smtp=FakeSMTP) == "sent"
    assert [e[0] for e in FakeSMTP.log] == ["connect", "starttls", "login", "send"]     # TLS before AUTH
    assert mail.send("a@example.com", "s", "b", cfg=_cfg(tmp_path, ssl="yes", port=465), smtp=FakeSMTP) == "sent"


# ---- INFRA-606 (FL-4): force-open email is sent from a background worker ----
def test_606_force_open_does_not_wait_for_smtp(app, monkeypatch):  # noqa: F811
    w, code = app
    adm, aid = _admin(w, code)
    inv = w.a.invite(aid, "al@example.com")
    uid = w.a.register("al@example.com", PW, invite_code=inv)["account_id"]
    release, started = threading.Event(), threading.Event()
    sent = []

    def slow_send(to, subject, body, cfg=None, smtp=None):
        started.set()
        release.wait(10)
        sent.append(to)
        return "sent"
    monkeypatch.setattr(mail, "settings", lambda cfg=None: {"host": "h", "from": "f"})
    monkeypatch.setattr(mail, "send", slow_send)
    mail.OUTBOX.stats.update({k: 0 for k in mail.OUTBOX.stats})
    res = {}
    t = threading.Thread(target=lambda: res.update(w.a.force_open(aid, uid, "legal hold", "al@example.com")))
    t.start()
    try:
        t.join(3)
        assert not t.is_alive(), "force_open waited for the SMTP exchange inside the request"
        assert res["email_status"] == "queued" and res["new_password"] is None      # emailed only, not shown to the admin
    finally:
        release.set()
        t.join(5)
    assert mail.OUTBOX.drain(5) and sent == ["al@example.com"]
    assert mail.OUTBOX.stats["sent"] == 1
    assert any(r["action"] == "mail.result" for r in w.a.audit_rows())                # the real outcome is audited


def test_606_full_queue_is_a_visible_failure_and_failures_are_counted():
    gate = threading.Event()
    box = mail.Outbox(sender=lambda *a: (gate.wait(5), "failed: SMTPConnectError: down")[1], maxsize=2)
    results = [box.submit("a@example.com", "s", "b") for _ in range(6)]
    assert "queued" in results and any(r.startswith("failed: mail queue full") for r in results)
    assert box.stats["rejected_full"] >= 1
    gate.set()
    assert box.drain(5)
    assert box.stats["failed"] >= 1 and box.stats["sent"] == 0


# ---- INFRA-596 (F18): schedule + audit row in one transaction; the computer must exist ----
def test_596_schedule_change_and_audit_row_are_one_transaction(app, monkeypatch):  # noqa: F811
    w, code = app
    adm, aid = _admin(w, code)
    w.a.add_device(aid, "pc1")
    w.s.set(aid, "pc1", "interval", 60)
    assert [r["action"] for r in w.a.audit_rows() if r["action"] == "schedule.set"] == ["schedule.set"]

    def broken_audit(*a, **k):
        raise sqlite_error()
    import sqlite3

    def sqlite_error():
        return sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(accounts.Accounts, "_audit", staticmethod(broken_audit))
    with pytest.raises(sqlite3.OperationalError):
        w.s.set(aid, "pc1", "paused")
    assert w.s.get("pc1")["mode"] == "interval"                          # the change did not stick without its audit row


def test_596_schedule_for_an_unknown_computer_is_refused(app):  # noqa: F811
    w, code = app
    adm, aid = _admin(w, code)
    with pytest.raises(schedules.NotFound):
        w.s.set(aid, "typo-pc", "interval", 60)
    assert w.s.get("typo-pc") is None
    st, _, page = adm.post("/admin/schedules", {"device": "typo-pc", "mode": "interval", "every_min": "60"})
    assert st == "400 Bad Request" and "typo-pc" in page and w.s.get("typo-pc") is None


# ---- INFRA-595 (F17): state dir 0700, db and -wal/-shm 0600 whatever the umask ----
def test_595_state_dir_and_wal_files_ignore_a_loose_umask(tmp_path, monkeypatch):
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    old = os.umask(0o022)
    try:
        d = tmp_path / "newstate"
        a = accounts.Accounts(d / "accounts.db")
        con = a._con()                                                   # keep a connection open so -wal / -shm exist
        try:
            a.new_setup_code()
            for suffix in ("", "-wal", "-shm"):
                f = d / f"accounts.db{suffix}"
                assert f.exists(), suffix
                assert stat.S_IMODE(f.stat().st_mode) == 0o600, (suffix, oct(f.stat().st_mode))
        finally:
            con.close()
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
    finally:
        os.umask(old)


# ---- INFRA-585 (F3): admin password recovery from the hub console ----
def test_585_admin_recovery_resets_password_ends_sessions_and_audits(app):  # noqa: F811
    w, code = app
    adm, aid = _admin(w, code)
    assert adm.req("GET", "/admin/users")[0] == "200 OK"
    r = w.a.recover_admin()
    assert r["email"] == "boss@example.com" and r["sessions_revoked"] >= 1
    assert adm.req("GET", "/admin/users")[0] != "200 OK"                 # the old session is gone
    with pytest.raises(BackupError):
        w.a.login("boss@example.com", PW, kind="admin")                 # the old password is dead
    lg = w.a.login("boss@example.com", r["new_password"], kind="admin")
    assert lg["scope"] == "full" and not lg["must_ack"]
    rows = [x for x in w.a.audit_rows() if x["action"] == "admin.recovery_reset"]
    assert len(rows) == 1 and r["new_password"] not in rows[0]["detail"] and w.a.verify_audit()[0]
    with pytest.raises(BackupError, match="no active administrator"):
        w.a.recover_admin("nobody@example.com")


def test_585_there_is_no_web_route_and_the_cli_wants_confirmation(app, tmp_path):  # noqa: F811
    w, code = app
    adm, _ = _admin(w, code)
    for path in ("/admin/recover", "/admin-reset", "/reset-admin"):
        assert adm.req("GET", path)[0] == "404 Not Found"
    env = {**os.environ, "HAVNVARD_STATE_DIR": str(tmp_path / "s2"), "HAVNVARD_CONFIG_DIR": str(tmp_path / "c2")}
    p = subprocess.run([sys.executable, "-m", "backup", "hub", "admin-reset"], cwd=REPO, env=env, capture_output=True, text=True)
    assert p.returncode == config.PROBLEM_EXIT and "RESET ADMIN PASSWORD" in p.stdout
    time.sleep(0)


# ---- Opus review of 3.3.6 (FIX-NOW): the console force-open must not hand its mail to the in-process outbox ----
def test_review_cli_force_open_sends_mail_before_exiting(app, monkeypatch, tmp_path, capsys):  # noqa: F811
    import argparse

    from backup import cli
    w, code = app
    _, aid = _admin(w, code)
    inv = w.a.invite(aid, "al@example.com")
    w.a.register("al@example.com", PW, invite_code=inv)
    sent = []
    monkeypatch.setattr(mail, "settings", lambda cfg=None: {"host": "h", "from": "f"})
    monkeypatch.setattr(mail, "send", lambda to, subject, body, cfg=None, smtp=None: (sent.append(to), "sent")[1])
    monkeypatch.setattr(accounts, "Accounts", lambda *a, **k: w.a)
    pwf = tmp_path / "adm.pass"
    pwf.write_text(PW + "\n")
    ns = argparse.Namespace(user_email="al@example.com", confirm="al@example.com", admin="boss@example.com",
                            admin_password_file=str(pwf), reason="legal hold")
    before = dict(mail.OUTBOX.stats)
    assert cli._force_open_cli(ns) == 0
    assert sent == ["al@example.com"]                                 # sent before the command returned
    assert "Email to the user: sent" in capsys.readouterr().out
    assert mail.OUTBOX.stats["queued"] == before["queued"]            # nothing left to a thread that dies with the process


# ---- Opus review of 3.3.6: a computer added under 3.3.0-3.3.5 with a name the new rule refuses still checks in ----
def test_review_legacy_device_name_still_checks_in(app, monkeypatch):  # noqa: F811
    w, code = app
    _, aid = _admin(w, code)
    real = accounts.valid_device_name
    accounts.valid_device_name = lambda n: True                           # as 3.3.5 allowed it
    try:
        tok = w.a.add_device(aid, "-old-pc")
    finally:
        accounts.valid_device_name = real
    assert not accounts.valid_device_name("-old-pc")
    st, _, body = Client(w).req("POST", "/api/v1/devices/-old-pc/checkin", {"client_version": "3.3.4"},
                                {"HTTP_AUTHORIZATION": f"Bearer {tok}"}, as_json=True)
    assert st == "200 OK", body
