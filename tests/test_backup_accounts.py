"""HavnVard 3.3.0 accounts (INFRA-579 registration, INFRA-575 company-owned files). Throwaway SQLite in tmp dirs only;
no Postgres, no hub, no network."""
from __future__ import annotations

import os
import sqlite3
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import accounts  # noqa: E402
from backup.config import BackupError  # noqa: E402

PW = "correct horse battery"


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)          # fast in tests; production keeps 2**15
    a = accounts.Accounts(tmp_path / "accounts.db")
    code = a.new_setup_code()
    return a, code


def _admin(a, code, email="boss@example.com"):
    return a.register(email, PW, setup_code=code, company="Acme")


def test_first_account_needs_setup_code_and_becomes_admin_then_registration_closes(db):
    a, code = db
    with pytest.raises(BackupError, match="setup code"):
        a.register("x@example.com", PW, setup_code="wrong words", company="Acme")
    r = _admin(a, code)
    assert r["kind"] == "admin" and len(r["store_key"]) >= 40 and r["company_id"]
    assert a.store_key_matches(r["store_key"]) and not a.store_key_matches("nope")
    # the store key is shown once and never kept: only its fingerprint is on disk
    raw = (a.path).read_bytes()
    assert r["store_key"].encode() not in raw
    with pytest.raises(BackupError, match="invite"):
        a.register("late@example.com", PW, setup_code=code)
    with pytest.raises(BackupError, match="invite"):              # the setup code is single use
        a.register("late@example.com", PW)


def test_concurrent_first_registrations_make_exactly_one_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    a = accounts.Accounts(tmp_path / "accounts.db")
    code = a.new_setup_code()
    results = []

    def go(i):
        try:
            results.append(accounts.Accounts(tmp_path / "accounts.db").register(f"a{i}@example.com", PW,
                                                                                  setup_code=code, company="C"))
        except BackupError as e:
            results.append(e)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(1 for r in results if isinstance(r, dict)) == 1
    assert len(a.list_accounts(kind="admin")) == 1


def test_invite_same_email_admin_and_user_same_password_password_rules(db):
    a, code = db
    adm = _admin(a, code)
    inv = a.invite(adm["account_id"], "boss@example.com", "user")
    u = a.register("boss@example.com", PW, invite_code=inv)                 # same person, same password allowed
    assert u["kind"] == "user"
    assert a.login("boss@example.com", PW, kind="admin")["kind"] == "admin"
    assert a.login("boss@example.com", PW, kind="user")["kind"] == "user"
    with pytest.raises(BackupError, match="invite"):
        a.register("boss@example.com", PW, invite_code=inv)                 # invite used
    inv2 = a.invite(adm["account_id"], "kid@example.com", "user")
    with pytest.raises(BackupError, match="12 characters"):
        a.register("kid@example.com", "short", invite_code=inv2)
    with pytest.raises(BackupError, match="invite is for"):
        a.register("other@example.com", PW, invite_code=inv2)
    with pytest.raises(BackupError, match="admin"):
        a.invite(u["account_id"], "x@example.com", "user")                  # users cannot invite


def test_disable_revokes_every_session_at_once_and_keeps_files(db):
    a, code = db
    adm = _admin(a, code)
    u = a.register("al@example.com", PW, invite_code=a.invite(adm["account_id"], "al@example.com", "user"))
    tok = a.login("al@example.com", PW)["token"]
    tok2 = a.login("al@example.com", PW)["token"]
    a.add_device(adm["account_id"], "al-laptop", primary_user=u["account_id"])
    assert a.session(tok)["account_id"] == u["account_id"]
    a.disable(adm["account_id"], u["account_id"], reason="quit")
    assert a.session(tok) is None and a.session(tok2) is None
    with pytest.raises(BackupError, match="disabled"):
        a.login("al@example.com", PW)
    assert a.device("al-laptop")["primary_user_id"] == u["account_id"]        # files stay under the company
    assert a.can_read(adm["account_id"], "al-laptop", "/home/al/x") is False   # admin still needs force-open
    with pytest.raises(BackupError, match="last admin"):
        a.disable(adm["account_id"], adm["account_id"], reason="oops")
    a.enable(adm["account_id"], u["account_id"])
    assert a.session(tok) is None                                               # old sessions stay dead
    assert a.login("al@example.com", PW)["kind"] == "user"


def test_filter_path_components_rules_release_and_shared_folder_owned_by_pc_admin(db):
    a, code = db
    adm = _admin(a, code)
    mk = lambda e: a.register(e, PW, invite_code=a.invite(adm["account_id"], e, "user"))["account_id"]  # noqa: E731
    al, alice, kid = mk("al@example.com"), mk("alice@example.com"), mk("kid@example.com")
    a.add_device(adm["account_id"], "family-pc", primary_user=None, pc_admin=alice)
    a.add_rule(adm["account_id"], "family-pc", "/home/al", al)
    a.add_rule(adm["account_id"], "family-pc", "/home/alice", alice)
    a.mark_shared(adm["account_id"], "family-pc", "/srv/shared")
    assert a.can_read(al, "family-pc", "/home/al/tax.pdf")
    assert not a.can_read(al, "family-pc", "/home/alice/diary.txt")           # /home/al never matches /home/alice
    assert not a.can_read(al, "family-pc", "/srv/shared/plan.xlsx")           # shared folder: the PC's admin owns it
    assert a.can_read(alice, "family-pc", "/srv/shared/plan.xlsx")
    assert not a.can_read(kid, "family-pc", "/etc/passwd")                    # no rule, no primary user: nobody
    assert a.filter_paths(al, "family-pc", ["/home/al/a", "/home/alice/b", "/home/al"]) == ["/home/al/a", "/home/al"]
    with pytest.raises(BackupError, match="admin"):
        a.release(al, al, kid, "family-pc", "/home/al")                       # only an admin releases
    a.release(adm["account_id"], al, kid, "family-pc", "/home/al/school")
    assert a.can_read(kid, "family-pc", "/home/al/school/essay.doc")
    assert not a.can_read(kid, "family-pc", "/home/al/tax.pdf")


class Mail:
    """Fake mailer: records what would be sent and answers like backup.mail.send."""
    def __init__(self, status="sent"):
        self.status, self.sent = status, []

    def __call__(self, to, subject, body):
        self.sent.append((to, subject, body))
        return self.status


def _user(a, adm, email="al@example.com"):
    return a.register(email, PW, invite_code=a.invite(adm["account_id"], email, "user"))["account_id"]


def test_force_open_new_password_old_password_notice_unclearable_and_logged(db):
    a, code = db
    adm = _admin(a, code)
    u = _user(a, adm)
    a.add_device(adm["account_id"], "al-laptop", primary_user=u)
    tok = a.login("al@example.com", PW)["token"]
    mail = Mail()
    with pytest.raises(BackupError, match="type the user's email"):
        a.force_open(adm["account_id"], u, reason="investigation", typed_email="wrong@example.com", mailer=mail)
    with pytest.raises(BackupError, match="only an active admin"):
        a.force_open(u, u, reason="x", typed_email="al@example.com", mailer=mail)
    r = a.force_open(adm["account_id"], u, reason="investigation", typed_email="al@example.com", mailer=mail)
    # R3b: mail is configured (the fake answers "sent"), so the generated password goes ONLY to the user's email
    assert r["new_password"] is None and r["code_delivery"].startswith("emailed to the user only")
    new = mail.sent[0][2].split("Generated password (it only shows the notice): ")[1].split()[0]
    assert len(new) == 29 and new.count("-") == 5 and r["email_status"] == "sent"
    assert a.session(tok) is None                                             # sessions revoked
    # never stored in clear: not in any column of the database file
    raw = b"".join(p.read_bytes() for p in (a.path, a.path.with_name(a.path.name + "-wal")) if p.exists())
    assert new.encode() not in raw
    # email to the user, with who / when / reason, and NOT the new password
    (to, _subj, body), = mail.sent
    assert to == "al@example.com" and "boss@example.com" in body and "investigation" in body
    assert "accessed all your files" in body
    assert a.can_read(adm["account_id"], "al-laptop", "/home/al/x")          # admin may look, for the window
    # wrong password: refused
    with pytest.raises(BackupError, match="wrong email or password"):
        a.login("al@example.com", "not the right one at all")
    # OLD password -> a 'notice' session: the notice only, never a normal session
    old = a.login("al@example.com", PW)
    assert old["scope"] == "notice" and old["must_ack"] is True
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(old["token"])
    n = a.notice(u)
    assert n["text"].startswith("Your administrator boss@example.com reset your password on ")
    assert "accessed all your files. Reason: investigation" in n["text"] and n["unacked"]
    # NEW (admin-known) password -> the notice, read only (FN-1)
    fresh = a.login("al@example.com", new)
    assert fresh["scope"] == "gated" and fresh["must_ack"] is True
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(fresh["token"])
    # nothing an admin can call clears it (enable/disable/second force-open)
    a.disable(adm["account_id"], u, reason="x")
    a.enable(adm["account_id"], u)
    assert a.account(u)["must_ack_force_open"] == 1 and a.account(u)["must_set_password"] == 1
    assert a.told_password(u) is None                                         # not before the acknowledgement
    old = a.login("al@example.com", PW)                                        # disable revoked the earlier ones
    with pytest.raises(BackupError, match="acknowledge the notice first"):
        a.set_own_password(old["token"], "my very own password")
    w = a.ack_warning(old["token"])
    assert w["new_password"] == new                                           # told the generated password
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(old["token"])                                          # still gated: must set their own
    with pytest.raises(BackupError, match="administrator knows"):
        a.set_own_password(old["token"], new)
    s = a.set_own_password(old["token"], "my very own password")
    assert a.require_ready(s["token"])["account_id"] == u
    assert a.session(old["token"]) is None                                     # notice session gone
    acc = a._one("SELECT old_pw_hash, sealed_pw, must_set_password FROM account WHERE id=?", (u,))
    assert acc == {"old_pw_hash": None, "sealed_pw": None, "must_set_password": 0}
    for pw in (PW, new):                                                       # both old ones are dead now
        with pytest.raises(BackupError, match="wrong email or password"):
            a.login("al@example.com", pw)
    assert a.login("al@example.com", "my very own password")["scope"] == "full"
    acts = [r["action"] for r in a.audit_rows()]
    assert {"force_open.start", "force_open.email", "login.old_password_notice", "force_open.ack",
            "password.set_after_force_open"} <= set(acts)
    em = [r for r in a.audit_rows() if r["action"] == "force_open.email"][0]
    assert '"email_status": "sent"' in em["detail"]
    assert a.verify_audit()[0] is True


def test_force_open_email_not_configured_and_failed_are_recorded(db, tmp_path, monkeypatch):
    from backup import mail as mailmod
    a, code = db
    adm = _admin(a, code)
    u = _user(a, adm)
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg-none"))
    r = a.force_open(adm["account_id"], u, reason="r1", typed_email="al@example.com")   # real sender, no [mail]
    assert r["email_status"] == "not configured"
    failing = Mail("failed: SMTPConnectError: nope")
    r = a.force_open(adm["account_id"], u, reason="r2", typed_email="al@example.com", mailer=failing)
    assert r["email_status"].startswith("failed:")
    assert r["new_password"] is None and "FAILED" in r["code_delivery"]        # R3b: mail configured -> never shown
    r["new_password"] = failing.sent[0][2].split("Generated password (it only shows the notice): ")[1].split()[0]
    rows = a._one("SELECT GROUP_CONCAT(email_status, '|') AS s FROM force_open")["s"]
    assert rows == "not configured|failed: SMTPConnectError: nope"
    # a second force-open before the user came back keeps the user's REAL old password working for the notice
    assert a.login("al@example.com", PW)["scope"] == "notice"
    assert a.login("al@example.com", r["new_password"])["scope"] == "gated"
    assert a.notice(u)["reason"] == "r2"
    assert mailmod.settings({}) is None


def test_mail_sender_on_off_and_failure_with_fake_smtp(tmp_path):
    from backup import mail
    assert mail.send("u@example.com", "s", "b", cfg={}) == "not configured"
    pwf = tmp_path / "smtp.pass"
    pwf.write_text("s3cret\n")
    cfg = {"mail": {"host": "smtp.test", "port": 587, "user": "hub@example.com", "password_file": str(pwf),
                    "from": "HavnVard <hub@example.com>"}}
    log = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, **kw): log.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): log.append(("starttls",))
        def login(self, u, p): log.append(("login", u, p))
        def send_message(self, m): log.append(("send", m["To"], m["Subject"], m.get_content()))

    assert mail.send("u@example.com", "Subj", "Body text", cfg=cfg, smtp=FakeSMTP) == "sent"
    assert log[0] == ("connect", "smtp.test", 587) and ("starttls",) in log
    assert ("login", "hub@example.com", "s3cret") in log and log[-1][:3] == ("send", "u@example.com", "Subj")

    class DownSMTP(FakeSMTP):
        def __init__(self, *a, **k): raise ConnectionRefusedError("connection refused")
    st = mail.send("u@example.com", "s", "b", cfg=cfg, smtp=DownSMTP)
    assert st.startswith("failed: ConnectionRefusedError")
    st = mail.send("u@example.com", "s", "b", cfg={"mail": {**cfg["mail"], "password_file": str(tmp_path / "nope")}},
                   smtp=FakeSMTP)
    assert st.startswith("failed: FileNotFoundError")
    assert mail.send("bad\naddr@example.com", "s", "b", cfg=cfg, smtp=FakeSMTP).startswith("failed:")


def test_seal_roundtrip_and_tamper(tmp_path):
    k = tmp_path / "x.key"
    s1, s2 = accounts.seal(k, "ABCD-EFGH"), accounts.seal(k, "ABCD-EFGH")
    assert s1 != s2 and accounts.unseal(k, s1) == "ABCD-EFGH"
    assert oct(k.stat().st_mode & 0o777) == "0o600"
    v, n, ct, tag = s1.split("$")
    bad = "$".join([v, n, ("0" if ct[0] != "0" else "1") + ct[1:], tag])
    with pytest.raises(BackupError, match="does not match"):
        accounts.unseal(k, bad)


def test_notices_stay_until_dismissed_and_only_for_who_may_see(db):
    a, code = db
    adm = _admin(a, code)
    u, v = _user(a, adm), _user(a, adm, "bo@example.com")
    a.add_device(adm["account_id"], "al-laptop", primary_user=u)
    nid = a.add_notice("al-laptop", "pullback_blocked", "HavnVard could not put back 1 item(s) into /x")
    assert [n["id"] for n in a.open_notices(u)] == [nid]
    assert [n["id"] for n in a.open_notices(adm["account_id"])] == [nid]
    assert a.open_notices(v) == []
    with pytest.raises(BackupError, match="no such notice"):
        a.dismiss_notice(v, nid)
    a.dismiss_notice(u, nid)
    assert a.open_notices(u) == [] and a.open_notices(adm["account_id"]) == []
    assert {"notice.add", "notice.dismiss"} <= {r["action"] for r in a.audit_rows()}


def test_audit_is_hash_chained_and_tampering_is_detected(db):
    a, code = db
    adm = _admin(a, code)
    a.invite(adm["account_id"], "x@example.com", "user")
    ok, n, head = a.verify_audit()
    assert ok and n >= 2 and len(head) == 64
    con = sqlite3.connect(a.path)
    with pytest.raises(sqlite3.DatabaseError):                                # append-only: trigger refuses an edit
        con.execute("UPDATE audit SET detail='{\"forged\": 1}' WHERE seq=1")
    con.execute("DROP TRIGGER audit_no_update")                               # someone with root on the hub
    con.execute("UPDATE audit SET detail='{\"forged\": 1}' WHERE seq=1")
    con.commit()
    con.close()
    assert a.verify_audit()[0] is False
    con = sqlite3.connect(a.path)
    with pytest.raises(sqlite3.DatabaseError):                                # append-only: trigger refuses
        con.execute("DELETE FROM audit")
    con.close()


def test_adopt_repo_adds_the_store_key_and_changes_nothing_else(db, tmp_path):
    from conftest_backup_helpers import HAVE_RESTIC, restic
    if not HAVE_RESTIC:
        pytest.skip("restic not installed")
    a, code = db
    key = _admin(a, code)["store_key"]
    repo, pw, data = tmp_path / "repo", tmp_path / "dev.pass", tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("x\n")
    pw.write_text("device-password\n")
    restic(repo, pw, "init")
    restic(repo, pw, "backup", str(data))
    before = restic(repo, pw, "snapshots", "--json")
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    with pytest.raises(BackupError, match="not this company"):
        accounts.adopt_repo("restic", env, "wrong key", a)
    assert accounts.adopt_repo("restic", env, key, a) == "added"
    kf = tmp_path / "store.key"
    kf.write_text(key + "\n")
    assert restic(repo, kf, "snapshots", "--json") == before                 # the store key opens it; nothing changed
