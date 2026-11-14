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


def test_force_open_resets_password_sets_unclearable_ack_and_is_logged(db):
    a, code = db
    adm = _admin(a, code)
    u = a.register("al@example.com", PW, invite_code=a.invite(adm["account_id"], "al@example.com", "user"))["account_id"]
    a.add_device(adm["account_id"], "al-laptop", primary_user=u)
    tok = a.login("al@example.com", PW)["token"]
    with pytest.raises(BackupError, match="type the user's email"):
        a.force_open(adm["account_id"], u, reason="investigation", typed_email="wrong@example.com")
    reset = a.force_open(adm["account_id"], u, reason="investigation", typed_email="al@example.com")
    assert a.session(tok) is None                                             # sessions revoked
    with pytest.raises(BackupError, match="password"):
        a.login("al@example.com", PW)                                         # old password no longer works
    assert a.can_read(adm["account_id"], "al-laptop", "/home/al/x")          # admin may look, for the window
    # nothing an admin can call clears the flag
    for fn in ("enable", "disable"):
        try:
            getattr(a, fn)(adm["account_id"], u, reason="x") if fn == "disable" else a.enable(adm["account_id"], u)
        except BackupError:
            pass
    assert a.account(u)["must_ack_force_open"] == 1
    a.enable(adm["account_id"], u)
    s = a.set_password_with_reset(reset, "a brand new password!")
    assert s["must_ack"] is True
    w = a.ack_warning(s["account_id"], preview=True)
    assert "Your administrator reset your password, which means someone may have looked at your files." in w["text"]
    assert w["reason"] == "investigation" and w["admin"] == "boss@example.com" and w["at"]
    with pytest.raises(BackupError, match="acknowledge"):
        a.require_ready(s["token"])                                           # nothing works until acknowledged
    a.ack_warning(s["account_id"])
    assert a.require_ready(s["token"])["account_id"] == u
    acts = [r["action"] for r in a.audit_rows()]
    assert {"force_open.start", "force_open.ack", "password.reset"} <= set(acts)
    assert a.verify_audit()[0] is True


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
