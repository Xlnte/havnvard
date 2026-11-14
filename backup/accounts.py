"""HavnVard accounts (3.3.0; INFRA-579 registration, INFRA-575 company-owned files).

PAF rulings 20261113-14 this module enforces:
* The company (or household) owns the files. One store per company, opened by a STORE KEY the admin holds. The store key
  is generated at the first registration, shown ONCE (recovery kit) and never kept: only its SHA-256 fingerprint is
  stored, so the admin proves they hold it (`store_key_matches`) and uses it for `restic key add` (see `adopt_repo`).
* Admin and user are separate accounts. The same email may hold one of each, with the same password if they like.
* The first account on a new hub is the admin; it needs the one-time setup code printed on the hub's console.
  After that, registration is by invite only.
* A user sees only their own files (`can_read` / `filter_paths`): ownership rules by path COMPONENT prefix, the device's
  primary user, files an admin released to them. A folder marked shared is owned by the PC's administrator (PAF
  20261114: "nobody owns a shared folder; the administrator of that PC owns it").
* Disable: every session revoked at once, files untouched.
* Force-open: the admin opens a user's files only by forcing a password reset; the user must acknowledge a warning at
  next login. No admin call clears that flag; every step is in the append-only, hash-chained audit log.
* Login passwords never encrypt data: forgetting one loses nothing.

Storage: one SQLite file on the hub (standard library; the backup half needs no PostgreSQL). Nothing here deletes a
file or a backup; account rows are never deleted either (disable, not delete).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from pathlib import Path

from . import config
from .config import BackupError

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSWORD = 12
SETUP_CODE_TTL = dt.timedelta(hours=1)
INVITE_TTL = dt.timedelta(days=7)
FORCE_OPEN_WINDOW = dt.timedelta(hours=24)
WARNING = "Your administrator reset your password, which means someone may have looked at your files."
COMMON = {"password1234", "123456789012", "qwertyuiopas", "passwordpassword", "letmein12345", "iloveyou1234"}
_WORDS = ("amber anchor apple arrow aspen badge birch bison blade bloom brook cabin cedar chalk cliff cloud comet coral "
          "crane delta dune eagle ember fern field flint frost glade grain grove harbor hazel heron ivory jade kayak "
          "lake lark linen lotus maple marsh meadow mesa mint moss noble oak ocean olive opal orbit otter pearl pine "
          "plum prism quail quartz raven reed ridge river robin sage sand slate spruce stone storm swan thorn tide "
          "tulip valley willow wren yarrow zephyr").split()

SCHEMA = """
CREATE TABLE IF NOT EXISTS company (id INTEGER PRIMARY KEY, name TEXT NOT NULL, store_key_fpr TEXT NOT NULL,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS account (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES company(id),
    kind TEXT NOT NULL CHECK (kind IN ('admin','user')), email TEXT NOT NULL, pw_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','disabled')), must_ack_force_open INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL, disabled_at TEXT, disabled_reason TEXT, UNIQUE (company_id, kind, email));
CREATE TABLE IF NOT EXISTS session (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES account(id),
    token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS setup_code (id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
    used_at TEXT);
CREATE TABLE IF NOT EXISTS invite (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, email TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('admin','user')), code_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
    used_at TEXT, created_by INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reset (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, code_hash TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL, created_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS force_open (id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    reason TEXT NOT NULL, started_at TEXT NOT NULL, ends_at TEXT NOT NULL, acked_at TEXT);
CREATE TABLE IF NOT EXISTS device (id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, name TEXT NOT NULL UNIQUE,
    primary_user_id INTEGER REFERENCES account(id), pc_admin_id INTEGER REFERENCES account(id),
    token_hash TEXT, status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ownership_rule (id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES device(id),
    path_prefix TEXT NOT NULL, user_id INTEGER REFERENCES account(id), shared INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS release (id INTEGER PRIMARY KEY, from_user_id INTEGER NOT NULL, to_user_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL, path_prefix TEXT NOT NULL, released_by INTEGER NOT NULL, released_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor INTEGER, action TEXT NOT NULL,
    target TEXT, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
"""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${d.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, d = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), maxmem=128 * 1024 * 1024)
    return hmac.compare_digest(got.hex(), d)


def password_rule(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise BackupError(f"password must be at least {MIN_PASSWORD} characters")
    if pw.lower() in COMMON:
        raise BackupError("that password is on the common-password list; choose another")


def _under(path: str, prefix: str) -> bool:
    """Path-COMPONENT prefix: /home/al covers /home/al and /home/al/x, never /home/alice."""
    f = prefix.rstrip("/") or "/"
    return f == "/" or path == f or path.startswith(f + "/")


def default_path() -> Path:
    return config.state_dir() / "accounts.db"


class Accounts:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        con = self._con()
        try:
            con.executescript(SCHEMA)
        finally:
            con.close()
        if new:
            os.chmod(self.path, 0o600)

    # ---------- plumbing ----------
    def _con(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def _tx(self):
        """BEGIN IMMEDIATE: one writer at a time, so two 'first' registrations cannot both win."""
        con = self._con()
        con.execute("BEGIN IMMEDIATE")
        return con

    @staticmethod
    def _audit(con, actor, action: str, target: str = "", **detail) -> None:
        row = con.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "0" * 64
        at, det = _iso(_now()), json.dumps(detail, sort_keys=True)
        h = _h("|".join([prev, at, str(actor), action, target, det]))
        con.execute("INSERT INTO audit(at, actor, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                    (at, actor, action, target, det, prev, h))

    def _one(self, sql: str, args=()) -> dict | None:
        con = self._con()
        try:
            r = con.execute(sql, args).fetchone()
            return dict(r) if r else None
        finally:
            con.close()

    def _admin_of(self, con, actor: int) -> sqlite3.Row:
        a = con.execute("SELECT * FROM account WHERE id=?", (actor,)).fetchone()
        if not a or a["kind"] != "admin" or a["status"] != "active":
            raise BackupError("only an active admin can do that")
        return a

    # ---------- setup code + registration (INFRA-579) ----------
    def new_setup_code(self) -> str:
        """One-time code for the FIRST registration, printed on the hub console by `hub setup-code`."""
        code = " ".join(secrets.choice(_WORDS) for _ in range(6))
        con = self._tx()
        try:
            if con.execute("SELECT 1 FROM account WHERE kind='admin' LIMIT 1").fetchone():
                raise BackupError("this hub already has an admin; new accounts are by invite only")
            con.execute("INSERT INTO setup_code(code_hash, expires_at) VALUES (?,?)",
                        (_h(code), _iso(_now() + SETUP_CODE_TTL)))
            self._audit(con, None, "setup_code.create")
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return code

    def register(self, email: str, password: str, setup_code: str | None = None, invite_code: str | None = None,
                 company: str | None = None) -> dict:
        email = email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise BackupError("enter a valid email address")
        password_rule(password)
        pw_hash = hash_password(password)                              # before the lock: scrypt is slow on purpose
        con = self._tx()
        try:
            has_admin = con.execute("SELECT 1 FROM account WHERE kind='admin' LIMIT 1").fetchone()
            out: dict = {}
            if not has_admin and setup_code is not None:
                row = con.execute("SELECT * FROM setup_code WHERE code_hash=? AND used_at IS NULL",
                                  (_h(" ".join(setup_code.split())),)).fetchone()
                if not row or row["expires_at"] < _iso(_now()):
                    raise BackupError("wrong or expired setup code (print a new one on the hub: `hub setup-code`)")
                store_key = secrets.token_urlsafe(32)
                cid = con.execute("INSERT INTO company(name, store_key_fpr, created_at) VALUES (?,?,?)",
                                  ((company or "My company").strip()[:120], _h(store_key), _iso(_now()))).lastrowid
                kind = "admin"
                con.execute("UPDATE setup_code SET used_at=? WHERE id=?", (_iso(_now()), row["id"]))
                out["store_key"] = store_key
            else:
                if not invite_code:
                    raise BackupError("ask your administrator for an invite" if has_admin
                                      else "the first account needs the setup code shown on the hub")
                inv = con.execute("SELECT * FROM invite WHERE code_hash=? AND used_at IS NULL",
                                  (_h(invite_code.strip()),)).fetchone()
                if not inv or inv["expires_at"] < _iso(_now()):
                    raise BackupError("this invite is used, expired or wrong; ask your administrator for a new one")
                if inv["email"] != email:
                    raise BackupError(f"this invite is for {inv['email']}")
                cid, kind = inv["company_id"], inv["kind"]
                con.execute("UPDATE invite SET used_at=? WHERE id=?", (_iso(_now()), inv["id"]))
            if con.execute("SELECT 1 FROM account WHERE company_id=? AND kind=? AND email=?",
                           (cid, kind, email)).fetchone():
                raise BackupError(f"{email} already has a {kind} account")
            aid = con.execute("INSERT INTO account(company_id, kind, email, pw_hash, status, created_at) "
                              "VALUES (?,?,?,?, 'active', ?)", (cid, kind, email, pw_hash, _iso(_now()))).lastrowid
            self._audit(con, aid, "account.register", email, kind=kind, first_admin=bool(out))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"account_id": aid, "company_id": cid, "kind": kind, **out}

    def store_key_matches(self, key: str, company_id: int | None = None) -> bool:
        row = self._one("SELECT store_key_fpr FROM company " + ("WHERE id=?" if company_id else "ORDER BY id LIMIT 1"),
                        (company_id,) if company_id else ())
        return bool(row) and hmac.compare_digest(row["store_key_fpr"], _h(key.strip()))

    def invite(self, actor: int, email: str, kind: str = "user") -> str:
        if kind not in ("admin", "user"):
            raise BackupError("kind is admin or user")
        code = secrets.token_urlsafe(18)
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            con.execute("INSERT INTO invite(company_id, email, kind, code_hash, expires_at, created_by) VALUES (?,?,?,?,?,?)",
                        (adm["company_id"], email.strip().lower(), kind, _h(code), _iso(_now() + INVITE_TTL), actor))
            self._audit(con, actor, "invite.create", email.strip().lower(), kind=kind)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return code

    # ---------- login / sessions ----------
    def login(self, email: str, password: str, kind: str = "user") -> dict:
        email = email.strip().lower()
        acc = self._one("SELECT * FROM account WHERE email=? AND kind=?", (email, kind))
        if not acc or not check_password(password, acc["pw_hash"]):
            self._log(acc["id"] if acc else None, "login.fail", email, kind=kind)
            raise BackupError("wrong email or password")
        if acc["status"] != "active":
            self._log(acc["id"], "login.refused", email, why="disabled")
            raise BackupError("this account is disabled; ask your administrator")
        token = secrets.token_urlsafe(32)
        con = self._tx()
        try:
            con.execute("INSERT INTO session(account_id, token_hash, created_at) VALUES (?,?,?)",
                        (acc["id"], _h(token), _iso(_now())))
            self._audit(con, acc["id"], "login.ok", email, kind=kind)
            con.execute("COMMIT")
        finally:
            con.close()
        return {"token": token, "account_id": acc["id"], "kind": kind, "must_ack": bool(acc["must_ack_force_open"])}

    def _log(self, actor, action, target="", **detail) -> None:
        con = self._tx()
        try:
            self._audit(con, actor, action, target, **detail)
            con.execute("COMMIT")
        finally:
            con.close()

    def session(self, token: str | None) -> dict | None:
        """The live session for a token: checked on EVERY request (no cache), so a disable is instant."""
        if not token:
            return None
        row = self._one("SELECT s.account_id, a.kind, a.email, a.company_id, a.must_ack_force_open FROM session s "
                        "JOIN account a ON a.id = s.account_id WHERE s.token_hash=? AND s.revoked_at IS NULL "
                        "AND a.status='active'", (_h(token),))
        return row

    def require_ready(self, token: str | None) -> dict:
        s = self.session(token)
        if not s:
            raise BackupError("please log in")
        if s["must_ack_force_open"]:
            raise BackupError("you must acknowledge the administrator warning first")
        return s

    def logout(self, token: str) -> None:
        con = self._tx()
        try:
            con.execute("UPDATE session SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (_iso(_now()), _h(token)))
            con.execute("COMMIT")
        finally:
            con.close()

    # ---------- accounts ----------
    def account(self, aid: int) -> dict | None:
        return self._one("SELECT id, company_id, kind, email, status, must_ack_force_open, created_at, disabled_at, "
                         "disabled_reason FROM account WHERE id=?", (aid,))

    def list_accounts(self, kind: str | None = None) -> list[dict]:
        con = self._con()
        try:
            q = "SELECT id, kind, email, status, must_ack_force_open, created_at, disabled_at FROM account"
            rows = con.execute(q + (" WHERE kind=?" if kind else "") + " ORDER BY id", (kind,) if kind else ())
            return [dict(r) for r in rows]
        finally:
            con.close()

    def disable(self, actor: int, target: int, reason: str) -> None:
        """Quit or fired: logins stop at once (every session revoked), files stay with the company."""
        con = self._tx()
        try:
            self._admin_of(con, actor)
            t = con.execute("SELECT * FROM account WHERE id=?", (target,)).fetchone()
            if not t:
                raise BackupError("no such account")
            if t["kind"] == "admin":
                left = con.execute("SELECT COUNT(*) FROM account WHERE kind='admin' AND status='active' AND id<>?",
                                   (target,)).fetchone()[0]
                if left == 0:
                    raise BackupError("cannot disable the last admin; add a second admin first")
            now = _iso(_now())
            con.execute("UPDATE account SET status='disabled', disabled_at=?, disabled_reason=? WHERE id=?",
                        (now, reason[:500], target))
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (now, target)).rowcount
            self._audit(con, actor, "account.disable", t["email"], kind=t["kind"], reason=reason[:500], sessions_revoked=n)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    def enable(self, actor: int, target: int) -> None:
        """Login works again; old sessions stay revoked; a pending force-open warning stays pending."""
        con = self._tx()
        try:
            self._admin_of(con, actor)
            con.execute("UPDATE account SET status='active', disabled_at=NULL, disabled_reason=NULL WHERE id=?", (target,))
            self._audit(con, actor, "account.enable", str(target))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    # ---------- force-open (PAF ruling) ----------
    def force_open(self, actor: int, target: int, reason: str, typed_email: str) -> str:
        """Admin opens a user's files by forcing a password reset. Returns the reset code to hand to the user."""
        if not reason.strip():
            raise BackupError("give the reason (the user will see it)")
        code = secrets.token_urlsafe(18)
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            t = con.execute("SELECT * FROM account WHERE id=? AND kind='user'", (target,)).fetchone()
            if not t:
                raise BackupError("no such user account")
            if typed_email.strip().lower() != t["email"]:
                raise BackupError("type the user's email exactly to confirm")
            now = _now()
            con.execute("UPDATE account SET pw_hash=?, must_ack_force_open=1 WHERE id=?",
                        ("locked$" + secrets.token_hex(16), target))
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (_iso(now), target)).rowcount
            con.execute("INSERT INTO reset(account_id, code_hash, created_by, created_at) VALUES (?,?,?,?)",
                        (target, _h(code), actor, _iso(now)))
            con.execute("INSERT INTO force_open(admin_id, user_id, reason, started_at, ends_at) VALUES (?,?,?,?,?)",
                        (actor, target, reason.strip()[:500], _iso(now), _iso(now + FORCE_OPEN_WINDOW)))
            self._audit(con, actor, "force_open.start", t["email"], admin=adm["email"], reason=reason.strip()[:500],
                        sessions_revoked=n, window_h=FORCE_OPEN_WINDOW.total_seconds() / 3600)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return code

    def admin_reset(self, actor: int, target: int) -> str:
        """An ordinary 'forgot my password' reset by the admin (no force-open, no file access)."""
        code = secrets.token_urlsafe(18)
        con = self._tx()
        try:
            self._admin_of(con, actor)
            con.execute("INSERT INTO reset(account_id, code_hash, created_by, created_at) VALUES (?,?,?,?)",
                        (target, _h(code), actor, _iso(_now())))
            self._audit(con, actor, "password.reset_issued", str(target))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return code

    def set_password_with_reset(self, code: str, new_password: str) -> dict:
        password_rule(new_password)
        pw_hash = hash_password(new_password)
        con = self._tx()
        try:
            r = con.execute("SELECT * FROM reset WHERE code_hash=? AND used_at IS NULL", (_h(code.strip()),)).fetchone()
            if not r:
                raise BackupError("this reset code is used or wrong")
            con.execute("UPDATE reset SET used_at=? WHERE id=?", (_iso(_now()), r["id"]))
            con.execute("UPDATE account SET pw_hash=? WHERE id=?", (pw_hash, r["account_id"]))
            token = secrets.token_urlsafe(32)
            con.execute("INSERT INTO session(account_id, token_hash, created_at) VALUES (?,?,?)",
                        (r["account_id"], _h(token), _iso(_now())))
            a = con.execute("SELECT * FROM account WHERE id=?", (r["account_id"],)).fetchone()
            self._audit(con, r["account_id"], "password.reset", a["email"])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"token": token, "account_id": a["id"], "must_ack": bool(a["must_ack_force_open"])}

    def ack_warning(self, account_id: int, preview: bool = False) -> dict:
        """The warning the user must acknowledge. preview=True only reads it. Only the user's own call clears it."""
        con = self._tx()
        try:
            fo = con.execute("SELECT f.*, a.email AS admin_email FROM force_open f JOIN account a ON a.id=f.admin_id "
                             "WHERE f.user_id=? ORDER BY f.id DESC LIMIT 1", (account_id,)).fetchone()
            w = {"text": WARNING, "admin": fo["admin_email"] if fo else "", "reason": fo["reason"] if fo else "",
                 "at": fo["started_at"] if fo else ""}
            if not preview:
                con.execute("UPDATE account SET must_ack_force_open=0 WHERE id=?", (account_id,))
                if fo:
                    con.execute("UPDATE force_open SET acked_at=? WHERE id=?", (_iso(_now()), fo["id"]))
                self._audit(con, account_id, "force_open.ack", str(account_id), force_open_id=fo["id"] if fo else None)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return w

    def force_open_active(self, admin_id: int, user_id: int) -> bool:
        return bool(self._one("SELECT 1 AS x FROM force_open WHERE admin_id=? AND user_id=? AND ends_at>?",
                              (admin_id, user_id, _iso(_now()))))

    # ---------- devices, rules, release, filter ----------
    def add_device(self, actor: int, name: str, primary_user: int | None = None, pc_admin: int | None = None) -> str:
        """Register a computer; returns its check-in token (shown once, stored hashed)."""
        token = secrets.token_urlsafe(24)
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            con.execute("INSERT INTO device(company_id, name, primary_user_id, pc_admin_id, token_hash, created_at) "
                        "VALUES (?,?,?,?,?,?)", (adm["company_id"], name, primary_user, pc_admin, _h(token), _iso(_now())))
            self._audit(con, actor, "device.add", name, primary_user=primary_user, pc_admin=pc_admin)
            con.execute("COMMIT")
        except sqlite3.IntegrityError as e:
            con.execute("ROLLBACK")
            raise BackupError(f"device {name} already exists") from e
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return token

    def device(self, name: str) -> dict | None:
        return self._one("SELECT id, name, primary_user_id, pc_admin_id, status, created_at FROM device WHERE name=?", (name,))

    def device_by_token(self, name: str, token: str) -> dict | None:
        d = self._one("SELECT * FROM device WHERE name=? AND status='active'", (name,))
        return d if d and d["token_hash"] and hmac.compare_digest(d["token_hash"], _h(token or "")) else None

    def devices(self) -> list[dict]:
        con = self._con()
        try:
            return [dict(r) for r in con.execute("SELECT id, name, primary_user_id, pc_admin_id, status FROM device ORDER BY name")]
        finally:
            con.close()

    def _rule(self, actor: int, device: str, prefix: str, user: int | None, shared: bool) -> None:
        con = self._tx()
        try:
            self._admin_of(con, actor)
            d = con.execute("SELECT * FROM device WHERE name=?", (device,)).fetchone()
            if not d:
                raise BackupError(f"no device {device}")
            if shared:
                user = d["pc_admin_id"]
            con.execute("INSERT INTO ownership_rule(device_id, path_prefix, user_id, shared, created_by, created_at) "
                        "VALUES (?,?,?,?,?,?)", (d["id"], prefix.rstrip("/") or "/", user, int(shared), actor, _iso(_now())))
            self._audit(con, actor, "rule.shared" if shared else "rule.add", f"{device}:{prefix}", user=user)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    def add_rule(self, actor: int, device: str, prefix: str, user: int) -> None:
        self._rule(actor, device, prefix, user, False)

    def mark_shared(self, actor: int, device: str, prefix: str) -> None:
        """A shared folder: nobody owns it; the PC's administrator does (PAF 20261114)."""
        self._rule(actor, device, prefix, None, True)

    def release(self, actor: int, from_user: int, to_user: int, device: str, prefix: str) -> None:
        con = self._tx()
        try:
            self._admin_of(con, actor)
            d = con.execute("SELECT id FROM device WHERE name=?", (device,)).fetchone()
            if not d:
                raise BackupError(f"no device {device}")
            con.execute("INSERT INTO release(from_user_id, to_user_id, device_id, path_prefix, released_by, released_at) "
                        "VALUES (?,?,?,?,?,?)", (from_user, to_user, d["id"], prefix.rstrip("/") or "/", actor, _iso(_now())))
            self._audit(con, actor, "release.create", f"{device}:{prefix}", from_user=from_user, to_user=to_user)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    def owner_of(self, device: str, path: str) -> int | None:
        """Who owns PATH on DEVICE: the longest matching rule, else the device's primary user, else nobody."""
        con = self._con()
        try:
            d = con.execute("SELECT * FROM device WHERE name=?", (device,)).fetchone()
            if not d:
                return None
            rules = con.execute("SELECT * FROM ownership_rule WHERE device_id=?", (d["id"],)).fetchall()
            best = max((r for r in rules if _under(path, r["path_prefix"])), key=lambda r: len(r["path_prefix"]), default=None)
            if best is not None:
                return best["user_id"]
            return d["primary_user_id"]
        finally:
            con.close()

    def can_read(self, account_id: int, device: str, path: str) -> bool:
        acc = self.account(account_id)
        if not acc or acc["status"] != "active":
            return False
        owner = self.owner_of(device, path)
        if owner is not None and owner == account_id:
            return True
        if acc["kind"] == "admin" and owner is not None and self.force_open_active(account_id, owner):
            return True
        con = self._con()
        try:
            for r in con.execute("SELECT r.from_user_id, r.path_prefix FROM release r JOIN device d ON d.id=r.device_id "
                                 "WHERE d.name=? AND r.to_user_id=?", (device, account_id)):
                if _under(path, r["path_prefix"]) and self.owner_of(device, path) == r["from_user_id"]:
                    return True
        finally:
            con.close()
        return False

    def filter_paths(self, account_id: int, device: str, paths: list[str]) -> list[str]:
        return [p for p in paths if self.can_read(account_id, device, p)]

    # ---------- audit ----------
    def audit_rows(self, actor: int | None = None) -> list[dict]:
        con = self._con()
        try:
            q = "SELECT seq, at, actor, action, target, detail FROM audit"
            return [dict(r) for r in con.execute(q + (" WHERE actor=?" if actor else "") + " ORDER BY seq",
                                                 (actor,) if actor else ())]
        finally:
            con.close()

    def verify_audit(self) -> tuple[bool, int, str]:
        """(chain intact, rows, head hash). The head is what gets copied off the hub (catalog run, health-relay)."""
        con = self._con()
        try:
            prev, n = "0" * 64, 0
            for r in con.execute("SELECT * FROM audit ORDER BY seq"):
                h = _h("|".join([prev, r["at"], str(r["actor"]), r["action"], r["target"] or "", r["detail"]]))
                if r["prev_hash"] != prev or r["hash"] != h:
                    return False, n, prev
                prev, n = h, n + 1
            return True, n, prev
        finally:
            con.close()


def adopt_repo(restic: str, repo_env: dict, store_key: str, accts: Accounts) -> str:
    """Add the company's store key to an existing repository (`restic key add`). Additive: nothing is rewritten or
    removed, every snapshot stays. The key is checked against the stored fingerprint first."""
    from .util import run
    import tempfile
    if not accts.store_key_matches(store_key):
        raise BackupError("that is not this company's store key")
    with tempfile.TemporaryDirectory(prefix="havnvard-adopt-") as td:
        kf = Path(td) / "store.key"
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(store_key.strip() + "\n")
        r = run([restic, "key", "add", "--new-password-file", str(kf), "--host", "havnvard-store", "--user", "store"],
                env=repo_env)
        if r.returncode != 0:
            raise BackupError(f"restic key add failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
        # the temp dir is removed by TemporaryDirectory: our own scratch file, not a backup or a device file
    accts._log(None, "store.adopt_repo", repo_env.get("RESTIC_REPOSITORY", ""))
    return "added"
