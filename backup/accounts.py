"""HavnVard accounts (3.3.0; INFRA-579 registration, INFRA-575 company-owned files).

Owner rulings 20261113-14 this module enforces:
* The company (or household) owns the files. One store per company, opened by a STORE KEY the admin holds. The store key
  is generated at the first registration, shown ONCE (recovery kit) and never kept: only its SHA-256 fingerprint is
  stored, so the admin proves they hold it (`store_key_matches`) and uses it for `restic key add` (see `adopt_repo`).
* Admin and user are separate accounts. The same email may hold one of each, with the same password if they like.
* The first account on a new hub is the admin; it needs the one-time setup code printed on the hub's console.
  After that, registration is by invite only.
* Who owns which file (`can_read` / `filter_paths`): ownership rules by path COMPONENT prefix, the device's primary
  user, files an admin released to them. A folder marked shared is owned by the PC's administrator (owner ruling 20261114:
  "nobody owns a shared folder; the administrator of that PC owns it"). NOT YET ENFORCED in 3.3.0: no page or command
  shows or pulls files through the hub yet (users restore with their computer's own restic key), so nothing calls it.
* Disable: every session revoked at once, the check-in token of every computer the user is primary user of revoked,
  and that computer's line removed from the rest-server htpasswd (`disable`). Removing the computer's restic key
  from its repository needs the store key (`revoke_device_keys`, CLI `hub revoke-device-key`). Files untouched.
* Force-open: the admin opens a user's files only by forcing a password reset. A new random password is generated and
  shown to the admin once; it opens ONLY a read-only view of the notice (session scope 'gated'). The user's OLD
  password (or a reset code the user redeems, never from an administrator's session) is the proof that opens the
  'notice' scope, and only that scope can acknowledge the notice ("Your administrator X reset your password on DATE
  and accessed all your files. Reason: R") and set the user's own password. The user is emailed (status audited).
* Every admin-issued password reset (`admin_reset`) carries the same mandatory notice; an admin can never reset
  another admin (or an account outside their company). No admin call clears a notice; every step is in the
  append-only, hash-chained audit log with the client address and browser of each login, reset and acknowledgement.
  Honest limit: an admin who redeems a user's reset code from a browser with no admin session can act as the user
  once; the audit row (address, browser) and the permanent reset history on the user's page cannot be hidden.
* Login passwords never encrypt data: forgetting one loses nothing.

Storage: one SQLite file on the hub (standard library; the backup half needs no PostgreSQL). Nothing here deletes a
file or a backup; account rows are never deleted either (disable, not delete).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import posixpath
import secrets
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from pathlib import Path

from . import config
from .config import BackupError

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSWORD = 12
SETUP_CODE_TTL = dt.timedelta(hours=1)
INVITE_TTL = dt.timedelta(days=7)
FORCE_OPEN_WINDOW = dt.timedelta(hours=24)
RESET_TTL = dt.timedelta(hours=24)
WARNING = "Your administrator reset your password, which means someone may have looked at your files."
NOTICE = ("Your administrator {admin} reset your password on {when} and accessed all your files. Reason: {reason}")
NOTICE_RESET = ("Your administrator {admin} reset your password on {when}. Until you acknowledge this, whoever held "
                "the reset code could have logged in as you and seen all your files. Reason: {reason}")
RESET_REASON = "password reset by administrator"
UNUSABLE = "!"                    # pw_hash prefix: no password matches (after an admin reset, until the user acts)
LOGIN_MAX_FAILS, LOGIN_WINDOW_S, LOGIN_LOCK_S, LOGIN_MAX_KEYS = 5, 60.0, 60.0, 4096
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
CREATE TABLE IF NOT EXISTS notice (id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES device(id),
    kind TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL, dismissed_at TEXT, dismissed_by INTEGER);
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

# Columns added after the first 3.3.0 tables (never released, but a test hub may hold the older shape). Additive only.
#   account.old_pw_hash   the user's password hash from BEFORE a force-open; it reaches ONLY the notice, never a session
#                         with access, and is wiped when the user sets their own new password.
#   account.must_set_password  after a force-open the user must choose a password the administrator does not know.
#   account.sealed_pw     the generated password, sealed with the hub's own key file (never in clear in the database),
#                         so the user can be told it after acknowledging; wiped with old_pw_hash.
#   session.scope         'full'; 'notice' (proved by the user's OLD password or a reset code the user redeemed: may
#                         acknowledge and set their own password, nothing else); 'gated' (a password the administrator
#                         knows: may READ the notice and nothing else, never acknowledge it).
#   session.proof         what opened the session: password / old_password / reset_code / own_password_after_reset /
#                         admin_known_password.  session.ip / session.ua: client address and browser (audit).
#   force_open.email_status   sent / not configured / failed: ERROR - shown to the admin, never silent.
#   force_open.kind       'force_open' (opens the 24 h file window) or 'reset' (an admin-issued reset: notice only).
#   reset.expires_at      a reset code works for 24 h; issuing a new one ends the older ones.
_COLUMNS = (("account", "old_pw_hash", "TEXT"), ("account", "must_set_password", "INTEGER NOT NULL DEFAULT 0"),
            ("account", "sealed_pw", "TEXT"), ("session", "scope", "TEXT NOT NULL DEFAULT 'full'"),
            ("session", "proof", "TEXT"), ("session", "ip", "TEXT"), ("session", "ua", "TEXT"),
            ("force_open", "email_status", "TEXT"), ("force_open", "kind", "TEXT NOT NULL DEFAULT 'force_open'"),
            ("reset", "expires_at", "TEXT"), ("reset", "reason", "TEXT"),
            ("force_open", "ack_proof", "TEXT"), ("force_open", "ack_ip", "TEXT"), ("force_open", "ack_ua", "TEXT"),
            ("force_open", "code_delivery", "TEXT"))
#   force_open.ack_proof/ack_ip/ack_ua  HOW the notice was acknowledged (old_password / reset_code), from where: shown on
#                         the user's page for ever (R3a).  force_open.code_delivery: who got the code or generated
#                         password: "emailed to the user only" / "given to the admin (no mail configured)" / failed.


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


def check_password(pw: str, stored: str | None) -> bool:
    if not stored:
        return False
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


def clean_path(path: str) -> bool:
    """An absolute path already in normal form: no '..', no '.', no '//' and no trailing '/' (F8). Anything else is
    refused before an ownership check, so '/home/al/../bob/x' can never pass as being under /home/al. Purely lexical:
    nothing on disk is resolved, so no link is ever followed into another user's tree."""
    return isinstance(path, str) and path.startswith("/") and "\0" not in path and \
        (path == "/" or posixpath.normpath(path) == path) and not path.startswith("//")


def _under(path: str, prefix: str) -> bool:
    """Path-COMPONENT prefix: /home/al covers /home/al and /home/al/x, never /home/alice. A path that is not in normal
    form (F8: '..', '.', '//') is under nothing."""
    if not clean_path(path):
        return False
    f = prefix.rstrip("/") or "/"
    return f == "/" or path == f or path.startswith(f + "/")


_DUMMY: dict[int, str] = {}


def _delivery(status: str) -> tuple[bool, str]:
    """R3b: (show the code/password to the admin?, what the history says). Only when mail is NOT configured does the
    admin see it; when mail is configured it goes to the user's email only, even if sending failed."""
    if status == "not configured":
        return True, "code given to the admin (no mail configured)"
    if status == "sent":
        return False, "emailed to the user only (never shown to the admin)"
    return False, f"email to the user FAILED ({status}); the code was not shown to the admin: issue a new one"


def _dummy_hash() -> str:
    """A fixed scrypt hash nobody knows the password of, so an unknown email costs the same scrypt as a real one."""
    if SCRYPT_N not in _DUMMY:
        _DUMMY[SCRYPT_N] = hash_password(secrets.token_urlsafe(24))
    return _DUMMY[SCRYPT_N]


def _usable(h: str | None) -> bool:
    return bool(h) and not h.startswith(UNUSABLE)


class _Limiter:
    """Failed logins per key (account, source address): LOGIN_MAX_FAILS within LOGIN_WINDOW_S locks that key for
    LOGIN_LOCK_S. Bounded memory: at most LOGIN_MAX_KEYS keys, the least recently touched dropped first."""

    def __init__(self, max_fails=LOGIN_MAX_FAILS, window=LOGIN_WINDOW_S, lock=LOGIN_LOCK_S, max_keys=LOGIN_MAX_KEYS,
                 clock=time.monotonic):
        self.max_fails, self.window, self.lock_s, self.max_keys, self.clock = max_fails, window, lock, max_keys, clock
        self.d: OrderedDict[str, list] = OrderedDict()           # key -> [fail times, locked_until]
        self.mu = threading.Lock()

    def wait(self, key: str) -> float:
        with self.mu:
            v = self.d.get(key)
            return max(0.0, v[1] - self.clock()) if v else 0.0

    def fail(self, key: str) -> bool:
        """Record a failure; True when this failure starts a lock (audit once per lock, not per try)."""
        now = self.clock()
        with self.mu:
            v = self.d.pop(key, None) or [[], 0.0]
            v[0] = [t for t in v[0] if now - t < self.window] + [now]
            started = False
            if len(v[0]) >= self.max_fails and v[1] <= now:
                v[1], v[0], started = now + self.lock_s, [], True
            self.d[key] = v
            while len(self.d) > self.max_keys:
                self.d.popitem(last=False)
            return started

    def ok(self, key: str) -> None:
        with self.mu:
            self.d.pop(key, None)


def generated_password() -> str:
    """24 base32 characters (120 bits) in groups of four: strong and easy to read out or type."""
    raw = base64.b32encode(secrets.token_bytes(15)).decode()
    return "-".join(raw[i:i + 4] for i in range(0, 24, 4))


KEY_BYTES = 32


def _read_key(path: Path) -> bytes:
    """Read and CHECK the hub key on every use (FN-2): a regular file of ours, mode 600, exactly 32 bytes."""
    try:
        lst = os.lstat(path)
    except OSError as e:
        raise BackupError(f"hub key file {path} cannot be read: {e}") from e
    if not stat.S_ISREG(lst.st_mode):
        raise BackupError(f"hub key file {path} is not a regular file (a link?); refusing to use it")
    if lst.st_mode & 0o077:
        raise BackupError(f"hub key file {path} is readable by others (mode {oct(lst.st_mode & 0o777)}); expected 600")
    if hasattr(os, "getuid") and lst.st_uid != os.getuid():
        raise BackupError(f"hub key file {path} belongs to uid {lst.st_uid}, not to this hub's user")
    raw = path.read_text().strip()
    try:
        k = bytes.fromhex(raw)
    except ValueError as e:
        raise BackupError(f"hub key file {path} is damaged (not hex)") from e
    if len(k) != KEY_BYTES:
        raise BackupError(f"hub key file {path} is damaged ({len(k)} bytes, expected {KEY_BYTES})")
    return k


def _hub_key(path: Path) -> bytes:
    """The hub's sealing key (32 random bytes, mode 600, next to accounts.db; created on first use). It never leaves
    the hub and is not in the database, so a copy of accounts.db alone does not reveal a sealed password.
    Creation is atomic (FN-2): the key is written whole and fsynced to a private temp file, then hard-linked to the
    final name (link fails if the name exists), so no reader ever sees an empty or half-written key and two first
    uses at once end up with the same key."""
    if not os.path.lexists(path):
        import tempfile
        k = secrets.token_bytes(KEY_BYTES)
        # a private scratch dir next to the key (same file system, so link works); it and its temp name go away
        # with the TemporaryDirectory; the key itself lives on at `path`
        with tempfile.TemporaryDirectory(prefix=".havnvard-key-", dir=path.parent) as td:
            tmp = Path(td) / "key"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, (k.hex() + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass                                         # someone else won the race: use theirs (read below)
    return _read_key(path)


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    ek = hmac.new(key, b"havnvard-seal-enc|" + nonce, hashlib.sha256).digest()
    out = b"".join(hmac.new(ek, i.to_bytes(4, "big"), hashlib.sha256).digest() for i in range(n // 32 + 1))
    return out[:n]


def seal(key_file: Path, text: str) -> str:
    """Encrypt-then-MAC with HMAC-SHA256 only (standard library; a fresh random nonce every time)."""
    key, nonce, pt = _hub_key(key_file), secrets.token_bytes(16), text.encode()
    ct = bytes(a ^ b for a, b in zip(pt, _stream(key, nonce, len(pt))))
    tag = hmac.new(hmac.new(key, b"havnvard-seal-mac", hashlib.sha256).digest(), nonce + ct, hashlib.sha256).hexdigest()
    return f"v1${nonce.hex()}${ct.hex()}${tag}"


def unseal(key_file: Path, sealed: str) -> str:
    try:
        v, nonce_h, ct_h, tag = sealed.split("$")
        nonce, ct = bytes.fromhex(nonce_h), bytes.fromhex(ct_h)
    except ValueError as e:
        raise BackupError("sealed password is damaged") from e
    key = _hub_key(key_file)
    want = hmac.new(hmac.new(key, b"havnvard-seal-mac", hashlib.sha256).digest(), nonce + ct, hashlib.sha256).hexdigest()
    if v != "v1" or not hmac.compare_digest(want, tag):
        raise BackupError("sealed password does not match this hub's key (key file replaced?)")
    return bytes(a ^ b for a, b in zip(ct, _stream(key, nonce, len(ct)))).decode()


def default_path() -> Path:
    return config.state_dir() / "accounts.db"


class Accounts:
    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else default_path()
        self._limit = _Limiter()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        con = self._con()
        try:
            con.executescript(SCHEMA)
            for table, col, decl in _COLUMNS:
                have = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
                if col not in have:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
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

    @staticmethod
    def _end_codes(con, account_id: int) -> int:
        """R1: end every unused reset code of the account. Run in EVERY transaction that changes its credentials or its
        notice state, so a code can never be kept and redeemed after the user has finished."""
        now = _iso(_now())
        return con.execute("UPDATE reset SET expires_at=? WHERE account_id=? AND used_at IS NULL "
                           "AND (expires_at IS NULL OR expires_at > ?)", (now, account_id, now)).rowcount

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
    def login(self, email: str, password: str, kind: str = "user", ip: str | None = None,
              ua: str | None = None) -> dict:
        """Current password -> a session. While a notice is pending, which session depends on the PROOF (FN-1):
        * the user's OLD password                      -> 'notice' (may acknowledge, then set their own password)
        * a password the user set with a reset code    -> 'notice'
        * a password the administrator knows (the generated one) -> 'gated': READ the notice, nothing else, ever.
        Any other password -> refused. F10: at most LOGIN_MAX_FAILS failures per minute per account and per source
        address, then a 1-minute lock; an unknown email costs the same two scrypt checks as a real one."""
        email = email.strip().lower()
        keys = [f"acct:{kind}:{email}"] + ([f"ip:{ip}"] if ip else [])
        wait = max(self._limit.wait(k) for k in keys)
        if wait:
            raise BackupError(f"too many failed logins; try again in {int(wait) + 1} s")
        acc = self._one("SELECT * FROM account WHERE email=? AND kind=?", (email, kind))
        pending = bool(acc and (acc["must_ack_force_open"] or acc["must_set_password"]))
        cur = acc["pw_hash"] if acc and _usable(acc["pw_hash"]) else None
        old = acc["old_pw_hash"] if pending and acc["old_pw_hash"] else None
        # always exactly two scrypt checks (a dummy hash stands in), so timing does not tell which emails exist
        ok_cur = check_password(password, cur or _dummy_hash()) and cur is not None
        ok_old = check_password(password, old or _dummy_hash()) and old is not None
        if ok_old:
            scope, proof = "notice", "old_password"
        elif ok_cur and pending and acc["must_set_password"]:
            scope, proof = "gated", "admin_known_password"
        elif ok_cur and pending:
            scope, proof = "notice", "own_password_after_reset"
        elif ok_cur:
            scope, proof = "full", "password"
        else:
            locked = [k for k in keys if self._limit.fail(k)]
            self._log(acc["id"] if acc else None, "login.fail", email, kind=kind, ip=ip, ua=(ua or "")[:200],
                      **({"locked": locked, "lock_s": LOGIN_LOCK_S} if locked else {}))
            raise BackupError("wrong email or password")
        if acc["status"] != "active":
            self._log(acc["id"], "login.refused", email, why="disabled", ip=ip, ua=(ua or "")[:200])
            raise BackupError("this account is disabled; ask your administrator")
        self._limit.ok(keys[0])
        token = secrets.token_urlsafe(32)
        con = self._tx()
        try:
            con.execute("INSERT INTO session(account_id, token_hash, created_at, scope, proof, ip, ua) "
                        "VALUES (?,?,?,?,?,?,?)", (acc["id"], _h(token), _iso(_now()), scope, proof, ip, (ua or "")[:200]))
            self._audit(con, acc["id"], {"full": "login.ok", "notice": "login.old_password_notice",
                                         "gated": "login.notice_view_only"}[scope], email, kind=kind, scope=scope,
                        proof=proof, ip=ip, ua=(ua or "")[:200])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"token": token, "account_id": acc["id"], "kind": kind, "must_ack": pending, "scope": scope}

    def _log(self, actor, action, target="", **detail) -> None:
        con = self._tx()
        try:
            self._audit(con, actor, action, target, **detail)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    def session(self, token: str | None) -> dict | None:
        """The live session for a token: checked on EVERY request (no cache), so a disable is instant."""
        if not token:
            return None
        row = self._one("SELECT s.account_id, s.scope, s.proof, a.kind, a.email, a.company_id, a.must_set_password, "
                        "(a.must_ack_force_open OR a.must_set_password OR s.scope <> 'full') AS must_ack_force_open, "
                        "a.must_ack_force_open AS notice_unacked FROM session s "
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
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    # ---------- accounts ----------
    def account(self, aid: int) -> dict | None:
        return self._one("SELECT id, company_id, kind, email, status, must_ack_force_open, must_set_password, "
                         "created_at, disabled_at, "
                         "disabled_reason FROM account WHERE id=?", (aid,))

    def list_accounts(self, kind: str | None = None) -> list[dict]:
        con = self._con()
        try:
            q = ("SELECT id, kind, email, status, must_ack_force_open, must_set_password, created_at, disabled_at "
                 "FROM account")
            rows = con.execute(q + (" WHERE kind=?" if kind else "") + " ORDER BY id", (kind,) if kind else ())
            return [dict(r) for r in rows]
        finally:
            con.close()

    @staticmethod
    def _target(con, adm, target: int, user_only: bool = False) -> sqlite3.Row:
        """F3: the target must exist and be in the admin's own company (and be a user, where asked)."""
        t = con.execute("SELECT * FROM account WHERE id=?", (target,)).fetchone()
        if not t or t["company_id"] != adm["company_id"]:
            raise BackupError("no such account")
        if user_only and t["kind"] != "user":
            raise BackupError("an administrator's password cannot be reset by another administrator (or here); "
                              "nothing was changed")
        return t

    def disable(self, actor: int, target: int, reason: str, htpasswd: str | os.PathLike | None = None,
                reload=None) -> dict:
        """Quit or fired: EVERY access path is cut (F6), files stay with the company.
        * every web session revoked at once;
        * the check-in token of every computer the user is primary user of revoked (the device API refuses it);
        * that computer's line removed from the rest-server htpasswd (kept aside in `hub.htpasswd.removed`, 600),
          then the rest-server told to re-read it (`reload`, default `systemctl --user kill -s HUP restic-hub`);
        * the computer's restic key is NOT removed here: that needs the company store key, which the hub never
          keeps (`revoke_device_keys` / `hub revoke-device-key`). The result and the audit row say so.
        Returns {"sessions_revoked", "devices", "tokens_revoked", "htpasswd", "reload", "restic_key"}."""
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            t = self._target(con, adm, target)
            if t["kind"] == "admin":
                left = con.execute("SELECT COUNT(*) FROM account WHERE kind='admin' AND status='active' AND id<>? "
                                   "AND company_id=?", (target, adm["company_id"])).fetchone()[0]
                if left == 0:
                    raise BackupError("cannot disable the last admin; add a second admin first")
            now = _iso(_now())
            con.execute("UPDATE account SET status='disabled', disabled_at=?, disabled_reason=? WHERE id=?",
                        (now, reason[:500], target))
            self._end_codes(con, target)
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (now, target)).rowcount
            devs = [r["name"] for r in con.execute("SELECT name FROM device WHERE primary_user_id=? AND company_id=?",
                                                   (target, adm["company_id"]))]
            nt = con.execute("UPDATE device SET token_hash=NULL WHERE primary_user_id=? AND company_id=? "
                             "AND token_hash IS NOT NULL", (target, adm["company_id"])).rowcount
            self._audit(con, actor, "account.disable", t["email"], kind=t["kind"], reason=reason[:500], sessions_revoked=n,
                        devices=devs, device_tokens_revoked=nt)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        out = {"sessions_revoked": n, "devices": devs, "tokens_revoked": nt, "htpasswd": "no computer", "reload": "",
               "restic_key": ""}
        if devs:
            out["htpasswd"], removed = cut_htpasswd(Path(htpasswd) if htpasswd else _default_htpasswd(), devs)
            if removed:
                out["reload"] = (reload or _reload_rest_server)()
            out["restic_key"] = ("still in each computer's repository (and in NAS/offsite copies): remove it with "
                                 "`python -m backup hub revoke-device-key DEVICE --store-key-file FILE --confirm ...` "
                                 "for " + ", ".join(devs))
            self._log(actor, "account.disable.devices", t["email"], devices=devs, htpasswd=out["htpasswd"],
                      reload=out["reload"], restic_key=out["restic_key"])
        return out

    def enable(self, actor: int, target: int) -> None:
        """Login works again; old sessions stay revoked; a pending force-open warning stays pending; computer tokens
        and htpasswd lines cut by `disable` stay cut (issue a new token with `reissue_device_token`)."""
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            self._target(con, adm, target)
            con.execute("UPDATE account SET status='active', disabled_at=NULL, disabled_reason=NULL WHERE id=?", (target,))
            self._audit(con, actor, "account.enable", str(target))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    # ---------- force-open (Owner rulings 20261114) ----------
    def force_open(self, actor: int, target: int, reason: str, typed_email: str, mailer=None, ip: str | None = None,
                   ua: str | None = None) -> dict:
        """The admin opens a user's files by forcing a password reset.

        * A NEW random password replaces the user's login; it is returned here ONCE for the admin and is never stored
          in clear (only its scrypt hash, plus a copy sealed with the hub's key file so the USER can be told it after
          acknowledging; that copy is wiped when the user sets their own password). Because the administrator knows
          it, it opens only a read-only view of the notice (FN-1): it can never acknowledge it or set a password.
        * The user's OLD password hash is kept apart: it is the proof that opens the notice for acknowledgement.
        * Every session of the user is revoked; the notice is mandatory; no admin call clears it.
        * The user is emailed; the result (sent / not configured / failed: ERROR) is in the audit log and returned.
        Returns {"new_password", "email_status", "user_email"}."""
        if not reason.strip():
            raise BackupError("give the reason (the user will see it)")
        new_pw = generated_password()
        new_hash = hash_password(new_pw)                                   # before the lock: scrypt is slow on purpose
        sealed = seal(self.key_path(), new_pw)                             # FN-2: refuses a bad key, never seals with it
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            t = self._target(con, adm, target, user_only=True)
            if typed_email.strip().lower() != t["email"]:
                raise BackupError("type the user's email exactly to confirm")
            now = _now()
            pending = bool(t["must_ack_force_open"] or t["must_set_password"])
            # a second force-open before the user came back: keep the user's REAL old password, not our last one
            old = t["old_pw_hash"] if (pending and t["old_pw_hash"]) else t["pw_hash"]
            con.execute("UPDATE account SET pw_hash=?, old_pw_hash=?, sealed_pw=?, must_ack_force_open=1, "
                        "must_set_password=1 WHERE id=?", (new_hash, old if _usable(old) else None, sealed, target))
            self._end_codes(con, target)
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (_iso(now), target)).rowcount
            fid = con.execute("INSERT INTO force_open(admin_id, user_id, reason, started_at, ends_at, kind) "
                              "VALUES (?,?,?,?,?, 'force_open')",
                              (actor, target, reason.strip()[:500], _iso(now), _iso(now + FORCE_OPEN_WINDOW))).lastrowid
            self._audit(con, actor, "force_open.start", t["email"], admin=adm["email"], reason=reason.strip()[:500],
                        sessions_revoked=n, window_h=FORCE_OPEN_WINDOW.total_seconds() / 3600,
                        password="replaced by a generated one (shown to the admin once)", ip=ip, ua=(ua or "")[:200])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        # the email goes out AFTER the commit (never claim a reset that did not happen); its outcome is audited.
        # R3b: with [mail] configured the generated password goes ONLY to the user's email, never to the admin.
        when = _iso(now)
        body = (NOTICE.format(admin=adm["email"], when=when + " UTC", reason=reason.strip()[:500]) + "\n\n"
                "To read this notice on the hub, log in with YOUR OWN old password (the one you used before). If you "
                "have forgotten it, use the generated password below to READ the notice, and ask your administrator "
                "for a reset code to acknowledge it. After you acknowledge the notice you will choose a new password of "
                "your own.\n\nGenerated password (it only shows the notice): " + new_pw + "\n\n"
                "Nothing was deleted. This message was sent by HavnVard.")
        status = self._mail(mailer, t["email"],
                            "HavnVard: your administrator reset your password and accessed your files", body)
        shown, delivery = _delivery(status)
        con = self._tx()
        try:
            con.execute("UPDATE force_open SET email_status=?, code_delivery=? WHERE id=?", (status, delivery, fid))
            self._audit(con, actor, "force_open.email", t["email"], force_open_id=fid, email_status=status,
                        code_delivery=delivery)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"new_password": new_pw if shown else None, "email_status": status, "user_email": t["email"],
                "code_delivery": delivery}

    @staticmethod
    def _mail(mailer, to: str, subject: str, body: str) -> str:
        if mailer is None:
            from .mail import send as mailer
        return mailer(to, subject, body)

    def key_path(self) -> Path:
        return self.path.with_name(self.path.name + ".key")

    def admin_reset(self, actor: int, target: int, reason: str | None = None, ip: str | None = None,
                    ua: str | None = None, mailer=None) -> dict:
        """A 'forgot my password' reset issued by the admin. Every admin-issued reset carries the mandatory notice
        (F2, owner ruling: "the admin forces a password reset"); there is no silent kind. Only a USER account of the admin's
        own company (F3). Allowed while a notice is pending (D1): it then adds to that notice. The user's current
        password stops working (it is kept only as the proof that opens the notice); the code works for 24 h, ends
        every older code, and must be redeemed by the user (never from an administrator's session, D1).
        R3b: with [mail] configured the code goes ONLY to the user's email and is never returned to the admin; without
        mail it is returned (shown to the admin) and the history says so.
        Returns {"code" (None when emailed), "email_status", "code_delivery"}."""
        code = secrets.token_urlsafe(18)
        why = (reason or "").strip()[:500] or RESET_REASON
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            t = self._target(con, adm, target, user_only=True)
            now = _now()
            pending = bool(t["must_ack_force_open"] or t["must_set_password"])
            if pending and t["old_pw_hash"]:
                old = t["old_pw_hash"]                                # keep the user's real old password
            else:
                old = t["pw_hash"] if _usable(t["pw_hash"]) else None
            self._end_codes(con, target)
            con.execute("INSERT INTO reset(account_id, code_hash, created_by, created_at, expires_at, reason) "
                        "VALUES (?,?,?,?,?,?)", (target, _h(code), actor, _iso(now), _iso(now + RESET_TTL), why))
            con.execute("UPDATE account SET pw_hash=?, old_pw_hash=?, sealed_pw=NULL, must_ack_force_open=1, "
                        "must_set_password=1 WHERE id=?", (UNUSABLE + "reset", old, target))
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (_iso(now), target)).rowcount
            fid = con.execute("INSERT INTO force_open(admin_id, user_id, reason, started_at, ends_at, kind) "
                              "VALUES (?,?,?,?,?, 'reset')", (actor, target, why, _iso(now), _iso(now))).lastrowid
            self._audit(con, actor, "password.reset_issued", t["email"], admin=adm["email"], reason=why,
                        sessions_revoked=n, notice="mandatory", ip=ip, ua=(ua or "")[:200])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        body = (NOTICE_RESET.format(admin=adm["email"], when=_iso(now) + " UTC", reason=why) + "\n\n"
                "Your reset code (works for 24 hours, only once): " + code + "\n\nRedeem it yourself on the hub's "
                "/reset page. You will then read this notice and choose your own password.\n\n"
                "This message was sent by HavnVard.")
        status = self._mail(mailer, t["email"], "HavnVard: your administrator reset your password", body)
        shown, delivery = _delivery(status)
        self._log(actor, "password.reset_code_delivery", t["email"], force_open_id=fid, email_status=status,
                  code_delivery=delivery)
        con = self._tx()
        try:
            con.execute("UPDATE force_open SET email_status=?, code_delivery=? WHERE id=?", (status, delivery, fid))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"code": code if shown else None, "email_status": status, "code_delivery": delivery}

    def set_password_with_reset(self, code: str, new_password: str, redeemer: dict | None = None,
                                ip: str | None = None, ua: str | None = None) -> dict:
        """The USER redeems a reset code and chooses their password. The redeemed code is the proof that opens the
        notice (D1): the session returned is scope 'notice' while a notice is pending, so the next step is the
        acknowledgement. Refused when the browser holds an administrator's session (D1: the admin never redeems a
        user's code), when the code is used, wrong, expired or replaced, or when the account is disabled."""
        password_rule(new_password)
        pw_hash = hash_password(new_password)
        if redeemer and redeemer.get("kind") == "admin":
            self._log(redeemer.get("account_id"), "password.reset_refused", "", why="redeemed from an admin session",
                      ip=ip, ua=(ua or "")[:200])
            raise BackupError("an administrator cannot redeem a user's reset code: the user must do it themselves "
                              "(log out of the administrator account first if this is your own user account)")
        con = self._tx()
        try:
            r = con.execute("SELECT * FROM reset WHERE code_hash=? AND used_at IS NULL", (_h(code.strip()),)).fetchone()
            if not r or not r["expires_at"] or r["expires_at"] <= _iso(_now()):
                raise BackupError("this reset code is used, expired, replaced by a newer one, or wrong")
            a = con.execute("SELECT * FROM account WHERE id=?", (r["account_id"],)).fetchone()
            if not a or a["status"] != "active":
                raise BackupError("this account is disabled; ask your administrator")
            now = _iso(_now())
            con.execute("UPDATE reset SET used_at=? WHERE id=?", (now, r["id"]))
            self._end_codes(con, a["id"])
            # R1: a redeemed code ALWAYS leads to the notice. If none is pending (the user already finished), the
            # redemption is itself a reset the user must see: a new notice row, acknowledged only through it.
            if not a["must_ack_force_open"]:
                con.execute("INSERT INTO force_open(admin_id, user_id, reason, started_at, ends_at, kind) "
                            "VALUES (?,?,?,?,?, 'reset')",
                            (r["created_by"], a["id"], f"a reset code issued on {r['created_at']} UTC was redeemed "
                             f"({r['reason'] or RESET_REASON})", now, now))
            con.execute("UPDATE account SET pw_hash=?, old_pw_hash=NULL, sealed_pw=NULL, must_set_password=0, "
                        "must_ack_force_open=1 WHERE id=?", (pw_hash, r["account_id"]))
            con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL", (now, a["id"]))
            pending = True
            token = secrets.token_urlsafe(32)
            con.execute("INSERT INTO session(account_id, token_hash, created_at, scope, proof, ip, ua) "
                        "VALUES (?,?,?,?, 'reset_code', ?,?)",
                        (a["id"], _h(token), now, "notice", ip, (ua or "")[:200]))
            self._audit(con, a["id"], "password.reset", a["email"], proof="reset_code", notice_pending=pending, ip=ip,
                        ua=(ua or "")[:200], redeemer_session=(redeemer or {}).get("account_id"))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"token": token, "account_id": a["id"], "must_ack": pending}

    def notice(self, account_id: int) -> dict:
        """The notice for this user (read only): every unacknowledged force-open and admin reset (or the latest one
        once acknowledged), admin, reason, when, and whether the user still has to act."""
        con = self._con()
        try:
            a = con.execute("SELECT must_ack_force_open, must_set_password FROM account WHERE id=?",
                            (account_id,)).fetchone()
            rows = con.execute("SELECT f.*, a.email AS admin_email FROM force_open f JOIN account a ON a.id=f.admin_id "
                               "WHERE f.user_id=? ORDER BY f.id DESC", (account_id,)).fetchall()
        finally:
            con.close()
        unacked = bool(a and a["must_ack_force_open"])
        show = [r for r in rows if r["acked_at"] is None] if unacked else rows[:1]
        show = show or rows[:1]
        fo = show[0] if show else None

        def line(r) -> str:
            return (NOTICE_RESET if r["kind"] == "reset" else NOTICE).format(admin=r["admin_email"],
                                                                            when=r["started_at"] + " UTC",
                                                                            reason=r["reason"])
        admin, reason, at = (fo["admin_email"], fo["reason"], fo["started_at"]) if fo else ("", "", "")
        return {"text": "\n".join(line(r) for r in reversed(show)), "warning": WARNING,
                "admin": admin, "reason": reason, "at": at, "unacked": unacked,
                "must_set_password": bool(a and a["must_set_password"])}

    def reset_history(self, account_id: int) -> list[dict]:
        """Every password reset and force-open ever done to this account (shown on the user's page, permanently)."""
        con = self._con()
        try:
            return [dict(r) for r in con.execute(
                "SELECT f.kind, f.started_at, f.reason, f.acked_at, f.ack_proof, f.ack_ip, f.ack_ua, f.code_delivery, "
                "f.email_status, a.email AS admin_email FROM force_open f "
                "JOIN account a ON a.id=f.admin_id WHERE f.user_id=? ORDER BY f.id", (account_id,))]
        finally:
            con.close()

    def _proof(self, con, token: str | None) -> sqlite3.Row:
        """FN-1: re-read the session INSIDE the transaction; only a 'notice' scope (the user's old password, or a reset
        code the user redeemed) may acknowledge or set the password."""
        s = con.execute("SELECT s.id, s.account_id, s.scope, s.proof, a.kind, a.status, a.email FROM session s "
                        "JOIN account a ON a.id=s.account_id WHERE s.token_hash=? AND s.revoked_at IS NULL",
                        (_h(str(token or "")),)).fetchone()
        if not s or s["status"] != "active":
            raise BackupError("please log in")
        if s["scope"] != "notice":
            raise BackupError("only you can do this: log in with YOUR OWN old password (the password your "
                              "administrator was given only shows the notice), or redeem a reset code yourself")
        return s

    def ack_warning(self, token: str, ip: str | None = None, ua: str | None = None) -> dict:
        """The user's own acknowledgement (audited with scope, proof, address and browser). Needs a 'notice' session
        (FN-1). After acknowledging, the result carries the generated password (unsealed) so the user is told it;
        when it cannot be unsealed (FN-2) the result says why and the user still goes on to set their own."""
        con = self._tx()
        try:
            s = self._proof(con, token)
            aid = s["account_id"]
            a = con.execute("SELECT must_ack_force_open, must_set_password FROM account WHERE id=?", (aid,)).fetchone()
            if a and not a["must_set_password"]:
                # the user already chose their own password (a reset code they redeemed): this session is complete
                con.execute("UPDATE session SET scope='full' WHERE id=?", (s["id"],))
            if a and a["must_ack_force_open"]:
                ids = [r["id"] for r in con.execute("SELECT id FROM force_open WHERE user_id=? AND acked_at IS NULL",
                                                    (aid,))]
                con.execute("UPDATE account SET must_ack_force_open=0 WHERE id=?", (aid,))
                con.execute("UPDATE force_open SET acked_at=?, ack_proof=?, ack_ip=?, ack_ua=? WHERE user_id=? "
                            "AND acked_at IS NULL", (_iso(_now()), s["proof"], ip, (ua or "")[:200], aid))
                self._audit(con, aid, "force_open.ack", str(aid), force_open_ids=ids, scope=s["scope"],
                            proof=s["proof"], ip=ip, ua=(ua or "")[:200])
            self._end_codes(con, aid)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        w = self.notice(aid)
        w["unacked"] = False
        try:
            w["new_password"] = self.told_password(aid)
        except BackupError as e:
            w["new_password"], w["told_error"] = None, str(e)
            self._log(aid, "force_open.told_password_failed", str(aid), error=str(e))
        return w

    def told_password(self, account_id: int) -> str | None:
        """The generated password, for the user, only after they acknowledged and until they set their own.
        Raises BackupError when the sealed copy cannot be opened (key file replaced or damaged)."""
        a = self._one("SELECT must_ack_force_open, must_set_password, sealed_pw FROM account WHERE id=?", (account_id,))
        if not a or a["must_ack_force_open"] or not a["must_set_password"] or not a["sealed_pw"]:
            return None
        return unseal(self.key_path(), a["sealed_pw"])

    def set_own_password(self, token: str, new_password: str, ip: str | None = None, ua: str | None = None) -> dict:
        """After the acknowledgement: the user chooses a password the admin does not know. Needs a 'notice' session
        (FN-1). Every session is revoked, the old password hash and the sealed copy are wiped, and a fresh full
        session is returned."""
        password_rule(new_password)
        pw_hash = hash_password(new_password)
        con = self._tx()
        try:
            s = self._proof(con, token)
            account_id = s["account_id"]
            a = con.execute("SELECT * FROM account WHERE id=?", (account_id,)).fetchone()
            if a["must_ack_force_open"]:
                raise BackupError("acknowledge the notice first")
            if not a["must_set_password"]:
                raise BackupError("nothing to do: change your password from your security page")
            if check_password(new_password, a["pw_hash"]):
                raise BackupError("choose a password of your own: your administrator knows this one")
            now = _iso(_now())
            con.execute("UPDATE account SET pw_hash=?, old_pw_hash=NULL, sealed_pw=NULL, must_set_password=0 WHERE id=?",
                        (pw_hash, account_id))
            self._end_codes(con, account_id)
            n = con.execute("UPDATE session SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
                            (now, account_id)).rowcount
            token2 = secrets.token_urlsafe(32)
            con.execute("INSERT INTO session(account_id, token_hash, created_at, scope, proof, ip, ua) "
                        "VALUES (?,?,?, 'full', 'password', ?,?)", (account_id, _h(token2), now, ip, (ua or "")[:200]))
            self._audit(con, account_id, "password.set_after_force_open", a["email"], sessions_revoked=n,
                        scope=s["scope"], proof=s["proof"], ip=ip, ua=(ua or "")[:200])
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return {"token": token2, "account_id": account_id}

    def force_open_active(self, admin_id: int, user_id: int) -> bool:
        return bool(self._one("SELECT 1 AS x FROM force_open WHERE admin_id=? AND user_id=? AND ends_at>? "
                              "AND kind='force_open'", (admin_id, user_id, _iso(_now()))))

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

    def reissue_device_token(self, actor: int, name: str) -> str:
        """A new check-in token for a computer (the old one stops at once). Used after `disable` cut it."""
        token = secrets.token_urlsafe(24)
        con = self._tx()
        try:
            adm = self._admin_of(con, actor)
            n = con.execute("UPDATE device SET token_hash=? WHERE name=? AND company_id=?",
                            (_h(token), name, adm["company_id"])).rowcount
            if not n:
                raise BackupError(f"no device {name}")
            self._audit(con, actor, "device.token_reissued", name)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return token

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
        """A shared folder: nobody owns it; the PC's administrator does (owner ruling 20261114)."""
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
        """Who owns PATH on DEVICE: the longest matching rule, else the device's primary user, else nobody.
        A path not in normal form (F8: '..', '.', '//') has no owner."""
        if not clean_path(path):
            return None
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
        """Not yet called by any page or command in 3.3.0 (F7: the README says so). Refuses any path not in normal
        form before looking at owners (F8)."""
        if not clean_path(path):
            return False
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

    # ---------- notices on the hub page (a pullback that could not place files, ...) ----------
    def add_notice(self, device: str, kind: str, text: str) -> int:
        """Called by the device API (device token already checked). Stays on the page until someone dismisses it."""
        con = self._tx()
        try:
            d = con.execute("SELECT id FROM device WHERE name=?", (device,)).fetchone()
            if not d:
                raise BackupError(f"no device {device}")
            nid = con.execute("INSERT INTO notice(device_id, kind, text, created_at) VALUES (?,?,?,?)",
                              (d["id"], kind[:40], text[:8000], _iso(_now()))).lastrowid
            self._audit(con, None, "notice.add", device, kind=kind[:40], notice_id=nid)
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
        return nid

    def open_notices(self, account_id: int) -> list[dict]:
        """Undismissed notices this account may see: an admin sees every computer's; a user, their computers'
        (primary user or PC administrator)."""
        acc = self.account(account_id)
        if not acc:
            return []
        con = self._con()
        try:
            q = ("SELECT n.id, n.kind, n.text, n.created_at, d.name AS device FROM notice n JOIN device d ON d.id=n.device_id "
                 "WHERE n.dismissed_at IS NULL")
            if acc["kind"] == "admin":
                rows = con.execute(q + " AND d.company_id=? ORDER BY n.id", (acc["company_id"],))
            else:
                rows = con.execute(q + " AND (d.primary_user_id=? OR d.pc_admin_id=?) ORDER BY n.id",
                                   (account_id, account_id))
            return [dict(r) for r in rows]
        finally:
            con.close()

    def dismiss_notice(self, actor: int, notice_id: int) -> None:
        if not any(n["id"] == notice_id for n in self.open_notices(actor)):
            raise BackupError("no such notice for you (already dismissed?)")
        con = self._tx()
        try:
            con.execute("UPDATE notice SET dismissed_at=?, dismissed_by=? WHERE id=? AND dismissed_at IS NULL",
                        (_iso(_now()), actor, notice_id))
            self._audit(con, actor, "notice.dismiss", str(notice_id))
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()

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


def _default_htpasswd() -> Path:
    return config.config_dir() / "hub.htpasswd"                    # where `hub install` points the rest-server


def _reload_rest_server() -> str:
    from .util import run
    r = run(["systemctl", "--user", "kill", "-s", "HUP", "restic-hub.service"], timeout=20)
    return "rest-server told to re-read htpasswd" if r.returncode == 0 else \
        f"FAILED to signal restic-hub.service (rc={r.returncode}: {r.stderr.strip()[-200:]}); restart it by hand"


def cut_htpasswd(path: Path, names: list[str]) -> tuple[str, list[str]]:
    """Remove the htpasswd line of each computer in NAMES (F6). The removed lines are kept aside in
    PATH.removed (mode 600) so an admin can put a computer back; the file is replaced atomically and stays 600.
    Returns (status for the admin and the audit, names removed). Never raises for a missing file: says so."""
    if not path.is_file():
        return (f"no htpasswd file at {path} on this hub: remove the line(s) for {', '.join(names)} from the "
                "rest-server's htpasswd by hand"), []
    lines = path.read_text().splitlines(keepends=True)
    keep, gone = [], []
    for ln in lines:
        (gone if ln.split(":", 1)[0].strip() in names else keep).append(ln)
    if not gone:
        return f"no line for {', '.join(names)} in {path} (already removed?)", []
    side = path.with_name(path.name + ".removed")
    fd = os.open(side, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(f"# removed {_iso(_now())} (user disabled)\n" + "".join(x if x.endswith("\n") else x + "\n" for x in gone))
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("".join(keep))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic write of HavnVard's own hub htpasswd (allowlisted in test_crosshost_verify)
    removed = sorted({ln.split(":", 1)[0].strip() for ln in gone})
    return f"removed from {path}: {', '.join(removed)} (kept aside in {side})", removed


def revoke_device_keys(restic: str, repo: str, store_key: str, accts: Accounts, device: str,
                       hub_pass_file: Path | None = None) -> dict:
    """F6: remove every restic key of DEVICE's repository except the company store key(s), so the computer's own
    password no longer opens it. KEY REMOVAL ONLY: no snapshot, pack or file is touched.
    Opens the repository with the store key (checked against the fingerprint first). When the hub keeps its own copy
    of the device's password (HUB_PASS_FILE, used by catalog/drills), a NEW hub key is added first and that file is
    replaced by it (the old file is kept as .revoked), so the hub keeps working. Returns what was done."""
    from .util import run
    import tempfile
    if not accts.store_key_matches(store_key):
        raise BackupError("that is not this company's store key; nothing was changed")
    out: dict = {"removed": [], "kept": [], "hub_key": "no hub copy of this computer's password"}
    with tempfile.TemporaryDirectory(prefix="havnvard-revoke-") as td:
        kf = Path(td) / "store.key"
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(store_key.strip() + "\n")
        env = {"RESTIC_REPOSITORY": repo, "RESTIC_PASSWORD_FILE": str(kf)}
        r = run([restic, "key", "list", "--json"], env=env)
        if r.returncode != 0:
            raise BackupError(f"the store key does not open {device}'s repository (adopt it first): "
                              f"{r.stderr.strip()[-300:]}")
        keys = json.loads(r.stdout or "[]")
        if not any(k.get("current") for k in keys):
            raise BackupError("restic did not say which key is the store key; nothing was changed")
        gone = [k for k in keys if not k.get("current") and k.get("hostName") != "havnvard-store"]
        out["kept"] = [k["id"][:8] for k in keys if k not in gone]
        if hub_pass_file is not None and hub_pass_file.is_file():
            # the hub keeps working: add a NEW hub key first, keep the old password as .revoked (a copy, O_EXCL),
            # then put the new password into the hub's file in place; only then remove the old keys. A crash at any
            # point leaves the hub's file holding a key that still opens the repository.
            old_pw = hub_pass_file.read_text()
            new_pw = secrets.token_urlsafe(32) + "\n"
            nf = Path(td) / "hub.new"
            fd = os.open(nf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(new_pw)
            r = run([restic, "key", "add", "--new-password-file", str(nf), "--host", "havnvard-hub", "--user", "hub"],
                    env=env)
            if r.returncode != 0:
                raise BackupError(f"restic key add (new hub key) failed rc={r.returncode}: {r.stderr.strip()[-300:]}; "
                                  "nothing was removed")
            listed = json.loads(run([restic, "key", "list", "--json"], env=env).stdout or "[]")
            out["kept"] += [i[:8] for i in {k["id"] for k in listed} - {k["id"] for k in keys}]
            side = hub_pass_file.with_name(f"{hub_pass_file.name}.revoked-{_now().strftime('%Y%m%d%H%M%S')}")
            fd = os.open(side, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(old_pw)
            fd = os.open(hub_pass_file, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(fd, "w") as f:
                f.write(new_pw)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(hub_pass_file, 0o600)
            out["hub_key"] = f"new hub key in {hub_pass_file} (the old one, now dead, kept as {side.name})"
        for k in gone:
            r = run([restic, "key", "remove", k["id"]], env=env)
            if r.returncode != 0:
                raise BackupError(f"restic key remove {k['id'][:8]} failed rc={r.returncode}: {r.stderr.strip()[-300:]}"
                                  f"; removed so far: {out['removed']}")
            out["removed"].append(f"{k['id'][:8]} ({k.get('userName')}@{k.get('hostName')})")
    accts._log(None, "device.keys_revoked", device, removed=out["removed"], kept=out["kept"], hub_key=out["hub_key"])
    return out


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
