"""HavnVard 3.3.5 regression tests, one per Plane item (INFRA-582, 592, 591, 593, 623, 589, 600, 574). Throwaway SQLite,
local restic repos, in-process WSGI; no network, no database server, never the live hub."""
from __future__ import annotations

import ast
import datetime as dt
import io
import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import accounts, archive, hubweb  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import needs_restic, restic  # noqa: E402
from test_backup_archive import dev  # noqa: E402,F401  (fixture)
from test_backup_hubweb import PW, Client, app  # noqa: E402,F401  (fixtures)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _admin(w, code, email="boss@example.com"):
    c = Client(w)
    st, _, _ = c.req("POST", "/register", {"email": email, "password": PW, "password2": PW, "setup_code": code,
                                           "company": "Acme"})
    assert st == "200 OK"
    return c


# ---- INFRA-582: --vanished sees a file made and deleted between the day's snapshots (already fixed at 0e78420) ----
@needs_restic
def test_582_vanished_three_snapshots_one_day(dev):  # noqa: F811
    tmp, repo, pw, owner, photos = dev
    restic(repo, pw, "backup", "--time", "2026-11-10 12:00:00", str(photos))
    (photos / "only-in-middle.txt").write_text("created and deleted on the same day\n")
    restic(repo, pw, "backup", "--time", "2026-11-11 08:00:00", str(photos))                          # has it
    restic(repo, pw, "backup", "--time", "2026-11-11 12:00:00", "--exclude", "only-in-middle.txt", str(photos))  # gone
    restic(repo, pw, "backup", "--time", "2026-11-11 20:00:00", "--exclude", "only-in-middle.txt", str(photos))
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    snaps = archive.catalog.data_snapshots(archive.catalog.snapshots("restic", env))
    jobs = archive.vanished_jobs("restic", env, snaps, dt.date(2026, 11, 11))
    assert sorted(p for _, ps in jobs for p in ps) == [str(photos / "only-in-middle.txt")]


# ---- INFRA-592: CSRF on /login /register /reset, constant-time compare ----
def test_592_login_register_reset_need_a_pre_session_token(app):  # noqa: F811
    w, code = app
    _admin(w, code)
    c = Client(w)
    st, h, page = c.req("GET", "/login")
    assert "hv_csrf=" in h["Set-Cookie"] and "name='csrf'" in page
    body = {"email": "boss@example.com", "password": PW, "kind": "admin"}
    assert c.req("POST", "/login", body, raw=True)[0] == "403 Forbidden"                 # no token at all
    assert c.req("POST", "/login", {**body, "csrf": "0" * 32}, raw=True)[0] == "403 Forbidden"   # wrong token
    assert Client(w).req("POST", "/login", {**body, "csrf": hubweb.csrf_for("x")}, raw=True)[0] == "403 Forbidden"  # no cookie
    for path in ("/register", "/reset"):
        assert c.req("POST", path, {"email": "x@example.com"}, raw=True)[0] == "403 Forbidden"
    assert c.req("POST", "/login", body)[0] == "303 See Other"                            # the browser's own token works


def test_592_csrf_compare_is_constant_time(monkeypatch, app):  # noqa: F811
    seen = []
    real = hubweb.hmac.compare_digest
    monkeypatch.setattr(hubweb.hmac, "compare_digest", lambda a, b: seen.append(1) or real(a, b))
    w, code = app
    adm = _admin(w, code)
    adm.post("/admin/users", {"action": "invite", "email": "al@example.com", "kind": "user"})
    assert seen, "a session CSRF check must go through hmac.compare_digest"
    assert hubweb.csrf_ok(None, "tok") is False and hubweb.csrf_ok("x", None) is False


# ---- INFRA-591: server-side session expiry ----
class _Clock:
    def __init__(self):
        self.t = dt.datetime.now(dt.timezone.utc)

    def __call__(self):
        return self.t

    def add(self, **kw):
        self.t += dt.timedelta(**kw)


def test_591_admin_idle_and_absolute_expiry_user_stays(app, monkeypatch):  # noqa: F811
    clock = _Clock()
    monkeypatch.setattr(accounts, "_now", clock)
    w, code = app
    adm = _admin(w, code)
    _, _, page = adm.post("/admin/users", {"action": "invite", "email": "al@example.com", "kind": "user"})
    inv = re.search(r"/register\?invite=([\w-]+)", page).group(1)
    usr = Client(w)
    usr.req("POST", "/register", {"invite": inv, "email": "al@example.com", "password": PW, "password2": PW})
    clock.add(minutes=20)
    assert adm.req("GET", "/admin/users")[0] == "200 OK"                    # active within 30 min: kept alive
    clock.add(minutes=20)
    assert adm.req("GET", "/admin/users")[0] == "200 OK"                    # 40 min since login, 20 since last use
    clock.add(minutes=31)
    st, h, _ = adm.req("GET", "/admin/users")                               # idle > 30 min: gone, server-side
    assert st.startswith("303") and h["Location"] == "/login"
    assert any(r["action"] == "session.expired" and '"idle"' in r["detail"] for r in w.a.audit_rows())
    assert usr.req("GET", "/me")[0] == "200 OK"                             # a user has no idle limit
    adm2 = Client(w)
    adm2.req("POST", "/login", {"email": "boss@example.com", "password": PW, "kind": "admin"})
    for _ in range(40):                                                     # busy admin, active every 25 min
        clock.add(minutes=25)
        st = adm2.req("GET", "/admin/users")[0]
        if not st.startswith("200"):
            break
    assert st.startswith("303")
    assert any('"absolute"' in r["detail"] for r in w.a.audit_rows() if r["action"] == "session.expired")


# ---- INFRA-593: bad input is a 400, never an unhandled exception ----
def test_593_bad_input_gives_400_not_a_traceback(app):  # noqa: F811
    w, code = app
    adm = _admin(w, code)
    for path, data in (("/admin/users", {"action": "disable", "target": "abc"}),
                       ("/admin/users", {"action": "release"}),
                       ("/admin/computers", {"action": "add"}),
                       ("/admin/computers", {"action": "add", "name": "pc1", "primary_user": "x"}),
                       ("/admin/schedules", {"device": "pc1", "mode": "interval", "every_min": "soon"}),
                       ("/notice/dismiss", {"notice": "zz"})):
        st, _, page = adm.post(path, data)
        assert st == "400 Bad Request" and "Traceback" not in page, (path, data, st)
    assert w.errors["bad_request"] >= 3
    st, _, _ = w.handle({"REQUEST_METHOD": "POST", "PATH_INFO": "/login", "CONTENT_LENGTH": "nope",
                         "wsgi.input": io.BytesIO(b""), "CONTENT_TYPE": "application/x-www-form-urlencoded"})
    assert st == "400 Bad Request"
    body = b"[1, 2]"
    st, _, page = w.handle({"REQUEST_METHOD": "POST", "PATH_INFO": "/admin/users", "CONTENT_LENGTH": str(len(body)),
                            "wsgi.input": io.BytesIO(body), "CONTENT_TYPE": "application/json"})
    assert st == "400 Bad Request" and "object" in page


def test_593_unexpected_error_is_a_plain_500_with_an_id_and_is_counted(app, monkeypatch):  # noqa: F811
    w, code = app
    adm = _admin(w, code)
    monkeypatch.setattr(w.a, "devices", lambda: 1 / 0)
    st, _, page = adm.req("GET", "/admin/computers")
    assert st == "500 Internal Server Error" and "Error id" in page and "ZeroDivision" not in page
    assert w.errors["internal"] == 1


# ---- INFRA-623: register + the auto-login carry address and browser ----
def test_623_register_audit_and_auto_login_record_ip_and_ua(app):  # noqa: F811
    w, code = app
    c = Client(w)
    c.req("POST", "/register", {"email": "boss@example.com", "password": PW, "password2": PW, "setup_code": code,
                                "company": "Acme"}, headers={"REMOTE_ADDR": "100.64.0.7", "HTTP_USER_AGENT": "TestBrowser/1"})
    rows = {r["action"]: json.loads(r["detail"]) for r in w.a.audit_rows() if r["action"] in ("account.register", "login.ok")}
    for action in ("account.register", "login.ok"):
        assert rows[action]["ip"] == "100.64.0.7" and rows[action]["ua"] == "TestBrowser/1", action


# ---- INFRA-589: no f-string without a placeholder in hubweb (ruff F541) ----
def test_589_no_placeholderless_fstrings_in_hubweb():
    for fn in ("backup/hubweb.py", "backup/accounts.py"):
        tree = ast.parse(open(os.path.join(REPO, fn)).read())
        spec = {id(n.format_spec) for n in ast.walk(tree) if isinstance(n, ast.FormattedValue) and n.format_spec}
        bad = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.JoinedStr) and id(n) not in spec
               and not any(isinstance(v, ast.FormattedValue) for v in n.values)]
        assert not bad, f"{fn}: f-string without a placeholder at line(s) {bad}"


# ---- INFRA-600: one device-name validator ----
def test_600_add_device_and_api_share_one_name_rule(app):  # noqa: F811
    w, code = app
    adm = _admin(w, code)
    aid = w.a.list_accounts(kind="admin")[0]["id"]
    for bad in ("Al's laptop", "a b", "", "x" * 64, "-pc", "../etc", "naïve"):
        with pytest.raises(BackupError, match="computer name"):
            w.a.add_device(aid, bad)
        assert not accounts.valid_device_name(bad)
    for good in ("pc-1", "Al.laptop_2", "x" * 63):
        tok = w.a.add_device(aid, good)
        # the device can authenticate at the API route built from the SAME rule
        st, _, _ = Client(w).req("POST", f"/api/v1/devices/{good}/checkin", {}, {"HTTP_AUTHORIZATION": f"Bearer {tok}"},
                                 as_json=True)
        assert st == "200 OK", good
    st, _, page = adm.post("/admin/computers", {"action": "add", "name": "Al's laptop"})
    assert st == "400 Bad Request" and "computer name" in page


# ---- INFRA-574: report.py run as a script must not die with NameError ----
def test_574_report_main_has_no_nameerror():
    env = {**os.environ, "POSTGRES_URL": "postgresql://nobody@127.0.0.1:1/none", "HAVNVARD_SITE":
           os.path.join(REPO, "tests", "site.test.toml")}
    r = subprocess.run([sys.executable, os.path.join(REPO, "report.py")], env=env, capture_output=True, text=True,
                       timeout=60, cwd=REPO)
    assert "NameError" not in r.stderr, r.stderr[-400:]


def test_review_session_limit_rejects_negative_or_nan(monkeypatch):
    """Opus review: a negative or NaN limit would silently expire (or never expire) every session; it is a config error."""
    for bad in ("-1", "nan", "inf", "x"):
        monkeypatch.setenv("HAVNVARD_SESSION_ADMIN_ABS_H", bad)
        with pytest.raises(BackupError):
            accounts._limit_s("HAVNVARD_SESSION_ADMIN_ABS_H", 12.0, 3600)
    monkeypatch.setenv("HAVNVARD_SESSION_ADMIN_ABS_H", "0")
    assert accounts._limit_s("HAVNVARD_SESSION_ADMIN_ABS_H", 12.0, 3600) == 0


def test_review_device_api_null_number_is_a_json_400(app):  # noqa: F811
    """Opus review: a null run_id/exit_code (TypeError in int()) must stay a JSON 400 on the device API, not an HTML page."""
    w, code = app
    _admin(w, code)
    aid = w.a.list_accounts(kind="admin")[0]["id"]
    tok = w.a.add_device(aid, "pc-null")
    st, hdrs, body = Client(w).req("POST", "/api/v1/devices/pc-null/run", {"run_id": None, "exit_code": None},
                                   {"HTTP_AUTHORIZATION": f"Bearer {tok}"}, as_json=True)
    assert st == "400 Bad Request" and hdrs.get("Content-Type") == "application/json" and "error" in json.loads(body)
