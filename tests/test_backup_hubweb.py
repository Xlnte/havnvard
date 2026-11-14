"""HavnVard 3.3.0 hub pages + device API, driven through the WSGI app in-process. Throwaway SQLite, no network."""
from __future__ import annotations

import io
import json
import os
import re
import sys
from urllib.parse import urlencode

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import accounts, hubweb  # noqa: E402

PW = "correct horse battery"


class Client:
    def __init__(self, app):
        self.app, self.cookie = app, ""

    def req(self, method, path, data=None, headers=None, as_json=False):
        q = ""
        if "?" in path:
            path, q = path.split("?", 1)
        body = (json.dumps(data) if as_json else urlencode(data or {})).encode()
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": q, "HTTP_COOKIE": self.cookie,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body),
               "CONTENT_TYPE": "application/json" if as_json else "application/x-www-form-urlencoded", **(headers or {})}
        status, hdrs, text = self.app.handle(env)
        for k, v in hdrs:
            if k == "Set-Cookie":
                self.cookie = v.split(";")[0]
        return status, dict(hdrs), text

    def csrf(self):
        tok = self.cookie.split("=", 1)[1]
        return hubweb.csrf_for(tok)

    def post(self, path, data):
        return self.req("POST", path, {**data, "csrf": self.csrf()})


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))       # never the real backup.toml ([mail])
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(accounts, "SCRYPT_N", 2 ** 10)
    a = accounts.Accounts(tmp_path / "accounts.db")
    return hubweb.App(a), a.new_setup_code()


def test_first_visitor_registers_as_admin_with_setup_code_then_invite_only(app):
    w, code = app
    c = Client(w)
    st, _, page = c.req("GET", "/register")
    assert "first account becomes the <b>administrator</b>" in page
    st, _, page = c.req("POST", "/register", {"email": "boss@example.com", "password": PW, "password2": PW,
                                              "setup_code": code, "company": "Acme"})
    assert st == "200 OK" and "store key" in page and "shown <b>once</b>" in page
    st, _, page = c.req("GET", "/admin/users")
    assert st == "200 OK" and "boss@example.com" in page
    # a second visitor now needs an invite
    st, _, page = Client(w).req("GET", "/register")
    assert "Invite code" in page and "Setup code" not in page
    # posting without a valid session/csrf does nothing
    st, _, _ = Client(w).req("POST", "/admin/users", {"action": "invite", "email": "x@example.com"})
    assert st == "403 Forbidden"


def test_invite_disable_force_open_ack_flow_and_user_cannot_see_admin_pages(app):
    w, code = app
    adm = Client(w)
    adm.req("POST", "/register", {"email": "boss@example.com", "password": PW, "password2": PW, "setup_code": code,
                                  "company": "Acme"})
    _, _, page = adm.post("/admin/users", {"action": "invite", "email": "al@example.com", "kind": "user"})
    inv = re.search(r"/register\?invite=([\w-]+)", page).group(1)
    u = Client(w)
    st, _, _ = u.req("POST", "/register", {"invite": inv, "email": "al@example.com", "password": PW, "password2": PW})
    assert st == "200 OK"
    st, _, page = u.req("GET", "/admin/users")
    assert st == "400 Bad Request" and "administrators only" in page
    uid = w.a.login("al@example.com", PW)["account_id"]
    # force-open: a new password shown to the admin once, email status shown; the user is logged out
    _, _, page = adm.post("/admin/users", {"action": "force_open", "target": uid, "reason": "legal hold",
                                           "typed_email": "al@example.com"})
    new = re.search(r"not kept[^:]*: <code[^>]*>([A-Z2-7-]+)</code>", page).group(1)
    assert "Email to the user: <b>not configured</b>" in page and "tell them yourself" in page
    st, h, _ = u.req("GET", "/me")
    assert st.startswith("303") and h["Location"] == "/login"
    # old password -> the notice; nothing else is reachable
    st, h, _ = u.req("POST", "/login", {"email": "al@example.com", "password": PW})
    assert h["Location"] == "/ack"
    for path in ("/me", "/admin/users"):
        st, h, _ = u.req("GET", path)
        assert h.get("Location") == "/ack", path
    _, _, page = u.req("GET", "/ack")
    assert "Your administrator boss@example.com reset your password on " in page
    assert "accessed all your files. Reason: legal hold" in page and new not in page   # not before the click
    st, _, page = u.post("/ack", {"step": "password", "password": "mine mine mine!", "password2": "mine mine mine!"})
    assert st == "400 Bad Request" and "acknowledge the notice first" in page
    # the admin cannot clear or hide it: no such action, and the user list shows it
    adm.post("/admin/users", {"action": "ack", "target": uid})
    _, _, page = adm.req("GET", "/admin/users")
    assert "notice not yet read" in page
    u.post("/ack", {"step": "ack", "understand": "yes"})
    _, _, page = u.req("GET", "/ack")
    assert new in page and "choose your own" in page                              # told the generated password
    assert u.req("GET", "/me")[2] == "" and u.req("GET", "/me")[1]["Location"] == "/ack"
    st, h, _ = u.post("/ack", {"step": "password", "password": "mine mine mine!", "password2": "mine mine mine!"})
    assert h["Location"] == "/me" and u.req("GET", "/me")[0] == "200 OK"
    # the generated one and the old one are both dead now; the new password from the admin no longer works
    with pytest.raises(Exception, match="wrong email or password"):
        w.a.login("al@example.com", new)
    # a login with the NEW (generated) password after a second force-open also lands on the notice
    _, _, page = adm.post("/admin/users", {"action": "force_open", "target": uid, "reason": "audit 2",
                                           "typed_email": "al@example.com"})
    new2 = re.search(r"not kept[^:]*: <code[^>]*>([A-Z2-7-]+)</code>", page).group(1)
    g = Client(w)                                       # FN-1: the admin-known password only READS the notice
    st, h, _ = g.req("POST", "/login", {"email": "al@example.com", "password": new2})
    assert h["Location"] == "/ack" and "Reason: audit 2" in g.req("GET", "/ack")[2]
    assert "your own old password" in g.req("GET", "/ack")[2] and "Acknowledge" not in g.req("GET", "/ack")[2]
    st, _, page = g.post("/ack", {"step": "ack", "understand": "yes"})
    assert st == "400 Bad Request" and "only you can do this" in page
    st, _, page = g.post("/ack", {"step": "password", "password": "admin chose this!", "password2": "admin chose this!"})
    assert st == "400 Bad Request" and w.a.account(uid)["must_ack_force_open"] == 1
    u2 = Client(w)                                      # the user, with their own (old) password
    st, h, _ = u2.req("POST", "/login", {"email": "al@example.com", "password": "mine mine mine!"})
    assert h["Location"] == "/ack" and "Reason: audit 2" in u2.req("GET", "/ack")[2]
    u2.post("/ack", {"step": "ack", "understand": "yes"})
    u2.post("/ack", {"step": "password", "password": "mine again mine!", "password2": "mine again mine!"})
    assert u2.req("GET", "/me")[0] == "200 OK"
    u.cookie = ""
    u.req("POST", "/login", {"email": "al@example.com", "password": "mine again mine!"})
    # disable: the user's live session stops at once
    adm.post("/admin/users", {"action": "disable", "target": uid, "reason": "quit"})
    st, h, _ = u.req("GET", "/me")
    assert st.startswith("303") and h["Location"] == "/login"
    _, _, page = adm.req("GET", "/admin/audit")
    assert "Chain intact" in page and "force_open.start" in page and "account.disable" in page
    assert "force_open.ack" in page and "force_open.email" in page and "password.set_after_force_open" in page


def test_pullback_notice_from_device_api_stays_until_dismissed(app):
    w, code = app
    adm = Client(w)
    adm.req("POST", "/register", {"email": "boss@example.com", "password": PW, "password2": PW, "setup_code": code,
                                  "company": "Acme"})
    _, _, page = adm.post("/admin/computers", {"action": "add", "name": "air2017"})
    tok = re.search(r"\(shown once\): <code>([\w-]+)</code>", page).group(1)
    dev = Client(w)
    st, _, _ = dev.req("POST", "/api/v1/devices/air2017/notice", {"kind": "pullback_blocked", "text": "x"},
                       {"HTTP_AUTHORIZATION": "Bearer wrong"}, as_json=True)
    assert st == "401 Unauthorized"
    st, _, body = dev.req("POST", "/api/v1/devices/air2017/notice",
                          {"kind": "pullback_blocked", "text": "HavnVard could not put back 2 item(s) into /srv/ro <b>"},
                          {"HTTP_AUTHORIZATION": f"Bearer {tok}"}, as_json=True)
    nid = json.loads(body)["notice_id"]
    for _ in range(2):                                                    # stays across page loads
        page = adm.req("GET", "/me")[2]
        assert "could not put back 2 item(s) into /srv/ro &lt;b&gt;" in page and "Dismiss" in page
    assert "could not put back" in adm.req("GET", "/admin/computers")[2]
    adm.post("/notice/dismiss", {"notice": nid})
    assert "could not put back" not in adm.req("GET", "/me")[2]


def test_device_checkin_api_and_schedules_page(app):
    w, code = app
    adm = Client(w)
    adm.req("POST", "/register", {"email": "boss@example.com", "password": PW, "password2": PW, "setup_code": code,
                                  "company": "Acme"})
    _, _, page = adm.post("/admin/computers", {"action": "add", "name": "air2017"})
    tok = re.search(r"\(shown once\): <code>([\w-]+)</code>", page).group(1)
    adm.post("/admin/schedules", {"device": "air2017", "mode": "constant_loop", "min_gap_s": "0"})
    dev = Client(w)
    st, _, body = dev.req("POST", "/api/v1/devices/air2017/checkin", {"client_version": "3.3.0"},
                          {"HTTP_AUTHORIZATION": "Bearer wrong"}, as_json=True)
    assert st == "401 Unauthorized"
    auth = {"HTTP_AUTHORIZATION": f"Bearer {tok}"}
    st, _, body = dev.req("POST", "/api/v1/devices/air2017/checkin", {"client_version": "3.3.0"}, auth, as_json=True)
    assert st == "200 OK" and json.loads(body)["due"] is True
    rid = json.loads(dev.req("POST", "/api/v1/devices/air2017/run", {"action": "start"}, auth, as_json=True)[2])["run_id"]
    assert json.loads(dev.req("POST", "/api/v1/devices/air2017/checkin", {}, auth, as_json=True)[2])["due"] is False
    dev.req("POST", "/api/v1/devices/air2017/run", {"action": "end", "run_id": rid, "exit_code": 0, "snapshot_id": "ab"},
            auth, as_json=True)
    dev.req("POST", "/api/v1/devices/air2017/late", {"started_at": "2026-11-14T03:00:00+00:00",
                                                     "ended_at": "2026-11-14T03:01:00+00:00", "exit_code": 1,
                                                     "error": "hub unreachable"}, auth, as_json=True)
    _, _, page = adm.req("GET", "/admin/schedules")
    assert "air2017" in page and "constant_loop" in page
    assert [r["reported_via"] for r in w.s._runs("air2017")] == ["late", "checkin"]     # kept in time order
    assert "schedule.set" in adm.req("GET", "/admin/audit")[2]


def test_device_checkin_client_runs_when_due_and_reports_late_after_an_outage(app, tmp_path, monkeypatch):
    from backup import checkin, config
    w, code = app
    w.a.register("boss@example.com", PW, setup_code=code, company="Acme")
    adm_id = w.a.list_accounts(kind="admin")[0]["id"]
    tok = w.a.add_device(adm_id, "air2017")
    w.s.set(adm_id, "air2017", mode="interval", every_min=60)
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "st"))
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "checkin.token").write_text(tok + "\n")
    config.save({"checkin": {"url": "http://hub:8001", "token_file": str(tmp_path / "cfg" / "checkin.token")},
                 "device": {"name": "air2017"}})
    down = {"on": True}

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def opener(req, timeout):
        if down["on"]:
            raise OSError("timed out")
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": req.full_url.split("hub:8001", 1)[1], "QUERY_STRING": "",
               "CONTENT_LENGTH": str(len(req.data)), "wsgi.input": io.BytesIO(req.data), "CONTENT_TYPE": "application/json",
               "HTTP_AUTHORIZATION": req.get_header("Authorization")}
        st, _, body = w.handle(env)
        assert st == "200 OK", body
        return Resp(body.encode())

    ran = []
    assert checkin.checkin(run=True, opener=opener, runner=lambda: ran.append(1) or 0) == config.PROBLEM_EXIT
    assert not ran                                                           # hub down: nothing run, no long retries
    down["on"] = False
    assert checkin.checkin(run=True, opener=opener, runner=lambda: ran.append(1) or 0) == 0
    assert ran == [1]
    runs = w.s._runs("air2017")
    # F9: the check-in that could not reach the hub is a missed check-in, never a failed backup run
    assert [(r["reported_via"], r["status"]) for r in runs] == [("checkin", "completed")]
    assert w.s._rows("SELECT COUNT(*) AS n FROM checkin WHERE reason LIKE 'missed:%'")[0]["n"] == 1
    assert checkin.checkin(run=True, opener=opener, runner=lambda: ran.append(1) or 0) == 0
    assert ran == [1]                                                        # not due again within the hour
