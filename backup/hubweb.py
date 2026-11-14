"""HavnVard hub pages and device API (3.3.0; INFRA-579, INFRA-575, INFRA-576). Standard-library WSGI app, served on the
hub by `python -m backup hub web` (wsgiref). Tailnet-only like the rest-server.

Pages: /register /login /logout /reset /ack /me /admin/users /admin/computers /admin/schedules /admin/audit
Device API (Bearer = the computer's check-in token):
  POST /api/v1/devices/NAME/checkin   {"client_version"}            -> {"due", "reason", "next_checkin_s", ...}
  POST /api/v1/devices/NAME/run       {"action":"start"} | {"action":"end","run_id","exit_code","snapshot_id"}
  POST /api/v1/devices/NAME/late      {"started_at","ended_at","exit_code","error"}
Every request re-reads the session (a disable is instant). A user with a pending force-open warning sees /ack first.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import re
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

from .accounts import WARNING, Accounts
from .config import BackupError
from .schedules import MODES, Schedules

COOKIE = "hv_session"
CSS = ("body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1b1f23}"
       "table{border-collapse:collapse;width:100%}td,th{border:1px solid #d0d7de;padding:6px 8px;text-align:left}"
       ".ok{background:#e6f4ea}.late{background:#fff4ce}.failed,.silent{background:#fde2e1}.warn{border:3px solid #c62828;"
       "padding:16px;background:#fde2e1}input,select,button{padding:6px;margin:2px}nav a{margin-right:12px}")


def _e(s) -> str:
    return html.escape("" if s is None else str(s))


class _Redirect(Exception):
    def __init__(self, to: str):
        super().__init__(to)
        self.to = to


def csrf_for(token: str) -> str:
    return hashlib.sha256((token + "|csrf").encode()).hexdigest()[:32]


class App:
    def __init__(self, accounts: Accounts | None = None, schedules: Schedules | None = None):
        self.a = accounts or Accounts()
        self.s = schedules or Schedules(self.a.path)

    # ---------- WSGI ----------
    def __call__(self, environ, start_response):
        status, headers, body = self.handle(environ)
        start_response(status, headers)
        return [body.encode() if isinstance(body, str) else body]

    def handle(self, env) -> tuple[str, list, str]:
        path, method = env.get("PATH_INFO", "/"), env.get("REQUEST_METHOD", "GET")
        try:
            if path.startswith("/api/v1/devices/"):
                return self.api(env, path, method)
            form = self._form(env) if method == "POST" else {k: v[0] for k, v in parse_qs(env.get("QUERY_STRING", "")).items()}
            token = self._cookie(env)
            sess = self.a.session(token)
            if method == "POST" and path not in ("/register", "/login", "/reset") and \
                    (not sess or form.get("csrf") != csrf_for(token or "")):
                return self._page("403 Forbidden", "Not allowed", "<p>Your session ended or the form is stale. "
                                  "<a href='/login'>Log in again</a>.</p>")
            route = {"/register": self.register, "/login": self.login, "/logout": self.logout, "/reset": self.reset,
                     "/ack": self.ack, "/me": self.me, "/": self.me}.get(path)
            if route:
                return route(method, form, token, sess)
            if path.startswith("/admin/"):
                return self.admin(path, method, form, token, sess)
            return self._page("404 Not Found", "Not found", "")
        except _Redirect as r:
            return self._redirect(r.to)
        except BackupError as e:
            return self._page("400 Bad Request", "Problem", f"<p class='warn'>{_e(e)}</p><p><a href='javascript:history.back()'>Back</a></p>")

    @staticmethod
    def _form(env) -> dict:
        n = int(env.get("CONTENT_LENGTH") or 0)
        raw = env["wsgi.input"].read(min(n, 1 << 20)).decode() if n else ""
        if (env.get("CONTENT_TYPE") or "").startswith("application/json"):
            return json.loads(raw or "{}")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    @staticmethod
    def _cookie(env) -> str | None:
        c = SimpleCookie(env.get("HTTP_COOKIE", ""))
        return c[COOKIE].value if COOKIE in c else None

    def _page(self, status: str, title: str, body: str, token: str | None = None, sess: dict | None = None,
              extra_headers: list | None = None) -> tuple[str, list, str]:
        nav = ""
        if sess:
            nav = "<nav><a href='/me'>My files</a>" + ("".join(f"<a href='/admin/{p}'>{p.title()}</a>" for p in
                   ("users", "computers", "schedules", "audit")) if sess["kind"] == "admin" else "") + \
                  f"<form method='post' action='/logout' style='display:inline'>{self._csrf(token)}<button>Log out " \
                  f"{_e(sess['email'])}</button></form></nav>"
        doc = f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>" \
              f"<title>HavnVard - {_e(title)}</title><style>{CSS}</style></head><body>{nav}<h1>{_e(title)}</h1>{body}</body></html>"
        return status, [("Content-Type", "text/html; charset=utf-8"), ("X-Frame-Options", "DENY"),
                        ("Cache-Control", "no-store")] + (extra_headers or []), doc

    @staticmethod
    def _csrf(token: str | None) -> str:
        return f"<input type='hidden' name='csrf' value='{csrf_for(token or '')}'>"

    @staticmethod
    def _redirect(to: str, headers: list | None = None) -> tuple[str, list, str]:
        return "303 See Other", [("Location", to)] + (headers or []), ""

    @staticmethod
    def _set_cookie(token: str) -> list:
        return [("Set-Cookie", f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000")]

    def _need(self, sess, admin: bool = False):
        if not sess:
            raise _Redirect("/login")
        if sess["must_ack_force_open"]:
            raise _Redirect("/ack")
        if admin and sess["kind"] != "admin":
            raise BackupError("administrators only")

    # ---------- registration / login (INFRA-579) ----------
    def register(self, method, f, token, sess):
        first = not self.a.list_accounts(kind="admin")
        if method == "POST":
            if f.get("password") != f.get("password2"):
                raise BackupError("the two passwords differ")
            r = self.a.register(f.get("email", ""), f.get("password", ""), setup_code=f.get("setup_code") if first else None,
                                invite_code=f.get("invite") or None, company=f.get("company"))
            lg = self.a.login(f["email"], f["password"], kind=r["kind"])
            body = f"<p>Account created: <b>{_e(r['kind'])}</b>.</p>"
            if r.get("store_key"):
                body += ("<div class='warn'><h2>Your company's store key (recovery kit)</h2><p>This key opens every backup "
                         "of your company. It is shown <b>once</b> and is not kept on the hub. Print it or put it in your "
                         f"password manager now.</p><p><code style='font-size:1.3em'>{_e(r['store_key'])}</code></p>"
                         "<p>Add a second administrator soon: if you are the only one and lose this key, recovery needs the "
                         "hub's console.</p></div>")
            body += f"<p><a href='/me'>Continue</a></p>"
            return self._page("200 OK", "Welcome", body, lg["token"], self.a.session(lg["token"]), self._set_cookie(lg["token"]))
        fields = ("<p>This is a new hub. The first account becomes the <b>administrator</b>. Enter the setup code shown on "
                  "the hub's console (<code>python -m backup hub setup-code</code>).</p>"
                  "<label>Company or household <input name='company' required></label><br>"
                  "<label>Setup code <input name='setup_code' required size='50'></label><br>") if first else \
                 f"<label>Invite code <input name='invite' value='{_e(f.get('invite'))}' required></label><br>"
        return self._page("200 OK", "Register", f"<form method='post'>{fields}<label>Email <input name='email' type='email' "
                          "required></label><br><label>Password (12+ characters) <input name='password' type='password' "
                          "required></label><br><label>Again <input name='password2' type='password' required></label><br>"
                          "<button>Register</button></form>")

    def login(self, method, f, token, sess):
        if method == "POST":
            lg = self.a.login(f.get("email", ""), f.get("password", ""), kind=f.get("kind", "user"))
            return self._redirect("/ack" if lg["must_ack"] else "/me", self._set_cookie(lg["token"]))
        return self._page("200 OK", "Log in", "<form method='post'><label>Email <input name='email' type='email' required>"
                          "</label><br><label>Password <input name='password' type='password' required></label><br>"
                          "<label>As <select name='kind'><option value='user'>user</option><option value='admin'>"
                          "administrator</option></select></label><br><button>Log in</button></form>"
                          "<p>New here? <a href='/register'>Register</a></p>")

    def logout(self, method, f, token, sess):
        if token:
            self.a.logout(token)
        return self._redirect("/login", [("Set-Cookie", f"{COOKIE}=; Path=/; Max-Age=0")])

    def reset(self, method, f, token, sess):
        if method == "POST":
            if f.get("password") != f.get("password2"):
                raise BackupError("the two passwords differ")
            r = self.a.set_password_with_reset(f.get("code", ""), f.get("password", ""))
            return self._redirect("/ack" if r["must_ack"] else "/me", self._set_cookie(r["token"]))
        return self._page("200 OK", "Set a new password", f"<form method='post'><label>Reset code <input name='code' "
                          f"value='{_e(f.get('code'))}' required></label><br><label>New password <input name='password' "
                          "type='password' required></label><br><label>Again <input name='password2' type='password' "
                          "required></label><br><button>Save</button></form>")

    def ack(self, method, f, token, sess):
        if not sess:
            return self._redirect("/login")
        if not sess["must_ack_force_open"]:
            return self._redirect("/me")
        if method == "POST" and f.get("understand") == "yes":
            self.a.ack_warning(sess["account_id"])
            return self._redirect("/me")
        w = self.a.ack_warning(sess["account_id"], preview=True)
        return self._page("200 OK", "Your administrator reset your password",
                          f"<div class='warn'><p><b>{_e(WARNING)}</b></p><p>When: {_e(w['at'])} (UTC)<br>"
                          f"Administrator: {_e(w['admin'])}<br>Reason given: {_e(w['reason'])}</p></div>"
                          f"<form method='post'>{self._csrf(token)}<label><input type='checkbox' name='understand' "
                          "value='yes' required> I understand</label> <button>Continue</button></form>")

    # ---------- my files ----------
    def me(self, method, f, token, sess):
        self._need(sess)
        mine = [d for d in self.a.devices() if d["primary_user_id"] == sess["account_id"]]
        rows = {r["device"]: r for r in self.s.overview()}
        tr = "".join(f"<tr class='{_e(rows.get(d['name'], {}).get('health', ''))}'><td>{_e(d['name'])}</td>"
                     f"<td>{_e(rows.get(d['name'], {}).get('mode'))}</td><td>{_e(rows.get(d['name'], {}).get('last_started_at'))}</td>"
                     f"<td>{_e(rows.get(d['name'], {}).get('last_status'))}</td><td>{_e(rows.get(d['name'], {}).get('next_due'))}</td></tr>"
                     for d in mine)
        body = ("<h2>My computers</h2><table><tr><th>Computer</th><th>Schedule</th><th>Last run</th><th>Result</th>"
                f"<th>Next</th></tr>{tr or '<tr><td colspan=5>No computers assigned to you yet.</td></tr>'}</table>"
                "<p>Find and pull back your files on any of your computers with <code>python -m backup find NAME</code> "
                "and <code>python -m backup pullback FILE</code>.</p>")
        return self._page("200 OK", "My files", body, token, sess)

    # ---------- admin ----------
    def admin(self, path, method, f, token, sess):
        self._need(sess, admin=True)
        me = sess["account_id"]
        if path == "/admin/users":
            note = ""
            if method == "POST":
                act, tgt = f.get("action"), int(f.get("target") or 0)
                if act == "invite":
                    code = self.a.invite(me, f.get("email", ""), f.get("kind", "user"))
                    note = f"<p class='warn'>Invite code for {_e(f.get('email'))}: <code>{_e(code)}</code> (link: /register?invite={_e(code)})</p>"
                elif act == "disable":
                    self.a.disable(me, tgt, f.get("reason") or "disabled by admin")
                elif act == "enable":
                    self.a.enable(me, tgt)
                elif act == "reset":
                    note = f"<p class='warn'>Reset code: <code>{_e(self.a.admin_reset(me, tgt))}</code> (/reset)</p>"
                elif act == "force_open":
                    code = self.a.force_open(me, tgt, f.get("reason", ""), f.get("typed_email", ""))
                    note = (f"<p class='warn'>Force-open started and logged. The user's password is reset; they will see the "
                            f"warning at next login. Give them this reset code: <code>{_e(code)}</code></p>")
                elif act == "release":
                    self.a.release(me, int(f["from_user"]), int(f["to_user"]), f["device"], f["prefix"])
                    note = "<p>Released.</p>"
            rows = "".join(
                f"<tr><td>{u['id']}</td><td>{_e(u['email'])}</td><td>{_e(u['kind'])}</td><td>{_e(u['status'])}</td>"
                f"<td>{'warning pending' if u['must_ack_force_open'] else ''}</td><td>"
                + self._btn(token, "disable", u["id"], "Disable", "<input name='reason' placeholder='reason'>")
                + self._btn(token, "enable", u["id"], "Enable") + self._btn(token, "reset", u["id"], "Reset password")
                + (self._btn(token, "force_open", u["id"], "Force open",
                             "<input name='reason' placeholder='reason (user sees it)' required>"
                             "<input name='typed_email' placeholder='type their email' required>") if u["kind"] == "user" else "")
                + "</td></tr>" for u in self.a.list_accounts())
            body = (note + f"<form method='post'>{self._csrf(token)}<input type='hidden' name='action' value='invite'>"
                    "<input name='email' type='email' placeholder='email' required><select name='kind'><option>user</option>"
                    "<option>admin</option></select><button>Invite</button></form>"
                    f"<table><tr><th>#</th><th>Email</th><th>Kind</th><th>Status</th><th></th><th>Actions</th></tr>{rows}</table>"
                    f"<h2>Release files to another user</h2><form method='post'>{self._csrf(token)}"
                    "<input type='hidden' name='action' value='release'><input name='from_user' placeholder='from #' required>"
                    "<input name='to_user' placeholder='to #' required><input name='device' placeholder='computer' required>"
                    "<input name='prefix' placeholder='/home/al/work' required><button>Release</button></form>")
            return self._page("200 OK", "Users", body, token, sess)
        if path == "/admin/computers":
            note = ""
            if method == "POST":
                act = f.get("action")
                if act == "add":
                    t = self.a.add_device(me, f["name"], int(f["primary_user"]) if f.get("primary_user") else None,
                                          int(f["pc_admin"]) if f.get("pc_admin") else None)
                    note = f"<p class='warn'>Check-in token for {_e(f['name'])} (shown once): <code>{_e(t)}</code></p>"
                elif act == "rule":
                    self.a.add_rule(me, f["device"], f["prefix"], int(f["user"]))
                elif act == "shared":
                    self.a.mark_shared(me, f["device"], f["prefix"])
            rows = "".join(f"<tr><td>{_e(d['name'])}</td><td>{_e(d['primary_user_id'])}</td><td>{_e(d['pc_admin_id'])}</td>"
                           f"<td>{_e(d['status'])}</td></tr>" for d in self.a.devices())
            c = self._csrf(token)
            body = (note + f"<table><tr><th>Computer</th><th>Primary user #</th><th>PC administrator #</th><th>Status</th></tr>{rows}</table>"
                    f"<h2>Add a computer</h2><form method='post'>{c}<input type='hidden' name='action' value='add'>"
                    "<input name='name' placeholder='name' required><input name='primary_user' placeholder='user #'>"
                    "<input name='pc_admin' placeholder='PC admin #'><button>Add</button></form>"
                    f"<h2>Folder owner</h2><form method='post'>{c}<input type='hidden' name='action' value='rule'>"
                    "<input name='device' placeholder='computer' required><input name='prefix' placeholder='/home/al' required>"
                    "<input name='user' placeholder='user #' required><button>Set owner</button></form>"
                    f"<h2>Shared folder (owned by that PC's administrator)</h2><form method='post'>{c}"
                    "<input type='hidden' name='action' value='shared'><input name='device' placeholder='computer' required>"
                    "<input name='prefix' placeholder='/srv/shared' required><button>Mark shared</button></form>")
            return self._page("200 OK", "Computers", body, token, sess)
        if path == "/admin/schedules":
            if method == "POST":
                self.s.set(me, f["device"], f["mode"], int(f["every_min"]) if f.get("every_min") else None,
                           int(f.get("min_gap_s") or 60))
                self.a._log(me, "schedule.set", f["device"], mode=f["mode"], every_min=f.get("every_min"),
                            min_gap_s=f.get("min_gap_s"))
            ov = self.s.overview()
            silent = [r["device"] for r in ov if r["health"] == "silent"]
            banner = (f"<p class='warn'>{len(silent)} computer(s) have not checked in: {_e(', '.join(silent))}</p>" if silent else "")
            opts = "".join(f"<option>{m}</option>" for m in MODES)
            rows = "".join(
                f"<tr class='{_e(r['health'])}'><td>{_e(r['device'])}</td><td>{_e(r['mode'])}"
                f"{' every ' + str(r['every_min']) + ' min' if r['mode'] == 'interval' else ''}</td>"
                f"<td>{_e(r['last_started_at'])}</td><td>{_e(r['last_duration_s'])}</td><td>{_e(r['last_status'])}"
                f"{' (reported late)' if r['last_reported_via'] == 'late' else ''}</td><td>{_e(r['next_due'])}</td>"
                f"<td>{_e(r['last_checkin_at'])}</td><td>{_e(r['stat_median_s'])} / {_e(r['stat_max_s'])}</td>"
                f"<td>{_e(r['health'])}</td></tr>" for r in ov)
            body = (banner + "<table><tr><th>Computer</th><th>Schedule</th><th>Last run</th><th>Length s</th><th>Result</th>"
                    f"<th>Next</th><th>Last check-in</th><th>Median / max s</th><th>Health</th></tr>{rows}</table>"
                    f"<h2>Set a schedule</h2><form method='post'>{self._csrf(token)}<input name='device' placeholder='computer' "
                    f"required><select name='mode'>{opts}</select><input name='every_min' placeholder='every N min'>"
                    "<input name='min_gap_s' placeholder='loop gap s (60)'><button>Save</button></form>"
                    "<p>Computers check in every 5 minutes and ask whether they are due; a change here takes effect at the "
                    "next check-in. Constant loop: the next run starts when the last one ends (plus the gap); after a "
                    "failure the gap doubles, up to 60 minutes.</p>")
            return self._page("200 OK", "Schedules", body, token, sess)
        if path == "/admin/audit":
            ok, n, head = self.a.verify_audit()
            rows = "".join(f"<tr><td>{r['seq']}</td><td>{_e(r['at'])}</td><td>{_e(r['actor'])}</td><td>{_e(r['action'])}</td>"
                           f"<td>{_e(r['target'])}</td><td>{_e(r['detail'])}</td></tr>" for r in reversed(self.a.audit_rows()[-500:]))
            body = (f"<p>Chain {'intact' if ok else '<b>BROKEN - the log was changed</b>'}: {n} entries, head <code>{head[:16]}</code></p>"
                    f"<table><tr><th>#</th><th>When (UTC)</th><th>By</th><th>Action</th><th>Target</th><th>Detail</th></tr>{rows}</table>")
            return self._page("200 OK", "Audit log", body, token, sess)
        return self._page("404 Not Found", "Not found", "", token, sess)

    def _btn(self, token, action, target, label, extra="") -> str:
        return (f"<form method='post' style='display:inline'>{self._csrf(token)}<input type='hidden' name='action' "
                f"value='{action}'><input type='hidden' name='target' value='{target}'>{extra}<button>{label}</button></form>")

    # ---------- device API (INFRA-576) ----------
    def api(self, env, path, method) -> tuple[str, list, str]:
        m = re.fullmatch(r"/api/v1/devices/([A-Za-z0-9._-]{1,64})/(checkin|run|late)", path)
        if not m or method != "POST":
            return self._json("404 Not Found", {"error": "not found"})
        name, what = m.groups()
        auth = env.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer ") or not self.a.device_by_token(name, auth[7:].strip()):
            return self._json("401 Unauthorized", {"error": "unknown computer or token"})
        try:
            body = self._form(env)
            if what == "checkin":
                return self._json("200 OK", self.s.checkin(name, body.get("client_version")))
            if what == "run":
                if body.get("action") == "start":
                    return self._json("200 OK", {"run_id": self.s.run_start(name, body.get("kind", "backup"))})
                self.s.run_end(int(body["run_id"]), int(body["exit_code"]), body.get("snapshot_id"), body.get("error"))
                return self._json("200 OK", {"ok": True})
            rid = self.s.report_late(name, dt.datetime.fromisoformat(body["started_at"]),
                                     dt.datetime.fromisoformat(body["ended_at"]), int(body["exit_code"]), body.get("error"))
            return self._json("200 OK", {"run_id": rid})
        except (BackupError, KeyError, ValueError) as e:
            return self._json("400 Bad Request", {"error": str(e)})

    @staticmethod
    def _json(status, obj) -> tuple[str, list, str]:
        return status, [("Content-Type", "application/json")], json.dumps(obj)


def serve(listen: str, port: int) -> None:  # pragma: no cover - thin wrapper around wsgiref
    from wsgiref.simple_server import make_server
    with make_server(listen, port, App()) as srv:
        print(f"HavnVard hub pages on http://{listen}:{port}/")
        srv.serve_forever()
