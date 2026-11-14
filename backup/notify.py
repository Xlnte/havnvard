"""A popup on the computer's screen that stays until the person clicks OK (3.3.0, owner ruling 20261114).

Used when a pullback cannot put files somewhere (a folder it cannot create or write). The popup has no time-out: it
stays until someone clicks it away. It is launched DETACHED, so the pullback never waits for the click.

* Linux with a graphical session: `zenity --warning --no-markup` (modal, blocks until OK; FN-3: the text is never
  read as Pango markup, so a file named `<a href=...>` shows as plain text). When run from a service or as another
  user, the active local graphical session is found with `loginctl` and its DISPLAY / WAYLAND_DISPLAY /
  XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS are used. A session that belongs to ANOTHER user can only be reached when
  running as root (`runuser -u USER`); otherwise we say so.
* D2 (orchestrator 20261114): when the pullback runs as ROOT, the popup goes only to the graphical session of the user
  who OWNS the folder that refused files (`owner_uid`). When that user has no session there is no popup (hub notice
  only) and the reason says so; it is never shown on someone else's screen.
* macOS: `osascript` `display dialog ... buttons {"OK"}` (no `giving up after`, so no time-out).
* Windows: PowerShell `[System.Windows.MessageBox]::Show`.

Text is passed as program arguments or environment variables, never pasted into a script, so a folder name with
quotes cannot change the command. No display: `popup` returns shown=False with the reason; the caller prints it to
stderr and records it (never silent).
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

try:
    import pwd
except ImportError:                                         # Windows
    pwd = None  # type: ignore[assignment]

TITLE = "HavnVard: some files could not be put back"

_PS = ("Add-Type -AssemblyName PresentationFramework; "
       "[void][System.Windows.MessageBox]::Show($env:HAVNVARD_POPUP_TEXT, $env:HAVNVARD_POPUP_TITLE, 'OK', 'Warning')")
_OSA = ['-e', 'on run argv',
        '-e', ('display dialog (item 1 of argv) with title (item 2 of argv) buttons {"OK"} default button "OK" '
               'with icon caution'),
        '-e', 'end run']


def _run_out(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout if r.returncode == 0 else ""


def find_session(run=_run_out, uid: int | None = None) -> dict | None:
    """The active, local graphical session (of user UID when given): {user, uid, type, display, runtime_dir}.
    None when there is none."""
    for ln in run(["loginctl", "list-sessions", "--no-legend"]).splitlines():
        sid = ln.split()[0] if ln.split() else ""
        if not sid:
            continue
        props = dict(x.split("=", 1) for x in run(["loginctl", "show-session", sid, "-p", "Type", "-p", "Active",
                                                   "-p", "Remote", "-p", "Name", "-p", "User", "-p", "Display",
                                                   "-p", "State"]).splitlines() if "=" in x)
        if props.get("Type") in ("x11", "wayland") and props.get("Active") == "yes" and props.get("Remote") != "yes":
            try:
                su = int(props.get("User") or -1)
            except ValueError:                                   # unexpected loginctl output: not this session
                continue
            if uid is not None and su != uid:
                continue
            return {"user": props.get("Name", ""), "uid": su, "type": props["Type"],
                    "display": props.get("Display", ""), "runtime_dir": f"/run/user/{su}"}
    return None


def _session_env(s: dict) -> dict:
    rt = Path(s["runtime_dir"])
    env = {"XDG_RUNTIME_DIR": str(rt), "DBUS_SESSION_BUS_ADDRESS": f"unix:path={rt / 'bus'}"}
    if s.get("display"):
        env["DISPLAY"] = s["display"]
    try:
        way = sorted(p.name for p in rt.iterdir() if p.name.startswith("wayland-") and not p.name.endswith(".lock"))
    except OSError:
        way = []
    if way:
        env["WAYLAND_DISPLAY"] = way[0]
    if not env.get("DISPLAY") and not way:
        env["DISPLAY"] = ":0"                                  # XWayland/X default; zenity reports if it is wrong
    home = None
    if pwd is not None and s["uid"] >= 0:
        try:
            home = Path(pwd.getpwuid(s["uid"]).pw_dir) / ".Xauthority"
        except KeyError:
            home = None
    for xa in (rt / "gdm" / "Xauthority", home):
        if xa is not None and xa.is_file():
            env["XAUTHORITY"] = str(xa)
            break
    return env


def build(title: str, text: str, system: str | None = None, env: dict | None = None, session: dict | None = None,
          euid: int | None = None, which=shutil.which) -> tuple[list[str] | None, dict, str]:
    """(command, extra environment, how-or-why). command None = no popup possible; the third item says why."""
    system = system or platform.system()
    env = dict(os.environ if env is None else env)
    if system == "Darwin":
        return ["osascript", *_OSA, text, title], {}, "osascript dialog"
    if system == "Windows":
        return (["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS],
                {"HAVNVARD_POPUP_TEXT": text, "HAVNVARD_POPUP_TITLE": title}, "PowerShell MessageBox")
    zen = which("zenity")
    if not zen:
        return None, {}, "zenity is not installed, so no popup can be shown (install the zenity package)"
    cmd = [zen, "--warning", "--no-wrap", "--no-markup", "--title", title, "--text", text]
    if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
        return cmd, {}, "zenity on this session's display"
    if session is None:
        return None, {}, "no graphical session is logged in on this computer"
    euid = os.geteuid() if euid is None else euid
    extra = _session_env(session)
    if session["uid"] == euid:
        return cmd, extra, f"zenity on {session['user']}'s {session['type']} session"
    if euid == 0:
        return (["runuser", "-u", session["user"], "--", "env", *[f"{k}={v}" for k, v in extra.items()], *cmd], {},
                f"zenity on {session['user']}'s {session['type']} session (as {session['user']})")
    try:
        me = pwd.getpwuid(euid).pw_name if pwd is not None else str(euid)
    except KeyError:
        me = f"uid {euid}"
    return None, {}, (f"the screen belongs to {session['user']} and this pullback runs as {me}; "
                      "only root can show a popup on another person's screen")


def popup(title: str, text: str, launcher=None, owner_uid: int | None = None, euid: int | None = None,
          finder=None) -> dict:
    """Show the popup without waiting for the click. {"shown": bool, "how": str} - how says why when not shown.
    OWNER_UID: who owns the folder the popup is about (D2: used when running as root)."""
    system = platform.system()
    finder = finder or find_session
    session, env = None, None
    if system not in ("Darwin", "Windows"):
        euid = (os.geteuid() if hasattr(os, "geteuid") else -1) if euid is None else euid
        if euid == 0 and owner_uid is None:
            return {"shown": False, "how": "running as root and the folder's owner could not be told, so no popup on "
                                           "anyone's screen (hub notice only)"}
        if euid == 0:
            session = finder(uid=owner_uid)
            if session is None:
                try:
                    who = pwd.getpwuid(owner_uid).pw_name if pwd is not None else str(owner_uid)
                except KeyError:
                    who = f"uid {owner_uid}"
                return {"shown": False, "how": f"running as root: the folder's owner ({who}) has no graphical session "
                                               "on this computer, so no popup (hub notice only)"}
            env = {}                                             # never root's own DISPLAY: the owner's session only
        elif not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            session = finder()
    cmd, extra, how = build(title, text, system=system, env=env, session=session, euid=euid)
    if cmd is None:
        return {"shown": False, "how": how}
    launch = launcher or _launch
    try:
        launch(cmd, {**os.environ, **extra}, system)
    except OSError as e:
        return {"shown": False, "how": f"could not start {cmd[0]}: {e}"}
    return {"shown": True, "how": how}


def _launch(cmd: list[str], env: dict, system: str) -> None:
    kw: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "env": env}
    if system == "Windows":
        kw["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kw["start_new_session"] = True                       # the popup outlives the pullback; we never wait on it
    subprocess.Popen(cmd, **kw)          # fixed program; the text is passed as arguments, never through a shell
