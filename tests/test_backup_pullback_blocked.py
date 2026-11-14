"""HavnVard 3.3.0 pullback challenges (owner ruling 20261114): identical file, same name different content, missing deep and
empty folders, and a folder that cannot be created or written -> the run carries on, exits 1, lists every item, and
raises one popup (stays until clicked) plus one hub notice per blocked folder.

The end-to-end test uses the REAL restic binary against a throwaway repository in pytest's tmp dir. No real backup,
hub, network or screen is touched: the popup and the hub notice are fakes that record their calls."""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import sys
import urllib.error

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import archive, checkin, config, notify  # noqa: E402
from conftest_backup_helpers import needs_restic, restic  # noqa: E402

ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class Recorder:
    def __init__(self, result):
        self.calls, self.kw, self.result = [], [], result

    def __call__(self, *a, **kw):
        self.calls.append(a)
        self.kw.append(kw)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    repo, pw = tmp_path / "repo", tmp_path / "repo.pass"
    pw.write_text("test-password\n")
    restic(repo, pw, "init")
    e = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    monkeypatch.setattr(archive, "device_env", lambda: (e, {"name": "dev1", "paths": []}))
    return tmp_path, repo, pw


@needs_restic
@pytest.mark.skipif(ROOT, reason="root ignores folder permissions, so a read-only folder cannot refuse it")
def test_pullback_end_to_end_identical_different_deep_empty_and_readonly(env, capsys):
    tmp, repo, pw = env
    src = tmp / "src"
    (src / "docs").mkdir(parents=True)
    (src / "docs" / "Résumé_001.txt").write_text("résumé ünïcode\n")
    (src / "docs" / "my report final.txt").write_text("spaces in the name\n")
    (src / "deep" / "a" / "b" / "c" / "d").mkdir(parents=True)
    (src / "deep" / "a" / "b" / "c" / "d" / "leaf.txt").write_text("deep leaf\n")
    (src / "empty" / "inner-empty").mkdir(parents=True)
    (src / "same.txt").write_text("same bytes\n")
    (src / "diff.txt").write_text("backed-up version\n")
    for ro in ("ro", "ro2"):
        (src / ro / "sub").mkdir(parents=True)
        (src / ro / "inside.txt").write_text(f"{ro} inside\n")
        (src / ro / "sub" / "x.txt").write_text(f"{ro} sub x\n")
    restic(repo, pw, "backup", str(src))
    snap = json.loads(restic(repo, pw, "snapshots", "--json"))[-1]

    tgt = tmp / "target"
    base = tgt / str(src).lstrip("/")
    base.mkdir(parents=True)
    (base / "same.txt").write_text("same bytes\n")                        # (a) identical already there
    (base / "diff.txt").write_text("edited on the computer\n")             # (b) same name, different content
    for ro in ("ro", "ro2"):                                               # (d) folders that refuse us
        (base / ro).mkdir()
        os.chmod(base / ro, 0o555)
    pop, hub = Recorder({"shown": True, "how": "fake"}), Recorder("sent")
    try:
        rc = archive.pullback(snapshot=snap["id"][:8], target=str(tgt), now=dt.datetime(2026, 11, 14, 3, 0),
                              notifier=pop, hub_notice=hub)
    finally:
        for ro in ("ro", "ro2"):
            os.chmod(base / ro, 0o755)
    out = capsys.readouterr()
    o = out.out
    assert rc == config.PROBLEM_EXIT, o                                     # not everything could be placed
    assert "Traceback" not in o + out.err
    # (a) identical: left alone, no copy written, counted as accounted for
    assert (base / "same.txt").read_text() == "same bytes\n"
    assert not list(base.glob("same_PULLBACK-*"))
    assert "1 already there and identical (left alone)" in o
    # (b) different: never touched; the backed-up bytes as NAME_PULLBACK-YYYYMMDD-HHMM.EXT
    assert (base / "diff.txt").read_text() == "edited on the computer\n"
    assert (base / "diff_PULLBACK-20261114-0300.txt").read_text() == "backed-up version\n"
    assert f"KEPT {base / 'diff.txt'}  ->  backed-up copy: {base / 'diff_PULLBACK-20261114-0300.txt'}" in o
    # (c) missing deep folders and empty folders are recreated; odd names are kept exactly
    assert (base / "deep" / "a" / "b" / "c" / "d" / "leaf.txt").read_text() == "deep leaf\n"
    assert (base / "empty" / "inner-empty").is_dir() and not any((base / "empty" / "inner-empty").iterdir())
    assert (base / "docs" / "Résumé_001.txt").read_text() == "résumé ünïcode\n"
    assert (base / "docs" / "my report final.txt").read_text() == "spaces in the name\n"
    # (d) read-only folders: nothing written there, every item listed, the rest still restored
    for ro in ("ro", "ro2"):
        assert list((base / ro).iterdir()) == []
        assert f"BLOCKED folder {base / ro}: permission denied" in o
        assert f"COULD NOT PLACE {base / ro / 'inside.txt'}" in o and f"COULD NOT PLACE {base / ro / 'sub'}" in o
    assert "5/9 files accounted for" in o and "3 restored" in o        # 4 files sit behind the 2 refused folders
    # exactly one popup and one hub notice per blocked folder, with the right text
    assert len(pop.calls) == 2 and len(hub.calls) == 2
    for (title, text), ro in zip(pop.calls, ("ro", "ro2")):
        assert title == notify.TITLE
        assert f"into this folder:\n\n  {base / ro}\n" in text and "permission denied" in text
        assert "inside.txt" in text and "What to do" in text and "Nothing on this computer was changed" in text
    assert [k for k, _ in hub.calls] == ["pullback_blocked", "pullback_blocked"]
    assert hub.calls[0][1] == pop.calls[0][1]
    assert f"hub notice for {base / 'ro'}: sent" in o
    # FN-6: every file not put back is listed, with the count; D2: the popup is told who owns the folder
    assert "NOT PUT BACK: 4 file(s)" in o
    for ro in ("ro", "ro2"):
        assert f"NOT PUT BACK {src / ro / 'inside.txt'}" in o and f"NOT PUT BACK {src / ro / 'sub' / 'x.txt'}" in o
    assert [k["owner_uid"] for k in pop.kw] == [os.getuid(), os.getuid()]


@needs_restic
@pytest.mark.skipif(ROOT, reason="root ignores folder permissions")
def test_single_file_into_readonly_folder_never_hangs_and_no_display_is_said(env, capsys):
    """A single file is dumped raw through a pipe: when its folder refuses us the bytes are drained (restic is never
    left blocked) and the run still ends. With no display the popup says why, on stderr; the hub notice too."""
    tmp, repo, pw = env
    src = tmp / "s"
    src.mkdir()
    (src / "big.bin").write_bytes(os.urandom(400_000))
    (src / "ok.txt").write_text("ok\n")
    restic(repo, pw, "backup", str(src))
    tgt = tmp / "t"
    (tgt / str(src).lstrip("/")).mkdir(parents=True)
    os.chmod(tgt / str(src).lstrip("/"), 0o555)
    try:
        rc = archive.pullback(paths=[str(src / "big.bin"), str(src / "ok.txt")], target=str(tgt),
                              notifier=Recorder({"shown": False, "how": "no graphical session is logged in"}),
                              hub_notice=Recorder("not sent: check-in is not set up; kept on this computer in X"))
    finally:
        os.chmod(tgt / str(src).lstrip("/"), 0o755)
    out = capsys.readouterr()
    assert rc == config.PROBLEM_EXIT
    assert "NO POPUP" in out.err and "no graphical session" in out.err
    assert "hub notice" in out.err and "not sent" in out.err
    assert "FAILED" not in out.out                                         # a refused folder is not a restic failure


def test_mkdir_refused_is_recorded_not_raised(tmp_path, monkeypatch):
    """Unit: the writer turns EACCES/EPERM/EROFS into a recorded blocked folder; other errors still raise."""
    w = archive._Writer(tmp_path, "20261114-0300", tmp_path)
    real = os.mkdir

    def fake_mkdir(p, *a):
        if str(p).endswith("/locked"):
            raise PermissionError(13, "Permission denied", str(p))
        if str(p).endswith("/rofs"):
            raise OSError(30, "Read-only file system", str(p))
        if str(p).endswith("/full"):
            raise OSError(28, "No space left on device", str(p))
        return real(p, *a)
    monkeypatch.setattr(archive.os, "mkdir", fake_mkdir)
    w.put_file("/locked/a.txt", io.BytesIO(b"abc"), 3, 0o644, 0)
    w.put_file("/locked/b.txt", io.BytesIO(b"abc"), 3, 0o644, 0)
    w.put_dir("/rofs", 0o755, 0)
    w.put_link("/locked/l", "a.txt")
    w.put_file("/fine/c.txt", io.BytesIO(b"abc"), 3, 0o644, 0)
    assert list(w.blocked) == [str(tmp_path)]                               # the folder that refused both
    assert w.blocked[str(tmp_path)]["items"] == [str(tmp_path / "locked"), str(tmp_path / "rofs")]
    assert w.unplaced == {"/locked/a.txt", "/locked/b.txt"}
    assert (tmp_path / "fine" / "c.txt").read_bytes() == b"abc"
    with pytest.raises(OSError, match="No space"):
        w.put_file("/full/d.txt", io.BytesIO(b"abc"), 3, 0o644, 0)
    assert "read-only" in archive._why(OSError(30, "x")) and "permission" in archive._why(PermissionError(13, "x"))


# ---------- notifier: command construction per platform (no screen is touched) ----------

SESSION = {"user": "alice", "uid": 1234, "type": "wayland", "display": "", "runtime_dir": "/run/user/1234"}


def test_popup_commands_for_each_platform():
    t, x = "Title", 'Folder "/srv/it\'s"; rm -rf ~'
    cmd, extra, how = notify.build(t, x, system="Linux", env={"DISPLAY": ":0"}, which=lambda n: "/usr/bin/zenity")
    assert cmd == ["/usr/bin/zenity", "--warning", "--no-wrap", "--no-markup", "--title", t, "--text", x]
    assert extra == {}
    assert "--timeout" not in cmd                                           # stays until clicked
    cmd, extra, how = notify.build(t, x, system="Darwin")
    assert cmd[0] == "osascript" and cmd[-2:] == [x, t]                     # text as an argument, never in the script
    script = " ".join(cmd[1:-2])
    assert 'buttons {"OK"}' in script and "giving up" not in script and "with icon caution" in script
    cmd, extra, how = notify.build(t, x, system="Windows")
    assert cmd[0] == "powershell" and "[System.Windows.MessageBox]::Show" in cmd[-1]
    assert extra == {"HAVNVARD_POPUP_TEXT": x, "HAVNVARD_POPUP_TITLE": t} and x not in cmd[-1]


def test_popup_linux_sessions_and_no_display():
    z = lambda n: "/usr/bin/zenity" if n == "zenity" else None  # noqa: E731
    cmd, extra, how = notify.build("T", "x", system="Linux", env={}, session=None, which=z)
    assert cmd is None and "no graphical session" in how
    cmd, extra, how = notify.build("T", "x", system="Linux", env={}, session=None, which=lambda n: None)
    assert cmd is None and "zenity is not installed" in how
    cmd, extra, how = notify.build("T", "x", system="Linux", env={}, session=SESSION, euid=1234, which=z)
    assert cmd[0] == "/usr/bin/zenity" and extra["XDG_RUNTIME_DIR"] == "/run/user/1234"
    assert extra["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1234/bus"
    cmd, extra, how = notify.build("T", "x", system="Linux", env={}, session=SESSION, euid=0, which=z)
    assert cmd[:4] == ["runuser", "-u", "alice", "--"] and "XDG_RUNTIME_DIR=/run/user/1234" in cmd
    cmd, extra, how = notify.build("T", "x", system="Linux", env={}, session=SESSION, euid=os.getuid() or 1, which=z)
    assert cmd is None and "belongs to alice" in how and "only root" in how


def test_find_session_picks_the_active_local_graphical_one():
    out = {("loginctl", "list-sessions", "--no-legend"): "c1 1000 parker seat0 tty1\n4 1234 alice seat0 tty2\n"}

    def run(cmd):
        if cmd[:2] == ["loginctl", "show-session"]:
            return ("Type=tty\nActive=yes\nRemote=no\nName=parker\nUser=1000\n" if cmd[2] == "c1" else
                    "Type=wayland\nActive=yes\nRemote=no\nName=alice\nUser=1234\nDisplay=:1\n")
        return out.get(tuple(cmd), "")
    s = notify.find_session(run)
    assert s == {"user": "alice", "uid": 1234, "type": "wayland", "display": ":1", "runtime_dir": "/run/user/1234"}
    assert notify.find_session(lambda c: "") is None


def test_find_session_skips_the_login_screen():
    """Live trigkey 20261114: nobody logged in at the desk, only gdm's greeter (Class=greeter) - that is no desktop."""
    def run(cmd):
        if cmd[:2] == ["loginctl", "show-session"]:
            return "Type=x11\nActive=yes\nRemote=no\nName=gdm\nUser=120\nClass=greeter\nDisplay=:0\n"
        return "c1 120 gdm seat0 tty1\n"
    assert notify.find_session(run) is None
    assert notify.find_session(run, uid=120) is None


def test_popup_not_root_only_looks_for_its_own_session(monkeypatch):
    """Not root: only the person running the pullback's own desktop counts; nobody else's session is ever tried."""
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(notify.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notify.shutil, "which", lambda n: "/usr/bin/zenity")
    asked = []

    def finder(uid=None):
        asked.append(uid)
        return None
    r = notify.popup("T", "text", euid=1000, finder=finder, launcher=lambda *a: pytest.fail("must not launch"))
    assert asked == [1000] and r["shown"] is False and "no graphical session" in r["how"]


def test_session_env_survives_an_unreadable_xauthority(monkeypatch):
    """/run/user/120/gdm/Xauthority is unreadable to others: that must never raise out of the popup path."""
    real = notify.Path.is_file

    def is_file(self):
        if "gdm" in str(self):
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)
    monkeypatch.setattr(notify.Path, "is_file", is_file)
    env = notify._session_env({"user": "gdm", "uid": 120, "type": "x11", "display": ":0", "runtime_dir": "/run/user/120"})
    assert env["DISPLAY"] == ":0" and "XAUTHORITY" not in env


def test_popup_launches_detached_and_reports(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(notify.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notify.shutil, "which", lambda n: "/usr/bin/zenity")
    seen = []
    r = notify.popup("T", "text", launcher=lambda cmd, env, system: seen.append((cmd, system)))
    assert r["shown"] is True and seen[0][0][0] == "/usr/bin/zenity"

    def boom(cmd, env, system):
        raise FileNotFoundError(2, "No such file")
    assert notify.popup("T", "text", launcher=boom)["shown"] is False


# ---------- hub notice from the device ----------

def test_report_notice_not_configured_unreachable_then_flushed(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    st = checkin.report_notice("pullback_blocked", "t1")
    assert st.startswith("not sent: check-in is not set up") and "kept on this computer" in st
    (tmp_path / "tok").write_text("devtoken\n")
    config.save({"checkin": {"url": "http://hub:8001", "token_file": str(tmp_path / "tok")}, "device": {"name": "d1"}})

    def down(req, timeout=None):
        raise urllib.error.URLError("connection refused")
    st = checkin.report_notice("pullback_blocked", "t2", opener=down)
    assert "hub unreachable" in st and "kept on this computer" in st
    got = []

    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def up(req, timeout=None):
        got.append((req.full_url, json.loads(req.data)))
        if req.full_url.endswith("/checkin"):
            return Resp(b'{"due": false, "reason": "test"}')
        return Resp(b'{"notice_id": 1}')
    assert checkin.report_notice("pullback_blocked", "t3", opener=up) == "sent"
    assert checkin.checkin(opener=up) == 0                                    # flushes the two kept notices
    sent = [b["text"] for u, b in got if u.endswith("/notice")]
    assert sent[0] == "t3" and sent[1].startswith("t1") and sent[2].startswith("t2")
    assert "recorded on the computer at" in sent[1]
    assert (tmp_path / "state" / "notices-pending.jsonl").read_text() == ""


def test_renamed_collisions_get_2_and_3_extension_last(tmp_path):
    f = tmp_path / "report.final.pdf"
    f.write_text("x")
    a = archive.renamed(f, "20261114-0300")
    assert a.name == "report.final_PULLBACK-20261114-0300.pdf"
    a.write_text("y")
    b = archive.renamed(f, "20261114-0300")
    assert b.name == "report.final_PULLBACK-20261114-0300_2.pdf"
    b.write_text("z")
    assert archive.renamed(f, "20261114-0300").name == "report.final_PULLBACK-20261114-0300_3.pdf"
