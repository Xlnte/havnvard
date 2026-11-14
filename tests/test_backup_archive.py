"""HavnVard 3.2.0 long-term storage (INFRA-571): offload, pullback, find, forget-before/after, pack size,
interrupted transfers, NAS mirror after a hub prune. Local restic repos in tmp dirs only; no DB, no network."""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import signal
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, archive, config, enroll, offsite, prune  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import make_repo, needs_rclone, needs_restic, restic  # noqa: E402


@pytest.fixture
def dev(tmp_path, monkeypatch):
    """A 'device' whose backups go to a local repo (stands in for the hub's rest-server)."""
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    monkeypatch.setattr(alerts, "fire", lambda *a, **k: (True, "sent"))
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "excludes.txt").write_text("")
    root, pdir = tmp_path / "hub", tmp_path / "cfg" / "hub-passwords"
    pdir.mkdir()
    repo, pw = root / "dev1", pdir / "dev1.pass"
    pw.write_text("test-password\n")
    restic(repo, pw, "init")
    owner = tmp_path / "owner.pass"
    owner.write_text("test-password\n")                       # the owner's own copy (password manager)
    config.save({"hub_local": {"repo_root": str(root)}})
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    monkeypatch.setattr(archive, "device_env", lambda: (env, {"name": "dev1", "paths": []}))
    photos = tmp_path / "Photos"
    (photos / "2019").mkdir(parents=True)
    for i in range(5):
        (photos / "2019" / f"p{i}.jpg").write_bytes(os.urandom(3000) + bytes([i]))
    (photos / "notes.txt").write_text("hello\n")
    return tmp_path, repo, pw, owner, photos


class FakeConn:
    def __init__(self): self.rows, self.done = [], None
    def cursor(self): return self
    def executemany(self, sql, seq): self.rows += list(seq)
    def commit(self): self.done = "commit"
    def rollback(self): self.done = "rollback"
    def close(self): pass


@needs_restic
def test_offload_verifies_every_file_records_and_deletes_nothing(dev, capsys):
    tmp, repo, pw, owner, photos = dev
    conn = FakeConn()
    assert archive.offload(str(photos), connect=lambda: conn) == 0
    out = capsys.readouterr().out
    assert "6/6 files VERIFIED" in out and "HavnVard deletes nothing" in out
    assert conn.done == "commit" and len(conn.rows) == 6 and {r[5] for r in conn.rows} == {"VERIFIED"}
    assert len(list(photos.rglob("*.jpg"))) == 5                       # nothing deleted on the device
    snap = json.loads(restic(repo, pw, "snapshots", "--json"))[-1]
    assert "archive" in snap["tags"] and any(t.startswith("archive-") for t in snap["tags"])
    # a silent change (same size, same mtime) after the backup is caught by the full SHA-256 read-back
    victim = photos / "2019" / "p0.jpg"
    st = victim.stat()
    victim.write_bytes(b"X" * st.st_size)
    os.utime(victim, (st.st_atime, st.st_mtime))
    rows = archive._dump_verify("restic", {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)},
                                snap["id"], photos, archive._when(snap["time"]) + dt.timedelta(seconds=5))
    assert {r["path"]: r["status"] for r in rows}[str(victim)] == "MISMATCH"
    # no database: refused BEFORE any backup; a failed record after the read-back is loud (exit 1)
    def down():
        raise RuntimeError("db down")
    n = len(json.loads(restic(repo, pw, "snapshots", "--json")))
    with pytest.raises(BackupError, match="--no-db"):
        archive.offload(str(photos), connect=down)
    assert len(json.loads(restic(repo, pw, "snapshots", "--json"))) == n
    class BadConn(FakeConn):
        def executemany(self, sql, seq): raise RuntimeError("insert failed")
    assert archive.offload(str(photos), connect=BadConn) == config.PROBLEM_EXIT
    assert "ALERT: offload not recorded" in capsys.readouterr().out


@needs_restic
def test_pullback_files_never_overwrite_rename_and_any_device(dev, capsys):
    tmp, repo, pw, owner, photos = dev
    assert archive.offload(str(photos), no_db=True) == 0
    tgt = tmp / "newdesk"
    p0, p1 = str(photos / "2019" / "p0.jpg"), str(photos / "2019" / "p1.jpg")
    # pre-existing files at the destination: one identical, one different
    (tgt / p0.lstrip("/")).parent.mkdir(parents=True)
    (tgt / p0.lstrip("/")).write_bytes((photos / "2019" / "p0.jpg").read_bytes())
    (tgt / p1.lstrip("/")).write_bytes(b"someone else's p1")
    now = dt.datetime(2026, 11, 13, 1, 30)
    # --from another device with the owner's key (read only), files space-separated
    rc = archive.pullback(paths=[p0, p1, str(photos / "notes.txt")], target=str(tgt), from_device="dev1",
                          key_file=str(owner), now=now)
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "1 restored, 1 already there and identical" in out and "1 already there but different" in out
    assert (tgt / p1.lstrip("/")).read_bytes() == b"someone else's p1"            # never overwritten
    side = tgt / p1.lstrip("/").replace("p1.jpg", "p1_PULLBACK-20261113-0130.jpg")
    assert side.read_bytes() == (photos / "2019" / "p1.jpg").read_bytes()         # backed-up copy next to it
    assert (tgt / str(photos / "notes.txt").lstrip("/")).read_text() == "hello\n"
    assert "3/3 files accounted for; 3/3 SHA-256 match the offload manifest" in out
    # by offload date, limited to a folder
    tgt2 = tmp / "bydate"
    tgt2.mkdir()
    assert archive.pullback(date=dt.date.today().isoformat(), folder=str(photos / "2019"), target=str(tgt2)) == 0
    assert len(list(tgt2.rglob("*.jpg"))) == 5 and not list(tgt2.rglob("notes.txt"))
    with pytest.raises(BackupError, match="nothing was offloaded"):
        archive.pullback(date="2001-01-01", target=str(tgt2))


@needs_restic
def test_pullback_vanished_finds_what_disappeared_that_day(dev):
    tmp, repo, pw, owner, photos = dev
    restic(repo, pw, "backup", "--time", "2026-11-10 12:00:00", str(photos))
    restic(repo, pw, "backup", "--time", "2026-11-11 15:00:00", "--exclude", "p3.jpg", str(photos))
    # an offload of another folder later that day must not be compared against the regular backup (review FIX-NOW 4)
    restic(repo, pw, "backup", "--time", "2026-11-11 18:00:00", "--tag", "archive", str(photos / "2019"))
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    snaps = archive.catalog.data_snapshots(archive.catalog.snapshots("restic", env))
    src, gone = archive.vanished("restic", env, snaps, dt.date(2026, 11, 11))
    assert gone == [str(photos / "2019" / "p3.jpg")]
    tgt = tmp / "back"
    tgt.mkdir()
    assert archive.pullback(date="2026-11-11", gone_mode=True, target=str(tgt)) == 0
    assert (tgt / str(photos / "2019" / "p3.jpg").lstrip("/")).read_bytes() == (photos / "2019" / "p3.jpg").read_bytes()
    with pytest.raises(BackupError, match="needs a regular backup before"):
        archive.vanished("restic", env, snaps, dt.date(2026, 11, 1))


@needs_restic
def test_pullback_never_changes_anything_that_exists(dev, capsys):
    """Review FULL FIX-NOW 1-3: file where a folder belongs, symlinked folder, folder mode, odd names, re-tagged snapshot."""
    tmp, repo, pw, owner, photos = dev
    odd = photos / "2019" / "cost $HOME x "
    odd.write_text("odd\n")
    assert archive.offload(str(photos), no_db=True) == 0
    snap = json.loads(restic(repo, pw, "snapshots", "--json"))[-1]
    restic(repo, pw, "tag", "--add", "havnvard-name-x", snap["id"])            # what the hub's catalog does hourly
    tgt = tmp / "dest"
    base = tgt / str(photos).lstrip("/")
    base.mkdir(parents=True)
    os.chmod(base, 0o700)
    (base / "2019").write_text("I am a FILE where the backup has a folder")
    real = tmp / "elsewhere"
    real.mkdir()
    (base.parent / "PhotosLink").symlink_to(real)
    rc = archive.pullback(snapshot=snap["id"][:8], target=str(tgt), now=dt.datetime(2026, 11, 13, 2, 0))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert (base / "2019").read_text().startswith("I am a FILE")                # untouched
    alt = base / "2019_PULLBACK-20261113-0200"
    assert len(list(alt.glob("p*.jpg"))) == 5 and (alt / odd.name).read_text() == "odd\n"
    assert oct(base.stat().st_mode & 0o777) == "0o700"                         # existing folder mode kept
    assert (base.parent / "PhotosLink").is_symlink()                           # symlinked folder never replaced
    assert "7/7 files accounted for" in out and "7/7 SHA-256 match the offload manifest" in out   # re-tag: original id


@needs_restic
def test_forget_before_and_after_need_owner_key_and_exact_text(dev, capsys):
    tmp, repo, pw, owner, photos = dev
    for t, tag in (("2024-05-01 10:00:00", "archive"), ("2024-06-01 10:00:00", None),
                   ("2025-03-01 10:00:00", None), ("2026-02-01 10:00:00", None)):
        restic(repo, pw, "backup", "--time", t, *(["--tag", tag] if tag else []), str(photos))
    count = lambda: len(json.loads(restic(repo, pw, "snapshots", "--json")))  # noqa: E731
    with pytest.raises(BackupError, match="owner-key"):
        archive.forget_dated("dev1", "2025-01-01", None)
    with pytest.raises(BackupError, match="hub's stored"):
        archive.forget_dated("dev1", "2025-01-01", str(pw))
    with pytest.raises(BackupError, match="bad device"):
        archive.forget_dated("../x", "2025-01-01", str(owner))
    assert archive.forget_dated("dev1", "2025-01-01", str(owner), confirm="yes") == config.PROBLEM_EXIT
    assert 'must be exactly: "DELETE FROM dev1 1 SNAPSHOTS BEFORE 2025-01-01"' in capsys.readouterr().out
    assert count() == 4
    assert archive.forget_dated("dev1", "2025-01-01", str(owner), confirm="DELETE FROM dev1 1 SNAPSHOTS BEFORE 2025-01-01") == 0
    assert count() == 3                                                    # 2024-06 gone, 2024-05 archive kept
    assert archive.forget_dated("dev1", "2026-01-01", str(owner), after=True,
                                confirm="DELETE FROM dev1 1 SNAPSHOTS ON OR AFTER 2026-01-01") == 0
    times = sorted(s["time"][:7] for s in json.loads(restic(repo, pw, "snapshots", "--json")))
    assert times == ["2024-05", "2025-03"]


@needs_restic
def test_find_reads_catalog_from_own_repo(dev, capsys, monkeypatch):
    tmp, repo, pw, owner, photos = dev
    cat = tmp / "catdir" / "20261113_CATALOG_000002_catalog.tsv"
    cat.parent.mkdir()
    cat.write_text("# HavnVard catalog: NAME\tEVENT\tDEVICE\tPATH\tSIZE\tMTIME_UTC\n"
                   f"20261112_DEV1_000001\tADDED\tDEV1\t{photos}/2019/p2.jpg\t3001\t1762900000\n")
    restic(repo, pw, "backup", "--tag", "havnvard-catalog", str(cat))
    monkeypatch.setattr(archive.catalog, "catalog_path", lambda: tmp / "no-such-catalog.tsv")
    assert archive.find("p2.jpg") == 0
    out = capsys.readouterr().out
    assert "read from the repository" in out and "p2.jpg" in out


@needs_restic
def test_pack_size_64_by_default_and_no_big_files(tmp_path, monkeypatch):
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    cmd = enroll.backup_cmd("restic", {"name": "d"}, ["/x"])
    assert cmd[cmd.index("--pack-size") + 1] == "64"
    with pytest.raises(BackupError):
        enroll.pack_size({"pack_size_mib": 200})
    data = tmp_path / "d"
    data.mkdir()
    (data / "big.bin").write_bytes(os.urandom(30 * 1024 * 1024))
    pw = tmp_path / "pw"
    pw.write_text("p\n")
    restic(tmp_path / "r", pw, "init")
    restic(tmp_path / "r", pw, "backup", "--pack-size", "4", str(data))
    biggest = max(p.stat().st_size for p in (tmp_path / "r").rglob("*") if p.is_file())
    assert biggest <= (4 + 8) * 1024 * 1024                               # pack size + at most one chunk


@needs_restic
def test_backup_killed_midway_resumes_clean(tmp_path, monkeypatch):
    """Wi-Fi drop stand-in: SIGKILL restic after packs started landing, run again, full read check passes."""
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    data = tmp_path / "d"
    data.mkdir()
    for i in range(6):
        (data / f"f{i}.bin").write_bytes(os.urandom(20 * 1024 * 1024))
    repo, pw = tmp_path / "r", tmp_path / "pw"
    pw.write_text("p\n")
    restic(repo, pw, "init")
    env = {**os.environ, "RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    p = subprocess.Popen(["restic", "backup", "--pack-size", "4", str(data)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() - t0 < 30 and p.poll() is None and not any(f.is_file() for f in (repo / "data").rglob("*")):
        time.sleep(0.01)
    killed = p.poll() is None
    if killed:
        p.send_signal(signal.SIGKILL)
    p.wait()
    restic(repo, pw, "backup", "--pack-size", "4", str(data))    # the next run just works
    restic(repo, pw, "unlock")                                       # stale lock of the killed run (prune does this too)
    restic(repo, pw, "check", "--read-data")
    snaps = json.loads(restic(repo, pw, "snapshots", "--json"))
    assert killed, "restic finished before the kill; the interruption was not tested"
    assert len(snaps) == 1


@needs_rclone
def test_nas_mirror_keeps_snapshots_the_hub_pruned_and_survives_cut_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.bin").write_bytes(os.urandom(5000))
    root, pw = tmp_path / "hub", tmp_path / "pw"
    make_repo(root / "dev1", pw, data, snapshots=3)
    mirror = tmp_path / "nas"
    assert offsite._run_target("nas", str(mirror), root, 600, "0") == 0
    packs = sorted(p for p in (mirror / "dev1" / "data").rglob("*") if p.is_file())
    # cut-off copy (Wi-Fi drop): truncate one pack on the mirror; the next pass repairs it from the hub
    packs[0].write_bytes(packs[0].read_bytes()[:10])
    assert offsite._run_target("nas", str(mirror), root, 600, "0") == 0
    oldest = sorted(json.loads(restic(root / "dev1", pw, "snapshots", "--json")), key=lambda s: s["time"])[0]
    restic(root / "dev1", pw, "forget", "--keep-last", "1", "--prune")   # the owner deletes 2 of 3 on the hub
    assert offsite._run_target("nas", str(mirror), root, 600, "0") == 0
    m = mirror / "dev1"
    assert len(json.loads(restic(m, pw, "snapshots", "--json"))) == 3     # copy-only mirror kept all 3
    restic(m, pw, "check", "--read-data")
    restic(m, pw, "restore", oldest["id"], "--target", str(tmp_path / "out"))
    assert (tmp_path / "out" / str(data / "a.bin").lstrip("/")).is_file()
    # worst case: a mirror file is cut off AND the hub copy is already gone -> flagged loudly, never deleted
    gone = [p for p in (m / "data").rglob("*") if p.is_file() and not (root / "dev1" / p.relative_to(m)).exists()]
    assert gone, "the hub prune should have left mirror-only packs"
    gone[0].write_bytes(gone[0].read_bytes()[:10])
    (tmp_path / "state" / "offsite-nas.orphans-ok").write_text("")      # force a re-check of every orphan
    offsite._run_target("nas", str(mirror), root, 600, "0")
    flags = (tmp_path / "state" / "offsite-nas.flagged").read_text()
    assert gone[0].name in flags and gone[0].exists()
    assert json.loads((tmp_path / "state" / "offsite-nas.status.json").read_text())["flagged"] >= 1


def test_verify_stream_statuses(tmp_path):
    import tarfile
    live = tmp_path / "live"
    live.mkdir()
    (live / "same.txt").write_bytes(b"abc")
    (live / "extra.txt").write_bytes(b"not in backup")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(str(live / "same.txt").lstrip("/"))
        ti.size, ti.mtime = 3, int((live / "same.txt").stat().st_mtime)
        tf.addfile(ti, io.BytesIO(b"abc"))
    buf.seek(0)
    rows = {r["path"]: r["status"] for r in archive.verify_stream(buf, live, dt.datetime.now().astimezone())}
    assert rows == {str(live / "same.txt"): "VERIFIED", str(live / "extra.txt"): "MISSING_IN_SNAPSHOT"}
    assert archive.renamed(tmp_path / "r.pdf", "20261113-0130").name == "r_PULLBACK-20261113-0130.pdf"
    assert archive.renamed(tmp_path / "Makefile", "x").name == "Makefile_PULLBACK-x"


@needs_restic
def test_cut_stream_reports_partial_and_fifo_never_hangs(dev, capsys, monkeypatch):
    """Review N1: a restic dump cut mid-way -> PARTIAL/FAILED listed, exit 1, no traceback.
    Review N2: a FIFO in the folder never blocks offload and is not written back as a file."""
    tmp, repo, pw, owner, photos = dev
    (photos / "2019" / "big.bin").write_bytes(os.urandom(300_000))
    os.mkfifo(photos / "pipe")
    assert archive.offload(str(photos), no_db=True) == 0                 # returns: the FIFO is never opened
    assert "special file(s)" in capsys.readouterr().out
    ok = tmp / "ok"
    ok.mkdir()
    assert archive.pullback(date=dt.date.today().isoformat(), target=str(ok)) == 0
    assert not os.path.lexists(ok / str(photos / "pipe").lstrip("/"))
    assert "pipe/socket/device" in capsys.readouterr().out
    wrapper = tmp / "restic-cut.sh"                                       # real restic, but `dump` output is cut
    wrapper.write_text('#!/bin/sh\nif [ "$1" = dump ]; then restic "$@" | head -c 120000; exit 1; fi\nexec restic "$@"\n')
    wrapper.chmod(0o755)
    monkeypatch.setenv("HAVNVARD_RESTIC", str(wrapper))
    cut = tmp / "cut"
    cut.mkdir()
    big = str(photos / "2019" / "big.bin")
    assert archive.pullback(paths=[big], target=str(cut)) == config.PROBLEM_EXIT
    out = capsys.readouterr().out
    assert "FAILED" in out and "PARTIAL" in out and "Traceback" not in out
    assert (cut / big.lstrip("/")).stat().st_size < 300_000              # kept, reported, not removed
    cut2 = tmp / "cut2"
    cut2.mkdir()
    assert archive.pullback(date=dt.date.today().isoformat(), target=str(cut2)) == config.PROBLEM_EXIT
    assert "FAILED" in capsys.readouterr().out


@needs_restic
def test_pullback_snapshot_honours_the_file_list_infra578(dev, capsys):
    """INFRA-578: `pullback FILE --snapshot ID` restored the WHOLE snapshot (live: 29,019 files for one asked)."""
    tmp, repo, pw, owner, photos = dev
    restic(repo, pw, "backup", str(photos))
    snap = json.loads(restic(repo, pw, "snapshots", "--json"))[-1]
    tgt = tmp / "one"
    tgt.mkdir()
    want = str(photos / "2019" / "p2.jpg")
    assert archive.pullback(paths=[want], snapshot=snap["id"][:8], target=str(tgt)) == 0
    got = [p for p in tgt.rglob("*") if p.is_file()]
    assert got == [tgt / want.lstrip("/")], got                                  # exactly the one file asked for
    assert got[0].read_bytes() == (photos / "2019" / "p2.jpg").read_bytes()
    assert "1/1 files accounted for" in capsys.readouterr().out
    # a file that is not in that snapshot: refused before anything is written
    tgt2 = tmp / "none"
    tgt2.mkdir()
    with pytest.raises(BackupError, match="not in snapshot"):
        archive.pullback(paths=[str(photos / "nope.txt")], snapshot=snap["id"][:8], target=str(tgt2))
    assert not any(tgt2.rglob("*"))


@needs_restic
def test_pullback_twice_writes_one_PULLBACK_copy(dev, capsys):
    """owner ruling 20261114: a different same-name file is never overwritten; the copy is NAME_PULLBACK-STAMP.EXT, and a
    second pullback of the same backed-up file finds that copy instead of writing an identical _2."""
    tmp, repo, pw, owner, photos = dev
    restic(repo, pw, "backup", str(photos))
    tgt = tmp / "t"
    f = str(photos / "notes.txt")
    (tgt / f.lstrip("/")).parent.mkdir(parents=True)
    (tgt / f.lstrip("/")).write_text("edited locally\n")
    for minute in (1, 2):
        assert archive.pullback(paths=[f], target=str(tgt), now=dt.datetime(2026, 11, 14, 2, minute)) == 0
    d = (tgt / f.lstrip("/")).parent
    assert (tgt / f.lstrip("/")).read_text() == "edited locally\n"
    assert sorted(p.name for p in d.iterdir()) == ["notes.txt", "notes_PULLBACK-20261114-0201.txt"]
    assert "already pulled back earlier" in capsys.readouterr().out


@needs_restic
def test_vanished_finds_files_created_and_deleted_the_same_day(dev):
    """Live 20261114: 500 files created 15:00 and deleted 15:05 on one day were invisible to --vanished, which only
    compared the last backup before the day with the last one in it. Every backup of the day is now compared in turn."""
    tmp, repo, pw, owner, photos = dev
    restic(repo, pw, "backup", "--time", "2026-11-10 12:00:00", str(photos))
    day = photos / "made-today"
    day.mkdir()
    (day / "a.txt").write_text("made and lost the same day\n")
    restic(repo, pw, "backup", "--time", "2026-11-11 09:00:00", "--exclude", "notes.txt", str(photos))  # notes gone ...
    restic(repo, pw, "backup", "--time", "2026-11-11 18:00:00", "--exclude", "a.txt", str(photos))     # ... and back
    env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw)}
    snaps = archive.catalog.data_snapshots(archive.catalog.snapshots("restic", env))
    jobs = archive.vanished_jobs("restic", env, snaps, dt.date(2026, 11, 11))
    gone = sorted(p for _, ps in jobs for p in ps)
    assert gone == [str(day / "a.txt")]
    tgt = tmp / "back"
    tgt.mkdir()
    assert archive.pullback(date="2026-11-11", gone_mode=True, target=str(tgt)) == 0
    assert (tgt / str(day / "a.txt").lstrip("/")).read_text() == "made and lost the same day\n"
