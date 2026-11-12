"""1.4.3 (INFRA-522 R142-6, INFRA-518 R142-8): scan lock + per-scan staging, and held-back rows under unreadable paths.

All DB tests run on the throwaway schema through GuardedConn with `_test_*` hosts. The advisory lock lives in the
database session (not in a schema), so lock tests use `_test_*` host keys that no real scan takes.
"""
from __future__ import annotations

import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import load_nas_inventory as L  # noqa: E402
import scan  # noqa: E402
import scan_guard as G  # noqa: E402

COLS = "host, path, file_type, size_bytes, mode, uid, gid, inode, nlink, mtime, atime, btime, scan_id"


def _new_scan(cur, host, root="/", status="running"):
    cur.execute("INSERT INTO diskaudit.scan_runs (host, root_path, dry_run, status) VALUES (%s,%s,false,%s) RETURNING scan_id",
                (host, root, status))
    return cur.fetchone()[0]


def _stage(cur, host, paths, scan_id):
    cur.executemany(f"INSERT INTO diskaudit.files_staging ({COLS}) VALUES (%s,%s,'regular',10,420,1,1,5,1,now(),now(),NULL,%s)",
                    [(host, p, scan_id) for p in paths])


def _staged(cur, host):
    cur.execute("SELECT path, scan_id FROM diskaudit.files_staging WHERE host=%s ORDER BY path", (host,))
    return cur.fetchall()


# ---- R142-6: lock ----

def test_lock_second_scan_of_same_host_root_refused_other_host_or_root_allowed(gconn_factory):
    a, b = gconn_factory(), gconn_factory()
    assert G.acquire_scan_lock(a, "_test_lk1", "/data/x/") is True
    assert G.acquire_scan_lock(b, "_test_lk1", "/data/x") is False        # same host+root (trailing slash normalised)
    assert G.acquire_scan_lock(b, "_test_lk2", "/data/x") is True         # different host
    assert G.acquire_scan_lock(b, "_test_lk1", "/data/y") is True         # different root
    a.close()                                                             # lock dies with the session
    c = gconn_factory()
    assert G.acquire_scan_lock(c, "_test_lk1", "/data/x") is True
    c.close(); b.close()


def test_main_refuses_a_concurrent_scan_and_leaves_the_first_scans_staging_alone(gconn_factory, monkeypatch, tmp_path):
    host = "_test_lk3"
    first = gconn_factory()
    assert G.acquire_scan_lock(first, host, str(tmp_path))
    with first.cursor() as cur:
        sid1 = _new_scan(cur, host, str(tmp_path))
        _stage(cur, host, ["/t/a", "/t/b"], sid1)
    first.commit()

    second = gconn_factory()
    monkeypatch.setattr(sys, "argv", ["scan.py", "--host", host, "--root", str(tmp_path), "--no-btime"])
    monkeypatch.setattr(scan.psycopg, "connect", lambda *a, **k: second)
    with pytest.raises(SystemExit) as e:
        scan.main()
    assert e.value.code == G.EXIT_SCAN_REFUSED == 3

    with first.cursor() as cur:
        assert _staged(cur, host) == [("/t/a", sid1), ("/t/b", sid1)]       # untouched
        cur.execute("SELECT count(*) FROM diskaudit.scan_runs WHERE host=%s", (host,))
        assert cur.fetchone()[0] == 1                                       # the refused scan wrote nothing
    first.commit()


def test_load_nas_refuses_a_concurrent_load(gconn_factory, monkeypatch):
    host = "_test_lk4"
    first, second = gconn_factory(), gconn_factory()
    assert G.acquire_scan_lock(first, host, "/share/CACHEDEV1_DATA/Share")
    monkeypatch.setattr(sys, "argv", ["load_nas_inventory.py", "--host", host, "--share", "Share"])
    monkeypatch.setattr(L.psycopg, "connect", lambda *a, **k: second)
    with pytest.raises(SystemExit) as e:
        L.main()
    assert e.value.code == 3


# ---- R142-6: per-scan staging ----

def test_start_cleanup_deletes_only_rows_no_live_scan_can_own(gconn):
    h, other = "_test_st1", "_test_st2"
    with gconn.cursor() as cur:
        running_other_root = _new_scan(cur, h, "/y")           # live scan of the same host, different root
        done = _new_scan(cur, h, "/x", "completed")
        dead_same_root = _new_scan(cur, h, "/x")               # 'running' row of this host+root: dead (we hold the lock)
        other_host = _new_scan(cur, other, "/x")
        mine = _new_scan(cur, h, "/x")
        _stage(cur, h, ["/live"], running_other_root)
        _stage(cur, h, ["/done"], done)
        _stage(cur, h, ["/dead"], dead_same_root)
        _stage(cur, h, ["/legacy"], None)
        _stage(cur, h, ["/mine"], mine)
        _stage(cur, other, ["/o"], other_host)
        G.clear_stale_staging(cur, h, "/x", mine)
        # /legacy survives: another scan of this host is running and recent, and it may be pre-1.4.3 code (R143-1)
        assert [p for p, _ in _staged(cur, h)] == ["/legacy", "/live", "/mine"]
        assert _staged(cur, other) == [("/o", other_host)]       # another host: never disturbed
    gconn.commit()


def test_legacy_rows_cleared_only_when_no_other_recent_scan_of_the_host_runs(gconn):
    """R143-1 (switchover): a <= 1.4.2 scan stages NULL scan_id rows and takes no lock. A 1.4.3 scan starting on the
    same host while it runs must not delete them (its merge would then mark its whole root disappeared)."""
    h = "_test_st3"
    with gconn.cursor() as cur:
        old_live = _new_scan(cur, h, "/")                         # an old-code scan, still running
        stale = _new_scan(cur, h, "/")                            # a SIGKILLed leftover, 'running' for days
        cur.execute("UPDATE diskaudit.scan_runs SET started_at = now() - interval '3 days' WHERE scan_id=%s", (stale,))
        mine = _new_scan(cur, h, "/srv")
        _stage(cur, h, ["/legacy"], None)
        G.clear_stale_staging(cur, h, "/srv", mine)
        assert [p for p, _ in _staged(cur, h)] == ["/legacy"]     # kept while old_live runs
        cur.execute("UPDATE diskaudit.scan_runs SET status='completed' WHERE scan_id=%s", (old_live,))
        G.clear_stale_staging(cur, h, "/srv", mine)
        assert _staged(cur, h) == []                              # only the 3-day-old leftover remains: treated dead
    gconn.commit()


def test_held_merge_over_budget_defers_disappearance(gconn, monkeypatch):
    """R143-2: (not re-seen rows) x (held paths) over HELD_PAIR_BUDGET -> nothing marked disappeared, one loud error."""
    h, root = "_test_hb4", "/r"
    monkeypatch.setattr(scan, "HELD_PAIR_BUDGET", 1)
    with gconn.cursor() as cur:
        s1 = _new_scan(cur, h, root)
        _stage(cur, h, ["/r/a/1", "/r/b/2", "/r/c"], s1)
    gconn.commit()
    scan.merge(gconn, s1, h, root)
    with gconn.cursor() as cur:
        s2 = _new_scan(cur, h, root)
        _stage(cur, h, ["/r/a/1"], s2)                            # /r/b/2 under a held dir, /r/c genuinely gone
    gconn.commit()
    assert scan.merge(gconn, s2, h, root, {"/r/b", "/r/x"}) == 1  # 2 unseen x 2 held > 1
    with gconn.cursor() as cur:
        cur.execute("SELECT path, still_exists FROM diskaudit.files WHERE host=%s", (h,))
        assert dict(cur.fetchall()) == {"/r/a/1": True, "/r/b/2": True, "/r/c": True}
        cur.execute("SELECT path, error FROM diskaudit.scan_errors WHERE scan_id=%s", (s2,))
        (path, err), = cur.fetchall()
    assert path == "/r" and err.startswith("HELD_BACK_DEFERRED: 2 stored rows not re-seen x 2 unreadable")
    monkeypatch.setattr(scan, "HELD_PAIR_BUDGET", 50_000_000)
    with gconn.cursor() as cur:
        s3 = _new_scan(cur, h, root)
        _stage(cur, h, ["/r/a/1"], s3)
    gconn.commit()
    assert scan.merge(gconn, s3, h, root, {"/r/b"}) == 0          # within budget: normal held logic
    with gconn.cursor() as cur:
        cur.execute("SELECT path, still_exists FROM diskaudit.files WHERE host=%s", (h,))
        assert dict(cur.fetchall()) == {"/r/a/1": True, "/r/b/2": True, "/r/c": False}
    gconn.commit()


# ---- R142-8: unreadable directory in a complete crawl (local) ----

def _run_scan(gconn_factory, monkeypatch, host, root):
    """Run scan.main() on a fresh guarded connection (main closes it); return a fresh reader."""
    conn, reader = gconn_factory(), gconn_factory()      # both opened before psycopg.connect is patched
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", ["scan.py", "--host", host, "--root", str(root), "--no-btime"])
        m.setattr(scan.psycopg, "connect", lambda *a, **k: conn)
        scan.main()                                      # closes `conn`, releasing the scan lock
    return reader


def test_unreadable_dir_children_are_held_back_not_marked_disappeared(gconn_factory, monkeypatch, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads chmod 000 directories")
    host = "_test_hb1"
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "keep.txt").write_text("k")
    (tmp_path / "ok" / "gone.txt").write_text("g")
    locked = tmp_path / "locked"
    (locked / "deep").mkdir(parents=True)
    (locked / "f1.txt").write_text("1")
    (locked / "deep" / "f2.txt").write_text("2")
    _run_scan(gconn_factory, monkeypatch, host, tmp_path)

    (tmp_path / "ok" / "gone.txt").unlink()
    locked.chmod(0)
    try:
        conn = _run_scan(gconn_factory, monkeypatch, host, tmp_path)
    finally:
        locked.chmod(stat.S_IRWXU)
    with conn.cursor() as cur:
        cur.execute("SELECT path, still_exists FROM diskaudit.files WHERE host=%s", (host,))
        got = {os.path.relpath(p, tmp_path): s for p, s in cur.fetchall()}
        cur.execute("SELECT scan_id FROM diskaudit.scan_runs WHERE host=%s ORDER BY scan_id DESC LIMIT 1", (host,))
        sid = cur.fetchone()[0]
        cur.execute("SELECT path, error FROM diskaudit.scan_errors WHERE scan_id=%s", (sid,))
        errs = cur.fetchall()
        cur.execute("SELECT status, errors_count FROM diskaudit.scan_runs WHERE scan_id=%s", (sid,))
        status = cur.fetchone()
    assert got["ok/gone.txt"] is False                       # a genuinely deleted file still disappears
    assert got["ok/keep.txt"] is True
    assert got["locked/f1.txt"] is True and got["locked/deep/f2.txt"] is True and got["locked/deep"] is True
    assert len(errs) == 1 and errs[0][0] == str(locked)
    assert "[HELD_BACK: 3 stored rows" in errs[0][1]         # f1.txt, deep, deep/f2.txt
    assert status == ("completed", 1)

    # next scan with the directory readable again: normal accounting resumes (nothing held, nothing stale)
    conn = _run_scan(gconn_factory, monkeypatch, host, tmp_path)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FILTER (WHERE still_exists), count(*) FILTER (WHERE NOT still_exists) FROM diskaudit.files WHERE host=%s", (host,))
        assert cur.fetchone() == (6, 1)                       # ok, keep, locked, f1, deep, f2 live; (the root is not a row); gone.txt not


def test_crawl_collects_held_paths_for_listing_and_stat_failures(gconn, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads chmod 000 directories")
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "x").write_text("x")
    (tmp_path / "locked").chmod(0)
    try:
        with gconn.cursor() as cur:
            sid = _new_scan(cur, "_test_hb2", str(tmp_path))
        gconn.commit()
        held: set[str] = set()
        scan.crawl("_test_hb2", str(tmp_path), [], False, 5000, gconn, sid, held_out=held)
    finally:
        (tmp_path / "locked").chmod(stat.S_IRWXU)
    assert held == {str(tmp_path / "locked")}


# ---- R142-8: NAS crawl errors ----

def test_prune_nested():
    assert scan._prune_nested(["/a/b/c", "/a/b", "/a/bc", "", "/z", "/a/b"]) == ["/a/b", "/a/bc", "/z"]
    assert scan._prune_nested(["/", "/x"]) == ["/"]


@pytest.mark.parametrize("line,path", [
    ("find: /share/CACHEDEV1_DATA/Public/locked dir: Permission denied", "/share/CACHEDEV1_DATA/Public/locked dir"),  # BusyBox 1.24.1, verified on the NAS
    ("stat: can't stat '/share/x/gone': No such file or directory", "/share/x/gone"),
])
def test_busybox_error_lines_name_the_path(line, path):
    assert L.parse_error_line(line)[0] == path


def test_nas_load_holds_back_rows_under_unreadable_dir(gconn, tmp_path):
    host, root = "_test_hb3", "/share/x"
    row = lambda p: f"{p}|81a4|10|0|0|{abs(hash(p)) % 10**6}|1|1700000000|1700000000|1700000000\n"  # noqa: E731
    drow = lambda p: f"{p}|41ed|4096|0|0|{abs(hash(p)) % 10**6}|1|1700000000|1700000000|1700000000\n"  # noqa: E731

    def load(lines, errs):
        tsv, ef = tmp_path / "s.tsv", tmp_path / "s.errs"
        tsv.write_text("".join(lines), encoding="utf-8")
        ef.write_text(errs, encoding="utf-8")
        with gconn.cursor() as cur:
            sid = _new_scan(cur, host, root)
            L.clear_stale_staging(cur, host, root, sid)
        gconn.commit()
        held: set[str] = set()
        *_, nerr = L.load_share_into_db(gconn, sid, host, root, str(tsv), str(ef), {}, {}, {}, 5000, held_out=held)
        scan.merge(gconn, sid, host, root, held)
        return sid, held, nerr

    full = [drow("/share/x"), drow("/share/x/locked"), row("/share/x/locked/f1"), drow("/share/x/locked/sub"),
            row("/share/x/locked/sub/f2"), row("/share/x/ok"), row("/share/x/gone")]
    load(full, "")
    sid, held, nerr = load([drow("/share/x"), drow("/share/x/locked"), row("/share/x/ok")],
                           "find: /share/x/locked: Permission denied\n")
    assert held == {"/share/x/locked"} and nerr == 1
    with gconn.cursor() as cur:
        cur.execute("SELECT path, still_exists FROM diskaudit.files WHERE host=%s", (host,))
        got = dict(cur.fetchall())
        cur.execute("SELECT error FROM diskaudit.scan_errors WHERE scan_id=%s", (sid,))
        err = cur.fetchone()[0]
    assert got["/share/x/locked/f1"] and got["/share/x/locked/sub/f2"] and got["/share/x/locked/sub"]
    assert got["/share/x/gone"] is False
    assert err.startswith("Permission denied") and "[HELD_BACK: 3 stored rows" in err
    gconn.commit()
