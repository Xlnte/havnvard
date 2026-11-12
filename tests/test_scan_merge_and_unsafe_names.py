"""1.4.2 (INFRA-518 / INFRA-520): scan.py merge on a new host, --root vs default excludes, LF-in-name quarantine.

DB tests run on the throwaway schema through GuardedConn (never a real host, never a production table).
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import load_nas_inventory as L  # noqa: E402
import scan  # noqa: E402

H = "_test_newhost"
OTHER = "_test_otherhost"
COLS = ("host, path, file_type, size_bytes, mode, uid, gid, inode, nlink, mtime, atime, btime, scan_id")


def _stage(cur, host, paths, scan_id, btime=None):
    cur.executemany(
        f"INSERT INTO diskaudit.files_staging ({COLS}) VALUES (%s,%s,'regular',10,420,1,1,5,1,now(),now(),%s,%s)",
        [(host, p, btime, scan_id) for p in paths],
    )


def _new_scan(cur, host, root="/"):
    cur.execute("INSERT INTO diskaudit.scan_runs (host, root_path, dry_run, status) VALUES (%s,%s,false,'running') RETURNING scan_id", (host, root))
    return cur.fetchone()[0]


def test_merge_into_empty_host_does_not_hang(gconn):
    """The 20261109 hang: a host with no prior rows, staging statistics describing ANOTHER host. statement_timeout turns
    a regression (planner spinning in a nested loop) into a failure instead of a hung suite."""
    with gconn.cursor() as cur:
        cur.execute("SET statement_timeout = '60s'")
        sid_old = _new_scan(cur, OTHER)
        cur.execute(
            f"INSERT INTO diskaudit.files ({COLS.replace(', scan_id', '')}, first_seen_scan_id, last_seen_scan_id) "
            "SELECT %s, '/p/'||g, 'regular', 10, 420, 1, 1, g, 1, now(), now(), NULL, %s, %s FROM generate_series(1,60000) g",
            (OTHER, sid_old, sid_old),
        )
        cur.execute(
            f"INSERT INTO diskaudit.files_staging ({COLS}) SELECT %s, '/p/'||g, 'regular', 10, 420, 1, 1, g, 1, now(), now(), NULL, %s "
            "FROM generate_series(1,60000) g", (OTHER, sid_old))
        cur.execute("ANALYZE diskaudit.files")
        cur.execute("ANALYZE diskaudit.files_staging")
        sid = _new_scan(cur, H)
        _stage(cur, H, [f"/n/{i}" for i in range(100000)], sid)  # stats still say "one host"
    gconn.commit()
    scan.merge(gconn, sid, H, "/")
    with gconn.cursor() as cur:
        cur.execute("SELECT count(*), min(first_seen_scan_id), max(last_seen_scan_id), bool_and(still_exists) FROM diskaudit.files WHERE host=%s", (H,))
        assert cur.fetchone() == (100000, sid, sid, True)
        cur.execute("SELECT count(*) FROM diskaudit.files WHERE host=%s AND still_exists", (OTHER,))
        assert cur.fetchone()[0] == 60000  # another host's rows never touched
    gconn.commit()


def test_merge_semantics_preserved(gconn):
    with gconn.cursor() as cur:
        s1 = _new_scan(cur, H, "/")
        cur.execute("DELETE FROM diskaudit.files_staging WHERE host=%s", (H,))
        cur.execute("DELETE FROM diskaudit.files WHERE host=%s", (H,))
        _stage(cur, H, ["/a/keep", "/a/gone", "/b/outside"], s1, btime="2020-01-01T00:00:00+00")
    gconn.commit()
    scan.merge(gconn, s1, H, "/")
    with gconn.cursor() as cur:
        s2 = _new_scan(cur, H, "/a")
        cur.execute("DELETE FROM diskaudit.files_staging WHERE host=%s", (H,))
        # /a/keep re-seen with no btime (COALESCE keeps the old one) and a new size; /a/new is new; /a/gone and /b/outside absent
        cur.execute(f"INSERT INTO diskaudit.files_staging ({COLS}) VALUES (%s,'/a/keep','regular',99,420,1,1,5,1,now(),now(),NULL,%s)", (H, s2))
        _stage(cur, H, ["/a/new"], s2)
        # two staged names that collapse to the same stored path must not abort the merge; the kept row is
        # deterministic (lowest inode) and the collapse is logged
        cur.execute(f"INSERT INTO diskaudit.files_staging ({COLS}) VALUES (%s,'/a/dup','regular',77,420,1,1,9,1,now(),now(),NULL,%s)", (H, s2))
        cur.execute(f"INSERT INTO diskaudit.files_staging ({COLS}) VALUES (%s,'/a/dup','regular',66,420,1,1,3,1,now(),now(),NULL,%s)", (H, s2))
    gconn.commit()
    assert scan.merge(gconn, s2, H, "/a") == 1
    with gconn.cursor() as cur:
        cur.execute("SELECT path, error FROM diskaudit.scan_errors WHERE scan_id=%s", (s2,))
        errs = cur.fetchall()
        cur.execute("SELECT inode, size_bytes FROM diskaudit.files WHERE host=%s AND path='/a/dup'", (H,))
        assert cur.fetchone() == (3, 66)
    assert len(errs) == 1 and errs[0][0] == "/a/dup" and errs[0][1].startswith("DUPLICATE_STAGED_PATH: 2 ")
    with gconn.cursor() as cur:
        cur.execute("SELECT path, still_exists, first_seen_scan_id, last_seen_scan_id, size_bytes, btime IS NOT NULL, disappeared_at IS NOT NULL "
                    "FROM diskaudit.files WHERE host=%s ORDER BY path", (H,))
        got = {r[0]: r[1:] for r in cur.fetchall()}
    assert got["/a/keep"] == (True, s1, s2, 99, True, False)
    assert got["/a/new"] == (True, s2, s2, 10, False, False)
    assert got["/a/gone"][0] is False and got["/a/gone"][-1] is True and got["/a/gone"][2] == s1
    assert got["/b/outside"] == (True, s1, s1, 10, True, False)  # outside this run's root: not marked disappeared
    assert got["/a/dup"][0] is True


def test_disappearance_never_crosses_into_a_like_lookalike_root(gconn):
    """--root /d/my_dir must not mark /d/myXdir/* or /d/my%dir-twin/* disappeared ("_" and "%" are LIKE wildcards)."""
    with gconn.cursor() as cur:
        cur.execute("DELETE FROM diskaudit.files_staging WHERE host=%s", (H,))
        cur.execute("DELETE FROM diskaudit.files WHERE host=%s", (H,))
        s1 = _new_scan(cur, H, "/")
        _stage(cur, H, ["/d/my_dir/a", "/d/myXdir/b", "/d/my%dir/c", "/d/my%dirZ/e"], s1)
    gconn.commit()
    scan.merge(gconn, s1, H, "/")
    with gconn.cursor() as cur:
        s2 = _new_scan(cur, H, "/d/my_dir")
        cur.execute("DELETE FROM diskaudit.files_staging WHERE host=%s", (H,))  # /d/my_dir/a is gone
        s3 = _new_scan(cur, H, "/d/my%dir")
    gconn.commit()
    scan.merge(gconn, s2, H, "/d/my_dir")
    scan.merge(gconn, s3, H, "/d/my%dir")
    with gconn.cursor() as cur:
        cur.execute("SELECT path, still_exists FROM diskaudit.files WHERE host=%s ORDER BY path", (H,))
        got = dict(cur.fetchall())
    assert got == {"/d/my%dir/c": False, "/d/my%dirZ/e": True, "/d/myXdir/b": True, "/d/my_dir/a": False}
    gconn.commit()


@pytest.mark.parametrize("root,waived", [
    ("/run/media/user/C", ["/run"]),
    ("/run", ["/run"]),
    ("/mnt/backup/x", ["/mnt/backup"]),
    ("/home/user", []),
    ("/runner", []),  # prefix match must respect path boundaries
])
def test_explicit_root_waives_ancestor_default_excludes(root, waived):
    eff, w = scan.effective_excludes(root, ["/home/user/skip"])
    assert w == waived
    assert all(p not in eff for p in waived)
    assert "/home/user/skip" in eff  # a deliberate --exclude is never waived
    assert not scan.is_excluded(root + "/sub/file", eff)
    for p in scan.DEFAULT_EXCLUDES:
        if p not in waived:
            assert p in eff


@pytest.mark.parametrize("argv", [
    ["--root", "/run/media/x/C", "--exclude", "/run"],      # a user --exclude is never waived
    ["--root", "/home/user/skip/sub", "--exclude", "/home/user/skip"],
    ["--root", "/var/lib/docker/volumes"],                  # excluded path component
])
def test_root_inside_an_exclude_is_refused_before_any_db_work(argv, monkeypatch):
    """A root that would crawl nothing must not reach merge (which would mark every row under it disappeared)."""
    monkeypatch.setattr(sys, "argv", ["scan.py", "--host", "_test_refuse"] + argv)
    monkeypatch.setattr(scan.psycopg, "connect", lambda *a, **k: pytest.fail("connected to the DB"))
    with pytest.raises(SystemExit) as e:
        scan.main()
    assert e.value.code == 2


def test_default_excludes_still_apply_to_other_roots():
    eff, w = scan.effective_excludes("/", [])
    assert w == [] and scan.is_excluded("/run/media/x", eff)


# ---- LF in a file name (R-4) ----

def _hex(p: str) -> str:
    return p.encode("utf-8", "surrogateescape").hex()


def test_parse_unsafe_decodes_and_never_skips(tmp_path):
    f = tmp_path / "s.unsafe"
    f.write_text(_hex("/share/x/a\nb.txt") + "\n\n" + _hex("/share/x/bad\udcff") + "\nzz-not-hex\n", encoding="ascii")
    got = L.parse_unsafe(str(f))
    assert got[0] == "/share/x/a\nb.txt"
    assert got[1] == "/share/x/bad\udcff"
    assert got[2].startswith("<undecodable unsafe-name record: zz-not-hex")
    assert L.parse_unsafe(None) == [] and L.parse_unsafe(str(tmp_path / "missing")) == []


def test_loader_records_every_unsafe_name_as_scan_error(gconn, tmp_path):
    tsv, errs, uns = tmp_path / "s.tsv", tmp_path / "s.errs", tmp_path / "s.unsafe"
    tsv.write_text("/share/x/ok.bin|81a4|100|0|0|5|1|1700000000|1700000000|1700000000\n", encoding="utf-8")
    errs.write_text("")
    uns.write_text(_hex("/share/x/a\nb.txt") + "\n" + _hex("/share/x/dir\nwith") + "\n", encoding="ascii")
    with gconn.cursor() as cur:
        sid = _new_scan(cur, H, "/share/x")
    gconn.commit()
    files, dirs, nbytes, nerr = L.load_share_into_db(gconn, sid, H, "/share/x", str(tsv), str(errs), {}, {}, {}, 5000, unsafe_path=str(uns))
    assert (files, nerr) == (1, 2)
    with gconn.cursor() as cur:
        cur.execute("SELECT path, error FROM diskaudit.scan_errors WHERE scan_id=%s ORDER BY path", (sid,))
        rows = cur.fetchall()
    assert [r[0] for r in rows] == ["/share/x/a\nb.txt", "/share/x/dir\nwith"]
    assert all(r[1].startswith("UNSAFE_NAME_LF:") for r in rows)
    gconn.commit()
