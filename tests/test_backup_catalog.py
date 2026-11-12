"""2.2.0 backup names + file catalog: pure helpers, and a real run against LOCAL restic repos (tmp dirs only)."""
from __future__ import annotations

import datetime as dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import catalog, config, coverage, drill, health  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import make_repo, needs_restic, restic  # noqa: E402

NAME = r"^\d{8}_[A-Z0-9-]+_\d{6}$"


def test_names_and_labels():
    t = dt.datetime(2026, 11, 11, 15, 0, tzinfo=dt.timezone.utc)
    assert catalog.make_name(t, "SERVER", 42) == t.astimezone().strftime("%Y%m%d") + "_SERVER_000042"
    assert catalog.device_label("laptop_2") == "LAPTOP-2"
    with pytest.raises(BackupError):
        catalog.make_name(t, "X", 0)


def test_diff_and_where_replay():
    prev = {"/a/bob.txt": (5, 100), "/a/old.txt": (1, 1)}
    cur = {"/a/bob.txt": (6, 200), "/a/new.txt": (2, 2)}
    added, gone = catalog.diff(prev, cur)
    assert added == [("/a/bob.txt", 6, 200), ("/a/new.txt", 2, 2)]
    assert gone == [("/a/bob.txt", 5, 100), ("/a/old.txt", 1, 1)]
    log = [catalog.HEADER,
           catalog.event_lines("20261101_SERVER_000001", "SERVER", sorted((p, *v) for p, v in prev.items()), []),
           catalog.event_lines("20261102_SERVER_000002", "SERVER", added, gone)]
    hits = catalog.where("".join(log).splitlines(True), "BOB.TXT")
    assert sorted((h["size"], h["first"], h["gone"]) for h in hits) == [
        (5, "20261101_SERVER_000001", "20261102_SERVER_000002"), (6, "20261102_SERVER_000002", "")]
    assert all(h["held_by"] is None for h in hits)                       # no #ALIVE line yet: unknown, not "pruned"
    # prune removed backup 1: the old version is held by nothing, the new one by backup 2 (review 2.2.0 #3)
    log.append(catalog.alive_line(dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc), 2, ["20261102_SERVER_000002"]))
    hits = {h["size"]: h["held_by"] for h in catalog.where("".join(log).splitlines(True), "bob.txt")}
    assert hits == {6: ["20261102_SERVER_000002"], 5: []}
    # a version first named AFTER the last #ALIVE line is "not checked", never "pruned" (round 2, R1)
    log.append(catalog.event_lines("20261104_SERVER_000003", "SERVER", [("/a/bob.txt", 7, 300)], [("/a/bob.txt", 6, 200)]))
    hits = {h["size"]: h["held_by"] for h in catalog.where("".join(log).splitlines(True), "bob.txt")}
    assert hits[7] is None and hits[6] == ["20261102_SERVER_000002"]
    # device match is exact, not a substring (R8)
    log.append(catalog.alive_line(dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc), 3, ["20261104_SERVER-2_000003"]))
    assert {h["size"]: h["held_by"] for h in catalog.where("".join(log).splitlines(True), "bob.txt")}[7] == []
    assert catalog.where(log, "nothing-here") == []


@pytest.fixture
def hub(tmp_path, monkeypatch):
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    data = tmp_path / "data"
    data.mkdir()
    (data / "bob.txt").write_text("hello\n")
    root, pdir = tmp_path / "hub", config.config_dir() / "hub-passwords"
    pdir.mkdir(parents=True)
    make_repo(root / "dev_1", pdir / "dev_1.pass", data, snapshots=2)
    config.save({"hub_local": {"repo_root": str(root)}})
    return data, root, pdir


def _snaps(root, pdir, repo="dev_1"):
    return json.loads(restic(root / repo, pdir / f"{repo}.pass", "snapshots", "--json"))


@needs_restic
def test_catalog_run_names_tags_and_backs_up_catalog(hub, capsys):
    data, root, pdir = hub
    assert catalog.catalog_run() == 0
    st = json.loads((catalog.cat_dir() / "state.json").read_text())
    assert st["counter"] == 2 and st["untagged"] == []          # newest data snapshot + the catalog copy
    snaps = _snaps(root, pdir)
    named = [t for s in snaps for t in (s.get("tags") or []) if "_DEV-1_" in t]
    assert len(named) == 1 and __import__("re").match(NAME, named[0])
    cat_snaps = [s for s in snaps if catalog.CATALOG_TAG in (s.get("tags") or [])]
    assert len(cat_snaps) == 1 and any("_CATALOG_000002" in t for t in cat_snaps[0]["tags"])
    # the catalog inside the repo answers the question on its own
    body = restic(root / "dev_1", pdir / "dev_1.pass", "dump", cat_snaps[0]["id"],
                  f"{catalog.cat_dir() / 'stage'}/" + [t for t in cat_snaps[0]["tags"] if "_CATALOG_" in t][0] + "_catalog.tsv")
    assert any(h["path"].endswith("/bob.txt") for h in catalog.where(body.splitlines(True), "bob.txt"))
    # tagged snapshot keeps its own time on disk; health ignores the catalog snapshot
    tagged = [s for s in snaps if named[0] in (s.get("tags") or [])][0]
    mt = (root / "dev_1" / "snapshots" / tagged["id"]).stat().st_mtime
    assert abs(mt - catalog.parse_time(tagged["time"]).timestamp()) < 2
    assert set(catalog.catalog_snapshot_ids()) == {cat_snaps[0]["id"]}
    assert health._newest_snapshot_age_h(root / "dev_1", mt + 3600, frozenset(catalog.catalog_snapshot_ids())) == pytest.approx(1, abs=0.01)
    # drill and coverage pick the data snapshot, never the catalog one
    assert drill.drill("dev_1", sample=2, seed=1, scratch=str(data.parent)) == 0
    sid, files = coverage.list_latest("dev_1")
    assert not any(sid and cid.startswith(sid) for cid in catalog.catalog_snapshot_ids())
    assert any(p.endswith("/bob.txt") for p in files)
    # catalog snapshot file time is pinned to the newest data snapshot, so health never depends on state.json
    cfile = root / "dev_1" / "snapshots" / cat_snaps[0]["id"]
    assert cfile.stat().st_mtime <= mt + 1
    # nothing new: no new names, no new catalog copy
    assert catalog.catalog_run() == 0
    assert json.loads((catalog.cat_dir() / "state.json").read_text())["counter"] == 2
    # a change on the device -> GONE + ADDED under the next name
    (data / "bob.txt").write_text("hello again, longer\n")
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(data))
    assert catalog.catalog_run() == 0
    assert catalog.run_where("bob.txt") == 0
    out = capsys.readouterr().out
    assert "newest of" in out and "pruned" not in out
    assert catalog.run_where("never-backed-up.txt") == config.PROBLEM_EXIT


@needs_restic
def test_uncommitted_tail_is_cut_and_missing_password_is_loud(hub):
    data, root, pdir = hub
    assert catalog.catalog_run() == 0
    cat = catalog.catalog_path()
    good = cat.read_bytes()
    with open(cat, "ab") as f:
        f.write(b"20990101_X_999999\tADDED\tX\t/half-written\t1\t1\n")   # a crash after append, before commit
    assert catalog.catalog_run() == 0
    assert cat.read_bytes() == good
    make_repo(root / "nopass", pdir.parent / "elsewhere.pass", data)       # repo the hub has no password for
    assert catalog.catalog_run() == config.PROBLEM_EXIT


@needs_restic
def test_lost_state_refuses_then_recover_keeps_catalog_and_numbers(hub):
    data, root, pdir = hub
    assert catalog.catalog_run() == 0
    cat = catalog.catalog_path()
    before = cat.read_bytes()
    os.remove(catalog.cat_dir() / "state.json")                         # test tmp dir only
    with pytest.raises(BackupError, match="--recover"):
        catalog.catalog_run()
    assert cat.read_bytes() == before                                    # nothing cut
    (data / "new.txt").write_text("x\n")
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(data))
    assert catalog.catalog_run(recover=True) == 0
    assert cat.read_bytes().startswith(before)
    tags = [t for s in _snaps(root, pdir) for t in (s.get("tags") or []) if catalog.NAME_RE.match(t)]
    assert len(tags) == len(set(n.rsplit("_", 1)[1] for n in tags))     # no number used twice


@needs_restic
def test_dead_retry_entry_is_reported_once_and_dropped(hub):
    data, root, pdir = hub
    assert catalog.catalog_run() == 0
    st = json.loads((catalog.cat_dir() / "state.json").read_text())
    st["untagged"].append(["0" * 64, "20261111_DEV-1_000777", "dev_1", "2026-11-11T00:00:00Z"])
    catalog._save_state(st)
    assert catalog.catalog_run() == config.PROBLEM_EXIT                  # reported
    assert json.loads((catalog.cat_dir() / "state.json").read_text())["untagged"] == []
    assert catalog.catalog_run() == 0                                    # and not again


def test_corrupt_state_is_loud_for_health():
    catalog.cat_dir().mkdir(parents=True, exist_ok=True)
    (catalog.cat_dir() / "state.json").write_text("{not json")
    with pytest.raises(BackupError):
        catalog.catalog_snapshot_ids()


@needs_restic
def test_lost_catalog_dir_with_catalog_snapshots_in_repos_refuses(hub):
    data, root, pdir = hub
    assert catalog.catalog_run() == 0
    for p in sorted(catalog.cat_dir().rglob("*"), reverse=True):          # the whole state dir is lost (tmp only)
        os.remove(p) if p.is_file() else p.rmdir()
    with pytest.raises(BackupError, match="restic dump"):
        catalog.catalog_run()


@needs_restic
def test_alive_written_even_when_one_repo_is_unreadable(hub):
    data, root, pdir = hub
    make_repo(root / "nopass", pdir.parent / "elsewhere.pass", data)       # a repo with no hub-side password
    assert catalog.catalog_run() == config.PROBLEM_EXIT
    lines = catalog.catalog_path().read_text().splitlines(True)
    assert any(ln.startswith("#ALIVE\t") for ln in lines)
    hits = catalog.where(lines, "bob.txt")
    assert hits and all(h["held_by"] for h in hits)                        # current backup is held, not "pruned"


@needs_restic
def test_two_streams_in_one_repo_are_diffed_separately(hub):
    """Review finding 9: A server repo holds one stream per app (host + paths). Alternating backups of two folders
    must not log each other's files as GONE, and `where` counts only backups of the file's own stream."""
    data, root, pdir = hub
    other = data.parent / "other"
    other.mkdir()
    (other / "alice.txt").write_text("a\n")
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(other))
    assert catalog.catalog_run() == 0
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(data))       # no change in the data stream
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(other))      # no change in the other stream
    assert catalog.catalog_run() == 0
    lines = catalog.catalog_path().read_text().splitlines(True)
    assert not any("\tGONE\t" in ln for ln in lines)
    bob = catalog.where(lines, "bob.txt")
    assert len(bob) == 1 and len(bob[0]["held_by"]) == 2                    # the two data-stream backups only


def _nm(name, host, *roots):
    return "\t".join(["#NAME", name, host, *roots]) + "\n"


def test_where_paths_change_starts_a_new_stream_old_version_not_held_by_it():
    """Review S1 repro A: app paths change -> new stream; v1 (old stream) is never held by new-stream backups."""
    t = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    log = [catalog.HEADER,
           _nm("20261101_SERVER_000001", "server-1", "/srv/a"),
           catalog.event_lines("20261101_SERVER_000001", "SERVER", [("/srv/a/f", 1, 1)], []),
           _nm("20261110_SERVER_000003", "server-1", "/srv/a", "/srv/b"),
           catalog.event_lines("20261110_SERVER_000003", "SERVER", [("/srv/a/f", 2, 2)], []),
           _nm("20261111_SERVER_000004", "server-1", "/srv/a", "/srv/b"),
           catalog.alive_line(t, 4, ["20261110_SERVER_000003", "20261111_SERVER_000004"])]
    held = {h["size"]: h["held_by"] for h in catalog.where("".join(log).splitlines(True), "/srv/a/f")}
    assert held == {1: [], 2: ["20261110_SERVER_000003", "20261111_SERVER_000004"]}


def test_where_nested_streams_do_not_overwrite_each_other():
    """Review S1 repro B: streams /srv and /srv/x both hold /srv/x/f; A logs it GONE at 5, B still holds it."""
    t = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    f = [("/srv/x/f", 9, 9)]
    log = [catalog.HEADER,
           _nm("20261101_SERVER_000001", "h", "/srv"), catalog.event_lines("20261101_SERVER_000001", "SERVER", f, []),
           _nm("20261101_SERVER_000002", "h", "/srv/x"), catalog.event_lines("20261101_SERVER_000002", "SERVER", f, []),
           _nm("20261102_SERVER_000005", "h", "/srv"), catalog.event_lines("20261102_SERVER_000005", "SERVER", [], f),
           _nm("20261102_SERVER_000006", "h", "/srv/x"),
           catalog.alive_line(t, 6, ["20261101_SERVER_000001", "20261101_SERVER_000002",
                                     "20261102_SERVER_000005", "20261102_SERVER_000006"])]
    held = sorted(tuple(h["held_by"]) for h in catalog.where("".join(log).splitlines(True), "/srv/x/f"))
    assert held == [("20261101_SERVER_000001",), ("20261101_SERVER_000002", "20261102_SERVER_000006")]


@needs_restic
def test_health_archive_repo_has_no_age_limit(hub):
    data, root, pdir = hub
    make_repo(root / "arch", pdir / "arch.pass", data)
    for f in (root / "arch" / "snapshots").iterdir():
        os.utime(f, (1, 1))                                               # very old snapshot
    cfg = config.load()
    cfg["health"] = {"archive_repos": ["arch"]}
    config.save(cfg)
    res = {n: ok for n, ok, _ in health.collect()}
    assert res["archive arch"] is True and "snapshot age arch" not in res
    cfg["health"] = {}
    config.save(cfg)
    assert {n: ok for n, ok, _ in health.collect()}["snapshot age arch"] is False
