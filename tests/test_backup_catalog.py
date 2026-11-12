"""2.2.0 backup names + file catalog: pure helpers, and a real run against LOCAL restic repos (tmp dirs only)."""
from __future__ import annotations

import datetime as dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import catalog, config, drill, health  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import make_repo, needs_restic, restic  # noqa: E402

NAME = r"^\d{8}_[A-Z0-9-]+_\d{6}$"


def test_names_and_labels():
    t = dt.datetime(2026, 11, 11, 15, 0, tzinfo=dt.timezone.utc)
    assert catalog.make_name(t, "SPARK", 42) == t.astimezone().strftime("%Y%m%d") + "_SPARK_000042"
    assert catalog.device_label("air_2017") == "AIR-2017"
    with pytest.raises(BackupError):
        catalog.make_name(t, "X", 0)


def test_diff_and_where_replay():
    prev = {"/a/bob.txt": (5, 100), "/a/old.txt": (1, 1)}
    cur = {"/a/bob.txt": (6, 200), "/a/new.txt": (2, 2)}
    added, gone = catalog.diff(prev, cur)
    assert added == [("/a/bob.txt", 6, 200), ("/a/new.txt", 2, 2)]
    assert gone == [("/a/bob.txt", 5, 100), ("/a/old.txt", 1, 1)]
    log = [catalog.HEADER,
           catalog.event_lines("20261101_SPARK_000001", "SPARK", sorted((p, *v) for p, v in prev.items()), []),
           catalog.event_lines("20261102_SPARK_000002", "SPARK", added, gone)]
    hits = catalog.where("".join(log).splitlines(True), "BOB.TXT")
    assert [(h["size"], h["first"], h["gone"]) for h in hits] == [
        (6, "20261102_SPARK_000002", ""), (5, "20261101_SPARK_000001", "20261102_SPARK_000002")]
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
    # nothing new: no new names, no new catalog copy
    assert catalog.catalog_run() == 0
    assert json.loads((catalog.cat_dir() / "state.json").read_text())["counter"] == 2
    # a change on the device -> GONE + ADDED under the next name
    (data / "bob.txt").write_text("hello again, longer\n")
    restic(root / "dev_1", pdir / "dev_1.pass", "backup", str(data))
    assert catalog.catalog_run() == 0
    assert catalog.run_where("bob.txt") == 0
    out = capsys.readouterr().out
    assert "still in backups from" in out and "up to (not in)" in out
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
