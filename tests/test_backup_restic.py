"""Drill, prune, NAS copy and offsite against real LOCAL restic repos and local-path rclone remotes (tmp dirs only)."""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import alerts, config, drill, health, nas, offsite, prune  # noqa: E402
from backup.config import BackupError  # noqa: E402
from conftest_backup_helpers import make_repo, needs_restic, needs_rclone, restic  # noqa: E402


@pytest.fixture
def hubenv(tmp_path, monkeypatch):
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "rcache"))
    monkeypatch.setattr(alerts, "fire", lambda *a, **k: (True, "sent"))
    monkeypatch.setattr(alerts, "resolve", lambda k: None)
    data = tmp_path / "data"
    data.mkdir()
    for i in range(6):
        (data / f"f{i}.bin").write_bytes(os.urandom(2000) + bytes([i]))
    root = tmp_path / "hub"
    pdir = tmp_path / "cfg" / "hub-passwords"
    pdir.mkdir(parents=True)
    make_repo(root / "dev1", pdir / "dev1.pass", data, snapshots=3)
    config.save({"hub_local": {"repo_root": str(root)}})
    return tmp_path, data, root, pdir


@needs_restic
def test_drill_matches_and_detects_silent_corruption(hubenv):
    tmp, data, root, pdir = hubenv
    assert drill.drill("dev1", sample=4, seed=1, scratch=str(tmp)) == 0
    victim = data / "f0.bin"
    st = victim.stat()
    victim.write_bytes(b"X" * st.st_size)            # same size, original mtime: a silent change
    os.utime(victim, (st.st_atime, st.st_mtime))
    assert drill.drill("dev1", sample=50, seed=1, scratch=str(tmp)) == config.PROBLEM_EXIT


@needs_restic
def test_drill_nothing_comparable_is_not_a_pass_and_unknown_device_errors(hubenv):
    tmp, data, root, pdir = hubenv
    for f in data.glob("f*.bin"):
        f.write_bytes(b"changed")                     # size differs: skipped, so nothing is proven
    for f in data.glob("extra*"):
        f.write_bytes(b"changed")
    assert drill.drill("dev1", scratch=str(tmp)) == config.PROBLEM_EXIT
    with pytest.raises(BackupError):
        drill.drill("nope")


@needs_restic
def test_prune_needs_rule_owner_key_and_exact_confirmation_and_keeps_archive(hubenv, monkeypatch, capsys):
    """3.2.0 never-delete: no rule, no owner key, hub's stored key, bad device or wrong text -> nothing deleted.
    The archive-tagged snapshot is the OLDEST, so only --keep-tag can save it (review FIX-NOW 1)."""
    tmp, data, root, pdir = hubenv
    repo, hubpw = root / "dev1", pdir / "dev1.pass"
    oldest = sorted(json.loads(restic(repo, hubpw, "snapshots", "--json")), key=lambda s: s["time"])[0]["id"]
    restic(repo, hubpw, "tag", "--add", "archive", oldest)
    oldest = next(s["id"] for s in json.loads(restic(repo, hubpw, "snapshots", "--json")) if "archive" in (s.get("tags") or []))
    snaps = lambda: json.loads(restic(repo, hubpw, "snapshots", "--json"))  # noqa: E731
    owner = tmp / "owner.pass"
    owner.write_text(hubpw.read_text())                                  # owner's own copy (password manager)
    with pytest.raises(BackupError, match="no keep rule"):
        prune.prune("dev1", {}, str(owner), confirm="x")
    with pytest.raises(BackupError, match="owner-key"):
        prune.prune("dev1", {"keep_daily": 1}, None)
    with pytest.raises(BackupError, match="not the hub's stored"):
        prune.prune("dev1", {"keep_daily": 1}, str(hubpw))
    with pytest.raises(BackupError, match="bad device"):
        prune.prune("../dev1", {"keep_daily": 1}, str(owner))
    assert prune.prune("dev1", {"keep_last": 9, "keep_daily": 1}, str(owner), dry_run=True) == 0 and len(snaps()) == 3
    assert prune.prune("dev1", {"keep_daily": 1}, str(owner), confirm="yes") == config.PROBLEM_EXIT
    assert 'must be exactly: "DELETE FROM dev1 1 SNAPSHOTS BY RULE keep_daily=1"' in capsys.readouterr().out
    monkeypatch.setattr(prune.sys.stdin, "isatty", lambda: False)
    assert prune.prune("dev1", {"keep_daily": 1}, str(owner), ask=lambda _: pytest.fail("no tty: never ask")) == config.PROBLEM_EXIT
    assert len(snaps()) == 3
    assert prune.prune("dev1", {"keep_daily": 1}, str(owner), confirm="DELETE FROM dev1 1 SNAPSHOTS BY RULE keep_daily=1") == 0
    left = snaps()
    assert len(left) == 2 and any(s["id"] == oldest for s in left)      # archive survived although oldest
    # control: the same rule WITHOUT --keep-tag would have removed it
    plain = json.loads(restic(repo, hubpw, "forget", "--dry-run", "--json", "--keep-daily=1", "--group-by", "host,paths"))
    assert any(s["id"] == oldest for g in plain for s in (g.get("remove") or []))


def test_oldest_lock_age(tmp_path):
    (tmp_path / "locks").mkdir()
    f = tmp_path / "locks" / "l1"
    f.write_text("x")
    t = time.time() - 10 * 3600
    os.utime(f, (t, t))
    assert 9.9 < prune.oldest_lock_age_h(tmp_path, time.time()) < 10.1
    assert prune.oldest_lock_age_h(tmp_path / "none", time.time()) is None


@needs_restic
def test_nas_copy_requires_mount_then_copies(hubenv, monkeypatch):
    tmp, data, root, pdir = hubenv
    mp = tmp / "nas"
    mp.mkdir()
    config.update("nas", {"mountpoint": str(mp), "repo_subdir": "restic"})
    with pytest.raises(BackupError):                  # not a mount point: must not write to the local disk
        nas.nas_copy()
    monkeypatch.setattr(nas.os.path, "ismount", lambda p: True)
    # F1: mirroring must not need hub-side passwords, so point the password dir at an empty one
    monkeypatch.setattr("backup.util.hub_password_dir", lambda: tmp / "no-passwords")
    assert nas.nas_copy() == 0
    # the mirror is a complete repo that opens with the device's own password
    assert len(json.loads(restic(mp / "restic" / "dev1", pdir / "dev1.pass", "snapshots", "--json"))) == 3


def test_nas_target_unit_name_and_credential_rules(tmp_path):
    assert nas.systemd_escape_path("/mnt/havnvard-nas") == "mnt-havnvard\\x2dnas"
    cred = tmp_path / "nas.cred"
    lines = nas.nas_target("//nas/havnvard-bkup", "havnvard", str(cred), "/mnt/hv", tmp_path / "o")
    assert cred.stat().st_mode & 0o777 == 0o600 and "password=\n" in cred.read_text()
    assert any("EMPTY password" in ln for ln in lines)
    assert "credentials=" in (tmp_path / "o" / "mnt-hv.mount").read_text()
    cred.chmod(0o644)
    with pytest.raises(BackupError):
        nas.nas_target("//nas/x", "havnvard", str(cred), "/mnt/hv", tmp_path / "o")
    with pytest.raises(BackupError):
        nas.nas_target("nas/x", "havnvard", str(cred), "/mnt/hv", tmp_path / "o")


def _same(a, b):
    """Same files with same sizes (empty directories are not copied by rclone and are not needed)."""
    def files(root):
        return sorted((str(p.relative_to(root)), p.stat().st_size) for p in root.rglob("*") if p.is_file())
    return files(a) == files(b) and bool(files(a))


@needs_rclone
def test_offsite_copy_repair_flag_and_health(hubenv):
    tmp, data, root, pdir = hubenv
    off = tmp / "offsite"
    offsite.offsite_add("local", str(off), crypt=False)
    assert offsite.offsite_run("local", max_seconds=120) == 0
    assert _same(root / "dev1" / "data", off / "dev1" / "data") and _same(root / "dev1" / "snapshots", off / "dev1" / "snapshots")
    pack = next(p for p in (off / "dev1" / "data").rglob("*") if p.is_file())
    full = pack.read_bytes()
    pack.write_bytes(full[:10])                       # cut-off upload: SMALLER than the hub copy -> removed, resent
    assert offsite.offsite_run("local", max_seconds=120) == 0 and pack.read_bytes() == full
    pack.write_bytes(full + b"junk")                  # LARGER, hub copy hash-verified -> resent up to MAX_TRIES
    assert offsite.offsite_run("local", max_seconds=120) == 0 and pack.read_bytes() == full
    (tmp / "state" / "offsite-local.tries").write_text(f"dev1/{pack.relative_to(off / 'dev1')} {offsite.MAX_TRIES}\n")
    pack.write_bytes(full + b"junk")
    assert offsite.offsite_run("local", max_seconds=120) == 0
    assert pack.read_bytes() == full + b"junk"         # flagged: kept, not resent
    assert "dev1/" + str(pack.relative_to(off / "dev1")) in (tmp / "state" / "offsite-local.flagged").read_text()
    bad = [r for r in health.collect() if r[0] == "offsite local"][0]
    assert bad[1] is False and "1 flagged" in bad[2]


def test_offsite_without_target_or_hub_errors(hubenv):
    with pytest.raises(BackupError):
        offsite.offsite_run()
    with pytest.raises(BackupError):
        offsite.offsite_add("x!", "r:", False)
