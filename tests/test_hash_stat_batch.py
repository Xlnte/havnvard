"""hash_stat_batch.sh -- the remote stat-bound hash script (HV-REQ-04, 05, 06, 17).

Runs the REAL script under `sh` against files in tmp_path. GNU `stat -c`
accepts the same %s %Y %i %d %h %F format codes BusyBox does, so this exercises
the production script text, not a re-implementation.
"""
from __future__ import annotations

import hashlib
import os
import subprocess

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hash_stat_batch.sh")


def run_script(tmp_path, lines, batch="b1"):
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    (scratch / f"{batch}.paths").write_text("".join(l + "\n" for l in lines), encoding="utf-8")
    r = subprocess.run(["sh", SCRIPT, str(scratch), batch], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    hashes = (scratch / f"{batch}.hashes").read_text(encoding="utf-8").splitlines()
    errs = (scratch / f"{batch}.hasherrs").read_text(encoding="utf-8").splitlines()
    return hashes, errs


def test_hash_batch_output_parses_stat_fields(tmp_path):
    """3 regular files, a symlink, a missing path and an S line: H lines carry
    digest + 5 stat fields + path, S lines 5 stat fields + path, the trailer
    counts match, and error reasons are structured (HV-REQ-04/05/06/17)."""
    files = {}
    for name, body in (("a.txt", b"alpha" * 100), ("b.txt", b"beta"), ("sub dir|x.txt", b"pipe in path")):
        p = tmp_path / name.replace("|", "|")
        p.write_bytes(body)
        os.utime(p, (1_700_000_000, 1_700_000_000))
        files[str(p)] = body
    link = tmp_path / "link.txt"
    link.symlink_to(tmp_path / "a.txt")
    missing = tmp_path / "nope.txt"
    sib = tmp_path / "sib.txt"
    os.link(tmp_path / "a.txt", sib)

    lines = [f"H|{p}" for p in files] + [f"H|{link}", f"H|{missing}", f"S|{sib}", f"S|{tmp_path / 'ghost.txt'}"]
    hashes, errs = run_script(tmp_path, lines)

    h = [l for l in hashes if l.startswith("H|")]
    s = [l for l in hashes if l.startswith("S|")]
    assert len(h) == 3
    for line in h:
        f = line.split("|", 7)
        assert len(f) == 8
        _, sha, size, mtime, ino, dev, nlink, path = f
        assert sha == hashlib.sha256(files[path]).hexdigest()
        assert int(size) == len(files[path])
        assert int(mtime) == 1_700_000_000
        st = os.stat(path)
        assert (int(ino), int(dev)) == (st.st_ino, st.st_dev)
        assert int(nlink) == st.st_nlink
    assert any("|sub dir|x.txt" in l or l.endswith("sub dir|x.txt") for l in h)  # '|' in path survives (path is last field)
    assert len(s) == 1
    f = s[0].split("|", 6)
    assert len(f) == 7 and f[6] == str(sib)
    assert int(f[4]) == os.stat(sib).st_dev and int(f[3]) == os.stat(sib).st_ino
    assert int(f[5]) == 2  # sib + a.txt
    structured = {tuple(l.split("|", 1)) for l in errs if l.split("|", 1)[0] in ("MISSING", "UNREADABLE", "UNSTABLE", "NOT_REGULAR")}
    assert ("NOT_REGULAR", str(link)) in structured      # symlink rejected even though it points at a regular file
    assert ("MISSING", str(missing)) in structured
    assert ("MISSING", str(tmp_path / "ghost.txt")) in structured
    assert hashes[-1] == "#DONE|hashed=3|statonly=1|errors=3"
    assert sum(1 for l in hashes if l.startswith("#DONE")) == 1


def test_directory_and_nonregular_rejected(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    hashes, errs = run_script(tmp_path, [f"H|{d}", f"S|{d}"])
    assert ("NOT_REGULAR|" + str(d)) in errs
    assert errs.count("NOT_REGULAR|" + str(d)) == 2
    assert hashes == ["#DONE|hashed=0|statonly=0|errors=2"]


def test_empty_path_list_still_writes_trailer(tmp_path):
    hashes, errs = run_script(tmp_path, [])
    assert hashes == ["#DONE|hashed=0|statonly=0|errors=0"]


def test_recently_modified_file_is_unstable_not_hashed(tmp_path):
    """INFRA-520 G1 (racy-clean): mtime has 1-second resolution, so a file whose mtime is within 2 s of the
    batch start (on the hashing host's OWN clock) could still be rewritten inside the same second, keeping
    size and mtime. Such a digest would later look fresh while the bytes differ. The script refuses it
    (UNSTABLE, no H line); the next run hashes it once it has settled."""
    import time as _t
    now = int(_t.time())
    fresh = tmp_path / "just_written.bin"
    fresh.write_bytes(b"still being written")
    os.utime(fresh, (now, now))
    future = tmp_path / "future.bin"
    future.write_bytes(b"clock ahead")
    os.utime(future, (now + 3600, now + 3600))
    settled = tmp_path / "settled.bin"
    settled.write_bytes(b"old enough")
    os.utime(settled, (now - 60, now - 60))
    hashes, errs = run_script(tmp_path, [f"H|{fresh}", f"H|{future}", f"H|{settled}"])
    assert f"UNSTABLE|{fresh}" in errs
    assert f"UNSTABLE|{future}" in errs
    assert [l.rsplit("|", 1)[1] for l in hashes if l.startswith("H|")] == [str(settled)]
    assert hashes[-1] == "#DONE|hashed=1|statonly=0|errors=2"
