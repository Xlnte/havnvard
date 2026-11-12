"""verify_tree.py (HavnVard 1.5.0, INFRA-538): full-byte proof before deletion.

The operator's test case first: one lowercase `m` changed to capital `M` in a book-sized text file must
read as DIFFERENT, with size, name and mtime all equal. The "NAS" here is a LocalShellTarget:
the REAL remote_script() runs under `sh` (dash, the same POSIX family as the NAS BusyBox ash)
against a tmp dir, so the production command text and parser are exercised end to end.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from types import SimpleNamespace

import psycopg
import pytest

import verify_tree as vt
from conftest import connect_retry, rewrite


class LocalShellTarget:
    """ssh -> `sh -c` locally; scp_put -> copy. Knobs: hash_override(text)->text rewrites the
    remote stdout (e.g. a broken NAS that ignores content); ssh_rc forces an ssh failure."""

    def __init__(self, tmp_path):
        self.scratch_dir = str(tmp_path / "nas_scratch")
        os.makedirs(self.scratch_dir, exist_ok=True)
        self.hash_override = None
        self.ssh_rc = None
        self.calls = []

    def ssh(self, cmd, timeout_sec=None):
        self.calls.append((cmd, timeout_sec))
        if self.ssh_rc is not None and "sha256sum" in cmd:
            return subprocess.CompletedProcess([], self.ssh_rc, stdout="", stderr="forced")
        r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=60)
        out = r.stdout
        if self.hash_override and "sha256sum" in cmd:
            out = self.hash_override(out)
        return subprocess.CompletedProcess([], r.returncode, stdout=out, stderr=r.stderr)

    def scp_put(self, local_path, remote_path, timeout_sec=None):
        shutil.copy2(local_path, remote_path)
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")


def _tree(root, files: dict):
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        os.utime(p, (1_700_000_000, 1_700_000_000))
    return str(root)


@pytest.fixture
def pair(tmp_path):
    return str(tmp_path / "local"), str(tmp_path / "nas"), LocalShellTarget(tmp_path)


# ---------------------------------------------------------------- the operator's m -> M case

def test_m_to_M_is_different_with_equal_size_name_mtime(pair):
    local, nas, t = pair
    original, mutated = vt.canary_texts()
    assert len(original) == vt.CANARY_SIZE == len(mutated) > 2 * 4 * 1024 * 1024
    diffs = [i for i, (a, b) in enumerate(zip(original, mutated)) if a != b]
    assert len(diffs) == 1 and diffs[0] > 2 * 4 * 1024 * 1024        # in the last, partial chunk
    assert original[diffs[0]:diffs[0] + 1] == b"m" and mutated[diffs[0]:diffs[0] + 1] == b"M"
    _tree(nas, {"book.txt": original})
    _tree(local, {"book.txt": mutated})
    st_l, st_n = os.stat(f"{local}/book.txt"), os.stat(f"{nas}/book.txt")
    assert (st_l.st_size, int(st_l.st_mtime)) == (st_n.st_size, int(st_n.st_mtime))
    verdict, results, reason, _ = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_MISMATCH, reason
    assert [r.verdict for r in results] == [vt.V_MISMATCH]


def test_identical_trees_verify(pair):
    local, nas, t = pair
    files = {"a.sql.gz": os.urandom(5000), "sub/b.dump": b"x" * 10, "space name.txt": b"hi"}
    _tree(local, files)
    _tree(nas, files)
    verdict, results, reason, stats = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_VERIFIED, reason
    assert stats["files"] == 3 and {r.verdict for r in results} == {vt.V_MATCH}


# ---------------------------------------------------------------- incomplete = NOT_VERIFIED

def test_missing_and_extra_files(pair):
    local, nas, t = pair
    _tree(local, {"a": b"1", "b": b"2"})
    _tree(nas, {"a": b"1", "c": b"3"})
    verdict, results, _, _ = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_NOT_VERIFIED
    by = {r.rel: r.verdict for r in results}
    assert by["./b"] == vt.V_MISSING_DEST and by["./c"] == vt.V_EXTRA_DEST and by["./a"] == vt.V_MATCH


def test_empty_tree_is_not_verified(pair):
    local, nas, t = pair
    os.makedirs(local)
    os.makedirs(nas)
    assert vt.verify_pair(local, nas, t)[0] == vt.T_NOT_VERIFIED


def test_missing_nas_dir_is_not_verified(pair):
    local, nas, t = pair
    _tree(local, {"a": b"1"})
    verdict, _, reason, _ = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_NOT_VERIFIED and "NAS_PATH_MISSING" in reason


def test_local_symlink_and_unsafe_name_block(pair):
    local, nas, t = pair
    _tree(local, {"a": b"1", "bad\\name": b"2"})
    _tree(nas, {"a": b"1", "bad\\name": b"2"})
    os.symlink("a", f"{local}/link")
    verdict, results, _, _ = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_NOT_VERIFIED
    notes = " ".join(r.notes for r in results)
    assert "NON_REGULAR" in notes and "BACKSLASH_PATH" in notes


def test_unreadable_local_file(pair):
    if os.geteuid() == 0:
        pytest.skip("root reads mode-000 files")
    local, nas, t = pair
    _tree(local, {"a": b"1"})
    _tree(nas, {"a": b"1"})
    os.chmod(f"{local}/a", 0)
    try:
        verdict, results, _, _ = vt.verify_pair(local, nas, t)
    finally:
        os.chmod(f"{local}/a", 0o644)
    assert verdict == vt.T_NOT_VERIFIED and results[0].verdict == vt.V_UNREADABLE_SOURCE


def test_ssh_failure_is_not_verified(pair):
    local, nas, t = pair
    _tree(local, {"a": b"1"})
    _tree(nas, {"a": b"1"})
    t.ssh_rc = 124
    verdict, _, reason, _ = vt.verify_pair(local, nas, t)
    assert verdict == vt.T_NOT_VERIFIED and "SSH_RC:124" in reason


# ---------------------------------------------------------------- parser

SHA = "a" * 64


def _out(nonreg="", files="./a\n", hashes=f"{SHA}  ./a\n", rcs=("0", "0", "0"), end="END|\n"):
    return (f"BEGIN_NONREG|\n{nonreg}RC_NONREG|{rcs[0]}\n"
            f"BEGIN_FILE|\n{files}RC_FILE|{rcs[1]}\n"
            f"BEGIN_HASH|\n{hashes}RC_HASH|{rcs[2]}\n{end}")


@pytest.mark.parametrize("out,why", [
    (_out(end=""), "NO_END_MARKER"),
    (_out(rcs=("0", "0", "1")), "RC_HASH:1"),
    (_out(rcs=("0", "1", "0")), "RC_FILE:1"),
    (_out(hashes=""), vt.V_UNREADABLE_DEST),
    (_out(hashes=f"\\{SHA}  ./a\\\\b\n"), "ESCAPED_HASH_LINE"),
    (_out(hashes=f"{SHA}  ./a\n{SHA}  ./a\n"), "DUPLICATE_HASH_LINE"),
    (_out(nonreg="./lnk\n"), "NON_REGULAR_DEST"),
    (_out(hashes=f"{SHA}  ./a\n{SHA}  ./b\n"), "HASH_WITHOUT_FILE"),
    (_out(hashes=f"{SHA}  ./a\ngarbage\n"), "BAD_HASH_LINE"),
    (_out(files="./a\ncontinued-name\n"), "BAD_NAME_LINE"),
    (_out() + "trailing\n", "AFTER_END"),
    ("CDFAIL|\n", "NAS_PATH_MISSING"),
    (f"BEGIN_FILE|\n./a\nRC_FILE|0\nBEGIN_HASH|\n{SHA}  ./a\nRC_HASH|0\nEND|\n", "UNEXPECTED_LINE"),
])
def test_parse_remote_incomplete(out, why):
    t = vt.parse_remote(out, 0)
    assert not t.complete and why in {w for _, w in t.problems}, t.problems


def test_parse_remote_complete():
    t = vt.parse_remote(_out(files="./a b\n", hashes=f"{SHA}  ./a b\n"), 0)
    assert t.complete and t.hashes == {"./a b": SHA}


def test_parse_remote_ssh_rc():
    assert "SSH_RC:97" in {w for _, w in vt.parse_remote("CDFAIL|\n", 97).problems}


def test_nas_timeout_scales():
    assert vt.nas_timeout(0) == 600
    assert vt.nas_timeout(13_000_000_000) == 1301


# ---------------------------------------------------------------- canary

def test_canary_passes_on_honest_target(tmp_path):
    t = LocalShellTarget(tmp_path)
    ok, why = vt.run_canary(t)
    assert ok, why
    assert os.listdir(t.scratch_dir) == []          # NAS canary dir removed


@pytest.mark.parametrize("idx", range(6))
def test_canary_5_plus_1_any_position(tmp_path, idx):
    """The operator 20261110: 5 identical copies + 1 m->M copy. Whichever of the 6 holds the change,
    only that file reads different and the run passes."""
    ok, why = vt.run_canary(LocalShellTarget(tmp_path), planted_index=idx)
    assert ok, why
    assert f"only book_{idx + 1}.txt different" in why


def test_canary_fails_if_every_file_reads_different(tmp_path, monkeypatch):
    """A broken path that called ALL 6 files different would still say MISMATCH for the tree.
    The 5+1 canary requires exactly the planted file different, so it fails."""
    real = vt.verify_pair

    def all_differ(local, nas, target):
        verdict, results, reason, stats = real(local, nas, target)
        if verdict == vt.T_MISMATCH:
            results = [vt.FileResult(r.rel, r.size_bytes, r.sha_source, r.sha_dest, vt.V_MISMATCH) for r in results]
        return verdict, results, reason, stats
    monkeypatch.setattr(vt, "verify_pair", all_differ)
    ok, why = vt.run_canary(LocalShellTarget(tmp_path), planted_index=2)
    assert not ok and "5 copies + 1" in why


def test_canary_fails_if_wrong_file_reads_different(tmp_path, monkeypatch):
    real = vt.verify_pair

    def swap(local, nas, target):
        verdict, results, reason, stats = real(local, nas, target)
        out = []
        for r in results:
            v = {vt.V_MATCH: vt.V_MISMATCH, vt.V_MISMATCH: vt.V_MATCH}[r.verdict] if verdict == vt.T_MISMATCH and r.rel in ("./book_1.txt", "./book_2.txt") else r.verdict
            out.append(vt.FileResult(r.rel, r.size_bytes, r.sha_source, r.sha_dest, v))
        return verdict, out, reason, stats
    monkeypatch.setattr(vt, "verify_pair", swap)
    ok, why = vt.run_canary(LocalShellTarget(tmp_path), planted_index=0)
    assert not ok


def test_canary_fails_if_an_extra_row_hides_behind_a_match(tmp_path, monkeypatch):
    """Opus 1.6.0 #1: an extra NOT_VERIFIED row for a canary name, listed before its MATCH row,
    must not be collapsed away by the per-name dict. Exactly 6 rows are required."""
    real = vt.verify_pair

    def extra_row(local, nas, target):
        verdict, results, reason, stats = real(local, nas, target)
        bogus = vt.FileResult("./book_1.txt", None, None, None, vt.V_NOT_VERIFIED, "dest:X")
        return verdict, [bogus] + list(results), reason, stats
    monkeypatch.setattr(vt, "verify_pair", extra_row)
    ok, why = vt.run_canary(LocalShellTarget(tmp_path), planted_index=3)
    assert not ok and "5 copies + 1" in why


def test_canary_fails_if_a_copy_is_missing_on_nas(tmp_path):
    """The NAS listing drops one of the 6 copies: neither check can pass."""
    t = LocalShellTarget(tmp_path)
    t.hash_override = lambda out: "\n".join(l for l in out.split("\n") if "book_4.txt" not in l)
    ok, why = vt.run_canary(t, planted_index=0)
    assert not ok


def test_canary_fails_when_nas_cp_fails(tmp_path):
    t = LocalShellTarget(tmp_path)
    real = t.ssh
    t.ssh = lambda cmd, timeout_sec=None: (subprocess.CompletedProcess([], 1, "", "no cp")
                                           if " cp " in f" {cmd}" else real(cmd, timeout_sec))
    ok, why = vt.run_canary(t)
    assert not ok and "cp rc=1" in why
    assert os.listdir(t.scratch_dir) == []          # still cleaned up


def test_canary_fails_when_nas_hash_ignores_content(tmp_path):
    """A broken NAS path that always reports the ORIGINAL's digest would let m->M read as a
    match. The canary must catch it."""
    original, _ = vt.canary_texts()
    import hashlib  # noqa: PLC0415
    fixed = hashlib.sha256(vt.canary_texts()[1]).hexdigest()   # always report the MUTATED digest
    t = LocalShellTarget(tmp_path)
    t.hash_override = lambda out: "\n".join(
        (fixed + l[64:]) if len(l) > 66 and l[64:66] == "  " else l for l in out.split("\n"))
    ok, why = vt.run_canary(t)
    assert not ok and "m->M" in why


def test_canary_fails_when_nas_always_differs(tmp_path):
    t = LocalShellTarget(tmp_path)
    t.hash_override = lambda out: out.replace("  ./", "  ./zz")    # names never line up
    ok, why = vt.run_canary(t)
    assert not ok


def test_canary_uses_the_real_comparison_path(tmp_path, monkeypatch):
    """If verify_pair (the code the real check uses) were broken to always say VERIFIED, the
    canary must fail: it cannot have a private, healthier comparison of its own."""
    monkeypatch.setattr(vt, "verify_pair", lambda *a, **k: (vt.T_VERIFIED, [], "forced", {}))
    assert vt.cmd_canary(SimpleNamespace(), target=LocalShellTarget(tmp_path)) == vt.EXIT_CANARY


def test_head_only_hash_would_be_caught(tmp_path, monkeypatch):
    """A local hasher that read only the first 8 MiB would miss the flip: the canary fails."""
    import hashlib  # noqa: PLC0415

    def head_only(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read(8 * 1024 * 1024)).hexdigest()
    monkeypatch.setattr(vt.cv, "local_content_hash", head_only)
    t = LocalShellTarget(tmp_path)
    t.hash_override = None
    ok, why = vt.run_canary(t)
    assert not ok


def test_local_root_guards(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    os.symlink(d, tmp_path / "ln")
    assert vt.local_root_problem(str(d)) is None
    assert "symlink" in vt.local_root_problem(str(tmp_path / "ln"))
    assert "missing" in vt.local_root_problem(str(tmp_path / "nope"))
    mounts = tmp_path / "mounts"
    mounts.write_text(f"/dev/x / ext4 rw 0 0\nnas:/v {tmp_path} nfs4 rw 0 0\n")
    assert "network filesystem" in vt.local_root_problem(str(d), str(mounts))


def test_local_root_guard_autofs_then_nfs_same_mountpoint(tmp_path):
    """Opus diff review H1: the live /proc/mounts lists /mnt/nas-bkup-spark twice, `autofs`
    first and the real `nfs` mount on top. The longest-prefix match must take the LAST line
    on a tie, or the NFS-mounted NAS share passes as a local dir and is compared to itself."""
    d = tmp_path / "share"
    d.mkdir()
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/nvme0n1p2 / ext4 rw 0 0\n"
        f"systemd-1 {d} autofs rw,relatime,fd=70 0 0\n"
        f"192.0.2.40:/bkup_test {d} nfs rw,vers=3 0 0\n")
    assert "nfs" in vt.local_root_problem(str(d), str(mounts))
    only_autofs = tmp_path / "mounts2"
    only_autofs.write_text(f"/dev/x / ext4 rw 0 0\nsystemd-1 {d} autofs rw 0 0\n")
    assert "autofs" in vt.local_root_problem(str(d), str(only_autofs))


def test_local_fifo_is_not_verified_and_never_opened(pair):
    """Fable #2: a FIFO is refused by the lstat gate BEFORE any open(); open() on a FIFO with
    no writer would block forever."""
    import time  # noqa: PLC0415
    local, nas, t = pair
    _tree(local, {"a": b"1"})
    _tree(nas, {"a": b"1"})
    os.mkfifo(f"{local}/pipe")
    t0 = time.monotonic()
    verdict, results, _, _ = vt.verify_pair(local, nas, t)
    assert time.monotonic() - t0 < 5
    assert verdict == vt.T_NOT_VERIFIED
    assert any(r.rel == "./pipe" and "NON_REGULAR" in r.notes for r in results)


def test_canary_cleanup_has_no_recursive_delete(tmp_path):
    """The canary cleanup removes one named file then rmdirs; it never issues rm -rf."""
    t = LocalShellTarget(tmp_path)
    nas_dir = f"{t.scratch_dir}/verify_tree_canary_1_2"
    os.makedirs(nas_dir)
    for n in vt.CANARY_NAMES:
        open(f"{nas_dir}/{n}", "w").close()
    vt._remove_canary_dir(t, t.scratch_dir, nas_dir)
    assert not os.path.exists(nas_dir)
    assert all("rm -rf" not in c for c, _ in t.calls)
    # a foreign file in the canary dir is never removed: rmdir fails, the file stays
    os.makedirs(nas_dir)
    open(f"{nas_dir}/other", "w").close()
    vt._remove_canary_dir(t, t.scratch_dir, nas_dir)
    assert os.path.exists(f"{nas_dir}/other")


def test_canary_cleanup_refuses_foreign_path(tmp_path):
    t = LocalShellTarget(tmp_path)
    with pytest.raises(ValueError):
        vt._remove_canary_dir(t, t.scratch_dir, t.scratch_dir + "/../etc")
    with pytest.raises(ValueError):
        vt._remove_canary_dir(t, t.scratch_dir, "/share/other/verify_tree_canary_1")


# ---------------------------------------------------------------- CLI + DB (throwaway schema)

@pytest.fixture(scope="module")
def tv_schema():
    schema = "diskaudit_t_tv" + uuid.uuid4().hex[:8]
    try:
        admin = connect_retry(autocommit=True)
    except psycopg.OperationalError as e:
        pytest.skip(f"DB not reachable: {e}")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with admin.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {schema}")
            cur.execute(f"CREATE TABLE {schema}.integrity_checks (LIKE diskaudit.integrity_checks INCLUDING ALL)")
            with open(os.path.join(here, "migrations", "20261110_diskaudit_tree_verify_v1.sql")) as f:
                sql = rewrite(f.read(), schema)
            cur.execute(sql)
            cur.execute(sql)                      # idempotent
        yield schema
    finally:
        with admin.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        admin.close()


@pytest.fixture
def connect(tv_schema):
    from _dbguard import GuardedConn  # noqa: PLC0415
    return lambda: GuardedConn(connect_retry(), tv_schema)


def _args(local, nas):
    return SimpleNamespace(local=local, nas_path=nas, purpose="pytest", local_host="test-host",
                           nas_host="test-nas")


def test_cli_verified_records_and_mark_deleted(pair, connect, capsys, monkeypatch):
    local, nas, t = pair
    monkeypatch.setattr(vt, "_alarm", lambda text: pytest.fail(f"alarm: {text}"))
    _tree(local, {"a": b"1", "b": b"22"})
    _tree(nas, {"a": b"1", "b": b"22"})
    args = _args(local, nas)
    monkeypatch.setattr(vt, "_nas_path_ok", lambda p: True)
    rc = vt.cmd_verify(args, target=t, connect=connect)
    out = capsys.readouterr().out
    assert rc == vt.EXIT_VERIFIED, out
    run_id = int(out.split("VERIFY_RUN_ID=")[1].split()[0])
    c = connect()
    row = c.cursor().execute("SELECT verdict, files, canary_ok FROM diskaudit.tree_verifications WHERE run_id=%s",
                    (run_id,)).fetchone()
    assert row == ("VERIFIED", 2, True)
    n = c.cursor().execute("SELECT count(*) FROM diskaudit.integrity_checks WHERE tree_run_id=%s AND basis='fresh' "
                  "AND verdict='match'", (run_id,)).fetchone()[0]
    assert n == 2
    c.close()
    assert vt.cmd_mark_deleted(SimpleNamespace(run_id=run_id), connect=connect) == 0
    assert vt.cmd_mark_deleted(SimpleNamespace(run_id=run_id), connect=connect) == vt.EXIT_NOT_VERIFIED


def test_cli_mismatch_exit3_and_cannot_mark_deleted(pair, connect, capsys, monkeypatch):
    local, nas, t = pair
    monkeypatch.setattr(vt, "_nas_path_ok", lambda p: True)
    _tree(local, {"a": b"m"})
    _tree(nas, {"a": b"M"})
    assert vt.cmd_verify(_args(local, nas), target=t, connect=connect) == vt.EXIT_NOT_VERIFIED
    out = capsys.readouterr().out
    run_id = int(out.split("VERIFY_RUN_ID=")[1].split()[0])
    assert "VERDICT=MISMATCH" in out
    assert vt.cmd_mark_deleted(SimpleNamespace(run_id=run_id), connect=connect) == vt.EXIT_NOT_VERIFIED


def test_cli_db_failure_is_not_verified(pair, capsys, monkeypatch):
    local, nas, t = pair
    monkeypatch.setattr(vt, "_nas_path_ok", lambda p: True)
    _tree(local, {"a": b"1"})
    _tree(nas, {"a": b"1"})

    def boom():
        raise psycopg.OperationalError("db down")
    assert vt.cmd_verify(_args(local, nas), target=t, connect=boom) == vt.EXIT_NOT_VERIFIED
    assert "result not recorded" in capsys.readouterr().out


def test_cli_canary_failure_exit4_and_alarm(pair, connect, capsys, monkeypatch):
    local, nas, t = pair
    monkeypatch.setattr(vt, "_nas_path_ok", lambda p: True)
    alarms = []
    monkeypatch.setattr(vt, "_alarm", alarms.append)
    _tree(local, {"a": b"1"})
    _tree(nas, {"a": b"1"})
    t.hash_override = lambda out: out.replace("  ./", "  ./zz")
    assert vt.cmd_verify(_args(local, nas), target=t, connect=connect) == vt.EXIT_CANARY
    assert alarms and "VERDICT=CANARY_FAILED" in capsys.readouterr().out


def test_cli_rejects_non_share_nas_path(pair, capsys):
    local, nas, t = pair
    _tree(local, {"a": b"1"})
    assert vt.cmd_verify(_args(local, "/tmp/../etc"), target=t, connect=None) == vt.EXIT_USAGE
