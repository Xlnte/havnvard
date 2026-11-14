"""Pure-function tests for nas_dedup_core.py (no DB, no SSH) -- HV-REQ-01..28 oracles."""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nas_dedup_core as core  # noqa: E402
from nas_dedup_core import Binding, Cand  # noqa: E402

SHA_A = "a" * 64
SHA_B = "b" * 64


def like_match(pattern: str, text: str) -> bool:
    """Emulate SQL LIKE ... ESCAPE '\\' (% = any run, _ = one char)."""
    rx, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            rx += re.escape(pattern[i + 1])
            i += 2
            continue
        rx += ".*" if ch == "%" else "." if ch == "_" else re.escape(ch)
        i += 1
    return re.fullmatch(rx, text, re.S) is not None


# ---- freshness ----------------------------------------------------------

def _row(**kw):
    base = dict(path="/p/a", size_bytes=100, mtime=1_700_000_000, inode=7, nlink=1, content_sha256=SHA_A)
    base.update(kw)
    return Cand(**base)


def _bind(**kw):
    base = dict(sha256=SHA_A, size_bytes=100, mtime=1_700_000_000, st_ino=7, st_dev=64520,
                bound_at=1_700_000_000 + 86_400)   # bound a day after the write (not racy)
    base.update(kw)
    return Binding(**base)


def test_digest_reusable_truth_table():
    assert core.digest_is_fresh(_row(), _bind()) is True
    assert core.digest_is_fresh(_row(size_bytes=101), _bind()) is False      # size changed
    assert core.digest_is_fresh(_row(mtime=1_700_000_001), _bind()) is False  # mtime changed
    assert core.digest_is_fresh(_row(inode=8), _bind()) is False             # inode changed (replaced file)
    assert core.digest_is_fresh(_row(), None) is False                       # no binding
    assert core.digest_is_fresh(_row(content_sha256=SHA_B), _bind()) is False  # foreign rewrite of the digest column
    assert core.digest_is_fresh(_row(content_sha256=None), _bind()) is False
    assert core.digest_is_fresh(_row(inode=None), _bind()) is False
    assert core.digest_is_fresh(_row(mtime=None), _bind()) is False


def test_digest_without_binding_is_rehashed():
    """A legacy digest (content_sha256 set, no binding) is planned as H (HV-REQ-08)."""
    plan = core.plan_hash_work([_row()], bindings={})
    assert [w.path for w in plan.to_hash] == ["/p/a"]
    assert plan.reused == 0 and plan.inherit_only == []


def test_fresh_digest_is_reused_not_sent():
    plan = core.plan_hash_work([_row()], {"/p/a": _bind()})
    assert plan.to_hash == [] and plan.reused == 1


def test_hardlink_siblings_ride_with_one_representative():
    cands = [_row(path="/p/long/b", inode=7, content_sha256=None), _row(path="/p/a", inode=7, content_sha256=None),
             _row(path="/p/other", inode=9, content_sha256=None)]
    plan = core.plan_hash_work(cands, {})
    reps = {w.path: w.siblings for w in plan.to_hash}
    assert reps == {"/p/a": ["/p/long/b"], "/p/other": []}   # shortest path is the representative


def test_fresh_rep_makes_stale_sibling_inherit_only():
    cands = [_row(path="/p/a"), _row(path="/p/b", content_sha256=None)]
    plan = core.plan_hash_work(cands, {"/p/a": _bind()})
    assert plan.to_hash == []
    assert [(w.path, w.siblings, w.needs_hash) for w in plan.inherit_only] == [("/p/a", ["/p/b"], False)]


def test_same_inode_different_mtime_is_not_grouped_for_inheritance():
    cands = [_row(path="/p/a", content_sha256=None), _row(path="/p/b", mtime=1_700_000_005, content_sha256=None)]
    plan = core.plan_hash_work(cands, {})
    assert sorted(w.path for w in plan.to_hash) == ["/p/a", "/p/b"] and all(w.siblings == [] for w in plan.to_hash)


def test_null_inode_never_groups():
    cands = [_row(path="/p/a", inode=None, content_sha256=None), _row(path="/p/b", inode=None, content_sha256=None)]
    plan = core.plan_hash_work(cands, {})
    assert len(plan.to_hash) == 2


# ---- scope --------------------------------------------------------------

def test_scope_directory_boundary():
    pat = core.like_prefix("/a/b")
    assert like_match(pat, "/a/b/x") and like_match(pat, "/a/b/x/y/z")
    assert not like_match(pat, "/a/bc")
    assert not like_match(pat, "/a/b")          # equality is a separate predicate
    assert not like_match(pat, "/a/bc/x")
    assert core.normalize_scope("/a/b/") == "/a/b"
    for bad in ("rel/path", "/", "//", "/a\nb"):
        with pytest.raises(ValueError):
            core.normalize_scope(bad)


def test_scope_like_wildcards_escaped():
    pat = core.like_prefix("/a/_x_/%y")
    assert pat == "/a/\\_x\\_/\\%y/%"
    assert like_match(pat, "/a/_x_/%y/file")
    assert not like_match(pat, "/a/QxQ/%y/file")      # '_' must not be a wildcard
    assert not like_match(pat, "/a/_x_/zzzy/file")    # '%' must not be a wildcard
    assert like_match(core.like_prefix("/a\\b"), "/a\\b/c")


# ---- batching -----------------------------------------------------------

def _work(n, size, prefix="/f"):
    return [core.RepWork(f"{prefix}{i}", size) for i in range(n)]


def test_batch_planner_size_cap():
    # 500-file cap
    b = core.plan_batches(_work(1201, 10), batch_size=500, batch_bytes=4 * 1024 ** 3)
    assert [x.h_count for x in b] == [500, 500, 201]
    # byte cap: 1 GiB each, 4 GiB cap -> 4 per batch
    gib = 1024 ** 3
    b = core.plan_batches(_work(9, gib), batch_size=500, batch_bytes=4 * gib)
    assert [x.h_count for x in b] == [4, 4, 1]
    # a 6 GiB file is a batch of one, even after small files; small files before it stay together
    work = _work(3, 100) + [core.RepWork("/huge", 6 * gib)]
    b = core.plan_batches(work, batch_size=500, batch_bytes=4 * gib)
    assert [[p for k, p in x.items if k == "H"] for x in b] == [["/f0", "/f1", "/f2"], ["/huge"]]
    # S items stay with their H rep, in the same batch
    work = [core.RepWork("/r1", 10, ["/s1", "/s2"]), core.RepWork("/r2", 20, ["/s3"])]
    b = core.plan_batches(work, batch_size=1, batch_bytes=gib)
    assert b[0].items == [("H", "/r1"), ("S", "/s1"), ("S", "/s2")] and b[0].rep_of == {"/s1": "/r1", "/s2": "/r1"}
    assert b[1].items == [("H", "/r2"), ("S", "/s3")]
    # plan_hash_work output is ascending by size
    plan = core.plan_hash_work([_row(path=f"/p/{n}", size_bytes=s, inode=i, content_sha256=None)
                                for i, (n, s) in enumerate([("big", 900), ("small", 5), ("mid", 50)])], {})
    assert [w.size_bytes for w in plan.to_hash] == [5, 50, 900]


def test_stat_only_batches():
    w = [core.RepWork("/r", 1, [f"/s{i}" for i in range(5)], needs_hash=False)]
    b = core.plan_stat_batches(w, per_batch=2)
    assert [len(x.items) for x in b] == [2, 2, 1] and all(k == "S" for x in b for k, _ in x.items)


def test_batch_timeout_scales_with_bytes():
    assert core.batch_timeout(500 * 4096) == 600
    assert core.batch_timeout(6_200_000_000) == 600          # 120 + 310 = 430 -> floor-clamped
    assert core.batch_timeout(50_000_000_000) == 2620        # 120 + 2500
    assert core.batch_timeout(50_000_000_000, assumed_mbps=100) == 620


# ---- batch verification -------------------------------------------------

def _h(path, sha=SHA_A, size=10, mtime=1, ino=2, dev=3, nlink=1):
    return f"H|{sha}|{size}|{mtime}|{ino}|{dev}|{nlink}|{path}"


def _s(path, size=10, mtime=1, ino=2, dev=3, nlink=1):
    return f"S|{size}|{mtime}|{ino}|{dev}|{nlink}|{path}"


def _t(h, s, e):
    return f"#DONE|hashed={h}|statonly={s}|errors={e}"


def test_verify_batch_ok():
    sent = [("H", "/a"), ("S", "/b"), ("H", "/c"), ("H", "/d")]
    hashes = "\n".join([_h("/a"), _s("/b"), _h("/d", sha=SHA_B), _t(2, 1, 1)]) + "\n"
    errs = "MISSING|/c\nsha256sum: noise line\n"
    r = core.verify_batch(sent, hashes, errs)
    assert [x.path for x in r.hashed] == ["/a", "/d"] and r.hashed[0].st_dev == 3 and r.hashed[0].sha256 == SHA_A
    assert [x.path for x in r.stat] == ["/b"] and r.errors == [("MISSING", "/c")]


def test_missing_line_fails_batch():
    sent = [("H", "/a"), ("H", "/c")]
    with pytest.raises(core.BatchIntegrityError, match="accounted for"):
        core.verify_batch(sent, _h("/a") + "\n" + _t(1, 0, 0) + "\n", "")


def test_extra_path_fails_batch():
    sent = [("H", "/a")]
    with pytest.raises(core.BatchIntegrityError, match="not sent"):
        core.verify_batch(sent, _h("/a") + "\n" + _h("/zzz") + "\n" + _t(2, 0, 0) + "\n", "")
    with pytest.raises(core.BatchIntegrityError, match="not sent as S"):    # kind confusion
        core.verify_batch([("H", "/a"), ("H", "/b")], _h("/a") + "\n" + _s("/b") + "\n" + _t(1, 1, 0) + "\n", "")
    with pytest.raises(core.BatchIntegrityError, match="twice"):
        core.verify_batch([("H", "/a")], _h("/a") + "\n" + _h("/a") + "\n" + _t(2, 0, 0) + "\n", "")


def test_missing_trailer_fails_batch():
    with pytest.raises(core.BatchIntegrityError, match="trailer"):
        core.verify_batch([("H", "/a")], _h("/a") + "\n", "")
    with pytest.raises(core.BatchIntegrityError, match="trailer"):        # truncated mid-line, no trailer
        core.verify_batch([("H", "/a"), ("H", "/b")], _h("/a") + "\n" + "H|abc", "")


def test_malformed_digest_fails_batch():
    bad = [_h("/a", sha="g" * 64), _h("/a", sha="A" * 64), _h("/a", sha="a" * 63), f"H|{SHA_A}|x|1|2|3|4|/a"]
    for line in bad:
        with pytest.raises(core.BatchIntegrityError, match="malformed"):
            core.verify_batch([("H", "/a")], line + "\n" + _t(1, 0, 0) + "\n", "")
    # control byte inside the digest field (the 2026-08-30 echo-escape corruption)
    with pytest.raises(core.BatchIntegrityError):
        core.verify_batch([("H", "/a")], "H|\x89" + "a" * 63 + "|1|1|1|1|1|/a\n" + _t(1, 0, 0) + "\n", "")


def test_trailer_count_mismatch_fails_batch():
    with pytest.raises(core.BatchIntegrityError, match="trailer counts"):
        core.verify_batch([("H", "/a")], _h("/a") + "\n" + _t(5, 0, 0) + "\n", "")


def test_parse_path_with_pipe():
    p = "/share/a|b|c d.txt"
    r = core.verify_batch([("H", p), ("S", "/x|y")], _h(p) + "\n" + _s("/x|y") + "\n" + _t(1, 1, 0) + "\n", "")
    assert r.hashed[0].path == p and r.stat[0].path == "/x|y"


def test_file_changed_during_hash_is_unstable():
    """UNSTABLE comes back as a structured error and is counted, never as a digest.
    (The script-level 'file mutates between pre- and post-stat' case is a race and is
    not simulated -- deviation recorded in the runbook; the logic is the pre5 != post
    comparison in hash_stat_batch.sh, covered by review.)"""
    r = core.verify_batch([("H", "/a")], _t(0, 0, 1) + "\n", "UNSTABLE|/a\n")
    assert r.errors == [("UNSTABLE", "/a")] and r.hashed == []


def test_unsafe_and_non_utf8_paths_not_sent():
    assert core.classify_path("/ok/file") is None
    assert core.classify_path("/bad\nname") == "UNSAFE_PATH"
    assert core.classify_path("/bad\rname") == "UNSAFE_PATH"
    assert core.classify_path("/bad\udc89name") == "NON_UTF8_PATH"


def test_every_line_break_and_control_char_is_unsafe_path():
    """BH-1: str.splitlines() breaks on \\x0b \\x0c \\x1c-\\x1e \\x85 U+2028 U+2029 as well; all C0 controls and DEL are refused."""
    for ch in ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\t", "\x01", "\x1f", "\x7f", "\x00", "\n", "\r"]:
        assert core.classify_path(f"/a/b{ch}c") == "UNSAFE_PATH", repr(ch)
    assert core.classify_path("/a/caf\u00e9 \u4e2d\u6587 '\"*?[]|%_ \\.bin") is None     # ordinary awkward names stay legal


def test_replacement_char_path_is_non_utf8():
    """BH-8: scan.safe_str stores undecodable bytes as U+FFFD, which the NAS can never stat back."""
    assert core.classify_path("/share/x/caf\ufffd.bin") == "NON_UTF8_PATH"


# ---- keeper rule --------------------------------------------------------

def test_keeper_rule_order():
    cands = [
        ("/z/long/path/file", 100),     # later mtime
        ("/z/a_file", 50),               # earliest mtime, but longer than b
        ("/z/b", 50),                    # earliest mtime, shortest -> keeper
        ("/z/c", 50),                    # same mtime, same length as b, bytewise larger
    ]
    key = lambda c: core.keeper_sort_key(c[0], c[1])
    assert min(cands, key=key)[0] == "/z/b"
    assert [c[0] for c in sorted(cands, key=key)] == ["/z/b", "/z/c", "/z/a_file", "/z/long/path/file"]


def test_keeper_never_in_recycle_when_alternative():
    recycle = ("/share/CACHEDEV1_DATA/Public/@Recycle/old", 1)       # oldest AND shortest
    other = ("/share/CACHEDEV1_DATA/Public/some/much/longer/path.bin", 9_999)
    thumb = ("/share/x/.@__thumb/t", 1)
    key = lambda c: core.keeper_sort_key(c[0], c[1])
    assert min([recycle, other], key=key) == other
    assert min([thumb, other], key=key) == other


def test_keeper_never_in_backup_tree_when_alternative():
    """BH-3 / HV-REQ-28: a bkup_test replica (oldest mtime, shortest path) is never the keeper while a live copy exists."""
    backup = ("/share/CACHEDEV1_DATA/bkup_test/a", 1)
    live = ("/share/CACHEDEV1_DATA/Public/some/much/longer/path.bin", 9_999)
    recycle_live = ("/share/CACHEDEV1_DATA/Public/@Recycle/x", 2)
    key = lambda c: core.keeper_sort_key(c[0], c[1])
    assert min([backup, live], key=key) == live
    assert min([backup, recycle_live], key=key) == backup          # recycle outranks backup in the rule order
    assert min([backup, ("/share/CACHEDEV1_DATA/bkup_test_other/z", 5)], key=key) == ("/share/CACHEDEV1_DATA/bkup_test_other/z", 5)


# ---- progress -----------------------------------------------------------

def test_heartbeat_note_has_rate_and_eta():
    n = core.format_progress(done=1500, total=753487, done_bytes=3_000_000_000, total_bytes=1_100_000_000_000,
                             run_elapsed_s=300, last_files=500, last_bytes=1_000_000_000, last_elapsed_s=29,
                             batch_no=3, batch_files=1, batch_bytes=6_200_000_000, batch_elapsed_s=1203)
    for token in ("hashed 1500/753487", "f/s last", "f/s run", "MB/s last", "MB/s run", "ETA", " h", "batch 3: 1 file, 6.2 GB, 1,203 s elapsed"):
        assert token in n, (token, n)
    # ETA is the max of the file-count and byte-count estimates
    assert re.search(r"ETA (\d+\.\d) h", n)
    assert "ETA n/a" in core.format_progress(0, 10, 0, 100, 0)


# ---- INFRA-520 G1: racy-clean freshness ----------------------------------

def test_digest_bound_too_close_to_mtime_is_not_fresh():
    """A digest taken within RACY_MARGIN_S of the file's mtime cannot prove the bytes it read are the bytes
    the mtime describes (same-second rewrite keeps size and mtime). Such a binding is never reused and
    never published (publish SQL mirrors this term)."""
    from datetime import datetime, timezone
    mt = 1_700_000_000
    def at(s):
        return datetime.fromtimestamp(s, timezone.utc)
    assert core.digest_is_fresh(_row(), _bind(bound_at=at(mt + core.RACY_MARGIN_S))) is True
    assert core.digest_is_fresh(_row(), _bind(bound_at=at(mt + 1))) is False      # same / next second: racy
    assert core.digest_is_fresh(_row(), _bind(bound_at=at(mt))) is False
    assert core.digest_is_fresh(_row(), _bind(bound_at=at(mt - 100))) is False    # bound BEFORE the write
    assert core.digest_is_fresh(_row(), _bind(bound_at=None)) is False             # unknown bind time
    assert core.digest_is_fresh(_row(), _bind(bound_at=mt + 3600)) is True         # epoch number also accepted
    plan = core.plan_hash_work([_row()], {"/p/a": _bind(bound_at=at(mt + 1))})
    assert [w.path for w in plan.to_hash] == ["/p/a"] and plan.reused == 0       # racy -> re-hashed
