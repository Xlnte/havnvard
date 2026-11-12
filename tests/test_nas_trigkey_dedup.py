"""nas_trigkey_dedup.py -- DB + fake-SSH tests (HV-REQ-01..29, 31).

Everything runs against a THROWAWAY schema (conftest `nd_schema`) through a
GuardedConn that redirects `diskaudit.` to it and refuses real-host writes; the
remote side is FakeTarget (real hash_stat_batch.sh on local files) or a scripted
responder for stat values a local filesystem cannot produce (e.g. st_dev).
No production row is read-for-write, no NAS is contacted.
"""
from __future__ import annotations

import hashlib
import os
import re
import signal
import time
import uuid

import psycopg
import pytest

import conftest
import nas_dedup_core as core
import nas_trigkey_dedup as nd
import monitor
from _dbguard import GuardedConn, GuardedCursor, RealHostWriteRefused
from _fake_target import FakeTarget

MTIME = 1_700_000_000
X = b"content-X-" * 40          # 400 bytes
Y = b"content-Y-" * 40
Z = b"content-Z-" * 40


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Env:
    """One synthetic host + a real directory tree + a FakeTarget."""

    def __init__(self, gconn, factory, tmp_path, tag="nd"):
        self.conn, self.factory, self.tmp = gconn, factory, tmp_path
        self.host = f"_test_{tag}_{uuid.uuid4().hex[:8]}"
        base = tmp_path / tag
        base.mkdir(exist_ok=True)
        self.root = base / "data"
        self.root.mkdir()
        self.target = FakeTarget(base)
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO diskaudit.scan_runs (host, status) VALUES (%s, 'completed') RETURNING scan_id", (self.host,))
            self.scan_id = cur.fetchone()[0]
        self.conn.commit()

    # -- filesystem + inventory ------------------------------------------------
    def mk(self, rel, body, mtime=MTIME):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
        os.utime(p, (mtime, mtime))
        return str(p)

    def link(self, src, rel):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        os.link(src, p)
        return str(p)

    def add(self, path, size=None, mtime=None, inode=None, nlink=None, sha_=None, still_exists=True,
            file_type="regular", tool=None, group=None):
        """Insert an inventory row; unspecified stat fields come from the real file."""
        if size is None or mtime is None or inode is None or nlink is None:
            st = os.lstat(path)
            size = st.st_size if size is None else size
            mtime = int(st.st_mtime) if mtime is None else mtime
            inode = st.st_ino if inode is None else inode
            nlink = st.st_nlink if nlink is None else nlink
        with self.conn.cursor() as cur:
            cur.execute(
                """INSERT INTO diskaudit.files (host, path, file_type, size_bytes, still_exists, first_seen_scan_id,
                       last_seen_scan_id, content_sha256, inode, nlink, mtime, dedup_tool, duplicate_group_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,to_timestamp(%s),%s,%s)
                   ON CONFLICT (host, path) DO UPDATE SET size_bytes=EXCLUDED.size_bytes, mtime=EXCLUDED.mtime,
                       inode=EXCLUDED.inode, nlink=EXCLUDED.nlink, still_exists=EXCLUDED.still_exists""",
                (self.host, path, file_type, size, still_exists, self.scan_id, self.scan_id, sha_, inode, nlink, mtime, tool, group))
        self.conn.commit()

    def mk_add(self, rel, body, fs_mtime=MTIME, **kw):
        p = self.mk(rel, body, fs_mtime)
        self.add(p, **kw)
        return p

    # -- running ---------------------------------------------------------------
    def run(self, **kw):
        kw.setdefault("heartbeat_interval", 0.05)
        return nd.run_once(self.conn, self.host, target=self.target, conn_factory=self.factory, **kw)

    def q(self, sql, params=()):
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
        self.conn.commit()
        return rows

    def run_row(self, run_id):
        r = self.q("""SELECT status, current_stage, failure_reason, is_partial, root_dirs, exclude_paths, files_hashed,
                             files_inherited, files_reused, excluded_zero_byte, errors_by_reason, transport_failures, retries,
                             duplicate_groups_found, duplicate_files_found, grouped_identities, bytes_reclaimable,
                             total_files_considered, code_version, published_at
                      FROM diskaudit.dedup_runs WHERE dedup_run_id=%s""", (run_id,))[0]
        keys = ["status", "stage", "reason", "is_partial", "root_dirs", "exclude_paths", "hashed", "inherited", "reused",
                "zero", "errors", "tf", "retries", "groups", "files", "identities", "reclaim", "considered", "code_version", "published_at"]
        return dict(zip(keys, r))

    def snap_groups(self, run_id):
        return {g: (sz, idc, mc, kp, br) for g, sz, idc, mc, kp, br in self.q(
            "SELECT group_id, size_bytes, identity_count, member_count, keeper_path, bytes_reclaimable "
            "FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id=%s", (run_id,))}

    def snap_members(self, run_id):
        return {p: r for p, r in self.q(
            "SELECT path, role FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s", (run_id,))}

    def label(self, path):
        r = self.q("SELECT duplicate_group_id, dedup_tool, content_sha256 FROM diskaudit.files WHERE host=%s AND path=%s", (self.host, path))
        return r[0] if r else None

    def items(self, run_id):
        return {p: (o, r) for p, o, r in self.q(
            "SELECT path, outcome, reason FROM diskaudit.dedup_run_items WHERE dedup_run_id=%s", (run_id,))}

    def binding(self, path):
        r = self.q("SELECT sha256, bound_at, inherited_from, st_dev, st_ino, dedup_run_id FROM diskaudit.dedup_digest_bindings "
                   "WHERE host=%s AND path=%s", (self.host, path))
        return r[0] if r else None

    def h_calls(self):
        return sum(1 for op, d in self.target.log if op == "put" and d.endswith(".paths"))


@pytest.fixture
def env(gconn, gconn_factory, tmp_path):
    return Env(gconn, gconn_factory, tmp_path)


def scripted(spec, errors=None):
    """responder: spec[path] = (sha, size, mtime, ino, dev, nlink)"""
    errors = errors or {}

    def responder(name, items):
        lines, errs, h, s = [], [], 0, 0
        for kind, path in items:
            if path in errors:
                errs.append(f"{errors[path]}|{path}")
                continue
            sh, size, mt, ino, dev, nl = spec[path]
            if kind == "H":
                lines.append(f"H|{sh}|{size}|{mt}|{ino}|{dev}|{nl}|{path}")
                h += 1
            else:
                lines.append(f"S|{size}|{mt}|{ino}|{dev}|{nl}|{path}")
                s += 1
        lines.append(f"#DONE|hashed={h}|statonly={s}|errors={len(errs)}")
        return "\n".join(lines) + "\n", "".join(e + "\n" for e in errs)

    return responder


# ===========================================================================
# 1. definition of a duplicate (HV-REQ-01..04)
# ===========================================================================

def test_group_requires_equal_sha_and_size(env):
    a = env.mk_add("a/x", X)
    b = env.mk_add("b/x", X)           # same basename, same content -> group
    c = env.mk_add("c/x", Y)           # same basename, same size, DIFFERENT content -> no group
    rid, status = env.run()
    assert status == "completed"
    groups = env.snap_groups(rid)
    assert list(groups) == [sha(X)]
    assert set(env.snap_members(rid)) == {a, b}
    assert env.label(c)[0] is None

    # equal sha but unequal size is impossible for intact data: the run FAILS, it does not group
    e2 = Env(env.conn, env.factory, env.tmp, "nd2")
    p1, p2, p3, p4 = "/z/a1", "/z/a2", "/z/b1", "/z/b2"
    for p, sz, ino in ((p1, 100, 1), (p2, 100, 2), (p3, 200, 3), (p4, 200, 4)):
        e2.add(p, size=sz, mtime=MTIME, inode=ino, nlink=1)
    spec = {p1: (sha(X), 100, MTIME, 1, 9, 1), p2: (sha(Y), 100, MTIME, 2, 9, 1),
            p3: (sha(X), 200, MTIME, 3, 9, 1), p4: (sha(Z), 200, MTIME, 4, 9, 1)}
    e2.target.responder = scripted(spec)
    rid2, status2 = e2.run()
    row = e2.run_row(rid2)
    assert status2 == "failed" and row["reason"].startswith("SHA_SIZE_CONFLICT:") and sha(X) in row["reason"]
    assert e2.snap_groups(rid2) == {}


def test_hardlinks_same_dev_inode_are_one_member(env):
    a = env.mk_add("a", X)
    a2 = env.link(a, "a2")
    env.add(a2)
    env.add(a)                                       # refresh nlink=2 on both rows
    rid, status = env.run()
    assert status == "completed" and env.snap_groups(rid) == {}          # 2 paths, 1 identity -> no group
    assert env.items(rid)[a][0] == "hashed" and env.items(rid)[a2][0] == "inherited"
    # a third, distinct file with equal content makes ONE group of 2 identities / 3 members
    b = env.mk_add("b", X)
    rid2, _ = env.run()
    g = env.snap_groups(rid2)[sha(X)]
    assert (g[1], g[2], g[3]) == (2, 3, a)           # identity_count, member_count, keeper (shortest path, mtime tie)
    assert env.snap_members(rid2) == {a: "keeper", a2: "keeper_link", b: "victim"}


def test_same_inode_different_dev_not_merged(env):
    p1, p2, p3 = "/z/p1", "/z/p2", "/z/p3"
    for p in (p1, p2, p3):
        env.add(p, size=50, mtime=MTIME, inode=5, nlink=1)       # inventory cannot tell them apart (no dev column)
    spec = {p1: (sha(X), 50, MTIME, 5, 1, 1), p2: (sha(Y), 50, MTIME, 5, 2, 1), p3: (sha(Z), 50, MTIME, 5, 3, 1)}
    env.target.responder = scripted(spec)
    rid, status = env.run()
    assert status == "completed" and env.snap_groups(rid) == {}
    it = env.items(rid)
    assert it[p1][0] == "hashed" and it[p2][0] == "hashed" and it[p3][0] == "hashed"     # NOT inherited: dev differs
    assert {env.binding(p)[0] for p in (p1, p2, p3)} == {sha(X), sha(Y), sha(Z)}
    assert env.binding(p1)[3] != env.binding(p2)[3]


def test_zero_byte_files_never_grouped(env):
    for i in range(3):
        env.mk_add(f"empty{i}", b"")
    rid, status = env.run()
    row = env.run_row(rid)
    assert status == "completed" and row["zero"] == 3 and row["groups"] == 0
    assert env.h_calls() == 0                         # nothing was even sent
    assert env.q("SELECT count(*) FROM diskaudit.files WHERE host=%s AND file_type='regular' AND size_bytes=0 AND still_exists",
                 (env.host,))[0][0] == row["zero"]


def test_symlink_at_hash_time_rejected(env):
    env.mk_add("a", X)
    target_file = env.mk("t", X)
    link = str(env.root / "link")
    os.symlink(target_file, link)
    env.add(link, size=len(X), mtime=MTIME, inode=777, nlink=1)       # inventory (wrongly) says regular
    rid, _ = env.run()
    assert env.items(rid)[link] == ("error", "NOT_REGULAR")
    assert env.binding(link) is None
    assert env.run_row(rid)["errors"] == {"NOT_REGULAR": 1}


# ===========================================================================
# 2. digest freshness (HV-REQ-05..09)
# ===========================================================================

def test_fanout_preserves_original_binding_time(env):
    x = env.mk_add("x", X)
    env.mk_add("twin", X)                              # a size twin so x is a hashing candidate at all
    rid, _ = env.run()
    b1 = env.binding(x)
    later = env.link(x, "x_hl")
    env.add(later)
    time.sleep(0.05)
    rid2, _ = env.run()
    b2 = env.binding(later)
    assert env.items(rid2)[later][0] == "inherited"
    assert b2[1] == b1[1] and b2[2] == x              # bound_at == the representative's ORIGINAL bound_at, inherited_from set
    assert env.q("SELECT hashed_at FROM diskaudit.files WHERE host=%s AND path=%s", (env.host, later))[0][0] == b1[1]
    assert env.binding(x)[1] == b1[1]                 # the fresh representative was not re-stamped either


def test_fanout_refused_when_sibling_stat_differs(env):
    r, s = "/z/rep", "/z/sib"
    env.add(r, size=70, mtime=MTIME, inode=5, nlink=2)
    env.add(s, size=70, mtime=MTIME, inode=5, nlink=2)
    calls = {"n": 0}

    def responder(name, items):
        calls["n"] += 1
        # the S line for the sibling reports a DIFFERENT mtime than the representative's binding
        {r: (sha(X), 70, MTIME, 5, 9, 2)}
        lines, h, st = [], 0, 0
        for kind, path in items:
            if path == r:
                lines.append(f"H|{sha(X)}|70|{MTIME}|5|9|2|{path}")
                h += 1
            elif kind == "S":
                lines.append(f"S|70|{MTIME + 99}|5|9|2|{path}")
                st += 1
            else:                                        # straggler batch: the sibling hashed in its own right
                lines.append(f"H|{sha(Y)}|70|{MTIME + 99}|5|9|2|{path}")
                h += 1
        lines.append(f"#DONE|hashed={h}|statonly={st}|errors=0")
        return "\n".join(lines) + "\n", ""

    env.target.responder = responder
    rid, status = env.run()
    assert status == "completed" and calls["n"] == 2                  # main batch + straggler batch
    assert env.items(rid)[s][0] == "hashed"                           # NOT inherited
    assert env.binding(s)[0] == sha(Y) and env.binding(s)[2] is None
    assert env.binding(r)[0] == sha(X)


def test_foreign_digest_write_makes_row_non_fresh(env):
    a = env.mk_add("a", X)
    b = env.mk_add("b", X)
    rid, _ = env.run()
    assert env.snap_groups(rid) and env.items(rid)[a][0] == "hashed"
    env.q("UPDATE diskaudit.files SET content_sha256=%s WHERE host=%s AND path=%s", ("f" * 64, env.host, a))
    rid2, _ = env.run()
    assert env.items(rid2)[a][0] == "hashed" and b not in env.items(rid2)      # a re-hashed, b fresh and reused
    assert env.label(a)[2] == sha(X) and set(env.snap_members(rid2)) == {a, b}


def test_legacy_digest_without_binding_is_rehashed_end_to_end(env):
    a = env.mk_add("a", X, sha_="e" * 64)              # legacy digest, WRONG on purpose: must never be trusted
    b = env.mk_add("b", X, sha_="e" * 64)
    rid, _ = env.run()
    assert env.items(rid)[a][0] == "hashed" and env.items(rid)[b][0] == "hashed"
    assert env.label(a)[2] == sha(X)
    assert set(env.snap_members(rid)) == {a, b}


# ===========================================================================
# 3. group lifecycle (HV-REQ-10..15)
# ===========================================================================

def test_vanished_member_removed_from_group(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    rid, _ = env.run()
    assert env.label(a)[0] == sha(X) and env.label(b)[0] == sha(X)
    env.q("UPDATE diskaudit.files SET still_exists=false WHERE host=%s AND path=%s", (env.host, b))
    rid2, _ = env.run()
    assert env.snap_groups(rid2) == {}
    assert env.label(a)[0] is None and env.label(b)[0] is None        # the vanished row AND the orphaned twin


def test_twin_deleted_group_cleared(env):
    a, b, c = env.mk_add("a", X), env.mk_add("b", X), env.mk_add("c", X)
    rid, _ = env.run()
    assert len(env.snap_members(rid)) == 3
    env.q("UPDATE diskaudit.files SET still_exists=false WHERE host=%s AND path=%s", (env.host, b))
    rid2, _ = env.run()
    assert set(env.snap_members(rid2)) == {a, c}                      # still a group of 2
    env.q("UPDATE diskaudit.files SET still_exists=false WHERE host=%s AND path=%s", (env.host, c))
    rid3, _ = env.run()
    assert env.snap_groups(rid3) == {} and env.label(a)[0] is None


def test_changed_member_removed_from_group(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    rid, _ = env.run()
    assert env.snap_groups(rid)
    # b is rewritten in place with the same size: only the inventory mtime tells us
    (env.root / "b").write_bytes(Y)
    os.utime(env.root / "b", (MTIME + 500, MTIME + 500))
    env.add(b)
    rid2, _ = env.run()
    assert env.snap_groups(rid2) == {}
    assert env.label(a)[0] is None and env.label(b)[0] is None
    assert env.items(rid2)[b][0] == "hashed" and env.label(b)[2] == sha(Y)


def test_failed_run_publishes_nothing(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    env.q("UPDATE diskaudit.files SET duplicate_group_id='legacy', dedup_tool=%s WHERE host=%s AND path=%s", (nd.TOOL, env.host, a))
    env.target.scp_get_failures = {0: 99}
    rid, status = env.run()
    assert status == "failed"
    assert env.snap_groups(rid) == {} and env.snap_members(rid) == {}
    assert env.label(a)[0] == "legacy" and env.label(b)[0] is None   # shared columns untouched


def test_publication_is_atomic(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    env.q("UPDATE diskaudit.files SET duplicate_group_id='legacy', dedup_tool=%s WHERE host=%s AND path=%s", (nd.TOOL, env.host, a))

    class BoomCursor(GuardedCursor):
        def execute(self, query, params=None, **kw):
            if "INSERT INTO diskaudit.dedup_group_members" in query:
                raise RuntimeError("boom mid-publish")
            return super().execute(query, params, **kw)

    class BoomConn(GuardedConn):
        def cursor(self, *a, **kw):
            return BoomCursor(self._conn.cursor(*a, **kw), self)

    boom = BoomConn(conftest.connect_retry(), env.conn.schema)
    try:
        rid, status = nd.run_once(boom, env.host, target=env.target, conn_factory=env.factory, heartbeat_interval=0.05)
    finally:
        boom.close()
    assert status == "failed"
    assert env.run_row(rid)["reason"].startswith("RuntimeError: boom")
    assert env.snap_groups(rid) == {} and env.snap_members(rid) == {}        # snapshot INSERT rolled back with it
    assert env.label(a)[0] == "legacy" and env.label(b)[0] is None


def _checksum_outside(env, prefix):
    return env.q("""SELECT md5(coalesce(string_agg(path||'|'||coalesce(content_sha256,'')||'|'||coalesce(duplicate_group_id,'')||'|'||
                   coalesce(dedup_tool,'')||'|'||coalesce(hashed_at::text,'')||'|'||still_exists::text, ',' ORDER BY path), ''))
                   FROM diskaudit.files WHERE host=%s AND NOT (path = %s OR path LIKE %s ESCAPE '\\')""",
                 (env.host, prefix, core.like_prefix(prefix)))[0][0]


def test_scoped_run_never_touches_out_of_scope_rows(env):
    d1 = {n: env.mk_add(f"d1/{n}", body) for n, body in (("a", X), ("b", Y), ("b2", Y))}
    d1x = {n: env.mk_add(f"d1x/{n}", body) for n, body in (("p", Z), ("q", Z))}     # sibling dir: '/d1' must not match '/d1x'
    d2 = {n: env.mk_add(f"d2/{n}", body) for n, body in (("x", X), ("y", Y))}
    env.q("UPDATE diskaudit.files SET duplicate_group_id='legacy-outside', dedup_tool=%s WHERE host=%s AND path=%s",
          (nd.TOOL, env.host, d2["x"]))
    scope = str(env.root / "d1")
    before = _checksum_outside(env, scope)
    rid, status = env.run(scope=scope)
    assert status == "completed"
    assert _checksum_outside(env, scope) == before                     # rows outside scope: byte-identical
    assert env.run_row(rid)["root_dirs"] == [scope]
    assert env.items(rid).keys() <= set(d1.values())                   # nothing outside was even considered
    assert env.binding(d1x["p"]) is None and env.binding(d2["x"]) is None


def test_scoped_equals_full_restricted(env):
    d1 = {n: env.mk_add(f"d1/{n}", body) for n, body in (("a", X), ("b", Y), ("b2", Y))}
    {n: env.mk_add(f"d2/{n}", body) for n, body in (("x", X), ("y", Y))}
    scope = str(env.root / "d1")
    rs, _ = env.run(scope=scope)
    scoped = {(g, p) for g in env.snap_groups(rs) for p in env.q(
        "SELECT path FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s AND group_id=%s", (rs, g)) for p in p}
    rf, _ = env.run()
    members = env.q("SELECT group_id, path FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s", (rf,))
    by_group = {}
    for g, p in members:
        by_group.setdefault(g, []).append(p)
    restricted = set()
    for g, paths in by_group.items():
        inside = [p for p in paths if p.startswith(scope + "/")]
        idents = {os.stat(p).st_ino for p in inside}
        if len(idents) >= 2:                                           # keep only groups with >= 2 in-scope identities
            restricted |= {(g, p) for p in inside}
    assert scoped == restricted == {(sha(Y), d1["b"]), (sha(Y), d1["b2"])}
    assert sha(X) in env.snap_groups(rf) and sha(X) not in env.snap_groups(rs)      # X spans the boundary: full only


def test_unknown_scope_fails_loudly(env):
    env.mk_add("a", X)
    rid, status = env.run(scope="/__test_nasdedup__/nope")
    row = env.run_row(rid)
    assert status == "failed" and "scope not in inventory" in row["reason"] and row["stage"] == "failed"


def test_limit_run_publishes_nothing(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    rid, status = env.run(limit=1)
    row = env.run_row(rid)
    assert status == "completed" and row["is_partial"] is True and row["stage"] == "hashed-only (partial)"
    assert env.snap_groups(rid) == {} and row["published_at"] is None
    assert env.q("SELECT count(*) FROM diskaudit.dedup_digest_bindings WHERE host=%s", (env.host,))[0][0] == 1
    assert env.label(a)[0] is None and env.label(b)[0] is None


def test_exclude_leaves_rows_exactly_as_found(env):
    a, b = env.mk_add("keep/a", X), env.mk_add("keep/b", X)
    x1, x2 = env.mk_add("skip/x1", Y), env.mk_add("skip/x2", Y)
    env.q("UPDATE diskaudit.files SET duplicate_group_id='legacy-skip', dedup_tool=%s WHERE host=%s AND path=%s", (nd.TOOL, env.host, x1))
    rid, status = env.run(excludes=[str(env.root / "skip")])
    assert status == "completed" and set(env.snap_members(rid)) == {a, b}
    assert env.label(x1)[0] == "legacy-skip" and env.binding(x1) is None and env.binding(x2) is None
    assert env.run_row(rid)["exclude_paths"] == [str(env.root / "skip")]


def test_other_tools_labels_are_never_overwritten(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    env.q("UPDATE diskaudit.files SET duplicate_group_id=%s, dedup_tool='crosshost-sha256' WHERE host=%s AND path=%s",
          (sha(X), env.host, a))
    rid, _ = env.run()
    assert set(env.snap_members(rid)) == {a, b}                       # still in the snapshot ...
    assert env.label(a)[1] == "crosshost-sha256"                       # ... but the other tool's label is left alone
    assert env.label(b)[1] == nd.TOOL


# ===========================================================================
# 4. failure handling (HV-REQ-16..22)
# ===========================================================================

def test_scp_get_failure_is_batch_failure(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    env.target.scp_get_failures = {0: 1}                               # first fetch times out (rc 124), the retry succeeds
    rid, status = env.run()
    row = env.run_row(rid)
    assert status == "completed" and (row["tf"], row["retries"]) == (1, 1)
    assert set(env.snap_members(rid)) == {a, b}


def test_remote_results_kept_until_commit(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    checked = []

    def on_rm(paths):
        if any(p.endswith(".hashes") for p in paths):
            n = len(env.q("SELECT 1 FROM diskaudit.dedup_run_items WHERE host=%s", (env.host,)))
            other = conftest.connect_retry()                       # a SECOND session sees only COMMITTED rows
            try:
                with other.cursor() as cur:
                    cur.execute(f"SELECT count(*) FROM {env.conn.schema}.dedup_run_items WHERE host=%s", (env.host,))
                    committed = cur.fetchone()[0]
            finally:
                other.close()
            checked.append((paths, n, committed))

    env.target.on_rm = on_rm
    rid, status = env.run()
    assert status == "completed" and checked
    assert all(committed >= 2 for _p, _n, committed in checked)        # rows durable BEFORE the remote .hashes was removed


def test_single_retry_then_fail(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.scp_get_failures = {0: 99}
    rid, status = env.run()
    row = env.run_row(rid)
    assert status == "failed" and (row["retries"], row["tf"]) == (1, 2)
    assert row["reason"].startswith("batch 0 failed twice") and row["stage"] == "failed"
    assert row["groups"] in (None, 0) and env.snap_groups(rid) == {}
    # nothing was consumed from a failed transfer: no digest was written
    assert env.q("SELECT count(*) FROM diskaudit.dedup_digest_bindings WHERE host=%s", (env.host,))[0][0] == 0


def test_injected_scp_failure_run_failed_zero_groups(env, monkeypatch):
    """The live negative test (HV-REQ-33) in miniature: failure -> exit 2, failed row, zero groups."""
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.scp_get_failures = {0: 99}
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "_target_for_host", lambda h: env.target)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))
    rc = nd.main(["--host", env.host])
    assert rc == nd.EXIT_FAILED
    rid = env.q("SELECT max(dedup_run_id) FROM diskaudit.dedup_runs WHERE host=%s", (env.host,))[0][0]
    row = env.run_row(rid)
    assert row["status"] == "failed" and row["groups"] in (None, 0)


def test_ssh_timeout_of_hash_script_is_a_batch_failure_too(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.ssh_failures = {0: 1}
    rid, status = env.run()
    assert status == "completed" and env.run_row(rid)["retries"] == 1


def test_truncated_result_fails_batch_not_zero_hashes(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.mutate_hashes = lambda t: "\n".join(t.split("\n")[:1])        # chop the file after the first line: no trailer
    rid, status = env.run()
    assert status == "failed" and "trailer" in env.run_row(rid)["reason"]
    assert env.snap_groups(rid) == {}


def test_non_utf8_path_counted_as_error(env, monkeypatch):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    real = nd._load_candidates

    def with_bad(conn, host, scope, excludes):
        cands, bindings, n, z = real(conn, host, scope, excludes)
        cands.append(core.Cand("/z/bad\udc89name", 400, MTIME, 99, 1, None))
        cands.append(core.Cand("/z/new\nline", 400, MTIME, 98, 1, None))
        return cands, bindings, n, z

    monkeypatch.setattr(nd, "_load_candidates", with_bad)
    rid, status = env.run()
    assert status == "completed"
    it = env.items(rid)
    assert it["/z/bad\\udc89name"] == ("error", "NON_UTF8_PATH") and it["/z/new\nline"] == ("error", "UNSAFE_PATH")
    assert env.run_row(rid)["errors"] == {"NON_UTF8_PATH": 1, "UNSAFE_PATH": 1}
    assert set(env.snap_members(rid)) == {a, b}                         # the good pair still grouped; bad paths never sent
    assert env.target.sent_lists and not any("bad" in c or "new" in c for c in env.target.sent_lists)   # never sent


def test_per_file_error_excludes_from_group(env):
    a, b, c = env.mk_add("a", X), env.mk_add("b", X), env.mk_add("c", X)
    os.remove(env.root / "c")                                           # test-only: delete OUR OWN tmp file so the NAS reports MISSING
    rid, _ = env.run()
    assert env.items(rid)[c] == ("error", "MISSING") and set(env.snap_members(rid)) == {a, b}
    assert env.q("SELECT still_exists FROM diskaudit.files WHERE host=%s AND path=%s", (env.host, c))[0][0] is False
    # a MISSING member's twin is not grouped
    e2 = Env(env.conn, env.factory, env.tmp, "nd3")
    p1 = e2.mk_add("p1", Y)
    e2.mk_add("p2", Y)
    os.remove(e2.root / "p2")
    rid2, _ = e2.run()
    assert e2.snap_groups(rid2) == {} and e2.label(p1)[0] is None


def test_failed_run_triggers_monitor_error(env):
    env.mk_add("a", X)
    rid, status = env.run(scope="/__test_nasdedup__/nope")
    assert status == "failed"
    alerts = monitor.check_errors(env.conn, host_filter=env.host)
    env.conn.commit()
    assert [(a["run_type"], a["run_id"]) for a in alerts] == [("dedup", rid)]


def test_db_down_uses_alertlib(env, monkeypatch):
    calls = []
    monkeypatch.setattr(nd, "_alertlib_db_down", lambda src, err: calls.append((src, str(err))) or True)
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))
    monkeypatch.setattr(nd, "_finish_run", lambda *a, **k: (_ for _ in ()).throw(psycopg.OperationalError("db went away")))
    env.mk_add("a", X)
    rc = nd.main(["--host", env.host, "--path", "/__test_nasdedup__/nope"])
    assert rc == nd.EXIT_DB_DOWN and len(calls) == 1 and calls[0][0] == "nas_trigkey_dedup"


def test_lock_timeout_in_publish_is_a_failed_run_not_db_down(env, monkeypatch):
    """Review fix 20261109: lock_timeout / deadlock are OperationalError with the DB reachable. The run must end
    'failed' with the real error (exit 2), not stay 'running' behind a false 'database unreachable' alert."""
    calls = []
    monkeypatch.setattr(nd, "_alertlib_db_down", lambda src, err: calls.append(src) or True)
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "_target_for_host", lambda h: env.target)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))

    def boom(*a, **k):
        raise psycopg.errors.LockNotAvailable("canceling statement due to lock timeout")
    monkeypatch.setattr(nd, "_publish", boom)
    env.mk_add("a", X)
    env.mk_add("b", X)
    assert nd.main(["--host", env.host]) == nd.EXIT_FAILED and calls == []
    rid = env.q("SELECT max(dedup_run_id) FROM diskaudit.dedup_runs WHERE host=%s", (env.host,))[0][0]
    row = env.run_row(rid)
    assert row["status"] == "failed" and row["stage"] == "failed" and "LockNotAvailable" in row["reason"]
    assert env.snap_groups(rid) == {}


def test_db_unreachable_at_connect_alerts_once(monkeypatch):
    calls = []
    monkeypatch.setattr(nd, "_alertlib_db_down", lambda src, err: calls.append(src) or True)
    monkeypatch.setattr(nd, "_connect", lambda: (_ for _ in ()).throw(psycopg.OperationalError("refused")))
    assert nd.main(["--host", "nas-1"]) == nd.EXIT_DB_DOWN and calls == ["nas_trigkey_dedup"]


def test_sigterm_marks_run_failed(env, monkeypatch):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.on_ssh = lambda name: os.kill(os.getpid(), signal.SIGTERM)
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "_target_for_host", lambda h: env.target)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))
    before = signal.getsignal(signal.SIGTERM)
    rc = nd.main(["--host", env.host])
    assert rc == 128 + signal.SIGTERM and signal.getsignal(signal.SIGTERM) == before     # handlers restored
    rid = env.q("SELECT max(dedup_run_id) FROM diskaudit.dedup_runs WHERE host=%s", (env.host,))[0][0]
    row = env.run_row(rid)
    assert row["status"] == "failed" and row["reason"] == "terminated" and row["stage"] == "failed"
    assert env.snap_groups(rid) == {}


def test_exit_code_matches_status(env, monkeypatch):
    _a, _b = env.mk_add("a", X), env.mk_add("b", X)
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "_target_for_host", lambda h: env.target)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))
    assert nd.main(["--host", env.host]) == nd.EXIT_OK                                  # completed
    rid = env.q("SELECT max(dedup_run_id) FROM diskaudit.dedup_runs WHERE host=%s", (env.host,))[0][0]
    assert env.run_row(rid)["stage"] == "published"
    assert nd.main(["--host", env.host, "--path", "/__test_nasdedup__/nope"]) == nd.EXIT_FAILED      # failed
    assert nd.main(["--host", "not-a-known-host"]) == nd.EXIT_FAILED
    assert nd.main(["--host", env.host, "--path", "relative"]) == nd.EXIT_FAILED
    out = env.q("SELECT count(*) FROM diskaudit.dedup_runs WHERE host=%s AND current_stage='done'", (env.host,))[0][0]
    assert out == 0                                                                     # a failed run never reads 'done'


def test_failed_run_stage_not_done(env):
    env.mk_add("a", X)
    rid, _ = env.run(scope="/__test_nasdedup__/nope")
    assert env.run_row(rid)["stage"] == "failed"


def test_nothing_to_hash_is_completed_and_says_why(env, capsys):
    a, b = env.mk_add("a", X), env.mk_add("b", X)
    env.run()
    capsys.readouterr()
    before = env.h_calls()
    rid, status = env.run()
    assert status == "completed" and env.h_calls() == before             # second run: everything fresh, nothing sent
    assert "nothing to hash: all 2 candidates fresh" in capsys.readouterr().err
    assert env.run_row(rid)["reused"] == 2 and set(env.snap_members(rid)) == {a, b}


# ===========================================================================
# 5. run record, progress, concurrency (HV-REQ-23..26)
# ===========================================================================

def test_run_record_counts_match_rows(env):
    env.mk_add("a", X)
    a2 = env.mk_add("a2", X)
    env.add(env.link(str(env.root / "a"), "a_hl"))                       # -> 1 inherited
    env.mk_add("gone", X)
    os.remove(env.root / "gone")                                         # -> 1 error MISSING
    env.mk_add("e0", b"")
    env.mk_add("e1", b"")                                                # -> 2 zero-byte
    env.mk_add("u", b"unique-size-" * 7)
    rid, status = env.run()
    row = env.run_row(rid)
    cnt = lambda o: env.q("SELECT count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id=%s AND outcome=%s", (rid, o))[0][0]   # noqa: E731
    assert status == "completed"
    assert row["hashed"] == cnt("hashed") and row["inherited"] == cnt("inherited") == 1
    assert row["errors"] == {r: n for r, n in env.q(
        "SELECT reason, count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id=%s AND outcome='error' GROUP BY 1", (rid,))}
    assert row["zero"] == 2
    assert row["groups"] == len(env.snap_groups(rid)) == 1 and row["files"] == len(env.snap_members(rid))
    assert row["identities"] == env.q("SELECT count(DISTINCT (st_dev, st_ino)) FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s", (rid,))[0][0]
    assert row["code_version"] == nd._code_version() and row["code_version"] != "unknown"
    assert a2 in env.snap_members(rid)


def test_heartbeat_thread_beats_during_a_slow_batch(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.target.on_ssh = lambda name: time.sleep(0.4)                     # a batch far longer than the 0.05 s interval
    rid, status = env.run()
    beats = env.q("SELECT count(*), max(note) FROM diskaudit.run_heartbeats WHERE run_type='dedup' AND run_id=%s AND stage='remote hashing'", (rid,))[0]
    assert status == "completed" and beats[0] >= 4
    assert env.run_row(rid)["stage"] == "published"                      # a late beat never overwrites the final stage
    notes = [r[0] for r in env.q("SELECT note FROM diskaudit.run_heartbeats WHERE run_id=%s AND note LIKE 'hashed %%'", (rid,))]
    assert notes and "f/s" in notes[0] and "ETA" in notes[0]


def test_batch_timeout_passed_to_ssh(env):
    env.mk_add("a", X)
    env.mk_add("b", X)
    env.run()
    assert env.target.ssh_timeouts and all(t == 600 for t in env.target.ssh_timeouts)    # small files -> the 600 s floor


def test_second_full_run_refused(env, monkeypatch):
    env.mk_add("a", X)
    monkeypatch.setattr(nd, "_connect", env.factory)
    monkeypatch.setattr(nd, "_target_for_host", lambda h: env.target)
    monkeypatch.setattr(nd, "KNOWN_HOSTS", (env.host,))
    holder = conftest.connect_retry()
    try:
        holder.execute("SELECT pg_advisory_lock(hashtext(%s))", (f"nasdedup:full:{env.host}",))
        assert nd.main(["--host", env.host]) == nd.EXIT_REFUSED
        assert env.q("SELECT count(*) FROM diskaudit.dedup_runs WHERE host=%s", (env.host,))[0][0] == 0      # NO run row
        # ... and a scoped run is NOT blocked by it
        assert nd.main(["--host", env.host, "--path", str(env.root)]) == nd.EXIT_OK
    finally:
        holder.close()
    # a live 'running' whole-host row (fresh heartbeat) refuses too; a stale one does not
    with env.conn.cursor() as cur:
        cur.execute("INSERT INTO diskaudit.dedup_runs (host, root_dirs, dedup_tool, status, last_heartbeat_at) "
                    "VALUES (%s, '{}', %s, 'running', now()) RETURNING dedup_run_id", (env.host, nd.TOOL))
        live = cur.fetchone()[0]
    env.conn.commit()
    assert nd.main(["--host", env.host]) == nd.EXIT_REFUSED
    env.q("UPDATE diskaudit.dedup_runs SET last_heartbeat_at = now() - interval '2 hours' WHERE dedup_run_id=%s", (live,))
    assert nd.main(["--host", env.host]) == nd.EXIT_OK


def test_scoped_run_during_full_run(env):
    d1 = {n: env.mk_add(f"d1/{n}", X) for n in ("a", "b")}
    d2 = {n: env.mk_add(f"d2/{n}", Y) for n in ("c", "d")}
    with env.conn.cursor() as cur:                                       # a whole-host run is "running" right now
        cur.execute("INSERT INTO diskaudit.dedup_runs (host, root_dirs, dedup_tool, status, last_heartbeat_at) "
                    "VALUES (%s, '{}', %s, 'running', now())", (env.host, nd.TOOL))
    env.conn.commit()
    r1, s1 = env.run(scope=str(env.root / "d1"))
    r2, s2 = env.run(scope=str(env.root / "d2"))
    assert (s1, s2) == ("completed", "completed")
    assert set(env.snap_members(r1)) == set(d1.values()) and set(env.snap_members(r2)) == set(d2.values())


def test_row_changed_by_crawl_mid_run_not_published(env):
    a, b = env.mk_add("a", X), env.mk_add("b", X)

    def crawl(name):                                                     # a crawl refreshes b's mtime while we hash
        c = env.factory()
        with c.cursor() as cur:
            cur.execute("UPDATE diskaudit.files SET mtime = mtime + interval '7 seconds' WHERE host=%s AND path=%s", (env.host, b))
        c.commit()
        c.close()

    env.target.on_ssh = crawl
    rid, status = env.run()
    assert status == "completed" and env.snap_groups(rid) == {}          # b is non-fresh at publish: excluded
    assert env.label(a)[0] is None and env.label(b)[0] is None


# ===========================================================================
# 6. output contract (HV-REQ-27..29)
# ===========================================================================

def test_snapshot_record_has_all_fields(env):
    a, _b, _c = env.mk_add("a", X), env.mk_add("b", X), env.mk_add("c", X)
    rid, _ = env.run()
    rows = env.q("""SELECT group_id, host, path, st_dev, st_ino, nlink, size_bytes, mtime, sha256, bound_at, role,
                           in_recycle_bin, in_backup_tree, links_outside_inventory FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s""", (rid,))
    assert len(rows) == 3 and all(v is not None for r in rows for v in r)
    g = env.q("SELECT group_id, size_bytes, identity_count, member_count, keeper_path, bytes_reclaimable, code_version, host "
              "FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id=%s", (rid,))[0]
    assert all(v is not None for v in g) and g[0] == sha(X) and g[1] == len(X) and g[4] == a and g[5] == 2 * len(X)
    assert sorted(r[10] for r in rows) == ["keeper", "victim", "victim"]


def test_recycle_and_backup_flags_and_keeper_never_in_recycle(env):
    old = env.mk_add("@Recycle/a", X, fs_mtime=MTIME - 10_000)               # oldest AND shortest -- but in a recycle bin
    keep = env.mk_add("docs/n.bin", X)
    bk = env.mk_add("bkup_test/m", X)
    rid, _ = env.run()
    g = env.snap_groups(rid)[sha(X)]
    assert g[3] == keep
    flags = {p: (rc, bt) for p, rc, bt in env.q(
        "SELECT path, in_recycle_bin, in_backup_tree FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s", (rid,))}
    assert flags[old][0] is True and flags[keep] == (False, False)
    assert flags[bk][1] is False        # the synthetic tree is not under /share/CACHEDEV1_DATA/bkup_test


def test_keeper_never_in_backup_tree_when_a_live_copy_exists(env):
    """BH-3 / HV-REQ-28 (1.4.1): the replica in bkup_test has the OLDEST mtime and the SHORTEST path but must not be the keeper."""
    bk = "/share/CACHEDEV1_DATA/bkup_test/m"
    live = "/share/CACHEDEV1_DATA/Public/docs/much/longer/n.bin"
    for p, ino, mt in ((bk, 1, MTIME - 5_000), (live, 2, MTIME)):
        env.add(p, size=len(X), mtime=mt, inode=ino, nlink=1)
    env.target.responder = scripted({bk: (sha(X), len(X), MTIME - 5_000, 1, 9, 1), live: (sha(X), len(X), MTIME, 2, 9, 1)})
    rid, status = env.run()
    assert status == "completed"
    assert env.snap_groups(rid)[sha(X)][3] == live
    assert env.snap_members(rid) == {live: "keeper", bk: "victim"}
    flags = {p: bt for p, bt in env.q("SELECT path, in_backup_tree FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s", (rid,))}
    assert flags == {bk: True, live: False}


def test_replacement_char_path_is_error_not_missing(env):
    """BH-8 (1.4.1): a U+FFFD (undecodable) name is recorded NON_UTF8_PATH, never sent to the NAS, never marked still_exists=false."""
    bad = "/share/CACHEDEV1_DATA/Public/nonutf8/caf\ufffd.bin"
    ok = env.mk_add("ok/keep.bin", X)
    env.add(bad, size=len(X), mtime=MTIME, inode=777, nlink=1)
    rid, status = env.run()
    assert status == "completed"
    assert env.items(rid)[bad] == ("error", "NON_UTF8_PATH")
    still = env.q("SELECT still_exists FROM diskaudit.files WHERE host=%s AND path=%s", (env.host, bad))[0][0]
    assert still is True
    assert env.target.sent_lists and not any(bad in lst for lst in env.target.sent_lists)   # never sent to the NAS
    assert not any("caf" in e[1] for e in env.target.log if e[0] == "missing")


def test_unsafe_names_with_a_stale_fresh_binding_never_enter_a_snapshot(env, monkeypatch):
    """BH-1 / BH-8 (1.4.1): a run of an OLDER version bound a line-break name; the publish must still keep it out of every group."""
    keep = env.mk_add("ok/keep.bin", X)
    odd = env.mk_add("ok/du\x0cp.bin", X, fs_mtime=MTIME + 50)
    with monkeypatch.context() as m:
        m.setattr(core, "classify_path", lambda p: None)                 # "1.4.0": hashes and binds it
        rid0, st0 = env.run()
    assert st0 == "completed" and env.binding(odd) is not None
    rid, status = env.run()                                              # 1.4.1: classify_path refuses it, binding is still fresh
    assert status == "completed"
    assert env.items(rid)[odd] == ("error", "UNSAFE_PATH")
    assert odd not in env.snap_members(rid) and env.snap_groups(rid) == {}
    assert env.label(odd)[0] is None and env.label(keep)[0] is None


def test_reclaimable_ignores_partially_listed_hardlinks(env):
    k = env.mk_add("k", X)
    v = env.mk_add("v", X, fs_mtime=MTIME + 100)
    env.link(v, "v_link")                                                 # a 2nd link of the victim ... NOT in the inventory
    env.add(v)                                                            # refresh nlink=2 for v; v_link never added
    rid, _ = env.run()
    g = env.snap_groups(rid)[sha(X)]
    assert g[3] == k and g[1] == 2
    lo = env.q("SELECT links_outside_inventory FROM diskaudit.dedup_group_members WHERE dedup_run_id=%s AND path=%s", (rid, v))[0][0]
    assert lo is True and g[4] == 0
    assert env.q("SELECT bytes_reclaimable FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id=%s", (rid,))[0][0] == 0
    # fully listed -> counts
    env.add(str(env.root / "v_link"))
    rid2, _ = env.run()
    assert env.q("SELECT bytes_reclaimable FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id=%s", (rid2,))[0][0] == len(X)


def test_report_identical_on_unchanged_data(env):
    for n, body in (("a", X), ("b", X), ("c", Y), ("d", Y), ("d2", Y)):
        env.mk_add(n, body)
    r1, _ = env.run()
    r2, _ = env.run()
    e1, e2 = nd.export_snapshot(env.conn, r1), nd.export_snapshot(env.conn, r2)
    env.conn.commit()

    def strip(text):
        out = []
        for line in text.splitlines():
            f = line.split(",")
            out.append(",".join(f[1:10]))                                 # drop run_id (col 0) and the trailing timestamps
        return "\n".join(out)

    assert r1 != r2 and strip(e1) == strip(e2) and len(e1.splitlines()) == 6
    first_of_group = [l.split(",")[2] for l in e1.splitlines()[1:]]
    assert first_of_group[0] == "keeper"
    j = nd.export_snapshot(env.conn, r1, "json")
    assert '"role": "keeper"' in j


# ===========================================================================
# 7. DB guard + migrations
# ===========================================================================

def test_db_helper_refuses_real_host(gconn):
    with pytest.raises(RealHostWriteRefused):
        gconn.cursor().execute("UPDATE diskaudit.files SET still_exists=false WHERE host='nas-1'")
    with pytest.raises(RealHostWriteRefused):
        gconn.cursor().execute("UPDATE diskaudit.files SET still_exists=false WHERE host=%s", ("nas-1",))
    with pytest.raises(RealHostWriteRefused):
        gconn.cursor().executemany("INSERT INTO diskaudit.dedup_run_items (host) VALUES (%s)", [("_test_x",), (("server-1",))])
    gconn.rollback()
    with gconn.cursor() as cur:                                           # reads are allowed
        cur.execute("SELECT count(*) FROM diskaudit.files WHERE host=%s", ("nas-1",))
        assert cur.fetchone()[0] == 0                                     # ... and hit the EMPTY throwaway copy, not production
    with pytest.raises(AssertionError):
        GuardedConn(object(), "diskaudit")


def test_migration_is_idempotent_and_reconcile_clears_only_false_labels(nd_schema):
    admin = conftest.connect_retry(autocommit=True)
    try:
        with open(os.path.join(conftest.MIGRATIONS, "20261109_diskaudit_nas_dedup_v3.sql"), encoding="utf-8") as f:
            admin.execute(conftest.rewrite(f.read(), nd_schema))           # applied a SECOND time: must be a no-op
        scan = admin.execute(f"INSERT INTO {nd_schema}.scan_runs (host, status) VALUES ('nas-1','completed') RETURNING scan_id").fetchone()[0]
        ins = (f"INSERT INTO {nd_schema}.files (host, path, file_type, size_bytes, still_exists, first_seen_scan_id, last_seen_scan_id, "
               f"duplicate_group_id, dedup_tool, content_sha256, mtime, hashed_at) VALUES ('nas-1', %s, 'regular', 5, %s, {scan}, {scan}, "
               f"'g', %s, %s, to_timestamp(%s), to_timestamp(%s))")
        admin.execute(ins, ("/r/vanished", False, nd.TOOL, "a" * 64, 100, 200))
        admin.execute(ins, ("/r/modified", True, nd.TOOL, "a" * 64, 300, 200))
        admin.execute(ins, ("/r/ok", True, nd.TOOL, "a" * 64, 100, 200))
        admin.execute(ins, ("/r/other-tool", False, "crosshost-sha256", "a" * 64, 100, 200))
        with open(os.path.join(conftest.MIGRATIONS, "20261109_diskaudit_nas_dedup_v3_reconcile.sql"), encoding="utf-8") as f:
            # the migration names its site's NAS (INFRA-557); point it at the test site's NAS
            sql = re.sub(r"host = '[^']+'", "host = 'nas-1'", conftest.rewrite(f.read(), nd_schema))
            admin.execute(sql)
        left = dict(admin.execute(f"SELECT path, duplicate_group_id FROM {nd_schema}.files WHERE host='nas-1'").fetchall())
        assert left == {"/r/vanished": None, "/r/modified": None, "/r/ok": "g", "/r/other-tool": "g"}
        with open(os.path.join(conftest.MIGRATIONS, "20261109_diskaudit_nas_dedup_v3_indexes.sql"), encoding="utf-8") as f:
            idx_sql = f.read()
        assert idx_sql.count("CREATE INDEX CONCURRENTLY IF NOT EXISTS") == 2 and "BEGIN" not in idx_sql.upper()
        # CONCURRENTLY waits for every older transaction in the cluster (not testable on a busy box): validate the
        # statements' SQL (columns, predicates) with the plain, non-concurrent form on the throwaway schema.
        body = "\n".join(l for l in idx_sql.splitlines() if not l.lstrip().startswith("--"))
        for stmt in conftest.rewrite(body, nd_schema).replace("CONCURRENTLY ", "").split(";"):
            if stmt.strip():
                admin.execute(stmt)
        idx = [r[0] for r in admin.execute("SELECT indexname FROM pg_indexes WHERE schemaname=%s AND indexname LIKE 'idx_files_host_%%'", (nd_schema,)).fetchall()]
        assert sorted(idx) == ["idx_files_host_sha_hashed", "idx_files_host_size_regular"]
    finally:
        admin.close()


def test_migration_adds_nothing_destructive():
    sql = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations",
                            "20261109_diskaudit_nas_dedup_v3.sql"), encoding="utf-8").read().upper()
    body = "\n".join(l for l in sql.splitlines() if not l.strip().startswith("--"))
    for word in ("DROP ", "TRUNCATE", "DELETE FROM", "RENAME", "ALTER COLUMN", "SET NOT NULL"):
        assert word not in body, word
    assert "LOCK_TIMEOUT = '5S'" in body and body.count("ADD COLUMN IF NOT EXISTS") >= 14


def test_prune_old_items_only_prunes_old_runs(env):
    _a, _b = env.mk_add("a", X), env.mk_add("b", X)
    rid, _ = env.run()
    old = env.q("INSERT INTO diskaudit.dedup_runs (host, root_dirs, dedup_tool, status, started_at) "
                "VALUES (%s, '{}', %s, 'completed', now() - interval '40 days') RETURNING dedup_run_id", (env.host, nd.TOOL))[0][0]
    env.q("INSERT INTO diskaudit.dedup_run_items (dedup_run_id, host, path, outcome) VALUES (%s,%s,'/old','hashed')", (old, env.host))
    rid2, _ = env.run()
    assert env.q("SELECT count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id=%s", (old,))[0][0] == 0
    assert env.q("SELECT count(*) FROM diskaudit.dedup_run_items WHERE dedup_run_id=%s", (rid,))[0][0] >= 2


def test_heartbeat_thread_reconnects_after_connect_failures(env):
    """A full connection table at start must not silence the heartbeat for the whole run."""
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] <= 2:
            raise psycopg.OperationalError("sorry, too many clients already")
        return env.factory()

    rid = nd._start_run(env.conn, env.host, None, [], False, "1.4.0")
    hb = nd.HeartbeatThread(flaky, rid, env.host, nd.Progress(), 0.05)
    hb.start()
    time.sleep(0.6)
    hb.stop()
    assert hb.errors >= 2 and attempts["n"] >= 3
    assert env.q("SELECT count(*) FROM diskaudit.run_heartbeats WHERE run_type='dedup' AND run_id=%s", (rid,))[0][0] >= 1
    assert env.q("SELECT last_heartbeat_at IS NOT NULL FROM diskaudit.dedup_runs WHERE dedup_run_id=%s", (rid,))[0][0] is True
