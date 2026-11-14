"""Tests for crosshost_verify.py (HavnVard cross-host NAS-integrity tool).

First real pytest suite in this repo (tests/README.md previously documented
"no automated test suite exists yet" as an honest gap -- this file starts
closing it, scoped to the new crosshost_verify.py tool per the build task).

Four things are covered, per the build spec:
  1. candidate SQL shape        -- the size-based cross-host candidate query
                                    returns the right rows under a controlled
                                    synthetic fixture, not just "looked right
                                    on prod".
  2. hash-loader idempotency     -- hashing a file twice (or after touching
                                    its content) behaves correctly: a stable
                                    file is skipped on the second pass; a
                                    changed file is re-hashed.
  3. same-content/different-path grouping -- the `match` subcommand's
                                    duplicate_group_id + integrity_checks
                                    population, against synthetic same-hash
                                    rows across two hosts.
  4. delete/move guard            -- greps the WHOLE codebase (not just this
                                    tool) and FAILS if a delete/move/rename
                                    primitive is ever introduced against a
                                    scanned path. This is the single most
                                    important test in this file given the
                                    HARD CONSTRAINT that HavnVard must never
                                    delete, move, overwrite, or rename any
                                    scanned file.

DB tests use a real connection to the live diskaudit DB (same DSN resolution
as the tool itself). Most tests only ever open a transaction and rely on
`conn.rollback()` in fixture teardown -- never committed, never touches real
host data. A few tests (hash_local_host / run_match idempotency + matching)
exercise functions that COMMIT INTERNALLY by design (small transactions so
long hash jobs never hold locks against the concurrently-running
diskaudit-scan.service) -- rollback alone cannot undo that. For those, every
synthetic host name is made globally unique per test invocation (see
`_uniq_host()` below) so a permanently-committed row can never collide with
anything from a prior test, a prior pytest run, or real production data --
correctness never depends on cleanup having run at all. A single best-effort
sweep DELETEs any leftover `_test_`-tagged rows once, at the END of the whole
test session (not per-test), because `diskaudit.files` is large enough
(~8.6M rows) that `host ~ '^_test_'`/`LIKE` cleanup predicates force a
sequential scan (no index covers this pattern) -- doing that once per session
instead of 14x per-test is what keeps the suite fast. Synthetic rows use host
names prefixed `_test_` (or the real `nas-1` literal, only ever paired
with a `_TEST_PATH_PREFIX`-tagged path -- see the match tests below for why)
so they can never collide with real production data.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone

import pytest
import psycopg

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crosshost_verify as cv  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

# Every synthetic row this suite ever writes carries EITHER a host prefixed
# `_test_` (source-side hosts -- can never collide with a real host name:
# server-1/nas-1/agent-1) OR, where production code hardcodes the
# literal host `nas-1` (see `_MATCH_INTEGRITY_*_SQL` in
# crosshost_verify.py -- NOT parameterized, there is only ever one real NAS),
# a path under this distinctive prefix instead. That lets fixture teardown
# safely delete "anything synthetic" via path OR host pattern without any
# risk of matching real production nas-1 rows.
_TEST_PATH_PREFIX = "/__test_crosshost_verify__/"


def _uniq_host(tag: str) -> str:
    """A synthetic host name guaranteed never to collide with anything --
    not another test in this run, not a leftover row from a PAST pytest
    invocation, not real production data. This is what makes correctness NOT
    depend on cleanup timing: `hash_local_host()`/`run_match()` commit
    internally (small transactions, by design, so long hash jobs never hold
    locks against the concurrently-running diskaudit-scan.service), so any
    reused host name risks a later test seeing an earlier test's permanently
    committed row (this is exactly how a real bug was found: two tests both
    used the literal host `"_test_hostA"`, and a leftover row from the first
    caused the second to observe the wrong `files_skipped_unchanged` count).
    Still prefixed `_test_` so the end-of-session sweep below can find it."""
    return f"_test_{tag}_{uuid.uuid4().hex[:10]}"


@pytest.fixture
def conn():
    """Real DB connection, rolled back at teardown. NOTE: a few tests drive
    `hash_local_host()`/`run_match()`, which COMMIT INTERNALLY as part of
    normal, correct operation -- for those, `conn.rollback()` here does NOT
    undo their writes. We deliberately do NOT run a per-test cleanup DELETE
    for that (see `_uniq_host()` above for how correctness is guaranteed
    instead): `diskaudit.files` is ~8.6M rows and neither `host ~ '^_test_'`
    nor a `LIKE` prefix match is sargable against its (host, path) PK index
    (confirmed via EXPLAIN -- both force a Parallel Seq Scan), so doing that
    DELETE 14x (once per test) is what caused a prior full-suite run to blow
    past a 2-minute timeout. A single sweep at session end (below) picks up
    anything left behind instead."""
    from conftest import TEST_DSN  # noqa: PLC0415
    if not TEST_DSN:
        pytest.skip("database test: set HAVNVARD_TEST_DSN to a scratch database (see tests/README.md)")
    try:
        c = psycopg.connect(TEST_DSN, autocommit=False)
    except psycopg.OperationalError as e:
        pytest.skip(f"test database not reachable: {e}")
        return
    yield c
    c.rollback()  # undoes anything NOT already committed by the code under test
    c.close()


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_rows_after_session():
    """Best-effort, ONE-TIME sweep (not per-test -- see `conn` fixture above
    for why) that removes any `_test_`-tagged rows this suite committed
    during the session, keeping the DB tidy without paying a full-table
    sequential scan 14 times over. Safe even if it never ran (e.g. the
    process is killed mid-suite): every synthetic host name is unique per
    test (`_uniq_host()`), so leftovers are inert -- they can never be
    mistaken for real data or collide with a future test."""
    yield
    from conftest import TEST_DSN  # noqa: PLC0415
    if not TEST_DSN:
        return
    try:
        c = psycopg.connect(TEST_DSN, autocommit=False)
    except psycopg.OperationalError:
        return
    try:
        with c.cursor() as cur:
            cur.execute(
                "DELETE FROM diskaudit.integrity_checks WHERE spark_host ~ '^_test_' OR spark_path LIKE %s",
                (_TEST_PATH_PREFIX + "%",),
            )
            cur.execute(
                "DELETE FROM diskaudit.files WHERE host ~ '^_test_' OR path LIKE %s",
                (_TEST_PATH_PREFIX + "%",),
            )
            cur.execute("DELETE FROM diskaudit.scan_runs WHERE host ~ '^_test_'")
        c.commit()
    finally:
        c.close()


def _make_scan_id(conn, host: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO diskaudit.scan_runs (host, status) VALUES (%s, 'completed') RETURNING scan_id",
            (host,),
        )
        return cur.fetchone()[0]


def _insert_file(
    conn, scan_id: int, host: str, path: str, size_bytes: int,
    file_type: str = "regular", still_exists: bool = True,
    content_sha256: str | None = None, inode: int | None = None, nlink: int = 1,
    mtime: datetime | None = None,
):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO diskaudit.files
                (host, path, file_type, size_bytes, still_exists,
                 first_seen_scan_id, last_seen_scan_id, content_sha256, inode, nlink, mtime)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (host, path) DO UPDATE SET
                size_bytes = EXCLUDED.size_bytes, still_exists = EXCLUDED.still_exists,
                content_sha256 = EXCLUDED.content_sha256, inode = EXCLUDED.inode,
                nlink = EXCLUDED.nlink, mtime = EXCLUDED.mtime
            """,
            (host, path, file_type, size_bytes, still_exists, scan_id, scan_id,
             content_sha256, inode, nlink, mtime),
        )


# ---------------------------------------------------------------------------
# 1. candidate SQL shape
# ---------------------------------------------------------------------------

def test_candidate_files_requires_size_on_two_hosts(conn):
    """A size that exists on only ONE host must never appear as a candidate --
    the entire point of the size-prefilter is cross-host comparability."""
    scan_id = _make_scan_id(conn, "_test_a")
    _insert_file(conn, scan_id, "_test_hostA", "/only/on/a.bin", size_bytes=5_000_000)

    rows = cv.candidate_files(conn, "_test_hostA", min_size=1)
    paths = [r[0] for r in rows]
    assert "/only/on/a.bin" not in paths


def test_candidate_files_includes_size_on_two_hosts(conn):
    scan_id = _make_scan_id(conn, "_test_b")
    _insert_file(conn, scan_id, "_test_hostA", "/shared/size/a.bin", size_bytes=7_000_000)
    _insert_file(conn, scan_id, "_test_hostB", "/shared/size/b.bin", size_bytes=7_000_000)

    rows_a = cv.candidate_files(conn, "_test_hostA", min_size=1)
    rows_b = cv.candidate_files(conn, "_test_hostB", min_size=1)
    assert "/shared/size/a.bin" in [r[0] for r in rows_a]
    assert "/shared/size/b.bin" in [r[0] for r in rows_b]


def test_candidate_files_respects_min_size(conn):
    scan_id = _make_scan_id(conn, "_test_c")
    # Same size on two hosts, but BELOW the min_size floor passed to the query.
    _insert_file(conn, scan_id, "_test_hostA", "/tiny/a.bin", size_bytes=100)
    _insert_file(conn, scan_id, "_test_hostB", "/tiny/b.bin", size_bytes=100)

    rows = cv.candidate_files(conn, "_test_hostA", min_size=1_048_576)
    assert "/tiny/a.bin" not in [r[0] for r in rows]


def test_candidate_files_excludes_gone_and_nonregular(conn):
    scan_id = _make_scan_id(conn, "_test_d")
    _insert_file(conn, scan_id, "_test_hostA", "/gone/a.bin", size_bytes=9_000_000, still_exists=False)
    _insert_file(conn, scan_id, "_test_hostB", "/gone/b.bin", size_bytes=9_000_000)
    _insert_file(conn, scan_id, "_test_hostA", "/dir/a", size_bytes=9_000_000, file_type="dir")
    _insert_file(conn, scan_id, "_test_hostB", "/dir/b", size_bytes=9_000_000)

    rows = cv.candidate_files(conn, "_test_hostA", min_size=1)
    paths = [r[0] for r in rows]
    assert "/gone/a.bin" not in paths  # disappeared -- must not be a hash candidate
    assert "/dir/a" not in paths       # directory, not a regular file


def test_candidate_files_only_unhashed_filter(conn):
    scan_id = _make_scan_id(conn, "_test_e")
    _insert_file(conn, scan_id, "_test_hostA", "/x/already.bin", size_bytes=3_000_000, content_sha256="a" * 64)
    _insert_file(conn, scan_id, "_test_hostB", "/x/already2.bin", size_bytes=3_000_000)
    _insert_file(conn, scan_id, "_test_hostA", "/x/notyet.bin", size_bytes=3_000_000)

    rows = cv.candidate_files(conn, "_test_hostA", min_size=1, only_unhashed=True)
    paths = [r[0] for r in rows]
    assert "/x/already.bin" not in paths
    assert "/x/notyet.bin" in paths


# ---------------------------------------------------------------------------
# 2. hash-loader idempotency
# ---------------------------------------------------------------------------

def test_local_content_hash_matches_hashlib(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"havnvard crosshost verify test payload" * 1000)
    expected = hashlib.sha256(f.read_bytes()).hexdigest()
    assert cv.local_content_hash(str(f)) == expected


def test_local_content_hash_unreadable_returns_none(tmp_path):
    missing = tmp_path / "does-not-exist.bin"
    assert cv.local_content_hash(str(missing)) is None


def test_hash_local_host_skips_unchanged_on_second_pass(conn, tmp_path, monkeypatch):
    """Idempotency: running hash_local_host twice against an unchanged file
    hashes it once, then skips it (via the os.stat size/mtime check) on the
    second run -- not a bug, the whole point of resumability."""
    f = tmp_path / "stable.bin"
    f.write_bytes(b"stable content, never changes" * 500)
    st = os.stat(f)

    host_a = _uniq_host("hostA")
    host_b = _uniq_host("hostB")
    scan_id = _make_scan_id(conn, host_a)
    other_scan = _make_scan_id(conn, host_b)
    _insert_file(
        conn, scan_id, host_a, str(f), size_bytes=st.st_size,
        inode=st.st_ino, mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
    )
    _insert_file(conn, other_scan, host_b, "/elsewhere/same-size.bin", size_bytes=st.st_size)
    conn.commit()  # candidate_files/hash need to see committed rows within this session

    run_id = 1  # heartbeat writes are stubbed below; run_id doesn't need a real FK row
    monkeypatch.setattr(cv, "write_heartbeat", lambda *a, **k: None)

    stats1 = cv.hash_local_host(conn, host_a, run_id, min_size=1, limit=None)
    assert stats1["files_hashed"] == 1
    assert stats1["files_skipped_unchanged"] == 0

    stats2 = cv.hash_local_host(conn, host_a, run_id, min_size=1, limit=None)
    assert stats2["files_hashed"] == 0
    assert stats2["files_skipped_unchanged"] == 1

    conn.rollback()


def test_hash_local_host_rehashes_on_content_change(conn, tmp_path, monkeypatch):
    """Self-heal: if a file's mtime/size drifts from what's recorded (e.g. it
    was overwritten in place by something else on the host after the last
    scan), the next hash pass must re-hash it rather than trust the stale
    content_sha256 forever."""
    f = tmp_path / "changing.bin"
    f.write_bytes(b"version one" * 500)
    st1 = os.stat(f)

    host_a = _uniq_host("hostA")
    host_b = _uniq_host("hostB")
    scan_id = _make_scan_id(conn, host_a)
    other_scan = _make_scan_id(conn, host_b)
    _insert_file(
        conn, scan_id, host_a, str(f), size_bytes=st1.st_size,
        inode=st1.st_ino, mtime=datetime.fromtimestamp(st1.st_mtime, tz=timezone.utc),
    )
    _insert_file(conn, other_scan, host_b, "/elsewhere/same-size2.bin", size_bytes=st1.st_size)
    conn.commit()

    monkeypatch.setattr(cv, "write_heartbeat", lambda *a, **k: None)
    stats1 = cv.hash_local_host(conn, host_a, 1, min_size=1, limit=None)
    assert stats1["files_hashed"] == 1

    # Mutate the file's content+size (recorded DB row still has the OLD size)
    # -- simulates a real drift between "what the last scan recorded" and
    # "what's actually on disk right now".
    time.sleep(1.1)  # ensure mtime resolution (1s check in hash_local_host) actually differs
    f.write_bytes(b"version TWO, totally different length!!" * 700)

    stats2 = cv.hash_local_host(conn, host_a, 1, min_size=1, limit=None)
    assert stats2["files_hashed"] == 1  # re-hashed, not skipped
    assert stats2["files_skipped_unchanged"] == 0

    conn.rollback()


# ---------------------------------------------------------------------------
# 3. synthetic same-content/different-path grouping (match subcommand)
# ---------------------------------------------------------------------------

def test_match_groups_same_hash_across_hosts_and_writes_integrity_match(conn):
    # `_MATCH_INTEGRITY_MATCH_SQL` hardcodes the destination host as the
    # literal 'nas-1' (not parameterized -- there is only ever one real
    # NAS in production), so the synthetic "NAS-side" row here MUST use that
    # real host name to be found at all. Safety: it's tagged with
    # _TEST_PATH_PREFIX so teardown can delete it without any risk of
    # touching genuine nas-1 production rows (which never live under
    # that path).
    same_hash = "f" * 64
    source_path = _TEST_PATH_PREFIX + "data/report.pdf"
    nas_path = _TEST_PATH_PREFIX + "backup/report.pdf"
    source_host = _uniq_host("spark")
    scan_id = _make_scan_id(conn, source_host)
    _insert_file(conn, scan_id, source_host, source_path, size_bytes=42, content_sha256=same_hash)
    _insert_file(conn, scan_id, "nas-1", nas_path, size_bytes=42, content_sha256=same_hash)
    conn.commit()

    stats = cv.run_match(conn, run_id=1, source_hosts=(source_host,))

    with conn.cursor() as cur:
        cur.execute(
            "SELECT duplicate_group_id, dedup_tool FROM diskaudit.files WHERE host=%s AND path=%s",
            (source_host, source_path),
        )
        group_id, tool = cur.fetchone()
    assert group_id == same_hash
    assert tool == "crosshost-sha256"

    assert stats["files_hashed"] >= 1  # "matched" count reused via files_hashed field

    with conn.cursor() as cur:
        cur.execute(
            "SELECT verdict FROM diskaudit.integrity_checks WHERE spark_host=%s AND spark_path=%s ORDER BY id DESC LIMIT 1",
            (source_host, source_path),
        )
        verdict_row = cur.fetchone()
    assert verdict_row is not None
    assert verdict_row[0] == "match"


def test_match_reports_missing_when_no_nas_counterpart(conn):
    source_path = _TEST_PATH_PREFIX + "orphan/nobackup.bin"
    source_host = _uniq_host("spark")
    scan_id = _make_scan_id(conn, source_host)
    _insert_file(conn, scan_id, source_host, source_path, size_bytes=999, content_sha256="e" * 64)
    conn.commit()

    cv.run_match(conn, run_id=1, source_hosts=(source_host,))

    with conn.cursor() as cur:
        cur.execute(
            "SELECT verdict FROM diskaudit.integrity_checks WHERE spark_host=%s AND spark_path=%s ORDER BY id DESC LIMIT 1",
            (source_host, source_path),
        )
        row = cur.fetchone()
    assert row is not None
    assert row[0] == "missing_dest"


# ---------------------------------------------------------------------------
# 4. delete/move guard -- codebase-wide, must fail if ever violated
# ---------------------------------------------------------------------------

# Primitives that must NEVER appear anywhere in this repo's own code, under
# any circumstances -- there is no legitimate reason for HavnVard to ever
# rename, move, or recursively remove anything, including its own scratch
# files (discrete `rm -f`/`os.remove` on individually-named tempfiles is the
# only sanctioned cleanup pattern; see the allowlist below).
_FORBIDDEN_ALWAYS = [
    re.compile(r"shutil\.move\("),
    re.compile(r"shutil\.rmtree\("),
    re.compile(r"os\.rename\("),
    re.compile(r"os\.replace\("),
    re.compile(r"\brm\s+-rf\b"),
]

# The ONE narrowly-keyed exception to _FORBIDDEN_ALWAYS (INFRA-520, HV-REQ-30):
# (basename, stripped line text) -> consulted ONLY for the os.replace pattern.
# shutil.move / shutil.rmtree / os.rename / `rm -rf` remain absolute.
_ALLOWED_FORBIDDEN_SITES = {
    # atomic write of the tool's OWN generated HTML report (tmp file -> OUT);
    # neither path is a scanned path.
    ("gen_cleanup_page.py", "os.replace(tmp, OUT)"),
    # backup/catalog.py (2.2.0): atomic write of the catalog's OWN state.json in ~/.local/state/havnvard/catalog/.
    ("catalog.py", "os.replace(tmp, p)"),
    # backup/accounts.py (3.3.0 fix wave, F6): atomic write of HavnVard's OWN hub htpasswd (config dir) after a
    # disabled user's computer line is cut; the removed line is kept in hub.htpasswd.removed. Never a scanned path.
    ("accounts.py", "os.replace(tmp, path)  # atomic write of HavnVard's own hub htpasswd (allowlisted in test_crosshost_verify)"),
}
_REPLACE_PATTERN_SRC = r"os\.replace\("

# Every (file, line-text) where a delete primitive (os.remove/os.unlink, or a
# shell `rm -f` issued via ssh/subprocess) is currently allowed to appear,
# because it has been manually reviewed and confirmed to target ONLY the
# tool's own tempfiles/scratch files -- never a scanned path. Adding a new
# delete call anywhere NOT in this list fails the test until a human adds it
# here deliberately (that review step is the entire point of this guard).
_ALLOWED_DELETE_SITES = {
    ("load_nas_inventory.py", "os.remove(tmppath)"),          # own sshpass password tempfile
    ("load_nas_inventory.py", "os.remove(p)"),                 # own downloaded .tsv/.errs/.symlinks scratch files
    ("load_nas_inventory.py", 'nas_ssh(f"rm -f {remote_glob} {_shq(remote_script)}", check=False)'),  # own NAS scratch dir
    ("crosshost_verify.py", "os.remove(tmppath)"),             # own sshpass password tempfile
    ("crosshost_verify.py", "os.remove(p)"),                   # own local batch tempfiles (paths/hashes/hasherrs)
    ("crosshost_verify.py", 'target.ssh(f"rm -f {remote_list} {remote_hashes} {remote_errs}")'),  # own remote scratch batch files
    ("crosshost_verify.py", 'target.ssh(f"rm -f {remote_script}")'),  # own remote scratch copy of hash_batch.sh
    # nas_trigkey_dedup.py (1.4.0): ONE site. Every remote cleanup goes through _remote_cleanup(), which
    # only ever names this tool's own scratch files (<batch>.paths/.hashes/.hasherrs, hash_stat_batch.sh)
    # under the scratch dir; local temp files live in TemporaryDirectory (no os.remove at all).
    ("nas_trigkey_dedup.py", 'r = target.ssh("rm -f " + " ".join(remote_paths))'),
    # verify_tree.py (INFRA-538): the canary's OWN six 8.5 MB book_N.txt copies (1.6.0) in
    # <NAS scratch>/verify_tree_canary_<pid>_<ts>/ (prefix-guarded in _remove_canary_dir),
    # then `rmdir` of that dir. Never a scanned path; no recursive delete.
    ("verify_tree.py", 'target.ssh(f"rm -f {files}; rmdir {shlex.quote(nas_dir)}")'),
    # backup/catalog.py (2.2.0): only files the catalog job itself wrote in ~/.local/state/havnvard/catalog/:
    # the previous per-device live listing (live/<repo>.<NNNNNN>.tsv, superseded once state.json commits the new one)
    # and the previous staged catalog copy (stage/*_catalog.tsv). Never a backed-up or scanned path.
    ("catalog.py", "os.remove(_live_path(repo, old_live))"),
    ("catalog.py", "os.remove(old)"),
}

_DELETE_CALL_PATTERN = re.compile(r"os\.remove\(|os\.unlink\(|\brm\s+-f\b")


def _iter_source_files(root=None):
    # "tests" is deliberately excluded: this very file's docstrings/comments
    # and the _ALLOWED_DELETE_SITES allowlist below necessarily CONTAIN the
    # literal text of the patterns being searched for (that's what an
    # allowlist of matched-line-text looks like) -- it would permanently
    # false-positive against itself. Test code also never touches a scanned
    # filesystem path (only pytest's own tmp_path + DB rows), so there is no
    # safety reason to police it the same way as the shipped tool code.
    for dirpath, dirnames, filenames in os.walk(root or REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".venv", "__pycache__", ".git", "reports", "logs", "data", "exports", "tmp", "nas_inbox", "tests")]
        for fn in filenames:
            if fn.endswith(".py") or fn.endswith(".sh"):
                yield os.path.join(dirpath, fn)


def scan_forbidden(root=None):
    """Lines carrying an absolute-forbidden primitive (minus the one keyed
    os.replace exception). Returns a list of 'path:lineno: ...' strings."""
    violations = []
    for path in _iter_source_files(root):
        basename = os.path.basename(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                for pattern in _FORBIDDEN_ALWAYS:
                    if pattern.search(line):
                        if pattern.pattern == _REPLACE_PATTERN_SRC and (basename, line.strip()) in _ALLOWED_FORBIDDEN_SITES:
                            continue
                        violations.append(f"{path}:{lineno}: forbidden primitive: {line.strip()}")
    return violations


def scan_deletes(root=None):
    """Delete calls not on the reviewed allowlist."""
    unexpected = []
    for path in _iter_source_files(root):
        basename = os.path.basename(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                if _DELETE_CALL_PATTERN.search(line):
                    stripped = line.strip()
                    if (basename, stripped) not in _ALLOWED_DELETE_SITES:
                        unexpected.append(f"{path}:{lineno}: {stripped}")
    return unexpected


def test_no_forbidden_delete_move_primitives_anywhere():
    violations = scan_forbidden()
    assert not violations, (
        "HARD CONSTRAINT VIOLATION -- a delete/move/rename primitive that must never exist "
        "in this codebase was found:\n" + "\n".join(violations)
    )


def test_every_delete_call_is_on_the_reviewed_allowlist():
    unexpected = scan_deletes()
    assert not unexpected, (
        "A delete call (os.remove/os.unlink/`rm -f`) was found that is NOT on the reviewed "
        "allowlist in tests/test_crosshost_verify.py. HavnVard may only ever delete its OWN "
        "tempfiles/scratch files -- if this is genuinely one of those, add it to "
        "_ALLOWED_DELETE_SITES with a comment explaining what it targets and why it's safe. "
        "If it touches a scanned path, it must be removed instead:\n" + "\n".join(unexpected)
    )


def test_guard_rejects_new_unlisted_delete(tmp_path):
    """Negative guard test (HV-REQ-30): the guard must actually FAIL on a new,
    unlisted delete call, and on a new unlisted os.replace -- otherwise a
    green guard proves nothing."""
    (tmp_path / "x.py").write_text("import os\nos.remove(victim)\n")
    (tmp_path / "y.py").write_text("import os\nos.replace(a, b)\n")
    (tmp_path / "z.sh").write_text("rm -f /some/scanned/file\n")
    deletes = scan_deletes(str(tmp_path))
    assert any("x.py" in d for d in deletes) and any("z.sh" in d for d in deletes)
    assert any("y.py" in v for v in scan_forbidden(str(tmp_path)))
    # the keyed exception is per (file, line): the same text in another file is NOT allowed
    (tmp_path / "other.py").write_text("os.replace(tmp, OUT)\n")
    assert any("other.py" in v for v in scan_forbidden(str(tmp_path)))


@pytest.mark.parametrize("script", ["hash_batch.sh", "hash_stat_batch.sh"])
def test_hash_batch_sh_has_no_delete_primitives_at_all(script):
    """The remote hash scripts run on the NAS/agent machines against scanned files
    directly -- they must be even more conservative than the Python driver:
    never a delete/move primitive of any kind (cleanup of their own output
    files is handled by the Python driver issuing discrete `rm -f` over ssh
    AFTER the results have been safely loaded into Postgres)."""
    path = os.path.join(REPO_ROOT, script)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    for pattern in list(_FORBIDDEN_ALWAYS) + [re.compile(r"\brm\s+-f\b"), re.compile(r"\bmv\b")]:
        assert not pattern.search(content), f"{script} must never contain a delete/move primitive, found: {pattern.pattern}"


# ---------------------------------------------------------------------------
# INFRA-242: a timed-out/failed scp_get of batch results must be a LOUD,
# distinct failure -- never an empty result that reads as "0 files hashed".
# Before the guard, hash_remote_host ignored scp_get's returncode: a rc=124
# transport timeout left the local results file empty, the loop recorded zero
# hashes for the batch, then `rm -f` cleanup DELETED the remote result files,
# silently discarding the work (docs/STANDARDS/SILENT_FAILURE_STANDARD.md).
# ---------------------------------------------------------------------------

import subprocess as _subprocess


class _FakeScpGetTimeoutTarget(cv._RemoteHashTarget):
    """ssh + scp_put succeed; fetching results back times out (rc=124,
    exactly what _run_with_timeout returns on subprocess.TimeoutExpired)."""
    scratch_dir = "/tmp/_test_infra242_scratch"

    def ssh(self, remote_cmd):
        return _subprocess.CompletedProcess(remote_cmd, 0, stdout="", stderr="")

    def scp_put(self, local_path, remote_path):
        return _subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def scp_get(self, remote_path, local_path):
        return _subprocess.CompletedProcess(
            [], 124, stdout="",
            stderr="timed out after 600s (see Plane INFRA-240)",
        )


class _NoDbConn:
    """hash_remote_host only needs commit() before any remote work when
    candidate_files is stubbed out; reaching for a cursor would mean the
    code got further than this test permits."""

    def commit(self):
        pass

    def cursor(self):  # pragma: no cover - reaching here IS the failure
        raise AssertionError(
            "hash_remote_host consumed batch results after a failed scp_get"
        )


def test_scp_get_timeout_is_a_loud_failure_not_zero_hashes(monkeypatch):
    monkeypatch.setattr(cv, "candidate_files",
                        lambda *a, **k: [("/data/somefile.bin", 4096)])
    monkeypatch.setattr(cv, "_target_for_host",
                        lambda host: _FakeScpGetTimeoutTarget())
    with pytest.raises(RuntimeError, match="timed out"):
        cv.hash_remote_host(_NoDbConn(), "agent-1", run_id=999999, min_size=1,
                            limit=None)


def test_run_with_timeout_per_call_override_and_default():
    """INFRA-520: _run_with_timeout gained an optional per-call timeout_sec
    (nas_trigkey_dedup's byte-scaled batch timeout). None keeps 600 s."""
    r = cv._run_with_timeout(["sleep", "5"], timeout_sec=1, capture_output=True, text=True)
    assert r.returncode == 124 and "timed out after 1s" in r.stderr
    ok = cv._run_with_timeout(["true"], capture_output=True, text=True)
    assert ok.returncode == 0
    assert cv._REMOTE_CALL_TIMEOUT_SEC == 600
