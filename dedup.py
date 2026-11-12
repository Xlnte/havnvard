#!/usr/bin/env python3
"""diskaudit v2 — duplicate detection via rdfind, integrated into the diskaudit schema.

Runs the existing `rdfind` (apt 1.6.0: size-prefilter -> first/last-byte elimination ->
full sha256 checksum on remaining candidates -- see rdfind's own stdout for the exact
elimination counts) against a host's already-known file scope, then writes a STABLE,
cross-host-comparable duplicate_group_id back into diskaudit.files.

Why a separate hash step after rdfind already ran: rdfind's results.txt does not include
the actual checksum value, only per-run relative group ids (positive for the kept/first
occurrence, negative for its duplicates -- grouping key is abs(id), but that id is only
meaningful within this one run, not stable across runs or hosts). So once rdfind tells us
WHICH files are duplicates of each other (the expensive part -- size + partial + full
checksum elimination), we hash just ONE representative file per confirmed group ourselves
to derive a real content-hash identifier that IS stable across runs and hosts. This is
cheap: only one extra read per group, not per file, and only for files already confirmed
identical.

Never deletes, never hardlinks, never modifies files -- read-only with respect to the
files being scanned; only writes are into diskaudit.files.

Usage:
  dedup.py --host server-1                       # derive directory scope from diskaudit.files
  dedup.py --host nas-1 --root /mnt/nas-audit  # explicit root (v2 Part B, NAS mount case)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import select
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import psycopg

# bucketing.py / heartbeat.py live alongside this file (same diskaudit/ dir), not on
# the default import path when dedup.py is invoked from elsewhere (e.g. cron, a
# different cwd) -- make the import robust regardless of how this script is launched.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bucketing
from heartbeat import HeartbeatThrottle, mark_worker_done, write_heartbeat

# Stage markers matched against rdfind's own stdout lines, in the order they normally
# appear, so a monitor (or a human) can see WHERE a run is stuck, not just whether its
# heartbeat is stale. Order matters only for readability here -- _latest_stage_in_text
# always returns whichever marker last matched, regardless of list order.
_STAGE_MARKERS = [
    (re.compile(r"^Now scanning"), "scanning"),
    (re.compile(r"^Now have \d+ files in total"), "counted"),
    (re.compile(r"due to nonunique device and inode"), "inode-check"),
    (re.compile(r"^Total size is"), "sizing"),
    (re.compile(r"due to unique sizes"), "unique-size-elim"),
    (re.compile(r"eliminating candidates based on first bytes"), "first-bytes-elim"),
    (re.compile(r"eliminating candidates based on last bytes"), "last-bytes-elim"),
    (re.compile(r"eliminating candidates based on \w+ checksum"), "checksum-elim"),
    (re.compile(r"^It seems like you have"), "checksum-done"),
    (re.compile(r"^Now making results file"), "writing-results"),
]


def _stage_for_line(line: str) -> str | None:
    for pattern, stage in _STAGE_MARKERS:
        if pattern.search(line):
            return stage
    return None


def _latest_stage_in_text(text: str) -> str | None:
    stage = None
    for line in text.splitlines():
        s = _stage_for_line(line)
        if s:
            stage = s
    return stage

# rdfind's own stdout lines documenting each of its 4 elimination stages -- this is the
# only place these counts exist; parse them so the full pipeline result (not just the
# final duplicate_group_id verdict) is auditable in the DB.
_RE_TOTAL_FILES = re.compile(r"Now have (\d+) files in total\.")
_RE_ELIM_SIZE = re.compile(r"Removed (\d+) files due to unique sizes from list\.")
_RE_ELIM_FIRST = re.compile(r"eliminating candidates based on first bytes: removed (\d+) files")
_RE_ELIM_LAST = re.compile(r"eliminating candidates based on last bytes: removed (\d+) files")
_RE_ELIM_CHECKSUM = re.compile(r"eliminating candidates based on \w+ checksum: removed (\d+) files")
_RE_DUP_FILES = re.compile(r"It seems like you have (\d+) files that are not unique")


def parse_rdfind_stats(stdout: str) -> dict:
    def find(pattern):
        m = pattern.search(stdout)
        return int(m.group(1)) if m else None

    return {
        "total_files_considered": find(_RE_TOTAL_FILES),
        "eliminated_unique_size": find(_RE_ELIM_SIZE),
        "eliminated_first_bytes": find(_RE_ELIM_FIRST),
        "eliminated_last_bytes": find(_RE_ELIM_LAST),
        "eliminated_checksum": find(_RE_ELIM_CHECKSUM),
        "duplicate_files_found": find(_RE_DUP_FILES),
    }

from havnvard_site import get_dsn  # noqa: E402,F401  (3.0.0: one shared lookup; see havnvard_site.py)
from havnvard_site import local_host as _site_local_host  # noqa: E402


def derive_scan_dirs(conn, host: str) -> list[str]:
    """Reuse scan.py's already-correct scope (device-boundary + exclude-list aware)
    instead of re-deriving mount points and exclusions independently -- avoids the two
    implementations drifting apart. Returns the top-level directories scan.py actually
    descended into for this host."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT path FROM diskaudit.files
            WHERE host = %s AND file_type = 'dir' AND still_exists
              AND path ~ '^/[^/]+$'
            ORDER BY path
            """,
            (host,),
        )
        return [row[0] for row in cur.fetchall()]


def get_candidate_size_groups(conn, host: str, dirs: list[str]) -> list[tuple[int, list[str]]]:
    """Replace rdfind's own stage-1 (unique-size elimination) with a cheap SQL query
    against data we already have in diskaudit.files, instead of asking every parallel
    worker to re-derive it by walking whole directory trees itself. Returns candidate
    groups as (size_bytes, [paths_sharing_that_size]) -- only sizes shared by 2+ files
    (a unique size can never be part of a duplicate pair, same as rdfind's own filter).

    dirs are matched as path prefixes (parameterized -- never string-formatted into the
    query) so this is safe to call with directory lists derived from diskaudit.files or
    passed explicitly via --root.
    """
    if not dirs:
        return []
    like_clauses = " OR ".join(["path LIKE %s"] * len(dirs))
    like_params = [f"{d}/%" for d in dirs]
    sql = f"""
        SELECT size_bytes, array_agg(path)
        FROM diskaudit.files
        WHERE host = %s AND file_type = 'regular' AND still_exists
          AND ({like_clauses})
        GROUP BY size_bytes
        HAVING count(*) > 1
    """
    with conn.cursor() as cur:
        cur.execute(sql, (host, *like_params))
        return [(row[0], row[1]) for row in cur.fetchall()]


def _group_path_bytes(paths: list[str]) -> int:
    return sum(len(p) + 1 for p in paths)


def split_oversized_groups(size_groups, safety_margin_bytes: int = 200_000):
    """Separate out size-groups that can NEVER fit in a single ARG_MAX-safe rdfind
    invocation, no matter how they're chunked -- a group must never be split across
    chunks (see run_parallel()'s correctness note: rdfind only compares files WITHIN
    one invocation, so a split group's cross-chunk duplicates go permanently
    undetected), so a group whose own path bytes alone exceed the safe budget has no
    valid rdfind-based path at all. Found in production: a 2791-byte size-group with
    16,011 files totalled ~3.1MB of path bytes on its own -- over 3x the entire
    ARG_MAX budget before any chunking is even considered.

    Also drops size_bytes == 0 (empty files) entirely, matching rdfind's own default
    (-ignoreempty true): they're trivially identical but carry no real space-
    reclamation value (0 bytes of content, only inode/dirent overhead), and this
    project's whole duplicate-detection convention is built on rdfind's behavior --
    silently diverging from it (confirmed empirically: this was initially
    implemented as a "free win" duplicate group and inflated group/file counts
    beyond the established rdfind-based baseline by exactly the empty-file count)
    would be an inconsistency, not an improvement.

    Returns (normal_groups, oversized_groups) -- no third empty-file return value,
    they're dropped outright.
    """
    budget = bucketing._arg_byte_budget(safety_margin_bytes)
    normal, oversized = [], []
    for size_bytes, paths in size_groups:
        if size_bytes == 0:
            continue
        elif _group_path_bytes(paths) > budget:
            oversized.append((size_bytes, paths))
        else:
            normal.append((size_bytes, paths))
    return normal, oversized


def hash_oversized_groups_directly(oversized_groups) -> dict[str, list[str]]:
    """Bypass rdfind entirely for groups too large to ever fit in one invocation --
    hash every file directly (same content_hash() used elsewhere for representative
    files) and group by the resulting digest. Same-SIZE does not imply same-CONTENT,
    so this still needs a real hash, not just the size-group membership itself.

    quiet=True on every call here (not just the representative-file case elsewhere):
    an oversized group can have hundreds of thousands of members, many plausibly
    unreadable (found in production: Docker/containerd overlay snapshots owned by
    other users) -- per-file WARN prints at that volume produced a 9.2-million-line
    log in one real run, which is suspected to have contributed to the Postgres
    connection dropping ("SSL connection has been closed unexpectedly") near the very
    end of that run. One summary line instead."""
    by_digest: dict[str, list[str]] = {}
    read_errors = 0
    for _size_bytes, paths in oversized_groups:
        for path in paths:
            digest = content_hash(path, quiet=True)
            if digest is None:
                read_errors += 1
                continue
            by_digest.setdefault(digest, []).append(path)
    if read_errors:
        print(f"[dedup] {read_errors} files in oversized groups could not be read/hashed (permission denied or similar) -- skipped", file=sys.stderr)
    return {f"direct:{digest}": paths for digest, paths in by_digest.items() if len(paths) > 1}


def run_rdfind(dirs: list[str], results_path: str, conn, host: str, dedup_run_id) -> str:
    """Streams rdfind's stdout live (Popen, not run()+capture_output) so stage
    transitions ('now eliminating based on first bytes', etc.) update the heartbeat
    as they actually happen, instead of only being visible after the whole process
    exits -- this is the difference between "the run looks stale" and "the run is in
    the checksum stage, which is where it spends most of its time on large files."""
    cmd = ["rdfind", "-outputname", results_path, "-checksum", "sha256", *dirs]
    print(f"[dedup] running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    hb = HeartbeatThrottle(min_interval_s=20.0)
    lines: list[str] = []
    stage = "starting"
    write_heartbeat(conn, "dedup", dedup_run_id, host, stage)
    while True:
        ready, _, _ = select.select([proc.stdout], [], [], 15.0)
        if ready:
            line = proc.stdout.readline()
            if line == "":
                break  # EOF -- process is finishing
            lines.append(line)
            print(line, end="", file=sys.stderr)
            new_stage = _stage_for_line(line)
            if new_stage:
                stage = new_stage
                write_heartbeat(conn, "dedup", dedup_run_id, host, stage)
        elif hb.due():
            # No new output in the last 15s (typical during the checksum stage on
            # large files) -- prove the run is still alive, not just silent.
            write_heartbeat(conn, "dedup", dedup_run_id, host, stage, note="no new output, still running")
    returncode = proc.wait()
    stdout = "".join(lines)
    if returncode != 0:
        raise RuntimeError(f"rdfind exited {returncode}")
    return stdout


_RE_MULTI_SLASH = re.compile(r"/{2,}")


def _normalize_path(path: str) -> str:
    """Collapse repeated slashes. rdfind emits e.g. '.../dir//file' (a doubled slash
    before the basename) when given a bare FILE path -- rather than a directory -- as
    a scan argument (confirmed empirically: the parallel path passes explicit file
    lists per size-bucket, unlike the serial path which passes directories). POSIX
    itself treats repeated slashes as equivalent to one (open() on the raw path works
    fine either way), but the exact-string-match JOIN against diskaudit.files -- whose
    paths always come from os.scandir, never doubled -- does not, so every row from
    the parallel path silently matched zero rows despite dedup_runs reporting
    'completed'. Safe to apply unconditionally: valid Unix paths never intentionally
    contain consecutive slashes."""
    return _RE_MULTI_SLASH.sub("/", path)


def parse_results(results_path: str) -> dict[str, list[str]]:
    """Parse rdfind's results.txt into {relative_group_id: [paths...]}."""
    groups: dict[str, list[str]] = {}
    with open(results_path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split(maxsplit=7)
            if len(parts) != 8:
                continue
            _duptype, group_id, _depth, _size, _device, _inode, _priority, path = parts
            key = str(abs(int(group_id)))
            groups.setdefault(key, []).append(_normalize_path(path))
    # groups of size 1 mean nothing (rdfind shouldn't emit these, but be defensive)
    return {k: v for k, v in groups.items() if len(v) > 1}


def content_hash(path: str, quiet: bool = False) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(4 * 1024 * 1024):
                h.update(chunk)
    except OSError as e:
        if not quiet:
            print(f"[dedup] WARN: could not hash representative file {path}: {e}", file=sys.stderr)
        return None
    return h.hexdigest()


_DEDUP_COPY_SQL = (
    "COPY diskaudit.dedup_staging (host, path, duplicate_group_id, dedup_tool, dedup_method, dedup_checked_at) "
    "FROM STDIN"
)

_DEDUP_MERGE_SQL = """
UPDATE diskaudit.files f SET
    duplicate_group_id = s.duplicate_group_id, dedup_tool = s.dedup_tool,
    dedup_method = s.dedup_method, dedup_checked_at = s.dedup_checked_at
FROM diskaudit.dedup_staging s
WHERE f.host = s.host AND f.path = s.path AND s.host = %(host)s;
"""


def write_groups(conn, host: str, groups: dict[str, list[str]], batch_size: int = 10000, dedup_tool: str = "rdfind"):
    """Bulk-write via COPY-into-staging + one set-based UPDATE...FROM, instead of one
    UPDATE per file -- the per-file loop measured at ~22 of 78 total minutes on the
    /srv/apps test run (1.8M files), a real and unacceptable cost at this scale.

    dedup_tool is recorded per-row so serial (rdfind) vs parallel (rdfind-parallel)
    invocations are distinguishable in the DB afterward."""
    checked_at = datetime.now(timezone.utc)
    skipped = 0
    total_rows = 0

    with conn.cursor() as cur:
        cur.execute("DELETE FROM diskaudit.dedup_staging WHERE host = %s", (host,))
    conn.commit()

    with conn.cursor() as cur:
        batch: list[tuple] = []

        def flush():
            nonlocal batch
            if not batch:
                return
            with cur.copy(_DEDUP_COPY_SQL) as cp:
                for row in batch:
                    cp.write_row(row)
            batch = []

        for _key, paths in groups.items():
            digest = content_hash(paths[0])
            if digest is None:
                skipped += len(paths)
                continue
            for path in paths:
                batch.append((host, path, digest, dedup_tool, "sha256", checked_at))
                total_rows += 1
                if len(batch) >= batch_size:
                    flush()
        flush()
    conn.commit()

    with conn.cursor() as cur:
        cur.execute(_DEDUP_MERGE_SQL, {"host": host})
        written = cur.rowcount
    conn.commit()
    return written, skipped


class _ChunkedWorker:
    """Mutable per-worker state for run_parallel()'s (possibly multi-chunk) rdfind
    pipeline. A worker whose bucket exceeds the OS argv-byte budget (see
    bucketing._safe_arg_chunks()) runs its chunks SEQUENTIALLY -- one rdfind
    invocation per chunk, in order -- while still running CONCURRENTLY with every
    OTHER worker. This is what actually fixes the full-disk-scale crash (each
    individual argv stays under budget) without losing the existing cross-worker
    parallelism.

    All of a worker's chunks share ONE stdout file (opened once, reused across every
    chunk's Popen call by never closing/reopening it) so the existing
    heartbeat/stage-tailing logic -- which reads that one file and looks for the
    LATEST matching stage marker -- keeps working unmodified: a running chunk's
    newest lines are always physically appended at the end of the file, so they're
    still what gets picked up as 'latest'. Per-chunk byte offsets into that shared
    file are recorded so stats/results can still be attributed to the correct chunk
    afterward.
    """

    def __init__(self, worker_idx: int, chunks: list[list[str]]):
        self.worker_idx = worker_idx
        self.chunks = chunks
        self.chunk_idx = -1  # index of the chunk currently running / just finished
        self.stdout_path: str | None = None
        self._stdout_f = None  # opened once, kept open across every chunk in this worker
        self.proc: subprocess.Popen | None = None
        self.results_paths: list[str] = []  # one per started chunk, in order
        self.chunk_stdout_ranges: list[tuple[int, int]] = []  # (start, end) byte offsets per finished chunk
        self._chunk_start_offset = 0
        self.failed_rc: int | None = None

    def start_next_chunk(self):
        self.chunk_idx += 1
        paths = self.chunks[self.chunk_idx]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=f".w{self.worker_idx}.c{self.chunk_idx}.txt", delete=False
        ) as tf:
            results_path = tf.name
        self.results_paths.append(results_path)
        if self._stdout_f is None:
            self.stdout_path = results_path + ".stdout"
            self._stdout_f = open(self.stdout_path, "w")
        # Query the real on-disk size rather than this Python file object's own
        # position bookkeeping -- the actual writes happen via the child process's
        # dup'd fd (bypassing any buffering this handle itself would track), and by
        # the time poll() reports the previous chunk's process has exited, libc's
        # stdio flush-on-exit guarantees everything it wrote is already on disk.
        self._chunk_start_offset = os.path.getsize(self.stdout_path)
        cmd = ["rdfind", "-outputname", results_path, "-checksum", "sha256", *paths]
        print(
            f"[dedup] worker {self.worker_idx} chunk {self.chunk_idx}/{len(self.chunks) - 1}: "
            f"rdfind on {len(paths)} files -> {results_path}",
            file=sys.stderr,
        )
        self.proc = subprocess.Popen(cmd, stdout=self._stdout_f, stderr=subprocess.STDOUT)

    def finish_current_chunk(self, rc: int):
        end_offset = os.path.getsize(self.stdout_path)
        self.chunk_stdout_ranges.append((self._chunk_start_offset, end_offset))
        if rc != 0:
            self.failed_rc = rc

    def close(self):
        if self._stdout_f is not None:
            self._stdout_f.close()


def run_parallel(conn, host: str, dirs: list[str], n_workers: int, dedup_run_id) -> tuple[dict[str, list[str]], dict]:
    """Parallel alternative to run_rdfind()+parse_results(): partition same-size
    candidate files (queried directly from diskaudit.files, not rediscovered by rdfind)
    into n_workers size-balanced buckets, then run one rdfind subprocess per bucket
    concurrently, each given its own EXPLICIT FILE LIST (not a directory to re-walk)
    and its own results file.

    A single worker's bucket can itself be too large to pass as one argv (OS ARG_MAX
    -- see bucketing._safe_arg_chunks()): at full-disk scale individual buckets have
    hit 500k-800k+ files, far past the ~25k-30k path ceiling measured on this host.
    So each worker's bucket is FIRST split into byte-safe chunks (bucketing module);
    a worker with >1 chunk runs them SEQUENTIALLY (see _ChunkedWorker) while still
    running CONCURRENTLY with every other worker.

    Returns (merged_groups, aggregated_stats) in the same shapes main() already knows
    how to hand to write_groups() / the dedup_runs UPDATE for the serial path.

    Correctness note: rdfind's relative group ids in results.txt are only unique WITHIN
    one invocation -- group "3" from worker 0's chunk 0 and group "3" from worker 0's
    chunk 1 (or worker 1's chunk 0) are unrelated. Every group key is namespaced with
    BOTH its worker index AND its chunk index (f"w{worker_idx}:c{chunk_idx}:{key}") so
    groups can never collide/incorrectly merge across workers OR across chunks within
    the same worker. (The common single-chunk-per-worker case just always has
    chunk_idx == 0 -- this is a pure internal dict key, never written to the DB, so
    unifying the format doesn't change any output.)

    Second correctness note (found empirically while validating this at scale, not
    theoretically): chunking a worker's bucket MUST stay GROUP-aware
    (bucketing.bucket_groups_by_size() + _safe_arg_chunks_by_group()), never chunk by
    flat path list alone. A same-size candidate group split across two chunks would
    be split across two separate rdfind invocations -- and rdfind only ever compares
    files WITHIN one invocation, so any such split makes a real duplicate pair
    permanently undetectable. An earlier flat-path-chunking version of this function
    measured 23,192 groups / 54,029 rows against a forced single-bucket, 4-chunk test
    run -- 2 groups/5 rows short of the correct 23,194/54,034 baseline -- from exactly
    this bug.
    """
    all_size_groups = get_candidate_size_groups(conn, host, dirs)
    size_groups, oversized_groups = split_oversized_groups(all_size_groups)
    total_candidate_files = sum(len(paths) for _, paths in all_size_groups)
    dropped_empty = sum(len(paths) for size_bytes, paths in all_size_groups if size_bytes == 0)
    print(
        f"[dedup] dedup_run_id={dedup_run_id} parallel: {len(all_size_groups)} candidate "
        f"size-groups, {total_candidate_files} candidate files, n_workers={n_workers} "
        f"({len(oversized_groups)} oversized groups handled directly bypassing rdfind, "
        f"{dropped_empty} empty files dropped matching rdfind's -ignoreempty default)",
        file=sys.stderr,
    )

    direct_groups: dict[str, list[str]] = {}
    if oversized_groups:
        direct_groups.update(hash_oversized_groups_directly(oversized_groups))

    if not size_groups:
        # Everything was empty-file/oversized -- nothing left for rdfind to do.
        return direct_groups, {
            "total_files_considered": total_candidate_files,
            "eliminated_unique_size": None,
            "eliminated_first_bytes": None,
            "eliminated_last_bytes": None,
            "eliminated_checksum": None,
            "duplicate_files_found": sum(len(p) for p in direct_groups.values()),
            "duplicate_groups_found": len(direct_groups),
            "raw_stdout": "",
        }

    grouped_buckets = bucketing.bucket_groups_by_size(size_groups, n_workers)

    # Start EVERY worker's first chunk before waiting on any of them -- true
    # concurrency across workers, unlike run_rdfind()'s subprocess.run() (which
    # blocks until exit). stdout/stderr are redirected to a per-worker file (reused
    # across that worker's chunks -- see _ChunkedWorker) rather than PIPE so a large
    # volume of rdfind output can never fill a pipe buffer and deadlock while we poll
    # rather than block on each process.
    workers: list[_ChunkedWorker] = []
    for worker_idx, bucket_groups in enumerate(grouped_buckets):
        total_paths = sum(len(paths) for _, paths in bucket_groups)
        if total_paths == 0:
            print(f"[dedup] worker {worker_idx}: empty bucket, skipping", file=sys.stderr)
            continue
        # Group-aware chunking (not bucketing._safe_arg_chunks() on a flat path
        # list) -- see the correctness note above; never split a same-size group
        # across two chunks.
        chunks = bucketing._safe_arg_chunks_by_group(bucket_groups)
        if len(chunks) > 1:
            print(
                f"[dedup] worker {worker_idx}: bucket of {total_paths} files exceeds the "
                f"argv byte budget -- split into {len(chunks)} sequential chunks",
                file=sys.stderr,
            )
        w = _ChunkedWorker(worker_idx, chunks)
        w.start_next_chunk()
        workers.append(w)

    # Poll every worker concurrently (non-blocking poll(), not a sequential blocking
    # wait() per worker) so a heartbeat can be emitted for whichever workers are
    # STILL running while others may already be done -- a monitor can then tell WHICH
    # of N workers is stuck, not just that the overall run looks stale. A worker with
    # multiple chunks stays "active" (keeps its worker_idx key in `active`) until ALL
    # of its chunks have completed, or one of them fails.
    active = {w.worker_idx: w for w in workers}
    per_worker_hb = {w.worker_idx: HeartbeatThrottle(min_interval_s=20.0) for w in workers}
    last_stage_by_worker: dict[int, str] = {}
    overall_hb = HeartbeatThrottle(min_interval_s=20.0)

    while active:
        for worker_idx in list(active.keys()):
            w = active[worker_idx]
            rc = w.proc.poll()
            if rc is not None:
                w.finish_current_chunk(rc)
                if rc != 0 or w.chunk_idx >= len(w.chunks) - 1:
                    # Either this chunk failed (abort the whole worker -- a partial
                    # rdfind run has no usable results for the group merge) or this
                    # was the worker's LAST chunk and it succeeded.
                    w.close()
                    del active[worker_idx]
                    mark_worker_done(conn, dedup_run_id, worker_idx, "completed" if rc == 0 else "failed")
                else:
                    w.start_next_chunk()
                continue
            if per_worker_hb[worker_idx].due():
                try:
                    with open(w.stdout_path, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except OSError:
                    text = ""
                stage = _latest_stage_in_text(text) or last_stage_by_worker.get(worker_idx, "running")
                last_stage_by_worker[worker_idx] = stage
                write_heartbeat(conn, "dedup", dedup_run_id, host, stage, worker_idx=worker_idx)
        if active and overall_hb.due():
            write_heartbeat(
                conn, "dedup", dedup_run_id, host, "parallel-running",
                note=f"{len(active)}/{len(workers)} workers still running",
            )
        if active:
            time.sleep(2.0)

    merged_groups: dict[str, list[str]] = {}
    agg_stats = {
        "total_files_considered": 0,
        "eliminated_unique_size": 0,
        "eliminated_first_bytes": 0,
        "eliminated_last_bytes": 0,
        "eliminated_checksum": 0,
        "duplicate_files_found": 0,
    }
    all_stdout_parts: list[str] = []

    for w in workers:
        if w.failed_rc is not None:
            failed_chunk_idx = len(w.chunk_stdout_ranges) - 1
            raise RuntimeError(f"[dedup] worker {w.worker_idx} chunk {failed_chunk_idx} rdfind exited {w.failed_rc}")
        for chunk_idx, (results_path, (start, end)) in enumerate(zip(w.results_paths, w.chunk_stdout_ranges)):
            with open(w.stdout_path, "rb") as f:
                f.seek(start)
                chunk_stdout = f.read(end - start).decode("utf-8", errors="replace")
            print(chunk_stdout, file=sys.stderr)
            all_stdout_parts.append(f"--- worker {w.worker_idx} chunk {chunk_idx} ---\n{chunk_stdout}")

            stats = parse_rdfind_stats(chunk_stdout)
            for k, v in stats.items():
                if v is not None:
                    agg_stats[k] += v

            chunk_groups = parse_results(results_path)
            for key, paths in chunk_groups.items():
                merged_groups[f"w{w.worker_idx}:c{chunk_idx}:{key}"] = paths

    merged_groups.update(direct_groups)
    agg_stats["duplicate_files_found"] = (agg_stats.get("duplicate_files_found") or 0) + sum(
        len(p) for p in direct_groups.values()
    )
    agg_stats["duplicate_groups_found"] = len(merged_groups)
    agg_stats["raw_stdout"] = "\n".join(all_stdout_parts)
    return merged_groups, agg_stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=_site_local_host())
    ap.add_argument("--root", action="append", default=[], help="Explicit root dir(s) to scan (repeatable). If omitted, derives scope from diskaudit.files for --host.")
    ap.add_argument("--parallel", type=int, default=1, help="Number of concurrent rdfind workers. Default 1 = existing serial run_rdfind() path, unchanged. >1 uses run_parallel() (size-balanced buckets, one rdfind subprocess per bucket).")
    args = ap.parse_args()

    conn = psycopg.connect(get_dsn(), autocommit=False)
    dedup_run_id = None
    try:
        dirs = args.root or derive_scan_dirs(conn, args.host)
        if not dirs:
            sys.exit(f"[dedup] no directories found for host={args.host} -- run scan.py first, or pass --root explicitly")
        print(f"[dedup] host={args.host} scanning {len(dirs)} top-level dirs: {dirs}", file=sys.stderr)

        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO diskaudit.dedup_runs (host, root_dirs, status) "
                "VALUES (%s, %s, 'running') RETURNING dedup_run_id",
                (args.host, dirs),
            )
            dedup_run_id = cur.fetchone()[0]
        conn.commit()
        write_heartbeat(conn, "dedup", dedup_run_id, args.host, "starting")

        if args.parallel > 1:
            print(f"[dedup] parallel mode: n_workers={args.parallel}", file=sys.stderr)
            groups, stats = run_parallel(conn, args.host, dirs, args.parallel, dedup_run_id)
            dedup_tool = "rdfind-parallel"
        else:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                results_path = tf.name
            stdout = run_rdfind(dirs, results_path, conn, args.host, dedup_run_id)
            stats = parse_rdfind_stats(stdout)
            groups = parse_results(results_path)
            stats["duplicate_groups_found"] = len(groups)
            stats["raw_stdout"] = stdout
            dedup_tool = "rdfind"
        print(f"[dedup] {len(groups)} duplicate groups found", file=sys.stderr)
        write_heartbeat(conn, "dedup", dedup_run_id, args.host, "writing-to-db")

        written, skipped = write_groups(conn, args.host, groups, dedup_tool=dedup_tool)
        print(f"[dedup] wrote duplicate_group_id to {written} rows ({skipped} skipped due to read errors)", file=sys.stderr)

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.dedup_runs SET
                    finished_at = now(), status = 'completed',
                    total_files_considered = %(total_files_considered)s,
                    eliminated_unique_size = %(eliminated_unique_size)s,
                    eliminated_first_bytes = %(eliminated_first_bytes)s,
                    eliminated_last_bytes = %(eliminated_last_bytes)s,
                    eliminated_checksum = %(eliminated_checksum)s,
                    duplicate_files_found = %(duplicate_files_found)s,
                    duplicate_groups_found = %(duplicate_groups_found)s,
                    raw_stdout = %(raw_stdout)s
                WHERE dedup_run_id = %(dedup_run_id)s
                """,
                {**stats, "dedup_run_id": dedup_run_id},
            )
        conn.commit()
        print(f"[dedup] dedup_run_id={dedup_run_id} status=completed", file=sys.stderr)
    except Exception as e:
        conn.rollback()
        if dedup_run_id is not None:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE diskaudit.dedup_runs SET finished_at=now(), status='failed' WHERE dedup_run_id=%s",
                    (dedup_run_id,),
                )
            conn.commit()
            write_heartbeat(conn, "dedup", dedup_run_id, args.host, "failed", note=str(e)[:500])
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
