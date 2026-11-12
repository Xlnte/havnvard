#!/usr/bin/env python3
"""nas_dedup_core — pure functions for nas_trigkey_dedup.py (HavnVard 1.4.0).

NO database, NO ssh, NO subprocess imports here. Everything in this module is
a deterministic function of its arguments, so the safety-critical decisions
(is this digest still true? is this batch complete? which file is the keeper?)
are unit-testable without a Postgres or a NAS (HV-REQ-31).

Plane: INFRA-519 (work), INFRA-520 (source gaps). Design:
/home/user/runbooks/20261109-havnvard-nas-dedup/20261109_ARCHITECTURE.md
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# --------------------------------------------------------------------------
# constants shared with the publish SQL (single definition, passed as params)
# --------------------------------------------------------------------------

HEX64_RE = re.compile(r"[0-9a-f]{64}")
ERROR_REASONS = ("MISSING", "UNREADABLE", "UNSTABLE", "NOT_REGULAR")
RECYCLE_REGEX = r"/(@Recycle|\.@__thumb)/"                      # QNAP recycle / thumbnail dirs (HV-REQ-27/28)
RECYCLE_RE = re.compile(RECYCLE_REGEX)


def _backup_tree_prefix() -> str:
    """The NAS folder that holds backup REPLICAS of other machines (site file [nas] backup_tree_prefix).
    A replica is never chosen as the keeper while a live copy exists (BH-3). '' = the site has none.
    Read once at import from the site file (a config read, not I/O on the data being judged)."""
    import havnvard_site  # noqa: PLC0415  (stdlib-only site-file reader)
    p = havnvard_site.nas("backup_tree_prefix") or ""
    return p if not p or p.endswith("/") else p + "/"


BACKUP_TREE_PREFIX = _backup_tree_prefix()
# HV-REQ-27 in_backup_tree flag (LIKE ... ESCAPE '\'); '' never matches a real path.
BACKUP_TREE_LIKE = re.sub(r"([\\%_])", r"\\\1", BACKUP_TREE_PREFIX) + "%" if BACKUP_TREE_PREFIX else ""
_TRAILER_RE = re.compile(r"#DONE\|hashed=(\d+)\|statonly=(\d+)\|errors=(\d+)")

DEFAULT_BATCH_SIZE = 500
DEFAULT_BATCH_BYTES = 4 * 1024 ** 3        # 4 GiB of file bytes per batch
DEFAULT_ASSUMED_MBPS = 20                   # conservative NAS read rate for the ssh timeout
MIN_BATCH_TIMEOUT_SEC = 600                 # matches crosshost_verify._REMOTE_CALL_TIMEOUT_SEC
STAT_ONLY_PER_BATCH = 2000                  # stat-only (S) lines per batch when no hashing rides along


class BatchIntegrityError(Exception):
    """A batch's returned files disagree with what was sent (HV-REQ-17)."""


# --------------------------------------------------------------------------
# scope (HV-REQ-12)
# --------------------------------------------------------------------------

def normalize_scope(path: str) -> str:
    """Validate and normalise a --path / --exclude directory. Absolute, not
    '/', no NUL/newline. A trailing slash is removed."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"scope must be an absolute path: {path!r}")
    if "\x00" in path or "\n" in path or "\r" in path:
        raise ValueError(f"scope contains a control character: {path!r}")
    norm = os.path.normpath(path)
    if norm.startswith("//"):          # POSIX normpath keeps a leading '//'
        norm = "/" + norm.lstrip("/")
    if norm == "/":
        raise ValueError("scope '/' is the whole host: omit --path instead")
    return norm


def like_escape(text: str) -> str:
    """Escape LIKE metacharacters for use with ESCAPE '\\'."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like_prefix(scope: str) -> str:
    """LIKE pattern matching everything BELOW scope on a directory boundary
    ('/a/b' -> '/a/b/%'; never matches '/a/bc'; does not match '/a/b' itself,
    callers add an equality test for that)."""
    return like_escape(scope) + "/%"


# --------------------------------------------------------------------------
# path hygiene (HV-REQ-19)
# --------------------------------------------------------------------------

# The same set as a Postgres regex: the publish excludes these paths from every group even when an older version left a
# fresh binding on them (a 1.4.0 run bound some before 1.4.1 refused them), so no snapshot ever lists one (BH-1 / BH-8).
UNSAFE_PATH_REGEX = r"[\x01-\x1f\x7f\u0085\u2028\u2029\ufffd]"
_UNSAFE_PATH_CHARS = frozenset(chr(c) for c in range(0x20)) | {"\x7f", "\x85", "\u2028", "\u2029"}


def classify_path(path: str) -> Optional[str]:
    """None when the path can be sent in a newline-framed list; otherwise the
    per-file error reason it must be recorded under.

    UNSAFE_PATH: any C0 control character, DEL, or a Unicode line separator
    (U+0085, U+2028, U+2029): every one of them is a line break to some parser
    (Python str.splitlines, universal newlines) in the chain from the crawl to the
    operator delete script (BH-1 / BH-7, INFRA-520).
    NON_UTF8_PATH: undecodable bytes (stored as U+FFFD by scan.safe_str, so the NAS
    can never stat the stored string back: BH-8) or a lone surrogate."""
    if any(ch in _UNSAFE_PATH_CHARS for ch in path):
        return "UNSAFE_PATH"
    if "\ufffd" in path:
        return "NON_UTF8_PATH"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "NON_UTF8_PATH"
    return None


# --------------------------------------------------------------------------
# freshness (HV-REQ-05, 07, 08, 09)
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Cand:
    """One inventory row that is a hashing candidate."""
    path: str
    size_bytes: int
    mtime: object          # epoch seconds (int/Decimal/float) or None
    inode: Optional[int]
    nlink: Optional[int]
    content_sha256: Optional[str]


@dataclass(frozen=True, slots=True)
class Binding:
    """The stat a digest was computed against (diskaudit.dedup_digest_bindings)."""
    sha256: str
    size_bytes: int
    mtime: object          # epoch seconds
    st_ino: int
    st_dev: int
    bound_at: object = None


def digest_is_fresh(row: Cand, binding: Optional[Binding]) -> bool:
    """fresh(f, b) := b exists AND b.sha256 = f.content_sha256 AND
    b.size = f.size AND b.mtime = f.mtime AND b.st_ino = f.inode.

    Mirrors, term for term, the freshness join in the publish SQL. A legacy
    digest (no binding) is never fresh (HV-REQ-08); a foreign rewrite of
    content_sha256 breaks freshness (HV-REQ-09)."""
    if binding is None or row.content_sha256 is None:
        return False
    if row.inode is None or row.mtime is None:
        return False
    return (
        binding.sha256 == row.content_sha256
        and binding.size_bytes == row.size_bytes
        and binding.mtime == row.mtime
        and binding.st_ino == row.inode
    )


# --------------------------------------------------------------------------
# planning (HV-REQ-02, 07)
# --------------------------------------------------------------------------

@dataclass
class RepWork:
    path: str                       # the representative
    size_bytes: int
    siblings: list[str] = field(default_factory=list)   # hardlink siblings to stat-check (S lines)
    needs_hash: bool = True         # False: rep already carries a fresh binding, siblings only inherit


@dataclass
class HashPlan:
    to_hash: list[RepWork]          # reps needing bytes read (H), ascending (size, path)
    inherit_only: list[RepWork]     # fresh rep + non-fresh siblings (S lines only)
    reused: int                     # fresh rows that need nothing
    candidates: int


def _rep_key(c: Cand):
    return (len(c.path), c.path.encode("utf-8", "surrogateescape"))


def plan_hash_work(cands: Iterable[Cand], bindings: dict[str, Binding]) -> HashPlan:
    """Group candidates by (inode, size, mtime) -- hardlink siblings in the
    inventory -- and decide, per group, what must be read from the NAS.

    * some member fresh: it is the representative; non-fresh members become
      stat-only inherit candidates (the NAS must prove (dev, ino) equality);
    * none fresh: ONE representative (shortest path, then bytewise) is hashed
      and the rest ride along as S lines;
    * a NULL inode never groups (unique key).
    """
    groups: dict[object, list[Cand]] = {}
    n = 0
    for c in cands:
        n += 1
        key = (c.inode, c.size_bytes, c.mtime) if c.inode is not None else ("noinode", c.path)
        groups.setdefault(key, []).append(c)

    to_hash: list[RepWork] = []
    inherit_only: list[RepWork] = []
    reused = 0
    for grp in groups.values():
        fresh = [c for c in grp if digest_is_fresh(c, bindings.get(c.path))]
        fresh_ids = {id(c) for c in fresh}
        stale = [c for c in grp if id(c) not in fresh_ids]
        if fresh:
            rep = min(fresh, key=_rep_key)
            reused += len(fresh)
            if stale:
                inherit_only.append(RepWork(rep.path, rep.size_bytes,
                                            sorted((c.path for c in stale), key=lambda p: (len(p), p)),
                                            needs_hash=False))
        else:
            rep = min(grp, key=_rep_key)
            sibs = sorted((c.path for c in grp if c is not rep), key=lambda p: (len(p), p))
            to_hash.append(RepWork(rep.path, rep.size_bytes, sibs, needs_hash=True))
    to_hash.sort(key=lambda w: (w.size_bytes, w.path))
    inherit_only.sort(key=lambda w: w.path)
    return HashPlan(to_hash, inherit_only, reused, n)


@dataclass
class Batch:
    items: list[tuple[str, str]] = field(default_factory=list)      # ('H'|'S', path)
    rep_of: dict[str, str] = field(default_factory=dict)             # S path -> its representative path
    h_count: int = 0
    h_bytes: int = 0


def plan_batches(work: list[RepWork], batch_size: int = DEFAULT_BATCH_SIZE,
                 batch_bytes: int = DEFAULT_BATCH_BYTES) -> list[Batch]:
    """Cut hashing work (already sorted ascending by size) into batches: a
    batch closes at `batch_size` files OR `batch_bytes` bytes; a single file
    >= batch_bytes is a batch of one. Siblings (S) stay with their rep."""
    batches: list[Batch] = []
    cur = Batch()

    def flush():
        nonlocal cur
        if cur.items:
            batches.append(cur)
        cur = Batch()

    def add(w: RepWork, target: Batch):
        target.items.append(("H", w.path))
        target.h_count += 1
        target.h_bytes += w.size_bytes
        for s in w.siblings:
            target.items.append(("S", s))
            target.rep_of[s] = w.path

    for w in work:
        if w.size_bytes >= batch_bytes:
            flush()
            solo = Batch()
            add(w, solo)
            batches.append(solo)
            continue
        if cur.h_count and cur.h_bytes + w.size_bytes > batch_bytes:
            flush()
        add(w, cur)
        if cur.h_count >= batch_size:
            flush()
    flush()
    return batches


def plan_stat_batches(work: list[RepWork], per_batch: int = STAT_ONLY_PER_BATCH) -> list[Batch]:
    """Stat-only batches for fresh reps whose non-fresh siblings may inherit."""
    batches: list[Batch] = []
    cur = Batch()
    for w in work:
        for s in w.siblings:
            cur.items.append(("S", s))
            cur.rep_of[s] = w.path
            if len(cur.items) >= per_batch:
                batches.append(cur)
                cur = Batch()
    if cur.items:
        batches.append(cur)
    return batches


def batch_timeout(h_bytes: int, assumed_mbps: float = DEFAULT_ASSUMED_MBPS) -> int:
    """ssh timeout for one batch: max(600, 120 + bytes / (assumed MB/s))."""
    return int(max(MIN_BATCH_TIMEOUT_SEC, math.ceil(120 + h_bytes / (assumed_mbps * 1e6))))


# --------------------------------------------------------------------------
# batch result parsing and completeness check (HV-REQ-17)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class HashedRec:
    path: str
    sha256: str
    size_bytes: int
    mtime: int
    st_ino: int
    st_dev: int
    nlink: int


@dataclass(frozen=True)
class StatRec:
    path: str
    size_bytes: int
    mtime: int
    st_ino: int
    st_dev: int
    nlink: int


@dataclass
class BatchResult:
    hashed: list[HashedRec] = field(default_factory=list)
    stat: list[StatRec] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)      # (reason, path)


def _ints(fields: list[str]) -> Optional[list[int]]:
    try:
        return [int(f) for f in fields]
    except ValueError:
        return None


def verify_batch(sent: list[tuple[str, str]], hashes_text: str, errs_text: str) -> BatchResult:
    """Parse one batch's result files and prove they account for EXACTLY what
    was sent. Raises BatchIntegrityError naming the first 5 defects:

      * missing completion trailer (truncated file)
      * trailer counts differ from the parsed line counts
      * any line that does not parse (64-hex digest, integer stat fields)
      * a returned path that was not sent, or sent as the other kind
      * a path returned twice
      * |hashed| + |statonly| + |structured errors| != |sent|
    """
    defects: list[str] = []
    sent_kind: dict[str, str] = {}
    for kind, path in sent:
        if path in sent_kind:
            raise ValueError(f"duplicate path in sent list: {path!r}")
        sent_kind[path] = kind

    res = BatchResult()
    trailer = None
    lines = hashes_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for i, line in enumerate(lines):
        if line == "":
            defects.append(f"hashes line {i + 1}: empty line")
            continue
        if line.startswith("#DONE|"):
            m = _TRAILER_RE.fullmatch(line)
            if not m or trailer is not None or i != len(lines) - 1:
                defects.append(f"hashes line {i + 1}: bad or misplaced trailer {line[:80]!r}")
            else:
                trailer = tuple(int(x) for x in m.groups())
            continue
        if line.startswith("H|"):
            f = line.split("|", 7)
            if len(f) != 8 or not HEX64_RE.fullmatch(f[1]) or (nums := _ints(f[2:7])) is None:
                defects.append(f"hashes line {i + 1}: malformed H line {line[:120]!r}")
                continue
            res.hashed.append(HashedRec(f[7], f[1], *nums))
        elif line.startswith("S|"):
            f = line.split("|", 6)
            if len(f) != 7 or (nums := _ints(f[1:6])) is None:
                defects.append(f"hashes line {i + 1}: malformed S line {line[:120]!r}")
                continue
            res.stat.append(StatRec(f[6], *nums))
        else:
            defects.append(f"hashes line {i + 1}: unrecognised line {line[:120]!r}")

    for raw in errs_text.split("\n"):
        reason, sep, path = raw.partition("|")
        if sep and reason in ERROR_REASONS and path:
            res.errors.append((reason, path))

    if trailer is None:
        defects.append("missing #DONE completion trailer (truncated or crashed script)")
    elif trailer != (len(res.hashed), len(res.stat), len(res.errors)):
        defects.append(
            f"trailer counts hashed/statonly/errors={trailer} but parsed "
            f"{(len(res.hashed), len(res.stat), len(res.errors))}")

    seen: set[str] = set()
    for rec in res.hashed:
        if sent_kind.get(rec.path) != "H":
            defects.append(f"hashed path not sent as H: {rec.path!r}")
        if rec.path in seen:
            defects.append(f"path returned twice: {rec.path!r}")
        seen.add(rec.path)
    for rec in res.stat:
        if sent_kind.get(rec.path) != "S":
            defects.append(f"stat-only path not sent as S: {rec.path!r}")
        if rec.path in seen:
            defects.append(f"path returned twice: {rec.path!r}")
        seen.add(rec.path)
    for reason, path in res.errors:
        if path not in sent_kind:
            defects.append(f"error path not sent: {reason}|{path!r}")
        if path in seen:
            defects.append(f"path returned twice: {path!r}")
        seen.add(path)

    accounted = len(res.hashed) + len(res.stat) + len(res.errors)
    if accounted != len(sent):
        missing = [p for p in sent_kind if p not in seen]
        defects.append(
            f"{len(sent)} sent but {accounted} accounted for ({len(missing)} unaccounted, "
            f"first {missing[:2]!r})")

    if defects:
        raise BatchIntegrityError(
            f"{len(defects)} defect(s): " + "; ".join(defects[:5])
            + (f"; ... +{len(defects) - 5} more" if len(defects) > 5 else ""))
    return res


# --------------------------------------------------------------------------
# keeper rule (HV-REQ-28) -- mirrored in SQL; this is the oracle for tests
# --------------------------------------------------------------------------

def keeper_sort_key(path: str, mtime_epoch, in_recycle: Optional[bool] = None, in_backup: Optional[bool] = None):
    """Smallest key is the keeper candidate: not in a recycle bin -> not in the
    backup tree (BH-3) -> earliest mtime -> shortest path -> bytewise-smallest path."""
    if in_recycle is None:
        in_recycle = bool(RECYCLE_RE.search(path))
    if in_backup is None:
        in_backup = bool(BACKUP_TREE_PREFIX) and path.startswith(BACKUP_TREE_PREFIX)
    return (
        1 if in_recycle else 0,
        1 if in_backup else 0,
        float(mtime_epoch) if mtime_epoch is not None else math.inf,
        len(path),
        path.encode("utf-8", "surrogateescape"),
    )


# --------------------------------------------------------------------------
# progress (HV-REQ-24)
# --------------------------------------------------------------------------

def _hours(seconds: float) -> str:
    return f"{seconds / 3600:.1f}"


def format_progress(done: int, total: int, done_bytes: int, total_bytes: int,
                    run_elapsed_s: float, last_files: int = 0, last_bytes: int = 0,
                    last_elapsed_s: float = 0.0, batch_no: Optional[int] = None,
                    batch_files: Optional[int] = None, batch_bytes: Optional[int] = None,
                    batch_elapsed_s: Optional[float] = None) -> str:
    """One heartbeat note: done/total, files/s and MB/s for the last batch and
    the whole run, ETA in hours, and the in-flight batch."""
    pct = (100.0 * done / total) if total else 100.0
    run_fps = done / run_elapsed_s if run_elapsed_s > 0 else 0.0
    run_bps = done_bytes / run_elapsed_s if run_elapsed_s > 0 else 0.0
    last_fps = last_files / last_elapsed_s if last_elapsed_s > 0 else 0.0
    last_bps = last_bytes / last_elapsed_s if last_elapsed_s > 0 else 0.0
    etas = []
    if run_fps > 0:
        etas.append(max(total - done, 0) / run_fps)
    if run_bps > 0:
        etas.append(max(total_bytes - done_bytes, 0) / run_bps)
    eta = f"ETA {_hours(max(etas))} h" if etas else "ETA n/a"
    note = (
        f"hashed {done}/{total} ({pct:.1f}%) | {last_fps:.1f} f/s last, {run_fps:.1f} f/s run | "
        f"{last_bps / 1e6:.0f} MB/s last, {run_bps / 1e6:.0f} MB/s run | {eta}"
    )
    if batch_no is not None:
        note += (f" | batch {batch_no}: {batch_files} file{'s' if batch_files != 1 else ''}, "
                 f"{(batch_bytes or 0) / 1e9:.1f} GB, {int(batch_elapsed_s or 0):,} s elapsed")
    return note
