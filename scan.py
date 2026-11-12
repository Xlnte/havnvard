#!/usr/bin/env python3
"""diskaudit v1 — monthly whole-disk file inventory (log-only).

Walks a single filesystem device (skips other mounts, -xdev style) and records
path / size / permissions / owner / group / inode / nlink / extension / mtime /
atime / btime into Postgres (schema `diskaudit`, database havnvard). Upserts a
living inventory keyed by path — files that disappear between scans are marked
still_exists=false, never dropped.

v1 is intentionally log-only: no duplicate detection, no PRESCAB dispatch, no
delete candidates. Never runs rm / unlink / any delete API — that is a hard
constraint, not an oversight. See:
  - design doc: /home/user/.claude/plans/witty-swinging-shore.md
  - runbook:    /home/user/runbooks/20260717-diskaudit-v1/README.md
  - Plane:      INFRA-97

Usage:
  scan.py --dry-run --root /home/user      # cheap bounded validation run
  scan.py --dry-run                          # full-disk dry run (no DB writes to `files`)
  scan.py                                    # full-disk real run (what the monthly timer runs)
"""
from __future__ import annotations

import argparse
import ctypes
import grp
import os
import pwd
import stat as statmod
import sys
from datetime import datetime, timezone

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heartbeat import HeartbeatThrottle, write_heartbeat  # noqa: E402
from scan_guard import clear_stale_staging, refuse_if_locked  # noqa: E402

# ---- DSN resolution — same SoT + fallback order as /srv/apps/cabinet-tools/_lib/pg_client.py
from havnvard_site import get_dsn  # noqa: E402,F401  (3.0.0: one shared lookup; see havnvard_site.py)
from havnvard_site import local_host as _site_local_host  # noqa: E402
from havnvard_site import section as _site_section  # noqa: E402


def _site_extra_excludes() -> list[str]:
    return list(_site_section("scan").get("extra_excludes") or [])


# ---- statx(2) for birth time — Python's os.stat() does not expose this on Linux
# even though ext4/xfs can store it. Direct libc call, no per-file subprocess.
_STATX_BTIME = 0x800
_AT_SYMLINK_NOFOLLOW = 0x100
_AT_FDCWD = -100


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_nsec", ctypes.c_uint32),
        ("__reserved", ctypes.c_int32),
    ]


class _Statx(ctypes.Structure):
    _fields_ = [
        ("stx_mask", ctypes.c_uint32),
        ("stx_blksize", ctypes.c_uint32),
        ("stx_attributes", ctypes.c_uint64),
        ("stx_nlink", ctypes.c_uint32),
        ("stx_uid", ctypes.c_uint32),
        ("stx_gid", ctypes.c_uint32),
        ("stx_mode", ctypes.c_uint16),
        ("__spare0", ctypes.c_uint16 * 1),
        ("stx_ino", ctypes.c_uint64),
        ("stx_size", ctypes.c_uint64),
        ("stx_blocks", ctypes.c_uint64),
        ("stx_attributes_mask", ctypes.c_uint64),
        ("stx_atime", _StatxTimestamp),
        ("stx_btime", _StatxTimestamp),
        ("stx_ctime", _StatxTimestamp),
        ("stx_mtime", _StatxTimestamp),
        ("stx_rdev_major", ctypes.c_uint32),
        ("stx_rdev_minor", ctypes.c_uint32),
        ("stx_dev_major", ctypes.c_uint32),
        ("stx_dev_minor", ctypes.c_uint32),
        ("stx_mnt_id", ctypes.c_uint64),
        ("stx_dio_mem_align", ctypes.c_uint32),
        ("stx_dio_offset_align", ctypes.c_uint32),
        ("__spare3", ctypes.c_uint64 * 12),
    ]


try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
except OSError:
    _libc = None


def get_btime(path: str):
    """Return the file's birth time via statx(2), or None if unsupported/unavailable."""
    if _libc is None:
        return None
    buf = _Statx()
    try:
        rc = _libc.statx(
            _AT_FDCWD, os.fsencode(path), _AT_SYMLINK_NOFOLLOW, _STATX_BTIME, ctypes.byref(buf)
        )
    except (OSError, ValueError):
        return None
    if rc != 0:
        return None
    if not (buf.stx_mask & _STATX_BTIME):
        return None
    if buf.stx_btime.tv_sec == 0 and buf.stx_btime.tv_nsec == 0:
        return None
    return datetime.fromtimestamp(buf.stx_btime.tv_sec, tz=timezone.utc)


# ---- exclusions ----
# /proc /sys /dev /run are defense-in-depth (the st_dev check below already skips
# them as separate mounts). /var/lib/docker + containerd are on the SAME device as
# / on this box, so the st_dev check won't catch them — overlay2 layers would
# otherwise multiply every image byte into "large file" noise with no operator
# meaning.
# Network/remote mounts are excluded by default: scan.py's --root defaults to "/",
# so anything mounted under /mnt would otherwise be crawled as if it were local disk.
# /mnt/laptop-3 is an on-demand sshfs automount of a PORTABLE laptop over Tailscale
# (added 20260901). Crawling it would pull that machine's whole filesystem across the
# tailnet into diskaudit.files, and would block on a sleeping laptop. The NAS mounts are
# excluded for the same reason -- they are crawled deliberately and separately by
# diskaudit-nas-crawl.service / load_nas_inventory.py with --host set correctly, which is
# how remote hosts are SUPPOSED to enter the inventory.
DEFAULT_EXCLUDES = ("/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd",
                    ) + tuple(_site_extra_excludes())   # 3.0.0: site mounts, [scan] extra_excludes

# Same "docker/containerd overlay noise" problem as above, but as a PATH COMPONENT
# match rather than a fixed absolute prefix -- found the hard way scanning a mounted
# NAS share: a stored backup archive contained
# ".../bkup_server/spark-db/weekly/20260712/olduser/.local/share/docker/containerd/.../
# snapshots/396/fs/..." -- a Docker/containerd overlay tree nested arbitrarily deep
# inside someone else's backup, not at a predictable absolute path. Matching by
# component (any path SEGMENT exactly equal to "docker" or "containerd") catches this
# wherever it occurs, instead of requiring every such nested instance to be enumerated
# as its own --exclude prefix.
DEFAULT_EXCLUDE_COMPONENTS = ("docker", "containerd")


def effective_excludes(root: str, extra=()) -> tuple[list[str], list[str]]:
    """An explicit --root is never excluded by a DEFAULT exclude that is its ancestor (or itself): scanning
    /run/media/<user>/C (DESKTOP-1's NTFS C: drive) was silently skipped because /run is a default exclude (INFRA-518).
    Returns (effective_excludes, waived). Only DEFAULT_EXCLUDES are waivable; caller-supplied `extra` (--exclude)
    entries are deliberate and always kept."""
    root = os.path.abspath(root)
    waived = [p for p in DEFAULT_EXCLUDES if root == p.rstrip("/") or root.startswith(p.rstrip("/") + "/")]
    return [p for p in DEFAULT_EXCLUDES if p not in waived] + list(extra), waived


def is_excluded(path: str, excludes, exclude_components=DEFAULT_EXCLUDE_COMPONENTS) -> bool:
    if any(path == p or path.startswith(p.rstrip("/") + "/") for p in excludes):
        return True
    if exclude_components:
        parts = path.split("/")
        if any(part in exclude_components for part in parts):
            return True
    return False


_uid_cache: dict[int, str | None] = {}
_gid_cache: dict[int, str | None] = {}


def owner_name(uid: int):
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = None
    return _uid_cache[uid]


def group_name(gid: int):
    if gid not in _gid_cache:
        try:
            _gid_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _gid_cache[gid] = None
    return _gid_cache[gid]


def file_type_of(mode: int) -> str:
    if statmod.S_ISDIR(mode):
        return "dir"
    if statmod.S_ISLNK(mode):
        return "symlink"
    if statmod.S_ISREG(mode):
        return "regular"
    return "other"


def to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def safe_str(s: str | None) -> str | None:
    """Sanitize a str that may contain lone surrogates from os.scandir's
    surrogateescape handling of undecodable filename bytes (real on this box —
    hit during the first full-disk dry run). Lossy (-> U+FFFD) but this is a
    log-only inventory, not a path we round-trip back to the filesystem."""
    if s is None:
        return None
    return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def build_row(host: str, path: str, st: os.stat_result, ftype: str, want_btime: bool):
    # NOTE: `path` here is the real filesystem path (possibly containing
    # surrogate-escaped bytes) — used for actual OS calls below. Only the
    # values placed into the returned row are sanitized for storage.
    symlink_target = None
    if ftype == "symlink":
        try:
            symlink_target = os.readlink(path)
        except OSError:
            symlink_target = None
    extension = None
    if ftype == "regular":
        _, ext = os.path.splitext(path)
        extension = ext[1:].lower() if ext else None
    btime = get_btime(path) if want_btime else None
    return (
        host,
        safe_str(path),
        ftype,
        safe_str(symlink_target),
        st.st_size if ftype == "regular" else None,
        statmod.S_IMODE(st.st_mode),
        st.st_uid,
        st.st_gid,
        owner_name(st.st_uid),
        group_name(st.st_gid),
        st.st_ino,
        st.st_nlink,
        extension,
        to_dt(st.st_mtime),
        to_dt(st.st_atime),
        btime,
    )


COPY_SQL = (
    "COPY diskaudit.files_staging "
    "(host, path, file_type, symlink_target, size_bytes, mode, uid, gid, "
    "owner_name, group_name, inode, nlink, extension, mtime, atime, btime, scan_id) "
    "FROM STDIN"
)


def crawl(host: str, root: str, excludes, want_btime: bool, batch_size: int, conn, scan_id: int, held_out=None):
    """Walk root, stage rows (tagged with scan_id). `held_out` (a set) collects every path whose directory listing or
    stat FAILED: its previously stored descendants are unverified and merge() must not mark them disappeared
    (1.4.3, R142-8)."""
    root = os.path.abspath(root)
    root_dev = os.lstat(root).st_dev
    stack = [root]
    files_scanned = 0
    dirs_scanned = 0
    bytes_scanned = 0
    errors = 0
    batch: list[tuple] = []
    hb = HeartbeatThrottle(min_interval_s=15.0)

    def log_error(cur, path: str, err: Exception):
        nonlocal errors
        errors += 1
        if held_out is not None:
            held_out.add(safe_str(path))
        cur.execute(
            "INSERT INTO diskaudit.scan_errors (scan_id, path, error) VALUES (%s, %s, %s)",
            (scan_id, safe_str(path), safe_str(str(err))),
        )

    def flush(cur):
        nonlocal batch
        if not batch:
            return
        with cur.copy(COPY_SQL) as cp:
            for row in batch:
                cp.write_row(row)
        conn.commit()
        batch = []

    with conn.cursor() as cur:
        while stack:
            current = stack.pop()
            if is_excluded(current, excludes):
                continue
            try:
                entries = list(os.scandir(current))
            except OSError as e:
                log_error(cur, current, e)
                continue

            for entry in entries:
                path = entry.path
                if is_excluded(path, excludes):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as e:
                    log_error(cur, path, e)
                    continue
                if st.st_dev != root_dev:
                    continue  # -xdev: separate mount, don't record or descend

                ftype = file_type_of(st.st_mode)
                if ftype == "dir":
                    dirs_scanned += 1
                    stack.append(path)
                else:
                    files_scanned += 1
                    if ftype == "regular":
                        bytes_scanned += st.st_size

                batch.append(build_row(host, path, st, ftype, want_btime) + (scan_id,))
                if len(batch) >= batch_size:
                    flush(cur)
                    if hb.due():
                        write_heartbeat(
                            conn, "scan", scan_id, host, "crawling",
                            note=f"{files_scanned} files, {dirs_scanned} dirs so far",
                        )
        flush(cur)

    return files_scanned, dirs_scanned, bytes_scanned, errors


# 1.4.2 (INFRA-518): the merge is ONE upsert plus one set-based UPDATE, with NO join between files and
# files_staging. The 1.4.0/1.4.1 form (UPDATE..FROM, then INSERT..LEFT JOIN anti-join, then a NOT EXISTS) let the
# planner choose a nested loop from a ~1-row estimate for the staged host -- files_staging is shared across hosts and
# its statistics describe whichever host loaded before -- so a host with no prior rows spun at 100% CPU forever
# (scans 4370/4371, 20261109; only PGOPTIONS='-c enable_nestloop=off' got them through). Semantics are unchanged:
#   - existing row  -> columns refreshed, btime kept if the scan has none, last_seen_scan_id=scan, still_exists=true,
#                      disappeared_at=NULL; first_seen_scan_id untouched
#   - new row       -> inserted with first_seen = last_seen = scan
#   - not re-seen   -> still_exists=false, disappeared_at=now(), but ONLY under this run's root_prefix; "not re-seen"
#                      is last_seen_scan_id <> scan, which is exactly "absent from staging" because the upsert stamps
#                      every staged row of this host.
# DISTINCT ON (path): two distinct on-disk names can collapse to one stored path (safe_str maps undecodable bytes to
# U+FFFD); the old UPDATE..FROM tolerated that for existing rows, and ON CONFLICT would otherwise abort the whole merge.
# The kept row is chosen by a full ORDER BY (deterministic, not heap order), and every collapsed path is first written
# to scan_errors as DUPLICATE_STAGED_PATH so the lost entry is visible, never silently dropped (1.4.2 Opus review).
MERGE_DUPLICATES = """
INSERT INTO diskaudit.scan_errors (scan_id, path, error)
SELECT %(scan_id)s, s.path,
    'DUPLICATE_STAGED_PATH: ' || count(*) || ' scanned entries map to this one stored path (undecodable bytes in the '
    || 'on-disk names); one was kept in files, the others are not inventoried'
FROM diskaudit.files_staging s
WHERE s.host = %(host)s AND s.scan_id = %(scan_id)s
GROUP BY s.path HAVING count(*) > 1;
"""

MERGE_UPSERT = """
INSERT INTO diskaudit.files AS f (host, path, file_type, symlink_target, size_bytes, mode, uid, gid,
    owner_name, group_name, inode, nlink, extension, mtime, atime, btime,
    first_seen_scan_id, last_seen_scan_id)
SELECT DISTINCT ON (s.path) s.host, s.path, s.file_type, s.symlink_target, s.size_bytes, s.mode, s.uid, s.gid,
    s.owner_name, s.group_name, s.inode, s.nlink, s.extension, s.mtime, s.atime, s.btime,
    %(scan_id)s, %(scan_id)s
FROM diskaudit.files_staging s
WHERE s.host = %(host)s AND s.scan_id = %(scan_id)s
ORDER BY s.path, s.inode, s.mtime, s.size_bytes, s.file_type, s.symlink_target
ON CONFLICT (host, path) DO UPDATE SET
    file_type=EXCLUDED.file_type, symlink_target=EXCLUDED.symlink_target, size_bytes=EXCLUDED.size_bytes,
    mode=EXCLUDED.mode, uid=EXCLUDED.uid, gid=EXCLUDED.gid, owner_name=EXCLUDED.owner_name,
    group_name=EXCLUDED.group_name, inode=EXCLUDED.inode, nlink=EXCLUDED.nlink, extension=EXCLUDED.extension,
    mtime=EXCLUDED.mtime, atime=EXCLUDED.atime, btime=COALESCE(EXCLUDED.btime, f.btime),
    last_seen_scan_id=EXCLUDED.last_seen_scan_id, still_exists=true, disappeared_at=NULL, updated_at=now();
"""

MERGE_DISAPPEARED = """
UPDATE diskaudit.files f SET still_exists=false, disappeared_at=now(), updated_at=now()
WHERE f.still_exists AND f.host = %(host)s AND f.path LIKE %(root_prefix)s
  AND f.last_seen_scan_id <> %(scan_id)s;
"""

# 1.4.3 (R142-8): rows under a path whose listing/stat FAILED this scan are not verified gone, so they keep their last
# state. Used only when the scan had such errors (the plain statement above is unchanged for the common case).
MERGE_DISAPPEARED_HELD = MERGE_DISAPPEARED.rstrip().rstrip(";") + """
  AND NOT (f.path = ANY(%(held)s::text[])
           OR EXISTS (SELECT 1 FROM unnest(%(held_pre)s::text[]) q WHERE starts_with(f.path, q)));
"""

# Annotate each error row of a held path with how many stored rows were held back. Runs after the disappearance
# UPDATE, when the only rows still "not re-seen" under the root are exactly the held ones.
MERGE_HELD_NOTE = """
WITH cand AS MATERIALIZED (
    SELECT f.path FROM diskaudit.files f
    WHERE f.still_exists AND f.host = %(host)s AND f.path LIKE %(root_prefix)s AND f.last_seen_scan_id <> %(scan_id)s),
per AS (
    SELECT h.p, count(c.path) AS n FROM unnest(%(held_all)s::text[]) AS h(p)
    LEFT JOIN cand c ON c.path = h.p OR starts_with(c.path, rtrim(h.p, '/') || '/') GROUP BY h.p)
UPDATE diskaudit.scan_errors e SET error = left(e.error, 1800) || ' [HELD_BACK: ' || per.n
    || ' stored rows at/under this path kept as last seen, not marked disappeared]'
FROM per WHERE e.scan_id = %(scan_id)s AND e.path = per.p;
"""


# Bound on the held-path statements (R143-2): both compare every not-re-seen row under the root with every held path,
# so their cost is (not-re-seen rows) x (held paths). Bench: 250 held x 50 k rows ~ 26 s on server-1. Above the
# budget the disappearance step is DEFERRED for this run (nothing is marked disappeared; one error row says so) -- the
# safe direction: the next clean scan catches up. A whole unreadable share is 1 held path, so it stays in budget.
HELD_PAIR_BUDGET = 50_000_000

MERGE_COUNT_UNSEEN = """
SELECT count(*) FROM diskaudit.files f
WHERE f.still_exists AND f.host = %(host)s AND f.path LIKE %(root_prefix)s AND f.last_seen_scan_id <> %(scan_id)s;
"""

MERGE_HELD_DEFERRED = """
INSERT INTO diskaudit.scan_errors (scan_id, path, error) VALUES (%(scan_id)s, %(root)s,
    'HELD_BACK_DEFERRED: ' || %(n_unseen)s || ' stored rows not re-seen x ' || %(n_held)s
    || ' unreadable paths exceeds the merge budget; NOTHING under this root was marked disappeared this run');
"""


def _prune_nested(paths) -> list[str]:
    """Drop empty entries and any path nested under another held path (the shorter prefix already covers it)."""
    uniq = sorted({p for p in paths if p})
    out: list[str] = []
    for p in uniq:
        if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            out.append(p)
    return out


def merge(conn, scan_id: int, host: str, root: str, held_paths=()):
    # "Disappeared" must only apply within what THIS run actually scanned -- a bounded
    # --root run must never mark the rest of the host's inventory as gone just because
    # it wasn't in this run's (necessarily partial) staging set. root='/' naturally
    # covers everything via '/%' , so this is a no-op restriction for full-disk runs
    # (the only mode the production monthly timer uses) and only matters for partial
    # rescans -- confirmed the hard way: this exact bug marked all 10.5M existing rows
    # as about to disappear during a bounded test run, caught and killed before COMMIT.
    # Returns the number of errors it logged (DUPLICATE_STAGED_PATH rows, plus 1 for HELD_BACK_DEFERRED), for errors_count.
    # 1.4.3: staged rows are read by scan_id (MERGE_* below); `held_paths` are paths whose listing/stat failed.
    # LIKE metacharacters in the root are escaped (backslash is LIKE's default escape): an unescaped "_" or "%" in
    # e.g. --root /data/my_dir would also match /data/myXdir/..., marking ANOTHER root's rows disappeared (1.4.2 review).
    esc = root.rstrip("/").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    root_prefix = esc + "/%"
    with conn.cursor() as cur:
        cur.execute(MERGE_DUPLICATES, {"scan_id": scan_id, "host": host})
        n_dup = cur.rowcount
        cur.execute(MERGE_UPSERT, {"scan_id": scan_id, "host": host})
        held_all = sorted({p for p in held_paths if p})
        n_unseen = 0
        if held_all:
            cur.execute(MERGE_COUNT_UNSEEN, {"host": host, "root_prefix": root_prefix, "scan_id": scan_id})
            n_unseen = cur.fetchone()[0]
        if held_all and n_unseen * len(held_all) > HELD_PAIR_BUDGET:
            cur.execute(MERGE_HELD_DEFERRED, {"scan_id": scan_id, "root": root.rstrip("/") or "/",
                                              "n_unseen": n_unseen, "n_held": len(held_all)})
            n_dup += 1  # counted in errors_count like the duplicate rows
            print(f"[diskaudit] HELD_BACK_DEFERRED: {n_unseen} not re-seen x {len(held_all)} held paths over budget; "
                  "disappearance skipped this run", file=sys.stderr)
        elif held_all:
            held = _prune_nested(held_all)
            cur.execute(MERGE_DISAPPEARED_HELD, {
                "host": host, "root_prefix": root_prefix, "scan_id": scan_id, "held": held,
                "held_pre": [p.rstrip("/") + "/" for p in held]})
            cur.execute(MERGE_HELD_NOTE, {"host": host, "root_prefix": root_prefix, "scan_id": scan_id,
                                          "held_all": held_all})
        else:
            cur.execute(MERGE_DISAPPEARED, {"host": host, "root_prefix": root_prefix, "scan_id": scan_id})
    conn.commit()
    return n_dup


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=_site_local_host(), help="Host tag for these rows (default: this machine's [hosts] local). Use a different value when scanning a mounted remote path, e.g. --host nas-1.")
    ap.add_argument("--root", default="/", help="Root path to crawl (default: /)")
    ap.add_argument("--dry-run", action="store_true", help="Crawl + stage only; skip merge into diskaudit.files")
    ap.add_argument("--batch-size", type=int, default=5000)
    ap.add_argument("--no-btime", action="store_true", help="Skip statx birth-time lookup (faster)")
    ap.add_argument("--exclude", action="append", default=[], help="Additional path prefix to exclude (repeatable)")
    args = ap.parse_args()

    excludes, waived = effective_excludes(args.root, args.exclude)
    for w in waived:
        print(f"[diskaudit] default exclude {w} waived: explicit --root {args.root} is inside it", file=sys.stderr)
    if is_excluded(os.path.abspath(args.root), excludes):
        # A root inside a --exclude (or a docker/containerd component) would crawl nothing, and the merge would then
        # mark every stored row under the root disappeared. Refuse instead (1.4.2 Opus review).
        print(f"[diskaudit] error: --root {args.root} is itself excluded (by --exclude or an excluded path component); "
              "nothing would be scanned", file=sys.stderr)
        sys.exit(2)
    conn = psycopg.connect(get_dsn(), autocommit=False)
    refuse_if_locked(conn, args.host, os.path.abspath(args.root), "diskaudit")  # 1.4.3: one scan per (host, root)
    scan_id = None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO diskaudit.scan_runs (host, root_path, dry_run, status) "
                "VALUES (%s, %s, %s, 'running') RETURNING scan_id",
                (args.host, args.root, args.dry_run),
            )
            scan_id = cur.fetchone()[0]
            clear_stale_staging(cur, args.host, args.root, scan_id)
        conn.commit()
        write_heartbeat(conn, "scan", scan_id, args.host, "starting")

        print(f"[diskaudit] scan_id={scan_id} host={args.host} root={args.root} dry_run={args.dry_run}", file=sys.stderr)
        held: set[str] = set()
        files_scanned, dirs_scanned, bytes_scanned, errors = crawl(
            args.host, args.root, excludes, not args.no_btime, args.batch_size, conn, scan_id, held_out=held
        )
        print(
            f"[diskaudit] crawl done: files={files_scanned} dirs={dirs_scanned} "
            f"bytes={bytes_scanned} errors={errors}",
            file=sys.stderr,
        )

        if args.dry_run:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT path, size_bytes, atime FROM diskaudit.files_staging "
                    "WHERE scan_id = %s AND file_type='regular' ORDER BY size_bytes DESC NULLS LAST LIMIT 20",
                    (scan_id,),
                )
                print("[diskaudit] top 20 largest files staged (not written to diskaudit.files):", file=sys.stderr)
                for path, size_bytes, atime in cur.fetchall():
                    print(f"  {size_bytes:>15} {atime}  {path}", file=sys.stderr)
            status = "dry_run"
        else:
            write_heartbeat(conn, "scan", scan_id, args.host, "merging")
            errors += merge(conn, scan_id, args.host, args.root, held)
            status = "completed"

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE diskaudit.scan_runs SET finished_at=now(), files_scanned=%s, "
                "dirs_scanned=%s, bytes_scanned=%s, errors_count=%s, status=%s WHERE scan_id=%s",
                (files_scanned, dirs_scanned, bytes_scanned, errors, status, scan_id),
            )
        conn.commit()
        print(f"[diskaudit] scan_id={scan_id} status={status}", file=sys.stderr)
    except Exception as e:
        conn.rollback()
        if scan_id is not None:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE diskaudit.scan_runs SET finished_at=now(), status='failed' WHERE scan_id=%s",
                    (scan_id,),
                )
            conn.commit()
            write_heartbeat(conn, "scan", scan_id, args.host, "failed", note=str(e)[:500])
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
