#!/usr/bin/env python3
"""verify_tree.py -- HavnVard 1.5.0 (Plane INFRA-538): full-byte proof before a copy is deleted.

PAF rule (20261109 23:39): no copy of a file is deleted unless 100% of its bytes are proven
equal to the copy that is kept. Size, mtime, or a partial hash never count. A one-character
change (one lowercase `m` -> capital `M` in a book-sized text file) must read as DIFFERENT.

    verify_tree.py verify --local DIR --nas-path PATH --purpose TEXT
        Hash every byte of every file on BOTH sides in this run (local: hashlib; NAS: sha256sum
        run ON the NAS over ssh, nothing crosses the network), compare file lists and digests,
        record the result in diskaudit.tree_verifications + diskaudit.integrity_checks.
        Prints VERIFY_RUN_ID=<n> and VERDICT=<v>.
    verify_tree.py mark-deleted --run-id N
        Link a deletion to the VERIFIED run that allowed it (sets deleted_at).
    verify_tree.py canary
        Run only the m->M canary (both code paths: local hash and NAS hash).

Exit codes: 0 VERIFIED; 3 MISMATCH or NOT_VERIFIED (never delete); 4 canary failed (the
check itself is broken: alarm, never delete); 2 usage error.

Fail-closed by construction (PART III section 3): every path that does not end in a complete,
recorded, all-match comparison returns non-zero. An empty tree is NOT_VERIFIED (never delete on
zero input). A result that cannot be written to the DB is NOT_VERIFIED.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crosshost_verify as cv  # noqa: E402  (read-only reuse: local_content_hash, _NasTarget, get_dsn)
from nas_dedup_core import classify_path  # noqa: E402

__version__ = "1.5.0"

EXIT_VERIFIED = 0
EXIT_USAGE = 2
EXIT_NOT_VERIFIED = 3
EXIT_CANARY = 4

NAS_HOST = "nas-ts453a"
# Measured 20261110 01:10: NAS sha256sum 36.7 MB/s (7.05 GiB / 201.5 s) under a concurrent
# HavnVard dedup run. The timeout assumes a floor 3.7x slower than that.
NAS_HASH_FLOOR_BPS = 10_000_000
NAS_HASH_MIN_TIMEOUT = 600

_HASH_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\./.*)$")

# integrity_checks per-file verdicts (migration 20261110 widens the CHECK).
V_MATCH = "match"
V_MISMATCH = "mismatch"
V_MISSING_DEST = "missing_dest"
V_EXTRA_DEST = "extra_dest"
V_UNREADABLE_SOURCE = "unreadable_source"
V_UNREADABLE_DEST = "unreadable_dest"
V_NOT_VERIFIED = "not_verified"

# tree verdicts
T_VERIFIED = "VERIFIED"
T_MISMATCH = "MISMATCH"
T_NOT_VERIFIED = "NOT_VERIFIED"
T_CANARY_FAILED = "CANARY_FAILED"


# --------------------------------------------------------------------------
# names
# --------------------------------------------------------------------------

def name_problem(rel: str) -> Optional[str]:
    """None if `rel` can be compared reliably against BusyBox sha256sum output, else a reason.
    BusyBox (and GNU) sha256sum escape a name holding a backslash or newline by prefixing the
    line with `\\`; rather than un-escape, such names are refused (backup trees never hold them)."""
    reason = classify_path(rel)
    if reason:
        return reason
    if "\\" in rel:
        return "BACKSLASH_PATH"
    return None


# --------------------------------------------------------------------------
# local side
# --------------------------------------------------------------------------

@dataclass
class LocalTree:
    files: dict = field(default_factory=dict)      # rel -> size_bytes
    problems: list = field(default_factory=list)   # (rel, reason)


def list_local(root: str) -> LocalTree:
    """Every regular file under root, as './'-relative paths (the same form `find .` prints on
    the NAS). Symlinks, fifos, sockets and devices are problems, never silently skipped."""
    out = LocalTree()

    def _err(e: OSError):
        out.problems.append((os.path.relpath(getattr(e, "filename", root) or root, root), f"WALK_ERROR:{e.strerror}"))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_err):
        for name in list(dirnames) + list(filenames):
            full = os.path.join(dirpath, name)
            rel = "./" + os.path.relpath(full, root)
            try:
                st = os.lstat(full)
            except OSError as e:
                out.problems.append((rel, f"LSTAT_ERROR:{e.strerror}"))
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                out.problems.append((rel, "NON_REGULAR"))
                continue
            bad = name_problem(rel)
            if bad:
                out.problems.append((rel, bad))
                continue
            out.files[rel] = st.st_size
    return out


def hash_local(root: str, rels) -> dict:
    """rel -> sha256 hex of EVERY byte (crosshost_verify.local_content_hash, 4 MiB reads),
    or None if unreadable."""
    return {rel: cv.local_content_hash(os.path.join(root, rel[2:])) for rel in rels}


# --------------------------------------------------------------------------
# NAS side
# --------------------------------------------------------------------------

def remote_script(nas_path: str) -> str:
    """One ssh call, run on the NAS. Lists non-regular entries and regular files, hashes every
    regular file, and reports find's exit status (non-zero when a sha256sum it ran failed; the
    NAS shell has no pipefail, so the hash lines are NOT piped through sed). Listing lines are
    tagged; a hash line is recognised by its own shape (64 hex, two spaces, name). Independently
    of the status, every listed file must have exactly one hash line."""
    q = shlex.quote(nas_path)
    return (
        f"cd {q} || {{ echo 'CDFAIL|'; exit 0; }}; "
        "find . ! -type d ! -type f | sed 's/^/NONREG|/'; "
        "find . -type f | sed 's/^/FILE|/'; "
        "find . -type f -exec sha256sum {} +; "
        "echo \"RC|$?\"; echo 'END|'"
    )


@dataclass
class RemoteTree:
    files: set = field(default_factory=set)
    hashes: dict = field(default_factory=dict)     # rel -> sha
    problems: list = field(default_factory=list)   # (rel or '', reason)
    complete: bool = False


def parse_remote(stdout: str, rc: int) -> RemoteTree:
    """Parse remote_script() output. `complete` is True only if ssh rc==0, the script reached
    END, sha256sum's pipeline status is 0, there is exactly one valid hash per listed file, and
    no NONREG entry exists. Anything else leaves complete=False with a reason."""
    t = RemoteTree()
    if rc != 0:
        t.problems.append(("", f"SSH_RC:{rc}"))
        return t
    saw_end = False
    hash_rc = None
    for line in stdout.split("\n"):
        if not line:
            continue
        if line.startswith("\\"):
            t.problems.append((line[:200], "ESCAPED_HASH_LINE"))
            continue
        hm = _HASH_LINE_RE.match(line)
        if hm:
            digest, name = hm.group(1), hm.group(2)
            if name in t.hashes:
                t.problems.append((name, "DUPLICATE_HASH_LINE"))
            else:
                t.hashes[name] = digest
            continue
        tag, _, rest = line.partition("|")
        if tag == "CDFAIL":
            t.problems.append(("", "NAS_PATH_MISSING"))
        elif tag == "NONREG":
            t.problems.append((rest, "NON_REGULAR_DEST"))
        elif tag == "FILE":
            bad = name_problem(rest)
            if bad:
                t.problems.append((rest, bad))
            t.files.add(rest)
        elif tag == "RC":
            try:
                hash_rc = int(rest)
            except ValueError:
                t.problems.append(("", f"BAD_RC_LINE:{rest}"))
        elif tag == "END":
            saw_end = True
        else:
            t.problems.append((line[:200], "UNTAGGED_LINE"))
    if not saw_end:
        t.problems.append(("", "NO_END_MARKER"))
    if hash_rc is None:
        t.problems.append(("", "NO_RC_LINE"))
    elif hash_rc != 0:
        t.problems.append(("", f"FIND_EXEC_RC:{hash_rc}"))
    for rel in sorted(t.files - set(t.hashes)):
        t.problems.append((rel, V_UNREADABLE_DEST))
    for rel in sorted(set(t.hashes) - t.files):
        t.problems.append((rel, "HASH_WITHOUT_FILE"))
    t.complete = not t.problems
    return t


def nas_timeout(total_bytes: int) -> int:
    return max(NAS_HASH_MIN_TIMEOUT, int(total_bytes / NAS_HASH_FLOOR_BPS) + 1)


def hash_remote(target, nas_path: str, total_bytes: int) -> tuple[RemoteTree, float]:
    t0 = time.monotonic()
    r = target.ssh(remote_script(nas_path), timeout_sec=nas_timeout(total_bytes))
    return parse_remote(r.stdout or "", r.returncode), time.monotonic() - t0


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FileResult:
    rel: str
    size_bytes: Optional[int]
    sha_source: Optional[str]
    sha_dest: Optional[str]
    verdict: str
    notes: str = ""


def compare(local: LocalTree, local_hashes: dict, remote: RemoteTree) -> tuple[str, list, str]:
    """(tree_verdict, [FileResult], reason). VERIFIED only when: no problem on either side,
    the remote listing is complete, the file sets are equal and non-empty, and every digest
    is equal. A real byte difference (mismatch) reports MISMATCH; anything incomplete reports
    NOT_VERIFIED."""
    results: list[FileResult] = []
    reasons: list[str] = []
    for rel, why in local.problems:
        results.append(FileResult(rel, None, None, None, V_NOT_VERIFIED, f"source:{why}"))
    for rel, why in remote.problems:
        if rel and why == V_UNREADABLE_DEST:
            continue  # reported per file below
        results.append(FileResult(rel, None, None, None, V_NOT_VERIFIED, f"dest:{why}"))
    if local.problems:
        reasons.append(f"{len(local.problems)} local problem(s)")
    if not remote.complete:
        reasons.append("remote incomplete: " + ",".join(sorted({w for _, w in remote.problems}))[:300])

    mismatches = 0
    for rel in sorted(set(local.files) | remote.files):
        size = local.files.get(rel)
        src = local_hashes.get(rel)
        dst = remote.hashes.get(rel)
        if rel not in remote.files:
            v = V_MISSING_DEST
        elif rel not in local.files:
            v = V_EXTRA_DEST
        elif src is None:
            v = V_UNREADABLE_SOURCE
        elif dst is None:
            v = V_UNREADABLE_DEST
        elif src == dst:
            v = V_MATCH
        else:
            v = V_MISMATCH
            mismatches += 1
        results.append(FileResult(rel, size, src, dst, v))

    not_match = [r for r in results if r.verdict != V_MATCH]
    n_files = sum(1 for r in results if r.verdict == V_MATCH)
    if not local.files and not remote.files:
        reasons.append("empty tree: nothing to prove")
    if mismatches:
        return T_MISMATCH, results, f"{mismatches} file(s) differ; " + "; ".join(reasons)
    if not_match or reasons or n_files == 0:
        other = sorted({r.verdict for r in not_match})
        return T_NOT_VERIFIED, results, "; ".join(reasons + ([f"non-match verdicts: {other}"] if other else []))
    return T_VERIFIED, results, f"{n_files} file(s), every byte equal"


def verify_pair(local_root: str, nas_path: str, target) -> tuple[str, list, str, dict]:
    """The ONE comparison path used by both the real check and the canary."""
    lt = list_local(local_root)
    t0 = time.monotonic()
    lh = hash_local(local_root, lt.files)
    t_local = time.monotonic() - t0
    total = sum(lt.files.values())
    rt, t_nas = hash_remote(target, nas_path, total)
    verdict, results, reason = compare(lt, lh, rt)
    stats = {"files": len(lt.files), "bytes": total,
             "hash_seconds_local": round(t_local, 3), "hash_seconds_nas": round(t_nas, 3)}
    return verdict, results, reason, stats


# --------------------------------------------------------------------------
# canary (PAF's m -> M test, every run)
# --------------------------------------------------------------------------

_CANARY_PARA = (
    "It is a truth universally acknowledged, that a man in possession of a good fortune must be "
    "in want of a wife. However little known the feelings or views of such a man may be on his first "
    "entering a neighbourhood, this truth is so well fixed in the minds of the surrounding families, "
    "that he is considered the rightful property of some one or other of their daughters. "
    "Mr. Bennet made no answer. My dear, you must know, Mrs. Long says that Netherfield is taken by a "
    "young man of large fortune from the north of England; that he came down on Monday in a chaise "
    "and four to see the place, and was so much delighted with it.\n"
)


def canary_texts() -> tuple[bytes, bytes]:
    """(original, mutated): ~200 KB of text; the mutated copy has exactly ONE lowercase `m`
    (the first one at or after byte 100,000) changed to `M`. Same length."""
    original = (_CANARY_PARA * (200_000 // len(_CANARY_PARA) + 1)).encode("ascii")
    i = original.index(b"m", 100_000)
    mutated = original[:i] + b"M" + original[i + 1:]
    assert len(mutated) == len(original) and sum(a != b for a, b in zip(original, mutated)) == 1
    return original, mutated


def run_canary(target) -> tuple[bool, str]:
    """True only if the real comparison path says MISMATCH for the m->M pair AND VERIFIED for
    the identical pair (positive control). The original goes to the NAS; the local side holds
    either the mutated or the original copy, with the same name and mtime."""
    original, mutated = canary_texts()
    tag = f"verify_tree_canary_{os.getpid()}_{int(time.time())}"
    nas_dir = f"{target.scratch_dir}/{tag}"
    with tempfile.TemporaryDirectory(prefix="verify_tree_canary_") as tmp:
        src = os.path.join(tmp, "book.txt")
        with open(src, "wb") as f:
            f.write(original)
        mk = target.ssh(f"mkdir -p {shlex.quote(nas_dir)}")
        if mk.returncode != 0:
            return False, f"canary: NAS mkdir rc={mk.returncode}"
        try:
            put = target.scp_put(src, f"{nas_dir}/book.txt")
            if put.returncode != 0:
                return False, f"canary: scp_put rc={put.returncode}"
            mut_dir = os.path.join(tmp, "mutated")
            same_dir = os.path.join(tmp, "same")
            os.makedirs(mut_dir)
            os.makedirs(same_dir)
            for d, data in ((mut_dir, mutated), (same_dir, original)):
                p = os.path.join(d, "book.txt")
                with open(p, "wb") as f:
                    f.write(data)
                os.utime(p, (1_700_000_000, 1_700_000_000))
            v_mut, _, why_mut, _ = verify_pair(mut_dir, nas_dir, target)
            v_same, _, why_same, _ = verify_pair(same_dir, nas_dir, target)
        finally:
            _remove_canary_dir(target, target.scratch_dir, nas_dir)
    if v_mut != T_MISMATCH:
        return False, f"canary: m->M pair gave {v_mut} ({why_mut}); the check cannot see a 1-byte change"
    if v_same != T_VERIFIED:
        return False, f"canary: identical pair gave {v_same} ({why_same}); the NAS hash path is broken"
    return True, "canary ok: m->M = MISMATCH, identical = VERIFIED"


def _remove_canary_dir(target, scratch_dir: str, nas_dir: str) -> None:
    prefix = f"{scratch_dir}/verify_tree_canary_"
    if not nas_dir.startswith(prefix) or "/" in nas_dir[len(prefix):] or ".." in nas_dir:
        raise ValueError(f"refusing to remove {nas_dir!r}")
    target.ssh(f"rm -rf {shlex.quote(nas_dir)}")


# --------------------------------------------------------------------------
# record (diskaudit.tree_verifications + integrity_checks)
# --------------------------------------------------------------------------

def record(conn, *, purpose: str, local_root: str, nas_path: str, verdict: str, reason: str,
           canary_ok: Optional[bool], results: list, stats: dict, local_host: str,
           nas_host: str = NAS_HOST) -> int:
    """One transaction: the run row plus one integrity_checks row per file (basis='fresh').
    Raises on any DB error; the caller turns that into NOT_VERIFIED."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO diskaudit.tree_verifications
                (purpose, local_host, local_path, nas_host, nas_path, files, bytes, canary_ok,
                 verdict, reason, hash_seconds_local, hash_seconds_nas, finished_at, code_version)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), %s)
            RETURNING run_id
            """,
            (purpose, local_host, local_root, nas_host, nas_path, stats.get("files"), stats.get("bytes"),
             canary_ok, verdict, reason[:2000], stats.get("hash_seconds_local"),
             stats.get("hash_seconds_nas"), __version__),
        )
        run_id = cur.fetchone()[0]
        for r in results:
            rel = r.rel[2:] if r.rel.startswith("./") else r.rel
            cur.execute(
                """
                INSERT INTO diskaudit.integrity_checks
                    (spark_path, spark_host, nas_path, size_bytes, sha_source, sha_dest, verdict,
                     notes, basis, tree_run_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'fresh', %s)
                """,
                (os.path.join(local_root, rel), local_host, f"{nas_path.rstrip('/')}/{rel}",
                 r.size_bytes, r.sha_source, r.sha_dest, r.verdict, r.notes or None, run_id),
            )
    conn.commit()
    return run_id


def mark_deleted(conn, run_id: int) -> bool:
    """Set deleted_at on a VERIFIED, not-yet-deleted run. False if no such run (the caller logs it)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE diskaudit.tree_verifications SET deleted_at = now()
            WHERE run_id = %s AND verdict = 'VERIFIED' AND deleted_at IS NULL
            """,
            (run_id,),
        )
        n = cur.rowcount
    conn.commit()
    return n == 1


def _alarm(text: str) -> None:
    """Canary failure = the safety check is broken. Deduped TG PRESI alert via alertlib
    (canonical); a missing alertlib is printed loudly, never swallowed silently."""
    try:
        sys.path.insert(0, "/srv/alertlib")
        import alertlib  # noqa: PLC0415
        alertlib.fire("havnvard-verify-tree-canary", f"HavnVard verify_tree: {text}", 3600,
                      source="verify_tree", severity="critical")
    except Exception as e:  # noqa: BLE001 -- reported, and the exit code is already 4
        print(f"[verify_tree] ALARM NOT SENT ({type(e).__name__}: {e}): {text}", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _connect():
    import psycopg  # noqa: PLC0415
    return psycopg.connect(cv.get_dsn(), connect_timeout=15)


def _nas_path_ok(p: str) -> bool:
    return p.startswith("/share/") and ".." not in p.split("/")


def cmd_verify(args, target=None, connect=_connect) -> int:
    local_root = os.path.realpath(args.local)
    if not os.path.isdir(local_root):
        print(f"VERDICT={T_NOT_VERIFIED}\nREASON=local dir missing: {local_root}")
        return EXIT_NOT_VERIFIED
    if not _nas_path_ok(args.nas_path):
        print(f"verify_tree: --nas-path must be an absolute /share/... path: {args.nas_path!r}", file=sys.stderr)
        return EXIT_USAGE
    target = target or cv._NasTarget()
    ok, why = run_canary(target)
    if not ok:
        print(f"VERDICT={T_CANARY_FAILED}\nREASON={why}")
        _alarm(why)
        try:
            conn = connect()
            try:
                rid = record(conn, purpose=args.purpose, local_root=local_root, nas_path=args.nas_path,
                             verdict=T_CANARY_FAILED, reason=why, canary_ok=False, results=[],
                             stats={}, local_host=args.local_host, nas_host=args.nas_host)
            finally:
                conn.close()
            print(f"VERIFY_RUN_ID={rid}")
        except Exception as e:  # noqa: BLE001 -- exit 4 stands either way
            print(f"[verify_tree] could not record canary failure: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_CANARY
    verdict, results, reason, stats = verify_pair(local_root, args.nas_path, target)
    try:
        conn = connect()
        try:
            rid = record(conn, purpose=args.purpose, local_root=local_root, nas_path=args.nas_path,
                         verdict=verdict, reason=reason, canary_ok=True, results=results,
                         stats=stats, local_host=args.local_host, nas_host=args.nas_host)
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001 -- an unrecorded check never authorises a delete
        print(f"VERDICT={T_NOT_VERIFIED}\nREASON=result not recorded ({type(e).__name__}: {e}); was {verdict}")
        return EXIT_NOT_VERIFIED
    print(f"VERIFY_RUN_ID={rid}\nVERDICT={verdict}\nREASON={reason}")
    print(f"STATS=files={stats['files']} bytes={stats['bytes']} "
          f"local_s={stats['hash_seconds_local']} nas_s={stats['hash_seconds_nas']}")
    for r in results:
        if r.verdict != V_MATCH:
            print(f"FILE|{r.verdict}|{r.rel}|{r.notes}")
    return EXIT_VERIFIED if verdict == T_VERIFIED else EXIT_NOT_VERIFIED


def cmd_mark_deleted(args, connect=_connect) -> int:
    conn = connect()
    try:
        ok = mark_deleted(conn, args.run_id)
    finally:
        conn.close()
    print(f"MARK_DELETED={'ok' if ok else 'NO_MATCHING_VERIFIED_RUN'} run_id={args.run_id}")
    return 0 if ok else EXIT_NOT_VERIFIED


def cmd_canary(args, target=None) -> int:
    ok, why = run_canary(target or cv._NasTarget())
    print(why)
    if not ok:
        _alarm(why)
    return 0 if ok else EXIT_CANARY


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--local", required=True)
    v.add_argument("--nas-path", required=True)
    v.add_argument("--purpose", required=True)
    v.add_argument("--local-host", default="spark-20cf")
    v.add_argument("--nas-host", default=NAS_HOST, help=argparse.SUPPRESS)
    m = sub.add_parser("mark-deleted")
    m.add_argument("--run-id", type=int, required=True)
    sub.add_parser("canary")
    args = ap.parse_args(argv)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "mark-deleted":
        return cmd_mark_deleted(args)
    return cmd_canary(args)


if __name__ == "__main__":
    sys.exit(main())
