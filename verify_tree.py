#!/usr/bin/env python3
"""verify_tree.py -- HavnVard 1.6.0 (Plane INFRA-538; 5+1 canary 20261110): full-byte proof before a copy is deleted.

The operator rule (20261109 23:39): no copy of a file is deleted unless 100% of its bytes are proven
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
        Run only the canary: 5 identical copies + 1 m->M copy must read as exactly that one file different; 6 identical copies must all read equal.

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
import secrets
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

__version__ = "1.6.0"

EXIT_VERIFIED = 0
EXIT_USAGE = 2
EXIT_NOT_VERIFIED = 3
EXIT_CANARY = 4

NAS_HOST = cv._site.nas_host()   # 3.0.0: from the site file
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
    """One ssh call, run on the NAS (BusyBox ash: no pipefail, no external printf). Three
    sections, each closed by its own exit status, then END:
        BEGIN_NONREG|  names of entries that are neither dir nor regular file   RC_NONREG|<rc>
        BEGIN_FILE|    names of regular files                                   RC_FILE|<rc>
        BEGIN_HASH|    `sha256sum` lines for every regular file                 RC_HASH|<rc>
    Every name `find .` prints starts with "./", so no name can be mistaken for a marker. A
    failed `cd` exits 97 before anything is listed (never hash the login dir instead)."""
    q = shlex.quote(nas_path)
    return (
        f"cd {q} || {{ echo 'CDFAIL|'; exit 97; }}; "
        "echo 'BEGIN_NONREG|'; find . ! -type d ! -type f -print; echo \"RC_NONREG|$?\"; "
        "echo 'BEGIN_FILE|'; find . -type f -print; echo \"RC_FILE|$?\"; "
        "echo 'BEGIN_HASH|'; find . -type f -exec sha256sum {} +; echo \"RC_HASH|$?\"; "
        "echo 'END|'"
    )


@dataclass
class RemoteTree:
    files: set = field(default_factory=set)
    hashes: dict = field(default_factory=dict)     # rel -> sha
    problems: list = field(default_factory=list)   # (rel or '', reason)
    complete: bool = False


_SECTIONS = ("NONREG", "FILE", "HASH")


def parse_remote(stdout: str, rc: int) -> RemoteTree:
    """Whitelist parser for remote_script(). `complete` only if: ssh rc 0; the three sections
    appear in order, each closed with RC 0; END is last; every FILE has exactly one hash line
    and every hash line names a FILE; no NONREG entry; no line outside the grammar."""
    t = RemoteTree()
    if rc != 0:
        t.problems.append(("", f"SSH_RC:{rc}"))
        if "CDFAIL|" in stdout.split("\n"):
            t.problems.append(("", "NAS_PATH_MISSING"))
        return t
    lines = stdout.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    expect = 0            # index into _SECTIONS of the next BEGIN we accept
    section = None
    closed = []
    saw_end = False
    for line in lines:
        if saw_end:
            t.problems.append((line[:200], "AFTER_END"))
            continue
        if line == "CDFAIL|":
            t.problems.append(("", "NAS_PATH_MISSING"))
            continue
        if section is None:
            if expect < 3 and line == f"BEGIN_{_SECTIONS[expect]}|":
                section = _SECTIONS[expect]
            elif line == "END|" and expect == 3:
                saw_end = True
            else:
                t.problems.append((line[:200], "UNEXPECTED_LINE"))
            continue
        if line.startswith(f"RC_{section}|"):
            val = line.partition("|")[2]
            if val != "0":
                t.problems.append(("", f"RC_{section}:{val}"))
            closed.append(section)
            section = None
            expect += 1
            continue
        if section == "NONREG":
            t.problems.append((line, "NON_REGULAR_DEST"))
        elif section == "FILE":
            if not line.startswith("./"):
                t.problems.append((line[:200], "BAD_NAME_LINE"))
                continue
            bad = name_problem(line)
            if bad:
                t.problems.append((line, bad))
            t.files.add(line)
        else:  # HASH
            if line.startswith("\\"):
                t.problems.append((line[:200], "ESCAPED_HASH_LINE"))
                continue
            hm = _HASH_LINE_RE.match(line)
            if not hm:
                t.problems.append((line[:200], "BAD_HASH_LINE"))
                continue
            digest, name = hm.group(1), hm.group(2)
            if name in t.hashes:
                t.problems.append((name, "DUPLICATE_HASH_LINE"))
            else:
                t.hashes[name] = digest
    if closed != list(_SECTIONS):
        t.problems.append(("", f"SECTIONS_INCOMPLETE:{','.join(closed) or 'none'}"))
    if not saw_end:
        t.problems.append(("", "NO_END_MARKER"))
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
# canary (the operator's m -> M test, every run)
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


CANARY_CHUNK = 4 * 1024 * 1024     # crosshost_verify.HASH_READ_BUFFER
CANARY_SIZE = 2 * CANARY_CHUNK + 100_000


def canary_texts() -> tuple[bytes, bytes]:
    """(original, mutated): ~8.5 MB of book text; the mutated copy has exactly ONE lowercase
    `m` changed to `M`, placed in the LAST, partial 4 MiB read chunk (past 2 x 4 MiB). A hash
    that reads only a head, a sample, or whole chunks would call the pair equal (Fable #6)."""
    reps = CANARY_SIZE // len(_CANARY_PARA) + 1
    original = (_CANARY_PARA * reps).encode("ascii")[:CANARY_SIZE]
    i = original.index(b"m", 2 * CANARY_CHUNK + 1)
    mutated = original[:i] + b"M" + original[i + 1:]
    assert len(mutated) == len(original) and sum(a != b for a, b in zip(original, mutated)) == 1
    return original, mutated


CANARY_COPIES = 6                  # the operator 20261110: 5 identical copies + 1 with the m->M change
CANARY_NAMES = tuple(f"book_{n}.txt" for n in range(1, CANARY_COPIES + 1))


def _canary_mutated_ok(verdict: str, results: list, planted: str) -> tuple[bool, str]:
    """The 5+1 set must read MISMATCH with EXACTLY one differing file, the planted one, and
    the other 5 must each read MATCH. A path that calls every file different, or the wrong
    file different, fails."""
    by = {r.rel: r.verdict for r in results}
    want = {f"./{n}": (V_MISMATCH if n == planted else V_MATCH) for n in CANARY_NAMES}
    # len() check: a dict keeps only the LAST verdict per rel, so a NOT_VERIFIED row for the
    # same name (or any extra row) would otherwise be hidden behind a later MATCH (Opus 1.6.0 #1).
    if verdict != T_MISMATCH or len(results) != CANARY_COPIES or by != want:
        got = ", ".join(f"{k[2:]}={v}" for k, v in sorted(by.items())) or "no per-file results"
        return False, f"tree={verdict}; per file: {got}"
    return True, ""


def _canary_same_ok(verdict: str, results: list) -> tuple[bool, str]:
    """6 identical copies must read VERIFIED with all 6 files MATCH."""
    by = {r.rel: r.verdict for r in results}
    if (verdict != T_VERIFIED or len(results) != CANARY_COPIES
            or by != {f"./{n}": V_MATCH for n in CANARY_NAMES}):
        got = ", ".join(f"{k[2:]}={v}" for k, v in sorted(by.items())) or "no per-file results"
        return False, f"tree={verdict}; per file: {got}"
    return True, ""


def run_canary(target, planted_index: Optional[int] = None) -> tuple[bool, str]:
    """the operator's m->M test, 5+1 form (20261110). The NAS gets 6 copies of the original book text.
    Check 1: the local side holds 5 identical copies + 1 copy with one m->M, at a position that
    changes every run; the real comparison path must call exactly that one file different and
    the other 5 equal. Check 2 (positive control): 6 identical local copies must all read equal.
    Same names and mtime on every copy, so only the bytes can tell them apart."""
    original, mutated = canary_texts()
    idx = secrets.randbelow(CANARY_COPIES) if planted_index is None else planted_index
    planted = CANARY_NAMES[idx]
    tag = f"verify_tree_canary_{os.getpid()}_{int(time.time())}"
    nas_dir = f"{target.scratch_dir}/{tag}"
    with tempfile.TemporaryDirectory(prefix="verify_tree_canary_") as tmp:
        src = os.path.join(tmp, CANARY_NAMES[0])
        with open(src, "wb") as f:
            f.write(original)
        mk = target.ssh(f"mkdir -p {shlex.quote(nas_dir)}")
        if mk.returncode != 0:
            return False, f"canary: NAS mkdir rc={mk.returncode}"
        try:
            put = target.scp_put(src, f"{nas_dir}/{CANARY_NAMES[0]}")
            if put.returncode != 0:
                return False, f"canary: scp_put rc={put.returncode}"
            cps = " && ".join(f"cp {CANARY_NAMES[0]} {n}" for n in CANARY_NAMES[1:])
            cp = target.ssh(f"cd {shlex.quote(nas_dir)} && {cps}")
            if cp.returncode != 0:
                return False, f"canary: NAS cp rc={cp.returncode}"
            mut_dir = os.path.join(tmp, "mutated")
            same_dir = os.path.join(tmp, "same")
            os.makedirs(mut_dir)
            os.makedirs(same_dir)
            for d, plant in ((mut_dir, True), (same_dir, False)):
                for n in CANARY_NAMES:
                    p = os.path.join(d, n)
                    with open(p, "wb") as f:
                        f.write(mutated if (plant and n == planted) else original)
                    os.utime(p, (1_700_000_000, 1_700_000_000))
            v_mut, r_mut, why_mut, _ = verify_pair(mut_dir, nas_dir, target)
            v_same, r_same, why_same, _ = verify_pair(same_dir, nas_dir, target)
        finally:
            _remove_canary_dir(target, target.scratch_dir, nas_dir)
    ok, got = _canary_mutated_ok(v_mut, r_mut, planted)
    if not ok:
        return False, (f"canary: 5 copies + 1 m->M (in {planted}) did not read as exactly that one "
                       f"file different ({got}; {why_mut}); the check cannot be trusted")
    ok, got = _canary_same_ok(v_same, r_same)
    if not ok:
        return False, f"canary: 6 identical copies did not all read equal ({got}; {why_same}); the NAS hash path is broken"
    return True, (f"canary ok: 5 copies + 1 m->M = only {planted} different, other 5 equal; "
                  f"6 identical = all equal")


def _remove_canary_dir(target, scratch_dir: str, nas_dir: str) -> None:
    """Remove ONLY this run's canary files and their (then empty) dir. No recursive delete
    (a recursive rm is a forbidden primitive in HavnVard, tests/test_crosshost_verify.py): the
    six named files, then rmdir, which fails safely if anything else is in the dir."""
    prefix = f"{scratch_dir}/verify_tree_canary_"
    if not nas_dir.startswith(prefix) or "/" in nas_dir[len(prefix):] or ".." in nas_dir:
        raise ValueError(f"refusing to remove {nas_dir!r}")
    files = " ".join(shlex.quote(f"{nas_dir}/{n}") for n in CANARY_NAMES)
    target.ssh(f"rm -f {files}; rmdir {shlex.quote(nas_dir)}")


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
        import havnvard_site as _hs  # noqa: PLC0415
        alertlib = _hs.import_alertlib()
        alertlib.fire("havnvard-verify-tree-canary", f"HavnVard verify_tree: {text}", 3600,
                      source="verify_tree", severity="critical")
    except Exception as e:  # noqa: BLE001 -- reported, and the exit code is already 4
        print(f"[verify_tree] ALARM NOT SENT ({type(e).__name__}: {e}): {text}", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _connect():
    import psycopg  # noqa: PLC0415
    return psycopg.connect(cv.get_dsn(), connect_timeout=10)


_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "fuse.rclone", "9p", "afs", "ceph",
               "glusterfs", "autofs"}


def local_root_problem(path: str, mounts_file: str = "/proc/mounts") -> Optional[str]:
    """Refuse a --local that is not a plain local dir: a symlink, a missing dir, anything under
    /mnt/nas, or a network filesystem. A NAS path compared against itself reads VERIFIED and
    the delete would remove the only copy (Fable #7; daily.sh warns of the same aliasing)."""
    if os.path.islink(path):
        return "local path is a symlink"
    if not os.path.isdir(path):
        return "local dir missing"
    real = os.path.realpath(path)
    if real == "/mnt/nas" or real.startswith("/mnt/nas/"):
        return "local path is under /mnt/nas"
    best, fstype = "", ""
    try:
        with open(mounts_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mp = parts[1].replace("\\040", " ")
                # >= : on a tie the LATER line wins, because a later mount on the same point
                # overlays the earlier one. Live 20261110: /mnt/nas-bkup-spark is listed as
                # `autofs` first, then the real `nfs` mount on top (Opus diff review H1).
                if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
                    best, fstype = mp, parts[2]
    except OSError as e:
        return f"cannot read {mounts_file}: {e.strerror}"
    if fstype in _NETWORK_FS:
        return f"local path is on a network filesystem ({fstype} at {best})"
    return None


def _nas_path_ok(p: str) -> bool:
    return p.startswith("/share/") and ".." not in p.split("/")


def cmd_verify(args, target=None, connect=_connect) -> int:
    bad = local_root_problem(args.local)
    if bad:
        print(f"verify_tree: refusing --local {args.local!r}: {bad}", file=sys.stderr)
        print(f"VERDICT={T_NOT_VERIFIED}\nREASON={bad}")
        return EXIT_USAGE if "missing" not in bad else EXIT_NOT_VERIFIED
    local_root = os.path.realpath(args.local)
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
    v.add_argument("--local-host", default=cv._site.local_host())
    v.add_argument("--nas-host", default=NAS_HOST, help=argparse.SUPPRESS)
    m = sub.add_parser("mark-deleted")
    m.add_argument("--run-id", type=int, required=True)
    sub.add_parser("canary")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "verify":
            return cmd_verify(args)
        if args.cmd == "mark-deleted":
            return cmd_mark_deleted(args)
        return cmd_canary(args)
    except Exception as e:  # noqa: BLE001 -- any crash is NOT_VERIFIED, never a silent pass
        print(f"VERDICT={T_NOT_VERIFIED}\nREASON=verify_tree crashed: {type(e).__name__}: {e}")
        return EXIT_NOT_VERIFIED


if __name__ == "__main__":
    sys.exit(main())
