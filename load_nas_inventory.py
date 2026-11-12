#!/usr/bin/env python3
"""diskaudit — NAS-native inventory loader (nas-1 via native BusyBox crawl).

Companion to scan.py (local the server filesystem crawl). Where scan.py walks the
filesystem itself in Python, this script drives a crawl that runs NATIVELY on
the NAS over SSH (see nas_native_crawl.sh) -- validated at ~29,300 files/sec
native vs ~20 files/sec over an NFS/SSHFS mount from the server (~1,450x), because
the bottleneck was the network-mount transport, not the NAS's disk. This
script ships the crawl's flat-file output back to the server and loads it into the
SAME diskaudit.files table via the SAME merge pattern scan.py already uses.

Reuses verbatim from scan.py (imported, not reimplemented): get_dsn(),
file_type_of(), safe_str(), to_dt(), is_excluded(), DEFAULT_EXCLUDE_COMPONENTS,
COPY_SQL, and the merge() function itself (MERGE_DUPLICATES/MERGE_UPSERT/
MERGE_DISAPPEARED, root_prefix-scoped -- see scan.py's merge() docstring for
the production bug that fix guards against).

One thing NOT reused from scan.py: owner_name()/group_name(). Those call
pwd.getpwuid()/grp.getgrgid() against the server's local user database, which is
wrong here -- NAS uid/gid numbers are not guaranteed to map to the same
identities as the server's. Instead this script parses the NAS's OWN /etc/passwd
and /etc/group (copied alongside each crawl) and resolves against those.

No birth time (btime) is available on the NAS at all (no statx path exists
against a text file, and BusyBox stat has nothing equivalent) -- btime is
NULL for every NAS-origin row, same end state as scan.py's own graceful
degradation when statx isn't supported, just reached a different way.

Usage:
    load_nas_inventory.py --share Public                 # full pipeline, one share
    load_nas_inventory.py --share Public --dry-run        # stage only, skip merge
    load_nas_inventory.py --share homes --keep-scratch    # leave NAS+local files for inspection
    load_nas_inventory.py --share Public --skip-crawl \\
        --skip-transfer                                   # reload from existing local inbox files

Plane: INFRA-97 (diskaudit). Runbook: /home/user/runbooks/20260717-diskaudit-v2-dedup/README.md
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan import (  # noqa: E402
    COPY_SQL,
    DEFAULT_EXCLUDE_COMPONENTS,
    file_type_of,
    get_dsn,
    is_excluded,
    merge,
    safe_str,
    to_dt,
)
from heartbeat import HeartbeatThrottle, write_heartbeat  # noqa: E402
from scan_guard import clear_stale_staging, refuse_if_locked  # noqa: E402

import stat as statmod

# ---- NAS connection facts ----
import havnvard_site as _site  # noqa: E402  (3.0.0)

NAS_HOST = _site.nas_host()
NAS_SHARE_BASE = _site.nas_share_base()
NAS_SCRATCH_DIR = f"{NAS_SHARE_BASE}/.diskaudit_scratch"
NAS_TOKEN_FILE = _site.nas("admin_token_file") or "/etc/havnvard/nas_admin.env"
# Never touch /etc/havnvard/nas_backup.env -- unrelated production credential
# used by spark-backup-db.sh, explicitly off-limits per this project's scope.

CRAWL_SCRIPT_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nas_native_crawl.sh")
CRAWL_SCRIPT_REMOTE_NAME = "nas_native_crawl.sh"

LOCAL_INBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nas_inbox")
LOCAL_ETC_DIR = os.path.join(LOCAL_INBOX_DIR, "_nas_etc")

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "PubkeyAuthentication=no",
    "-o", "ConnectTimeout=10",
]

# QNAP-internal app config/cache directories, confirmed present at the NAS
# share root (/share/CACHEDEV1_DATA/<name>) via `ls -la` on 2026-07-18, PLUS
# at least one confirmed to also recur NESTED inside an individual share
# (.@upload_cache was found inside Public itself, not just at the share
# root -- QNAP's upload-cache feature appears to be created per-share on
# demand). is_excluded()'s component matching (exact path-segment equality,
# same mechanism as scan.py's own DEFAULT_EXCLUDE_COMPONENTS = docker/
# containerd) catches these wherever they appear, at the share root or
# nested arbitrarily deep -- not just at one hardcoded absolute path.
# NOTE: since this script only ever crawls INSIDE one named share directory
# (e.g. /share/CACHEDEV1_DATA/Public), the share-root-level QNAP dirs
# (.@qsync, .@quarantine, etc. sitting as siblings of Public/Download/...)
# are never even visited by find -- this list matters for the per-share
# NESTED case (like .@upload_cache inside Public) and as defense-in-depth
# should per-user QNAP artifacts (e.g. a per-user .@qsync under homes/<user>/)
# turn up during the larger homes/ crawl.
# Deliberately NOT excluding @Recycle (no leading dot -- QNAP's per-share
# recycle bin) -- those are real former user files still consuming real
# disk space, which is exactly what a disk-inventory tool should count,
# not QNAP app-internal config/cache.
NAS_EXTRA_EXCLUDE_COMPONENTS = (
    ".@analytic", ".@app_center", ".@backup_code_signing", ".@backup_config",
    ".@backup_qbox", ".@qHAsync", ".@qmariadb", ".@qmonitor", ".@qsync",
    ".@quarantine", ".@station_config", ".@twonkymedia", ".@upload_cache",
    ".HLS", ".SSDLaboratory", ".antivirus", ".appDB", ".codesigning",
    ".idmap", ".ldapdb", ".locks", ".log", ".logs", ".musicdata", ".nc",
    ".php_session", ".php_session_sys", ".qbox", ".qcoolie", ".qpkg",
    ".qulog", ".samba", ".samba_python3", ".swap", ".system",
    ".system_disk_data", ".team_folder", ".tmp", ".torrent", ".versioning",
    ".wifi", ".diskaudit_scratch", ".malware_remover",
    # Found the hard way during the homes/ share test (2026-07-18): these are
    # PER-DIRECTORY / per-share QNAP app caches, not per-share-root -- e.g.
    # .@__thumb showed up nested under homes/user/downloads/, not at
    # any share root. .@__thumb is QNAP's thumbnail cache (File Station/Photo
    # Station) and is where the out-of-range synthetic uid 3701760710 came
    # from (see 20260718_diskaudit_nas_uid_gid_bigint.sql) -- excluding it
    # here avoids ingesting more such synthetic-identity noise going forward,
    # though the schema fix means it's no longer fatal even if one slips
    # through elsewhere. @DownloadStationTempFiles and @Transcode are
    # Download Station / video-transcode temp caches; .@QNAPCloudDriveSyncTemp_
    # is CloudDrive sync scratch space. @pwcache is a QNAP internal password/
    # protocol cache. None of these are user data.
    ".@__thumb", ".@QNAPCloudDriveSyncTemp_", "@DownloadStationTempFiles",
    "@Transcode", "@pwcache",
)
NAS_EXCLUDE_COMPONENTS = DEFAULT_EXCLUDE_COMPONENTS + NAS_EXTRA_EXCLUDE_COMPONENTS


# ---- NAS credential + SSH/SCP helpers ----

def _nas_creds() -> tuple[str, str]:
    """Read NAS_ADMIN_USER/NAS_ADMIN_PASS from the root:600 token file via sudo cat.
    Never inline these -- SoT is /etc/havnvard/nas_admin.env, root-owned."""
    out = subprocess.run(
        ["sudo", "cat", NAS_TOKEN_FILE], capture_output=True, text=True, check=True
    ).stdout
    user = pw = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("NAS_ADMIN_USER="):
            user = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("NAS_ADMIN_PASS="):
            pw = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not user or not pw:
        raise RuntimeError(f"could not parse NAS_ADMIN_USER/NAS_ADMIN_PASS from {NAS_TOKEN_FILE}")
    return user, pw


def _with_sshpass(argv: list[str]) -> subprocess.CompletedProcess:
    """Run argv (an ssh/scp command) with the NAS password supplied via sshpass -f
    against a tempfile that is created with umask 077 and deleted immediately after,
    win or lose. NEVER pass the password as a bare -p arg (leaks via `ps aux`)."""
    user, pw = _nas_creds()
    fd, tmppath = tempfile.mkstemp(prefix="naspw-")
    try:
        os.chmod(tmppath, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        full = ["sshpass", "-f", tmppath] + argv
        return subprocess.run(full, capture_output=True, text=True)
    finally:
        os.remove(tmppath)


def nas_ssh(remote_cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    user, _ = _nas_creds()
    argv = ["ssh"] + SSH_OPTS + [f"{user}@{NAS_HOST}", remote_cmd]
    r = _with_sshpass(argv)
    if check and r.returncode != 0:
        raise RuntimeError(f"ssh command failed (rc={r.returncode}): {remote_cmd}\nstderr:\n{r.stderr}")
    return r


def nas_scp_get(remote_path: str, local_path: str, check: bool = True) -> subprocess.CompletedProcess:
    user, _ = _nas_creds()
    argv = ["scp"] + SSH_OPTS + [f"{user}@{NAS_HOST}:{remote_path}", local_path]
    r = _with_sshpass(argv)
    if check and r.returncode != 0:
        raise RuntimeError(f"scp GET failed (rc={r.returncode}): {remote_path} -> {local_path}\nstderr:\n{r.stderr}")
    return r


def nas_scp_put(local_path: str, remote_path: str, check: bool = True) -> subprocess.CompletedProcess:
    user, _ = _nas_creds()
    argv = ["scp"] + SSH_OPTS + [local_path, f"{user}@{NAS_HOST}:{remote_path}"]
    r = _with_sshpass(argv)
    if check and r.returncode != 0:
        raise RuntimeError(f"scp PUT failed (rc={r.returncode}): {local_path} -> {remote_path}\nstderr:\n{r.stderr}")
    return r


def _shq(s: str) -> str:
    """Single-quote a string for safe inclusion in a remote shell command
    (handles share names with spaces, e.g. 'Family photos')."""
    return "'" + s.replace("'", "'\\''") + "'"


# ---- crawl / transfer orchestration ----

def crawl_share(share_name: str) -> None:
    """Push nas_native_crawl.sh to the NAS scratch dir and run it there for one share."""
    remote_script = f"{NAS_SCRATCH_DIR}/{CRAWL_SCRIPT_REMOTE_NAME}"
    print(f"[load_nas] ensuring scratch dir exists on NAS: {NAS_SCRATCH_DIR}", file=sys.stderr)
    nas_ssh(f"mkdir -p {_shq(NAS_SCRATCH_DIR)} && chmod 700 {_shq(NAS_SCRATCH_DIR)}")
    print(f"[load_nas] pushing crawl script -> {remote_script}", file=sys.stderr)
    nas_scp_put(CRAWL_SCRIPT_LOCAL, remote_script)
    print(f"[load_nas] running crawl on NAS for share={share_name!r} (this can take a while for large shares)", file=sys.stderr)
    r = nas_ssh(f"sh {_shq(remote_script)} {_shq(share_name)}", check=False)
    # crawl script's own stderr (progress lines) always useful to see, even on success
    if r.stderr:
        print(r.stderr, file=sys.stderr)
    if r.returncode != 0:
        raise RuntimeError(f"nas_native_crawl.sh failed (rc={r.returncode}) for share={share_name!r}")


def _safe_name(share_name: str) -> str:
    return share_name.replace(" ", "_").replace("/", "_")


def fetch_share(share_name: str) -> dict[str, str]:
    """scp back this share's .tsv/.errs/.symlinks, plus the NAS's /etc/passwd and
    /etc/group (small, no secrets, just uid/name mappings -- refetched every run
    for freshness, at negligible cost)."""
    os.makedirs(LOCAL_INBOX_DIR, exist_ok=True)
    os.makedirs(LOCAL_ETC_DIR, exist_ok=True)
    safe = _safe_name(share_name)
    paths = {}
    for ext in ("tsv", "errs", "symlinks", "unsafe"):
        remote = f"{NAS_SCRATCH_DIR}/{safe}.{ext}"
        local = os.path.join(LOCAL_INBOX_DIR, f"{safe}.{ext}")
        print(f"[load_nas] fetching {remote} -> {local}", file=sys.stderr)
        nas_scp_get(remote, local)
        paths[ext] = local

    passwd_local = os.path.join(LOCAL_ETC_DIR, "passwd")
    group_local = os.path.join(LOCAL_ETC_DIR, "group")
    nas_scp_get("/etc/passwd", passwd_local)
    nas_scp_get("/etc/group", group_local)
    paths["passwd"] = passwd_local
    paths["group"] = group_local
    return paths


def cleanup_share(share_name: str, local_paths: dict[str, str]) -> None:
    """Remove this share's scratch files on BOTH sides after a successful load --
    the NAS's real disk scratch dir and the local the server inbox dir. passwd/group
    caches under _nas_etc/ are left in place (small, reused across shares, not
    share-specific)."""
    safe = _safe_name(share_name)
    remote_glob = f"{NAS_SCRATCH_DIR}/{safe}.tsv {NAS_SCRATCH_DIR}/{safe}.errs {NAS_SCRATCH_DIR}/{safe}.symlinks {NAS_SCRATCH_DIR}/{safe}.unsafe"
    remote_script = f"{NAS_SCRATCH_DIR}/{CRAWL_SCRIPT_REMOTE_NAME}"
    print(f"[load_nas] cleaning up NAS scratch files for share={share_name!r}", file=sys.stderr)
    nas_ssh(f"rm -f {remote_glob} {_shq(remote_script)}", check=False)
    for ext in ("tsv", "errs", "symlinks", "unsafe"):
        p = local_paths.get(ext)
        if p and os.path.exists(p):
            os.remove(p)
    print(f"[load_nas] cleanup done for share={share_name!r}", file=sys.stderr)


# ---- passwd/group/symlink parsing ----

def parse_passwd(path: str) -> dict[int, str]:
    """name:x:uid:gid:gecos:home:shell -- from the NAS's own /etc/passwd,
    NOT the server's (uid numbers are not guaranteed to mean the same person)."""
    out: dict[int, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            name, uid_s = parts[0], parts[2]
            try:
                out[int(uid_s)] = name
            except ValueError:
                continue
    return out


def parse_group(path: str) -> dict[int, str]:
    """name:x:gid:members -- from the NAS's own /etc/group."""
    out: dict[int, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            name, gid_s = parts[0], parts[2]
            try:
                out[int(gid_s)] = name
            except ValueError:
                continue
    return out


def parse_symlinks(path: str) -> dict[str, str]:
    """path|target, one per line. Split left-to-right on the FIRST '|' only.
    KNOWN LIMITATION: if a symlink's own path contains a literal '|' character
    (legal in POSIX filenames but essentially never seen in practice), this will
    misparse -- there is no fully unambiguous delimiter-based fix when BOTH
    fields (path and target) are arbitrary filesystem strings. Accepted as a
    documented edge case rather than switching the wire format."""
    out: dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                continue
            out[parts[0]] = parts[1]
    return out


UNSAFE_NAME_LF_MSG = (
    "UNSAFE_NAME_LF: path contains a line feed; the NAS crawl cannot carry it in a newline-framed row, "
    "so this entry (and anything beneath it) was NOT inventoried"
)


def parse_unsafe(path: str | None) -> list[str]:
    """<share>.unsafe: one lowercase-hex line per topmost entry whose path contains a LF (nas_native_crawl.sh,
    1.4.2). Returns the decoded paths (undecodable bytes surrogate-escaped). A missing file means an older crawl
    script (no list); a line that is not valid hex is returned as a visible placeholder, never skipped."""
    if not path or not os.path.exists(path):
        return []
    out: list[str] = []
    with open(path, encoding="ascii", errors="replace", newline="\n") as f:
        for line in f:
            h = line.strip()
            if not h:
                continue
            try:
                out.append(bytes.fromhex(h).decode("utf-8", "surrogateescape"))
            except ValueError:
                out.append(f"<undecodable unsafe-name record: {h[:200]}>")
    return out


_ERR_FIND_RE = re.compile(r"^find: (.+): (.+)$")
_ERR_STAT_RE = re.compile(r"^stat: .*'([^']+)'.*$")


def parse_error_line(line: str) -> tuple[str | None, str]:
    m = _ERR_FIND_RE.match(line)
    if m:
        return m.group(1), m.group(2)
    m = _ERR_STAT_RE.match(line)
    if m:
        return m.group(1), line
    return None, line


# ---- TSV row parsing ----

# stat -c '%n|%f|%s|%u|%g|%i|%h|%Y|%X|%Z' -- 9 trailing numeric/hex fields after
# the path. Using rsplit (from the RIGHT) with maxsplit=9 is deliberate and load-
# bearing: filenames legally can contain a literal '|' character, but none of the
# 9 trailing fields ever can (they're stat-generated digits/hex only) -- so
# splitting from the right always correctly isolates the path, however many
# literal pipes it contains, whereas a naive left-to-right split would not.
_TSV_TRAILING_FIELDS = 9


def open_tsv(tsv_path: str):
    """Open the crawl TSV so ONLY '\\n' ends a record and nothing is translated. Python's default
    universal-newline mode (and newline='') also split on a bare '\\r', which tears a row whose
    file NAME contains one (BH-7); HavnVard then refuses that path as UNSAFE_PATH instead of
    never seeing it."""
    return open(tsv_path, encoding="utf-8", errors="surrogateescape", newline="\n")


def parse_tsv_line(line: str) -> tuple[str, int, int, int, int, int, int, float, float] | None:
    parts = line.rstrip("\n").rsplit("|", _TSV_TRAILING_FIELDS)
    if len(parts) != _TSV_TRAILING_FIELDS + 1:
        return None
    path, mode_hex, size_s, uid_s, gid_s, inode_s, nlink_s, mtime_s, atime_s, _ctime_s = parts
    # A torn/split line (e.g. the second half of a stat record whose first
    # half landed on the previous line, so this one starts with a leading
    # "|") parses as a syntactically valid N-field record with path="" --
    # rsplit has no way to distinguish that from a real empty path. Reject
    # it explicitly rather than silently insert a row with an empty path,
    # which collides with every other torn line on the (host, path) unique
    # constraint at merge time (found live 2026-07-18, bkup_server share).
    if not path or not path.startswith("/"):
        return None
    try:
        mode_int = int(mode_hex, 16)
        size = int(size_s)
        uid = int(uid_s)
        gid = int(gid_s)
        inode = int(inode_s)
        nlink = int(nlink_s)
        mtime = float(mtime_s)
        atime = float(atime_s)
    except ValueError:
        return None
    return path, mode_int, size, uid, gid, inode, nlink, mtime, atime


def build_nas_row(
    host: str,
    path: str,
    mode_int: int,
    size: int,
    uid: int,
    gid: int,
    inode: int,
    nlink: int,
    mtime: float,
    atime: float,
    owner_map: dict[int, str],
    group_map: dict[int, str],
    symlink_map: dict[str, str],
) -> tuple:
    ftype = file_type_of(mode_int)
    symlink_target = symlink_map.get(path) if ftype == "symlink" else None
    extension = None
    if ftype == "regular":
        _, ext = os.path.splitext(path)
        extension = ext[1:].lower() if ext else None
    return (
        host,
        safe_str(path),
        ftype,
        safe_str(symlink_target),
        size if ftype == "regular" else None,
        statmod.S_IMODE(mode_int),
        uid,
        gid,
        owner_map.get(uid),
        group_map.get(gid),
        inode,
        nlink,
        extension,
        to_dt(mtime),
        to_dt(atime),
        None,  # btime -- never available on this NAS, always NULL
    )


# ---- Postgres load ----

def load_share_into_db(
    conn,
    scan_id: int,
    host: str,
    root: str,
    tsv_path: str,
    errs_path: str,
    owner_map: dict[int, str],
    group_map: dict[int, str],
    symlink_map: dict[str, str],
    batch_size: int,
    unsafe_path: str | None = None,
    held_out: set | None = None,
) -> tuple[int, int, int, int]:
    files_scanned = 0
    dirs_scanned = 0
    bytes_scanned = 0
    errors = 0
    batch: list[tuple] = []
    hb = HeartbeatThrottle(min_interval_s=15.0)

    def log_error(cur, path: str | None, err: str):
        nonlocal errors
        errors += 1
        if held_out is not None and path and path.startswith("/"):
            # 1.4.3 (R142-8): a path the NAS crawl could not list/stat -- its stored descendants are unverified
            held_out.add(safe_str(path))
        # scan_errors.path is NOT NULL -- a genuinely path-less error (e.g. a
        # malformed/torn TSV line where we can't tell what path it was for)
        # must not crash the loader over a single bad line. Fall back to a
        # placeholder rather than pass NULL through.
        cur.execute(
            "INSERT INTO diskaudit.scan_errors (scan_id, path, error) VALUES (%s, %s, %s)",
            (scan_id, safe_str(path) or "<unknown-path>", safe_str(err)[:2000]),
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
        # crawl-time errors (permission-denied etc from find/stat on the NAS side)
        if os.path.exists(errs_path):
            with open(errs_path, encoding="utf-8", errors="replace", newline="\n") as ef:
                for line in ef:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    epath, emsg = parse_error_line(line)
                    log_error(cur, epath, emsg)
        # unsafe names (1.4.2, R-4): entries with a LF in the path were not crawled; each is a visible error.
        for upath in parse_unsafe(unsafe_path):
            log_error(cur, upath, UNSAFE_NAME_LF_MSG)
        conn.commit()

        with open_tsv(tsv_path) as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                parsed = parse_tsv_line(line)
                if parsed is None:
                    log_error(cur, None, f"malformed TSV line {lineno} in {tsv_path}: {line[:200]!r}")
                    continue
                path, mode_int, size, uid, gid, inode, nlink, mtime, atime = parsed

                if is_excluded(path, [], exclude_components=NAS_EXCLUDE_COMPONENTS):
                    continue

                ftype = file_type_of(mode_int)
                if ftype == "dir":
                    dirs_scanned += 1
                else:
                    files_scanned += 1
                    if ftype == "regular":
                        bytes_scanned += size

                batch.append(
                    build_nas_row(
                        host, path, mode_int, size, uid, gid, inode, nlink, mtime, atime,
                        owner_map, group_map, symlink_map,
                    ) + (scan_id,)
                )
                if len(batch) >= batch_size:
                    flush(cur)
                    if hb.due():
                        write_heartbeat(
                            conn, "scan", scan_id, host, "loading",
                            note=f"{files_scanned} files, {dirs_scanned} dirs so far (share load)",
                        )
        flush(cur)

    return files_scanned, dirs_scanned, bytes_scanned, errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--share", required=True, help="Top-level share directory name under /share/CACHEDEV1_DATA, e.g. Public, homes, 'Download'.")
    ap.add_argument("--host", default=NAS_HOST, help=f"Host tag for these rows (default: {NAS_HOST})")
    ap.add_argument("--share-base", default=NAS_SHARE_BASE, help=f"Share base path on the NAS (default: {NAS_SHARE_BASE})")
    ap.add_argument("--batch-size", type=int, default=5000)
    ap.add_argument("--dry-run", action="store_true", help="Stage only; skip merge into diskaudit.files")
    ap.add_argument("--skip-crawl", action="store_true", help="Skip the NAS-side crawl (reuse whatever's already in the local inbox / re-fetch only)")
    ap.add_argument("--skip-transfer", action="store_true", help="Skip scp transfer; load from files already present in nas_inbox/ (implies local files exist)")
    ap.add_argument("--keep-scratch", action="store_true", help="Do not clean up NAS scratch files or local inbox files after load (debugging)")
    args = ap.parse_args()

    share_name = args.share
    root = f"{args.share_base.rstrip('/')}/{share_name}"
    safe = _safe_name(share_name)

    conn = psycopg.connect(get_dsn(), autocommit=False)
    refuse_if_locked(conn, args.host, root, "load_nas")  # 1.4.3: one load per (host, share root)
    scan_id = None
    local_paths: dict[str, str] = {
        "tsv": os.path.join(LOCAL_INBOX_DIR, f"{safe}.tsv"),
        "errs": os.path.join(LOCAL_INBOX_DIR, f"{safe}.errs"),
        "symlinks": os.path.join(LOCAL_INBOX_DIR, f"{safe}.symlinks"),
        "unsafe": os.path.join(LOCAL_INBOX_DIR, f"{safe}.unsafe"),
    }

    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO diskaudit.scan_runs (host, root_path, dry_run, status) "
                "VALUES (%s, %s, %s, 'running') RETURNING scan_id",
                (args.host, root, args.dry_run),
            )
            scan_id = cur.fetchone()[0]
            clear_stale_staging(cur, args.host, root, scan_id)
        conn.commit()
        write_heartbeat(conn, "scan", scan_id, args.host, "starting")
        print(f"[load_nas] scan_id={scan_id} host={args.host} share={share_name!r} root={root} dry_run={args.dry_run}", file=sys.stderr)

        if not args.skip_crawl:
            write_heartbeat(conn, "scan", scan_id, args.host, "crawling (nas-native)")
            crawl_share(share_name)
        else:
            print("[load_nas] --skip-crawl: not re-running the NAS-side crawl", file=sys.stderr)

        if not args.skip_transfer:
            write_heartbeat(conn, "scan", scan_id, args.host, "transferring")
            fetched = fetch_share(share_name)
            local_paths.update(fetched)
        else:
            print("[load_nas] --skip-transfer: loading from existing local nas_inbox/ files", file=sys.stderr)
            local_paths["passwd"] = os.path.join(LOCAL_ETC_DIR, "passwd")
            local_paths["group"] = os.path.join(LOCAL_ETC_DIR, "group")

        for key in ("tsv", "passwd", "group"):
            if not os.path.exists(local_paths[key]):
                raise RuntimeError(f"required local input missing: {local_paths[key]} (key={key})")

        owner_map = parse_passwd(local_paths["passwd"])
        group_map = parse_group(local_paths["group"])
        symlink_map = parse_symlinks(local_paths.get("symlinks", ""))
        print(
            f"[load_nas] parsed {len(owner_map)} users, {len(group_map)} groups, "
            f"{len(symlink_map)} symlink targets",
            file=sys.stderr,
        )

        write_heartbeat(conn, "scan", scan_id, args.host, "loading")
        held: set[str] = set()
        files_scanned, dirs_scanned, bytes_scanned, errors = load_share_into_db(
            conn, scan_id, args.host, root,
            local_paths["tsv"], local_paths["errs"],
            owner_map, group_map, symlink_map,
            args.batch_size,
            unsafe_path=local_paths.get("unsafe"),
            held_out=held,
        )
        print(
            f"[load_nas] load done: files={files_scanned} dirs={dirs_scanned} "
            f"bytes={bytes_scanned} errors={errors}",
            file=sys.stderr,
        )

        if args.dry_run:
            status = "dry_run"
        else:
            write_heartbeat(conn, "scan", scan_id, args.host, "merging")
            errors += merge(conn, scan_id, args.host, root, held)
            status = "completed"

        with conn.cursor() as cur:
            cur.execute(
                "UPDATE diskaudit.scan_runs SET finished_at=now(), files_scanned=%s, "
                "dirs_scanned=%s, bytes_scanned=%s, errors_count=%s, status=%s WHERE scan_id=%s",
                (files_scanned, dirs_scanned, bytes_scanned, errors, status, scan_id),
            )
        conn.commit()
        print(f"[load_nas] scan_id={scan_id} status={status}", file=sys.stderr)

        if not args.keep_scratch and not args.dry_run:
            cleanup_share(share_name, local_paths)
        elif args.keep_scratch:
            print("[load_nas] --keep-scratch: leaving NAS + local scratch files in place", file=sys.stderr)

    except Exception as e:
        conn.rollback()
        if scan_id is not None:
            with conn.cursor() as cur:
                # errors_count must reflect what's actually in scan_errors, not stay at
                # its default. log_error() commits as it goes (crawl-error loop commits
                # once at load start, flush() commits per batch), so rows logged before
                # the crash that triggered this except block already survived the
                # rollback above -- count them live instead of leaving errors_count=0,
                # which made a real failure (1000+ NAS permission-denied errors) look
                # silently clean in scan_runs (found 2026-07-18, INFRA-108).
                cur.execute(
                    "UPDATE diskaudit.scan_runs SET finished_at=now(), status='failed', "
                    "errors_count=(SELECT count(*) FROM diskaudit.scan_errors WHERE scan_id=%s) "
                    "WHERE scan_id=%s",
                    (scan_id, scan_id),
                )
            conn.commit()
            write_heartbeat(conn, "scan", scan_id, args.host, "failed", note=str(e)[:500])
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
