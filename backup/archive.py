"""Long-term storage (HavnVard 3.2.0, INFRA-571): offload, pullback, find, forget-before.

offload FOLDER      back the folder up tagged `archive` + `archive-YYYYMMDD`, read every file back out of the backup
                    (streamed `restic dump`, no scratch disk) and compare full SHA-256 with the live file; writes a
                    manifest and diskaudit.archive_offload rows; prints X/Y VERIFIED. HavnVard never deletes anything
                    on the device: the owner deletes the VERIFIED files himself.
pullback            put files back: by offload date, by "disappeared that day" (restic diff), or one path/version;
                    onto this device or (--from) any device the owner holds the keys for. restore --overwrite never:
                    an existing file is never replaced. Restored files are hash-checked against the offload manifest.
find PATTERN        search the file catalog; on a device without the hub's catalog, read the newest catalog copy
                    from the owner's own repository.
forget-before DATE  the owner cuts a device's snapshots older than a date: owner key + list + exact typed text.
"""
from __future__ import annotations

import csv
import datetime as dt
import errno
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

from . import catalog, checkin, config, notify, prune
from .config import BackupError
from .util import read_secret, restic_bin, run, sha256_file

ARCHIVE = prune.ARCHIVE_TAG
STATUSES = ("VERIFIED", "MISMATCH", "CHANGED", "MISSING_IN_SNAPSHOT")


# ---------- repository access ----------

def device_env() -> tuple[dict, dict]:
    """(restic env, device settings) for this enrolled device. Indirection so tests can use a local repo."""
    from .enroll import client_env
    return client_env(config.load())


def other_env(device: str, key_file: str | None, login_file: str | None) -> dict:
    """Read access to ANOTHER device's repository. With --key-file (+ --login-file through the hub's rest-server)
    the owner's own copies are used; without them, the hub-local path or this device's own repo."""
    if key_file:
        kf = str(Path(key_file).expanduser().resolve())
        if not Path(kf).is_file():
            raise BackupError(f"--key-file {kf} is not a file")
        cfg = config.load()
        if login_file:
            hub = cfg.get("hub", {}).get("address")
            if not hub:
                raise BackupError("no hub set; run `hub set HOST[:PORT]` first")
            return {"RESTIC_REPOSITORY": f"rest:http://{hub}/{device}/", "RESTIC_PASSWORD_FILE": kf,
                    "RESTIC_REST_USERNAME": device, "RESTIC_REST_PASSWORD": read_secret(Path(login_file).expanduser())}
        root = cfg.get("hub_local", {}).get("repo_root")
        if not root:
            raise BackupError(f"--from {device} away from the hub needs --login-file (that device's hub login)")
        return {"RESTIC_REPOSITORY": str(Path(root) / device), "RESTIC_PASSWORD_FILE": kf}
    from .drill import _env_for
    return _env_for(device)


def _when(s: str) -> dt.datetime:
    return catalog.parse_time(s).astimezone()


def _day(d: str) -> dt.date:
    try:
        return dt.date.fromisoformat(d)
    except ValueError as e:
        raise BackupError(f"bad date {d!r}; use YYYY-MM-DD") from e


def _start(day: dt.date) -> dt.datetime:
    return dt.datetime.combine(day, dt.time()).astimezone()


# ---------- offload ----------

def verify_stream(tar_stream, live_root: Path, snap_time: dt.datetime) -> list[dict]:
    """Compare every regular file in a `restic dump --archive tar` stream with the live file under live_root.
    Returns one row per live file and per archived file: path, size, sha256 (from the backup), status."""
    rows, seen, skipped_special = [], set(), []
    with tarfile.open(fileobj=tar_stream, mode="r|") as tf:
        for m in tf:
            if not m.isreg():
                continue
            path = "/" + m.name.lstrip("/")
            seen.add(path)
            h = hashlib.sha256()
            src = tf.extractfile(m)
            for chunk in iter(lambda: src.read(1 << 20), b""):
                h.update(chunk)
            got = h.hexdigest()
            try:
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode):          # FIFO/socket/device/symlink: never opened (review N2)
                    skipped_special.append(path)
                    continue
                # The SHA-256 is the proof. A different size, or an mtime more than 1 s from the backed-up one (restic
                # rounds tar mtimes to whole seconds), means the file moved on after the backup: not proven.
                if st.st_size != m.size or abs(st.st_mtime - m.mtime) > 1.0:
                    status = "CHANGED"          # changed after the backup: not proven, do not delete
                else:
                    status = "VERIFIED" if sha256_file(path) == got else "MISMATCH"
            except OSError:
                status = "CHANGED"              # gone or unreadable live: nothing to compare against
            rows.append({"path": path, "size": m.size, "sha256": got, "status": status})
    for dp, _dn, fn in os.walk(live_root):
        for f in fn:
            p = os.path.join(dp, f)
            if p not in seen and os.path.isfile(p) and not os.path.islink(p):
                rows.append({"path": p, "size": os.path.getsize(p), "sha256": "", "status": "MISSING_IN_SNAPSHOT"})
    if skipped_special:
        print(f"offload: {len(skipped_special)} special file(s) (pipe, socket, device) not offloaded and not counted")
    return sorted(rows, key=lambda r: r["path"])


def _dump_verify(restic: str, env: dict, snap_id: str, folder: Path, snap_time: dt.datetime) -> list[dict]:
    with tempfile.TemporaryFile() as errf:            # stderr to a file: a chatty restic cannot block the pipe
        p = _popen([restic, "dump", "--archive", "tar", snap_id, str(folder)], env, errf)
        try:
            rows = verify_stream(p.stdout, folder, snap_time)
        except tarfile.TarError as e:
            p.kill()
            raise BackupError(f"restic dump stream unreadable: {e}") from e
        p.stdout.close()
        rc = p.wait()
        errf.seek(0)
        err = errf.read().decode(errors="replace")
    if rc != 0:
        raise BackupError(f"restic dump failed rc={rc}: {err.strip()[-300:]}")
    return rows


def write_manifest(rows: list[dict], snap_id: str, folder: Path, when: dt.datetime) -> Path:
    d = config.state_dir() / "offload"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{when:%Y%m%d_%H%M%S}_{snap_id[:8]}.tsv"
    with open(p, "w", newline="", encoding="utf-8", errors="surrogateescape") as f:
        f.write(f"# HavnVard offload {folder} snapshot {snap_id}\n")
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["path", "size", "sha256", "status"])
        for r in rows:
            w.writerow([r["path"], r["size"], r["sha256"], r["status"]])
    return p


def read_manifests() -> dict[str, dict[str, str]]:
    """{snapshot_id: {path: sha256}} for VERIFIED rows of every offload manifest on this device."""
    out: dict[str, dict[str, str]] = {}
    d = config.state_dir() / "offload"
    for p in sorted(d.glob("*.tsv")) if d.is_dir() else []:
        with open(p, encoding="utf-8", errors="surrogateescape") as f:
            head = f.readline().split()
            snap = head[-1] if head else ""
            for r in csv.DictReader(f, delimiter="\t"):
                if r.get("status") == "VERIFIED":
                    out.setdefault(snap, {})[r["path"]] = r["sha256"]
    return out


INSERT_SQL = ("INSERT INTO diskaudit.archive_offload (host, folder, path, size_bytes, sha256, status, snapshot_id, "
              "archive_tag, offloaded_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
              "ON CONFLICT (host, snapshot_id, path) DO NOTHING")


def record_db(conn, host: str, folder: Path, snap_id: str, tag: str, when: dt.datetime, rows: list[dict]) -> int:
    cur = conn.cursor()
    try:
        cur.executemany(INSERT_SQL, [(host, str(folder), r["path"], r["size"], r["sha256"] or None, r["status"],
                                      snap_id, tag, when) for r in rows])
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return len(rows)


def offload(folder: str, no_db: bool = False, connect=None, now: dt.datetime | None = None) -> int:
    from .drill import _canary
    from .enroll import backup_cmd
    fp = Path(folder).expanduser().resolve()
    if not fp.is_dir():
        raise BackupError(f"offload needs an existing folder: {fp}")
    _canary()
    conn = None
    if not no_db:                                     # connect BEFORE the backup + read-back (review FILE)
        try:
            conn = (connect or _connect)()
        except Exception as e:
            raise BackupError(f"cannot reach the inventory database ({e}); fix it or run with --no-db") from e
    env, dev = device_env()
    restic, when = restic_bin(), (now or dt.datetime.now().astimezone())
    tag = f"{ARCHIVE}-{when:%Y%m%d}"
    r = run(backup_cmd(restic, dev, [str(fp)], (ARCHIVE, tag, "auto"), json_out=True), env=env)
    summary = {}
    for ln in r.stdout.splitlines():
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        if o.get("message_type") == "summary":
            summary = o
    snap_id = summary.get("snapshot_id")
    if r.returncode not in (0, 3) or not snap_id:
        raise BackupError(f"offload backup failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    snap_time = _when(summary.get("backup_end") or summary.get("backup_start"))
    print(f"offload {fp}: backed up as snapshot {snap_id[:8]} tagged {ARCHIVE}, {tag}; reading every file back ...")
    cur_id = find_snapshot(restic, env, snap_id)["id"]   # the hub's catalog may have re-tagged it already
    rows = _dump_verify(restic, env, cur_id, fp, snap_time)
    man = write_manifest(rows, snap_id, fp, when)
    counts = {s: sum(1 for x in rows if x["status"] == s) for s in STATUSES}
    rc = 0 if rows and counts["VERIFIED"] == len(rows) else config.PROBLEM_EXIT
    if conn is not None:
        try:
            try:
                record_db(conn, dev["name"], fp, snap_id, tag, when, rows)
            finally:
                conn.close()
        except Exception as e:   # the verified list is still printed; a missing DB record is a visible problem
            print(f"ALERT: offload not recorded in diskaudit.archive_offload: {e} (re-run with --no-db to skip)")
            rc = config.PROBLEM_EXIT
    for x in rows:
        if x["status"] != "VERIFIED":
            print(f"  {x['status']}\t{x['path']}")
    print(f"offload {fp}: {counts['VERIFIED']}/{len(rows)} files VERIFIED (SHA-256 of the backup copy = live file) "
          f"in snapshot {snap_id[:8]} ({tag}); {counts['MISMATCH']} mismatch, {counts['CHANGED']} changed during "
          f"offload, {counts['MISSING_IN_SNAPSHOT']} not in the backup")
    print(f"verified list: {man}  -- only VERIFIED rows are safe to delete; HavnVard deletes nothing, you do")
    return rc


def _connect():
    from .coverage import connect
    return connect()


# ---------- pullback ----------
# 3.2.0 review (FULL FIX-NOW 1, 2): `restic restore` is NOT used. Even with --overwrite never it replaces a file that sits
# where a backed-up folder should be, replaces a symlinked folder and resets folder modes, and it silently skips names
# with `$` or a trailing space in an include file. Pullback streams `restic dump` itself and writes only NEW files
# (O_CREAT|O_EXCL|O_NOFOLLOW), creates only MISSING folders, and never changes or removes anything that already exists.

def snap_key(s: dict) -> str:
    """A snapshot's stable identity: restic keeps `original` when the hub's catalog re-tags it (new id)."""
    return s.get("original") or s["id"]


def find_snapshot(restic: str, env: dict, sid: str) -> dict:
    hit = [s for s in catalog.snapshots(restic, env) if s["id"].startswith(sid) or snap_key(s).startswith(sid)]
    if len(hit) != 1:
        raise BackupError(f"snapshot {sid}: {len(hit)} snapshots match (need exactly 1)")
    return hit[0]


def _ls_nodes(restic: str, env: dict, snap_id: str, paths: list[str], recursive: bool) -> list[dict]:
    r = run([restic, "ls", "--json", *(["--recursive"] if recursive else []), snap_id, *paths], env=env)
    if r.returncode != 0:
        raise BackupError(f"restic ls {snap_id[:8]} failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    out = []
    for ln in r.stdout.splitlines():
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        if o.get("struct_type") == "node":
            out.append(o)
    return out


def snapshot_files(restic: str, env: dict, snap_id: str, incs: list[str]) -> tuple[dict[str, dict], set[str]]:
    """({path: node} of every regular file, {paths of pipes/sockets/devices}) at or under the include paths."""
    files, special = {}, set()
    for o in _ls_nodes(restic, env, snap_id, incs, True):
        if not any(_under(o["path"], i) for i in incs):
            continue
        if o.get("type") == "file":
            files[o["path"]] = o
        elif o.get("type") not in ("dir", "symlink"):
            special.add(o["path"])
    return files, special


def _removed(restic: str, env: dict, a: dict, b: dict) -> tuple[list[str], list[str]]:
    """(file paths removed, file paths added) from snapshot a to snapshot b (`restic diff --json`)."""
    r = run([restic, "diff", "--json", a["id"], b["id"]], env=env)
    if r.returncode != 0:
        raise BackupError(f"restic diff failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    gone, added = [], []
    for ln in r.stdout.splitlines():
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        if o.get("message_type") == "change" and not o["path"].endswith("/"):
            if o.get("modifier") == "-":
                gone.append(o["path"])
            elif o.get("modifier") == "+":
                added.append(o["path"])
    return gone, added


def vanished_jobs(restic: str, env: dict, snaps: list[dict], day: dt.date) -> list[tuple[dict, list[str]]]:
    """[(snapshot to restore from, file paths)] for everything that disappeared during `day` and is still gone at the
    end of it. Every regular backup of the day is compared with the one before it (live 20261114: files created and
    deleted the same day were missed when only the last backup before the day was compared with the last one in it).
    Only regular backups (no archive/offload), same host and same backup paths (review FIX-NOW 4). Each file comes back
    from the last backup that still held it."""
    s0, s1 = _start(day), _start(day + dt.timedelta(days=1))
    reg = [s for s in snaps if ARCHIVE not in (s.get("tags") or [])]
    during = [s for s in reg if s0 <= _when(s["time"]) < s1]
    later = [s for s in reg if _when(s["time"]) >= s1]
    after = during[-1] if during else (later[0] if later else None)
    key = (lambda s: (s.get("hostname"), sorted(s.get("paths", []))))
    same = [s for s in reg if after and key(s) == key(after)]
    before = [s for s in same if _when(s["time"]) < s0]
    chain = before[-1:] + [s for s in same if s0 <= _when(s["time"]) < s1] + ([] if during else [after] if after else [])
    if not before or len(chain) < 2:
        raise BackupError(f"--vanished needs a regular backup before {day} and one during or after it with the same "
                          f"host and folders; found {len(before)} before, {'one' if after else 'none'} during/after")
    gone: dict[str, dict] = {}
    for a, b in zip(chain, chain[1:]):
        rem, add = _removed(restic, env, a, b)
        for p in add:
            gone.pop(p, None)                          # came back later the same day: not vanished
        for p in rem:
            gone[p] = a
    jobs: dict[str, tuple[dict, list[str]]] = {}
    for p, s in gone.items():
        jobs.setdefault(s["id"], (s, []))[1].append(p)
    return [(s, sorted(ps)) for s, ps in jobs.values()]


def vanished(restic: str, env: dict, snaps: list[dict], day: dt.date) -> tuple[dict, list[str]]:
    """Compatibility view of vanished_jobs: (the earliest source snapshot, every vanished path)."""
    jobs = vanished_jobs(restic, env, snaps, day)
    if not jobs:
        s0 = _start(day)
        reg = [s for s in snaps if ARCHIVE not in (s.get("tags") or []) and _when(s["time"]) < s0]
        return (reg[-1] if reg else {}), []
    return jobs[0][0], sorted(p for _, ps in jobs for p in ps)


def _under(path: str, folder: str | None) -> bool:
    if not folder:
        return True
    f = folder.rstrip("/") or "/"
    return f == "/" or path == f or path.startswith(f + "/")


def _abs(p: str) -> str:
    return str(Path(p).expanduser().absolute()) if not p.startswith("/") else (p.rstrip("/") or "/")


def plan(restic: str, env: dict, date: str | None, paths: list[str], version: str | None,
         folder: str | None, gone_mode: bool) -> list[tuple[dict, list[str]]]:
    """[(snapshot, include paths)] to restore."""
    snaps = catalog.data_snapshots(catalog.snapshots(restic, env))
    if paths:
        cands = [s for s in snaps if version in (s.get("tags") or [])] if version else list(reversed(snaps))
        jobs: dict[str, tuple[dict, list[str]]] = {}
        for p in (_abs(x) for x in paths):
            parent = str(Path(p).parent)
            hit = next((s for s in cands if any(o["path"] == p for o in _ls_nodes(restic, env, s["id"], [parent], False))), None)
            if not hit:
                raise BackupError(f"{p} is in no backup" + (f" named {version}" if version else ""))
            jobs.setdefault(hit["id"], (hit, []))[1].append(p)
        return list(jobs.values())
    if not date:
        raise BackupError("pullback needs FILES, --date or --snapshot")
    day = _day(date)
    if gone_mode:
        jobs = [(s, [g for g in ps if _under(g, folder)]) for s, ps in vanished_jobs(restic, env, snaps, day)]
        return [(s, ps) for s, ps in jobs if ps]
    tag = f"{ARCHIVE}-{day:%Y%m%d}"
    hits = [s for s in snaps if tag in (s.get("tags") or [])]
    if not hits:
        raise BackupError(f"nothing was offloaded on {day} (no snapshot tagged {tag})")
    out = []
    for s in hits:
        incs = [p for p in s.get("paths", []) if _under(p, folder)]
        if folder and not incs and any(_under(folder.rstrip("/"), p) for p in s.get("paths", [])):
            incs = [folder.rstrip("/")]
        if incs:
            out.append((s, incs))
    return out


PULLBACK_MARK = "_PULLBACK-"


def earlier_copy(path: Path, digest: str, size: int) -> Path | None:
    """An earlier NAME_PULLBACK-*.EXT next to `path` holding exactly these bytes (so a second pullback of the same
    backed-up file writes nothing). Old lowercase `_pullback-` copies from 3.2.0 count too."""
    stem, ext = (path.stem, path.suffix) if (path.suffix and path.stem) else (path.name, "")
    try:
        sibs = list(os.scandir(path.parent))
    except OSError:
        return None
    for e in sibs:
        n = e.name
        if not (n.endswith(ext) and (n.startswith(stem + PULLBACK_MARK) or n.startswith(stem + "_pullback-"))):
            continue
        if e.is_file(follow_symlinks=False) and e.stat().st_size == size and sha256_file(Path(e.path)) == digest:
            return Path(e.path)
    return None


def renamed(path: Path, stamp: str, is_dir: bool = False) -> Path:
    """report.pdf -> report_PULLBACK-20261113-0130.pdf (then _2, _3 ... if that exists too): PULLBACK in capitals,
    the extension stays last (owner ruling 20261114). Folders keep no suffix split."""
    stem, ext = (path.stem, path.suffix) if (path.suffix and path.stem and not is_dir) else (path.name, "")
    n = 1
    while True:
        cand = path.with_name(f"{stem}{PULLBACK_MARK}{stamp}{'' if n == 1 else '_' + str(n)}{ext}")
        if not os.path.lexists(cand):
            return cand
        n += 1


def _dest(tgt: Path, p: str) -> Path:
    return tgt / p.lstrip("/") if tgt != Path("/") else Path(p)


# A place we may not write: permission, a read-only disk, a folder owned by another user. Everything else (disk full,
# I/O error) stays a hard failure of that include path, as before.
_REFUSED = {errno.EACCES, errno.EPERM, errno.EROFS}


LINK_OUT = "the folder is a link to somewhere else (not followed)"


def _why(e: OSError | str) -> str:
    if isinstance(e, str):
        return e
    if e.errno == errno.EROFS:
        return "the disk or share is read-only"
    return "permission denied (the folder is read-only or belongs to another user)"


def _euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def _uid_of(p: Path, follow: bool) -> int:
    return (os.stat(p) if follow else os.lstat(p)).st_uid


ROOT_FOREIGN = ("another user controls this folder (not owned by root, or group/other-writable); as root HavnVard "
                "does not write into it: run the pullback as that user, or use --target")


def _mode_of(p: Path, follow: bool) -> int:
    return (os.stat(p) if follow else os.lstat(p)).st_mode


def _root_unsafe(p: Path) -> bool:
    """R2 (option c): as root, a folder on the way is safe only when root owns it (and the link to it, if any) and
    nobody else can write it. Otherwise its owner could swap a sub-folder for a link mid-run, so it is a blocked
    folder. (The race-free dir_fd walk is FILEd.)"""
    try:
        for follow in (False, True):
            if _uid_of(p, follow) != 0:
                return True
        return bool(_mode_of(p, True) & 0o022)
    except OSError:
        return True


def _safe_mode(mode: int) -> int:
    """FN-5: as root, never create a setuid/setgid file or folder (root would own it)."""
    mode &= 0o7777
    return mode & ~(stat.S_ISUID | stat.S_ISGID) if _euid() == 0 else mode


class _Blocked(Exception):
    """A folder refused us. Carries the folder that refused; the writer has already recorded it."""


def blocked_text(folder: str, why: str, items: list[str], target: str, files: list[str] | None = None) -> str:
    """The popup / hub notice text for one folder that refused files: plain words, which folder, why, what to do.
    FN-6: when files sit under the refused folder, every FILE is counted (first 10 shown), not just the folder."""
    items = list(files) if files else items
    shown = "\n".join(f"  {p}" for p in items[:10]) + (f"\n  ... and {len(items) - 10} more" if len(items) > 10 else "")
    return (f"HavnVard could not put back {len(items)} item(s) into this folder:\n\n  {folder}\n\n"
            f"Why: {why}.\n\nNot put back:\n{shown}\n\n"
            "Nothing on this computer was changed or deleted, and your backup still holds these files.\n"
            "What to do: ask the owner of that folder (or your administrator) to let you write there and run the "
            "pullback again, or pull back into a folder you own with --target "
            f"(this run used --target {target}).")


class _Writer:
    """Writes backed-up files onto the device without ever changing what is there."""

    def __init__(self, tgt: Path, stamp: str, scratch: Path):
        self.tgt, self.stamp, self.scratch = tgt, stamp, scratch
        self.redirect: dict[Path, Path] = {}     # a path blocked by a non-folder -> the NAME_PULLBACK-STAMP folder used
        self.new_dirs: dict[Path, tuple[int, float] | None] = {}
        self.new, self.same, self.side, self.partial, self.links, self.special = [], 0, [], [], 0, 0
        self.earlier: list[tuple[str, str]] = []  # (existing different file, earlier PULLBACK copy that already matches)
        self.hashes: dict[str, str] = {}         # source path -> SHA-256 of what was written / found identical
        # folder that refused us -> {"why", "items": destination paths not placed}; insertion order = first seen
        self.blocked: dict[str, dict] = {}
        self.unplaced: set[str] = set()          # source paths (files) not written because a folder refused them

    def _refuse(self, folder: Path, item: Path, e: OSError | str) -> _Blocked:
        b = self.blocked.setdefault(str(folder), {"why": _why(e), "items": [], "files": []})
        if str(item) not in b["items"]:
            b["items"].append(str(item))
        return _Blocked(str(folder))

    def _apply(self, p: Path) -> Path:
        for k in sorted(self.redirect, key=lambda x: len(str(x)), reverse=True):
            if p == k or k in p.parents:
                return self.redirect[k] / p.relative_to(k)
        return p

    def mkdirs(self, d: Path) -> Path:
        """Make sure folder d exists; create only missing folders. A FILE (or dead link) where a folder belongs is
        left alone and the folder goes to NAME_PULLBACK-STAMP next to it. A symlinked folder is used, never replaced."""
        d = self._apply(d)
        anchor = Path(d.anchor)
        cur = anchor
        root = _euid() == 0
        if root and _root_unsafe(cur):
            raise self._refuse(cur, cur, ROOT_FOREIGN)
        for part in d.relative_to(anchor).parts:
            nxt = cur / part
            if os.path.lexists(nxt):
                if nxt.is_dir():
                    if nxt.is_symlink() and self._link_escapes(nxt):
                        raise self._refuse(nxt, nxt, LINK_OUT)   # FN-5: listed as blocked, never followed
                    if root and _root_unsafe(nxt):
                        raise self._refuse(nxt, nxt, ROOT_FOREIGN)   # R2: never write where a user can swap a link
                    cur = nxt
                    continue
                alt = renamed(nxt, self.stamp, is_dir=True)
                try:
                    os.mkdir(alt, 0o755 if root else 0o777)
                except OSError as e:
                    if e.errno in _REFUSED:
                        raise self._refuse(cur, alt, e) from e
                    raise
                self.redirect[nxt] = alt
                self.new_dirs[alt] = None
                self.side.append((str(nxt), str(alt)))
                cur = alt
            else:
                try:
                    os.mkdir(nxt, 0o755 if root else 0o777)   # as root never group/other-writable, even at umask 0
                except OSError as e:
                    if e.errno in _REFUSED:                # cur refused us: record it, the caller carries on
                        raise self._refuse(cur, nxt, e) from e
                    raise
                self.new_dirs[nxt] = None
                cur = nxt
        return cur

    def _link_escapes(self, link: Path) -> bool:
        """FN-5: a symlinked folder on the way to a destination is used only when it stays inside the target and,
        when running as root, points at a folder owned by the same user as the link (a user's link into a
        root-owned folder such as /etc/cron.d is refused)."""
        try:
            real = link.resolve(strict=True)
        except (OSError, RuntimeError):
            return True
        if self.tgt != Path("/") and not real.is_relative_to(self.tgt.resolve()):
            return True
        if _euid() == 0:
            try:
                return _uid_of(link, follow=False) != _uid_of(real, follow=True)
            except OSError:
                return True
        return False

    def put_dir(self, src: str, mode: int, mtime: float) -> None:
        """A folder in the backup (empty ones too). A folder that refuses us is recorded, never fatal."""
        try:
            self.mkdirs(_dest(self.tgt, src))
        except _Blocked:
            return
        self.dir_meta(src, mode, mtime)

    def dir_meta(self, src: str, mode: int, mtime: float) -> None:
        d = self._apply(_dest(self.tgt, src))
        if d in self.new_dirs:
            self.new_dirs[d] = (mode, mtime)

    def _write_new(self, path: Path, reader, size: int, mode: int, mtime: float) -> str:
        h, n = hashlib.sha256(), 0
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            for chunk in iter(lambda: reader.read(1 << 20), b""):
                h.update(chunk)
                n += len(chunk)
                os.write(fd, chunk)
        except BaseException:
            self.partial.append(str(path))      # stream cut mid-file (review N1): kept and reported, never removed
            os.close(fd)
            raise
        try:
            if n == size:                       # FN-5: on the open fd, never by path (no race onto a swapped link)
                os.fchmod(fd, _safe_mode(mode))
                os.utime(fd, (mtime, mtime))
        finally:
            os.close(fd)
        if n != size:
            self.partial.append(str(path))      # kept, reported; never removed
        return h.hexdigest()

    @staticmethod
    def _drain(reader) -> None:
        """Read and drop the bytes of a file we cannot place, so restic is never left blocked on a full pipe."""
        if reader is not None:
            for _ in iter(lambda: reader.read(1 << 20), b""):
                pass

    def put_file(self, src: str, reader, size: int, mode: int, mtime: float) -> None:
        """Every outcome is recorded: new, identical (left alone), different (kept + NAME_PULLBACK copy), or not
        placed because a folder refused us (listed; the rest of the pullback carries on)."""
        dest = _dest(self.tgt, src)
        try:
            self._put_file(src, dest, reader, size, mode, mtime)
        except _Blocked as b:
            self.unplaced.add(src)
            self.blocked[b.args[0]]["files"].append(src)
            self._drain(reader)

    def _put_file(self, src: str, dest: Path, reader, size: int, mode: int, mtime: float) -> None:
        d = self.mkdirs(dest.parent) / dest.name
        if not os.path.lexists(d):
            try:
                self.hashes[src] = self._write_new(d, reader, size, mode, mtime)
            except OSError as e:
                if e.errno in _REFUSED and not os.path.lexists(d):   # the folder exists but will not take files
                    raise self._refuse(d.parent, d, e) from e
                raise
            self.new.append(str(d))
            return
        if d.is_file() and not d.is_symlink():
            spool = self.scratch / "spool"
            h = hashlib.sha256()
            with open(spool, "wb") as f:                 # our own scratch file in a TemporaryDirectory
                for chunk in iter(lambda: reader.read(1 << 20), b""):
                    h.update(chunk)
                    f.write(chunk)
            digest = h.hexdigest()
            if d.stat().st_size == size and sha256_file(d) == digest:
                self.same += 1
                self.hashes[src] = digest
                return
            prev = earlier_copy(d, digest, size)
            if prev is not None:                         # pulled back before: that copy already holds these bytes
                self.same += 1
                self.earlier.append((str(d), str(prev)))
                self.hashes[src] = digest
                return
            reader = open(spool, "rb")
        alt = renamed(d, self.stamp)
        try:
            self.hashes[src] = self._write_new(alt, reader, size, mode, mtime)
        except OSError as e:
            if e.errno in _REFUSED and not os.path.lexists(alt):
                raise self._refuse(d.parent, alt, e) from e
            raise
        finally:
            if reader is not None and getattr(reader, "name", None) == str(self.scratch / "spool"):
                reader.close()
        self.side.append((str(d), str(alt)))

    def put_link(self, src: str, target: str) -> None:
        dest = _dest(self.tgt, src)
        try:
            d = self.mkdirs(dest.parent) / dest.name
            if not os.path.lexists(d):
                try:
                    os.symlink(target, d)
                except OSError as e:
                    if e.errno in _REFUSED:
                        raise self._refuse(d.parent, d, e) from e
                    raise
                self.links += 1
        except _Blocked:
            pass

    def finish(self) -> None:
        """Folder modes and times, deepest first, set on an fd opened with O_NOFOLLOW (FN-5: never by path)."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        for d, meta in sorted(self.new_dirs.items(), key=lambda kv: len(kv[0].parts), reverse=True):  # deepest first
            if meta:
                fd = os.open(d, flags)
                try:
                    os.fchmod(fd, _safe_mode(meta[0]))
                    os.utime(fd, (meta[1], meta[1]))
                finally:
                    os.close(fd)


def _popen(cmd: list[str], env: dict, errf):
    return subprocess.Popen(cmd, env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=errf)


def _stream_into(w: _Writer, restic: str, env: dict, snap_id: str, inc: str, nodes: dict[str, dict],
                 special: set[str], scratch: Path) -> None:
    """One include path: a single file is dumped raw, a folder as a tar stream (names kept exactly as stored).
    Pipes, sockets and devices (restic dumps them as empty regular entries) are skipped (review N2).
    Any failure, including a stream cut mid-way, becomes a BackupError carrying restic's own error text (review N1)."""
    with tempfile.TemporaryFile(dir=scratch) as errf:
        if inc in special:
            w.special += 1
            return
        single = inc in nodes
        p = _popen([restic, "dump", snap_id, inc] if single else [restic, "dump", "--archive", "tar", snap_id, inc],
                   env, errf)
        problem = None
        try:
            if single:
                n = nodes[inc]
                w.put_file(inc, p.stdout, int(n.get("size") or 0), int(n.get("mode", 0o644)) & 0o7777,
                           _when(n["mtime"]).timestamp())
            else:
                with tarfile.open(fileobj=p.stdout, mode="r|") as tf:
                    for m in tf:
                        src = "/" + m.name.lstrip("/").rstrip("/")
                        if src in special:
                            w.special += 1
                        elif m.isdir():
                            w.put_dir(src, m.mode, m.mtime)
                        elif m.isreg():
                            w.put_file(src, tf.extractfile(m), m.size, m.mode, m.mtime)
                        elif m.issym():
                            w.put_link(src, m.linkname)
        except (tarfile.TarError, OSError) as e:
            problem = e
            p.kill()
        p.stdout.close()
        rc = p.wait()
        errf.seek(0)
        err = errf.read().decode(errors="replace").strip()
        if problem is not None or rc != 0:
            raise BackupError(f"restic dump {inc} failed rc={rc}: {err[-300:] or problem}")


def pullback(date: str | None = None, paths: list[str] | None = None, version: str | None = None,
             folder: str | None = None, gone_mode: bool = False, target: str = "/",
             from_device: str | None = None, key_file: str | None = None, login_file: str | None = None,
             snapshot: str | None = None, now: dt.datetime | None = None, notifier=None, hub_notice=None) -> int:
    """Never changes anything that exists: an identical file is left alone; a different one stays and the backed-up
    copy is written next to it as NAME_PULLBACK-YYYYMMDD-HHMM.EXT; a file where a folder belongs stays and the folder
    is written as NAME_PULLBACK-YYYYMMDD-HHMM/. Every expected file is accounted for, or the exit is 1.
    A folder that cannot be created or written (permission, read-only, owned by another user) never stops the run:
    everything else is still put back, every item not placed is listed, the exit is 1, and for EACH such folder a
    popup stays on the screen until clicked (`notifier`, default notify.popup) and a notice is left on the hub page
    until someone dismisses it (`hub_notice`, default checkin.report_notice)."""
    restic = restic_bin()
    env = other_env(prune.check_device(from_device), key_file, login_file) if from_device else device_env()[0]
    if snapshot:
        s = find_snapshot(restic, env, snapshot)
        if paths:                                    # INFRA-578: the file list was ignored (whole snapshot restored)
            incs = [p for p in (_abs(x) for x in paths) if _under(p, folder)]
            parents = sorted({str(Path(p).parent) for p in incs})
            present = {o["path"] for o in _ls_nodes(restic, env, s["id"], parents, False)} if parents else set()
            missing = [p for p in incs if p not in present]
            if missing or not incs:
                raise BackupError(f"not in snapshot {snapshot}: " + (", ".join(missing[:5]) if missing
                                  else "no FILE is under --folder") + "; nothing was written")
        else:
            incs = [p for p in s.get("paths", []) if _under(p, folder)] or ([folder.rstrip("/")] if folder else [])
            print(f"pullback: whole snapshot {s['id'][:8]}" + (f" under {folder}" if folder else "")
                  + " (add FILES or --folder to restore less)")
        jobs = [(s, incs)]
    else:
        jobs = plan(restic, env, date, list(paths or []), version, folder, gone_mode)
    if not jobs:
        print("pullback: nothing to restore (nothing disappeared in that window)")
        return 0
    tgt = Path(target).expanduser().resolve()
    if not tgt.is_dir():
        raise BackupError(f"--target {tgt} is not an existing folder")
    stamp = (now or dt.datetime.now()).strftime("%Y%m%d-%H%M")
    manifests = read_manifests()
    expected: dict[str, int] = {}
    checked, bad = 0, []
    with tempfile.TemporaryDirectory(prefix="havnvard-pullback-") as td:
        w = _Writer(tgt, stamp, Path(td))
        failed = []
        for snap, incs in jobs:
            files, special = snapshot_files(restic, env, snap["id"], incs)
            expected.update({p: int(n.get("size") or 0) for p, n in files.items()})
            for inc in incs:
                try:
                    _stream_into(w, restic, env, snap["id"], inc, files, special, Path(td))
                except BackupError as e:            # keep going; every failure is listed and the exit is 1
                    failed.append((inc, str(e)))
            man = next((m for sid, m in manifests.items() if sid[:8] in (snap["id"][:8], snap_key(snap)[:8])), {})
            for p in files:
                exp = man.get(p)
                if exp and p in w.hashes:
                    checked += 1
                    if w.hashes[p] != exp:
                        bad.append(p)
        try:
            w.finish()
        except OSError as e:
            failed.append(("folder modes", str(e)))
    blocked_src = w.unplaced
    missing = sorted(set(expected) - set(w.hashes) - blocked_src)
    print(f"pullback: {len(w.new)} restored, {w.same} already there and identical (left alone), "
          f"{len(w.side)} already there but different (kept; backed-up copy written next to it)"
          + (f", {w.links} symlink(s)" if w.links else "")
          + (f", {w.special} pipe/socket/device entr(ies) skipped" if w.special else ""))
    for orig, alt in w.side:
        print(f"  KEPT {orig}  ->  backed-up copy: {alt}")
    for orig, prev in w.earlier:
        print(f"  KEPT {orig}  (backed-up copy already pulled back earlier: {prev})")
    print(f"pullback: {len(expected) - len(missing) - len(blocked_src & set(expected))}/{len(expected)} files "
          "accounted for; "
          f"{checked - len(bad)}/{checked} SHA-256 match the offload manifest"
          + ("" if checked else " (no offload manifest for these files; restic checked its own hashes)"))
    for p in missing:
        print(f"  NOT RESTORED {p}")
    for p in w.partial:
        print(f"  PARTIAL {p} (copy cut short; kept for you to check, not removed)")
    for b in bad:
        print(f"  MISMATCH {b}")
    for inc, why in failed:
        print(f"  FAILED {inc}: {why}")
    if w.blocked:
        _report_blocked(w, str(tgt), notifier, hub_notice)
    return 0 if not (bad or missing or w.partial or failed or w.blocked or w.unplaced) else config.PROBLEM_EXIT


def _report_blocked(w: _Writer, target: str, notifier, hub_notice) -> list[str]:
    """Folders that refused files. FIRST every blocked folder, every item and every unplaced file is printed (FN-4,
    FN-6), so nothing a popup or the hub does can hide the list. THEN, per folder, one popup (stays until clicked;
    D2: as root, only on the graphical session of the user who owns that folder) and one hub notice, each in its own
    guard: a failure is printed on stderr with its error and the next folder still gets its popup and notice.
    Returns the errors (also on stderr); never silent."""
    import sys
    notifier = notifier or notify.popup
    hub_notice = hub_notice or checkin.report_notice
    n = sum(len(b["items"]) for b in w.blocked.values())
    print(f"pullback: {n} item(s) could NOT be put back: {len(w.blocked)} folder(s) refused them "
          "(nothing there was changed)")
    for folder, b in w.blocked.items():
        print(f"  BLOCKED folder {folder}: {b['why']}")
        for item in b["items"]:
            print(f"    COULD NOT PLACE {item}")
    print(f"pullback: NOT PUT BACK: {len(w.unplaced)} file(s)")
    for src in sorted(w.unplaced):
        print(f"  NOT PUT BACK {src}")
    errors: list[str] = []
    for folder, b in w.blocked.items():
        text = blocked_text(folder, b["why"], b["items"], target, b.get("files"))
        try:
            owner = _uid_of(Path(folder), follow=False)
        except OSError:
            owner = None
        try:
            shown = notifier(notify.TITLE, text, owner_uid=owner)
            if shown.get("shown"):
                print(f"  popup for {folder} shown ({shown.get('how')}); it stays until someone clicks OK")
            else:
                print(f"havnvard pullback: NO POPUP for {folder}: {shown.get('how')}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - FN-4: reported on stderr and returned; the next folder still runs
            errors.append(f"NO POPUP for {folder}: {type(e).__name__}: {e}")
            print(f"havnvard pullback: {errors[-1]}", file=sys.stderr)
        try:
            sent = hub_notice("pullback_blocked", text)
            print(f"  hub notice for {folder}: {sent}")
            if not str(sent).startswith("sent"):
                print(f"havnvard pullback: hub notice for {folder} not sent: {sent}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 - FN-4: reported on stderr and returned; the next folder still runs
            errors.append(f"hub notice for {folder} not sent: {type(e).__name__}: {e}")
            print(f"havnvard pullback: {errors[-1]}", file=sys.stderr)
    return errors


# ---------- find ----------

def find(pattern: str, device: str | None = None, catalog_file: str | None = None,
         from_device: str | None = None, key_file: str | None = None, login_file: str | None = None) -> int:
    if catalog_file or (not from_device and catalog.catalog_path().is_file()):
        return catalog.run_where(pattern, device, catalog_file)
    restic = restic_bin()
    env = other_env(prune.check_device(from_device), key_file, login_file) if from_device else device_env()[0]
    snaps = [s for s in catalog.snapshots(restic, env) if catalog.CATALOG_TAG in (s.get("tags") or [])]
    if not snaps:
        raise BackupError("no catalog copy in this repository yet (the hub's `catalog run` puts one in every repo)")
    newest = sorted(snaps, key=lambda s: catalog.parse_time(s["time"]))[-1]
    ls = run([restic, "ls", "--json", newest["id"]], env=env)
    tsv = [json.loads(ln)["path"] for ln in ls.stdout.splitlines()
           if '"type":"file"' in ln.replace(" ", "") and ln.rstrip().endswith("}") and "_catalog.tsv" in ln]
    if ls.returncode != 0 or not tsv:
        raise BackupError(f"cannot list the catalog snapshot {newest['id'][:8]}: {ls.stderr.strip()[-200:]}")
    with tempfile.TemporaryDirectory(prefix="havnvard-find-") as td:
        out = Path(td) / "catalog.tsv"
        with open(out, "wb") as f:
            r = subprocess.run([restic, "dump", newest["id"], tsv[-1]], env={**os.environ, **env},
                               stdout=f, stderr=subprocess.PIPE, check=False)
        if r.returncode != 0:
            raise BackupError(f"restic dump of the catalog failed rc={r.returncode}")
        print(f"(catalog copy {newest['id'][:8]} from {newest['time'][:10]}, read from the repository)")
        return catalog.run_where(pattern, device, str(out))


# ---------- forget-before / forget-after ----------

def forget_dated(device: str, date: str, key_file: str | None, after: bool = False, include_archive: bool = False,
                 confirm: str | None = None, ask=input) -> int:
    """before: snapshots taken before 00:00 local on DATE. after: snapshots taken on or after 00:00 on DATE.
    Archive-tagged snapshots are left out unless --include-archive (then the typed text says so)."""
    repo, env = prune.hub_repo_env(device, key_file)
    restic, cut = restic_bin(), _start(_day(date))
    prune.clear_stale_locks(restic, env, repo, device, 6.0)
    snaps = catalog.data_snapshots(catalog.snapshots(restic, env))
    snaps = [s for s in snaps if (_when(s["time"]) >= cut if after else _when(s["time"]) < cut)]
    if not include_archive:
        n = len(snaps)
        snaps = [s for s in snaps if ARCHIVE not in (s.get("tags") or [])]
        if n != len(snaps):
            print(f"{n - len(snaps)} archive-tagged snapshot(s) kept (add --include-archive to delete them too)")
    what = f"{'ON OR AFTER' if after else 'BEFORE'} {date}" + (" INCLUDING ARCHIVE" if include_archive else "")
    return prune.delete_snapshots(restic, env, device, snaps, what, confirm, ask)
