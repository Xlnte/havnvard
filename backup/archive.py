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
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

from . import catalog, config, prune
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


def vanished(restic: str, env: dict, snaps: list[dict], day: dt.date) -> tuple[dict, list[str]]:
    """(snapshot to restore from, file paths that disappeared during `day`). Only regular backups are compared
    (no archive/offload snapshots), and only snapshots of the same host and the same backup paths (review FIX-NOW 4).
    after = last regular backup during the day, else the first after it; before = last matching backup before it."""
    s0, s1 = _start(day), _start(day + dt.timedelta(days=1))
    reg = [s for s in snaps if ARCHIVE not in (s.get("tags") or [])]
    during = [s for s in reg if s0 <= _when(s["time"]) < s1]
    later = [s for s in reg if _when(s["time"]) >= s1]
    after = during[-1] if during else (later[0] if later else None)
    same = (lambda s: (s.get("hostname"), sorted(s.get("paths", []))) == (after.get("hostname"), sorted(after.get("paths", [])))) if after else None
    before = [s for s in reg if _when(s["time"]) < s0 and same(s)] if after else []
    if not before or not after:
        raise BackupError(f"--vanished needs a regular backup before {day} and one during or after it with the same "
                          f"host and folders; found {len(before)} before, {'one' if after else 'none'} during/after")
    r = run([restic, "diff", "--json", before[-1]["id"], after["id"]], env=env)
    if r.returncode != 0:
        raise BackupError(f"restic diff failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    gone = []
    for ln in r.stdout.splitlines():
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        if o.get("message_type") == "change" and o.get("modifier") == "-" and not o["path"].endswith("/"):
            gone.append(o["path"])
    return before[-1], gone


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
        src, gone = vanished(restic, env, snaps, day)
        gone = [g for g in gone if _under(g, folder)]
        return [(src, gone)] if gone else []
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


def renamed(path: Path, stamp: str, is_dir: bool = False) -> Path:
    """report.pdf -> report_pullback-20261113-0130.pdf (then _2, _3 ... if that exists too). Folders keep no suffix split."""
    stem, ext = (path.stem, path.suffix) if (path.suffix and path.stem and not is_dir) else (path.name, "")
    n = 1
    while True:
        cand = path.with_name(f"{stem}_pullback-{stamp}{'' if n == 1 else '_' + str(n)}{ext}")
        if not os.path.lexists(cand):
            return cand
        n += 1


def _dest(tgt: Path, p: str) -> Path:
    return tgt / p.lstrip("/") if tgt != Path("/") else Path(p)


class _Writer:
    """Writes backed-up files onto the device without ever changing what is there."""

    def __init__(self, tgt: Path, stamp: str, scratch: Path):
        self.tgt, self.stamp, self.scratch = tgt, stamp, scratch
        self.redirect: dict[Path, Path] = {}     # a path blocked by a non-folder -> the NAME_pullback-STAMP folder used
        self.new_dirs: dict[Path, tuple[int, float] | None] = {}
        self.new, self.same, self.side, self.partial, self.links, self.special = [], 0, [], [], 0, 0
        self.hashes: dict[str, str] = {}         # source path -> SHA-256 of what was written / found identical

    def _apply(self, p: Path) -> Path:
        for k in sorted(self.redirect, key=lambda x: len(str(x)), reverse=True):
            if p == k or k in p.parents:
                return self.redirect[k] / p.relative_to(k)
        return p

    def mkdirs(self, d: Path) -> Path:
        """Make sure folder d exists; create only missing folders. A FILE (or dead link) where a folder belongs is
        left alone and the folder goes to NAME_pullback-STAMP next to it. A symlinked folder is used, never replaced."""
        d = self._apply(d)
        anchor = Path(d.anchor)
        cur = anchor
        for part in d.relative_to(anchor).parts:
            nxt = cur / part
            if os.path.lexists(nxt):
                if nxt.is_dir():
                    cur = nxt
                    continue
                alt = renamed(nxt, self.stamp, is_dir=True)
                os.mkdir(alt)
                self.redirect[nxt] = alt
                self.new_dirs[alt] = None
                self.side.append((str(nxt), str(alt)))
                cur = alt
            else:
                os.mkdir(nxt)
                self.new_dirs[nxt] = None
                cur = nxt
        return cur

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
            raise
        finally:
            os.close(fd)
        if n != size:
            self.partial.append(str(path))      # kept, reported; never removed
        else:
            os.chmod(path, mode & 0o7777)
            os.utime(path, (mtime, mtime))
        return h.hexdigest()

    def put_file(self, src: str, reader, size: int, mode: int, mtime: float) -> None:
        dest = _dest(self.tgt, src)
        d = self.mkdirs(dest.parent) / dest.name
        if not os.path.lexists(d):
            self.hashes[src] = self._write_new(d, reader, size, mode, mtime)
            self.new.append(str(d))
            return
        if d.is_file() and not d.is_symlink() and d.stat().st_size == size:
            spool = self.scratch / "spool"
            h = hashlib.sha256()
            with open(spool, "wb") as f:                 # our own scratch file in a TemporaryDirectory
                for chunk in iter(lambda: reader.read(1 << 20), b""):
                    h.update(chunk)
                    f.write(chunk)
            if sha256_file(d) == h.hexdigest():
                self.same += 1
                self.hashes[src] = h.hexdigest()
                return
            reader = open(spool, "rb")
        alt = renamed(d, self.stamp)
        try:
            self.hashes[src] = self._write_new(alt, reader, size, mode, mtime)
        finally:
            if reader is not None and getattr(reader, "name", None) == str(self.scratch / "spool"):
                reader.close()
        self.side.append((str(d), str(alt)))

    def put_link(self, src: str, target: str) -> None:
        dest = _dest(self.tgt, src)
        d = self.mkdirs(dest.parent) / dest.name
        if not os.path.lexists(d):
            os.symlink(target, d)
            self.links += 1

    def finish(self) -> None:
        for d, meta in sorted(self.new_dirs.items(), key=lambda kv: len(kv[0].parts), reverse=True):  # deepest first
            if meta:
                os.chmod(d, meta[0] & 0o7777)
                os.utime(d, (meta[1], meta[1]))


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
                            w.mkdirs(_dest(w.tgt, src))
                            w.dir_meta(src, m.mode, m.mtime)
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
             snapshot: str | None = None, now: dt.datetime | None = None) -> int:
    """Never changes anything that exists: an identical file is left alone; a different one stays and the backed-up
    copy is written next to it as NAME_pullback-YYYYMMDD-HHMM.EXT; a file where a folder belongs stays and the folder
    is written as NAME_pullback-YYYYMMDD-HHMM/. Every expected file is accounted for, or the exit is 1."""
    restic = restic_bin()
    env = other_env(prune.check_device(from_device), key_file, login_file) if from_device else device_env()[0]
    if snapshot:
        s = find_snapshot(restic, env, snapshot)
        incs = [p for p in s.get("paths", []) if _under(p, folder)] or ([folder.rstrip("/")] if folder else [])
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
    missing = sorted(set(expected) - set(w.hashes))
    print(f"pullback: {len(w.new)} restored, {w.same} already there and identical (left alone), "
          f"{len(w.side)} already there but different (kept; backed-up copy written next to it)"
          + (f", {w.links} symlink(s)" if w.links else "")
          + (f", {w.special} pipe/socket/device entr(ies) skipped" if w.special else ""))
    for orig, alt in w.side:
        print(f"  KEPT {orig}  ->  backed-up copy: {alt}")
    print(f"pullback: {len(expected) - len(missing)}/{len(expected)} files accounted for; "
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
    return 0 if not (bad or missing or w.partial or failed) else config.PROBLEM_EXIT


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
