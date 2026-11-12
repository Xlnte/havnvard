"""Backup names and the file catalog (HavnVard 2.2.0).

Every data snapshot on the hub gets a name `YYYYMMDD_DEVICE_NNNNNN` (date of the snapshot, device in capitals,
a number that counts up across all devices and never resets). The name is added as a restic tag.

The catalog is one append-only text file of events, one line per file version:
    NAME <TAB> ADDED|GONE <TAB> DEVICE <TAB> PATH <TAB> SIZE <TAB> MTIME(UTC, seconds)
ADDED = this version is first in backup NAME; GONE = backup NAME is the first one without it. Lines are only ever
appended, so restic stores just the new tail each time and a full copy in every repository costs almost nothing.
After each run the whole catalog is backed up into every hub repository it has a password for, as
`<catalog dir>/YYYYMMDD_CATALOG_NNNNNN_catalog.tsv`, tagged `havnvard-catalog`. Those snapshots are not data
backups: health, restore-drill and coverage-sync skip them (CATALOG_TAG).

Runs on the hub (local repository paths, hub-side passwords, so append-only rest-server does not apply).
Crash safety: state.json is the commit point. It records the catalog length; a longer file on start means an
uncommitted tail, which is cut back. Tags applied after a commit are listed in state first, so a crash before
tagging is retried on the next run.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import subprocess
from pathlib import Path

from . import config
from .config import BackupError
from .util import hub_password_dir, restic_bin, run

CATALOG_TAG = "havnvard-catalog"
HEADER = "# HavnVard catalog: NAME\tEVENT\tDEVICE\tPATH\tSIZE\tMTIME_UTC\n"
NAME_RE = re.compile(r"^\d{8}_[A-Z0-9-]+_\d{6}$")


# ---------- pure helpers (tested without restic) ----------

def device_label(repo: str) -> str:
    """Repository name -> DEVICE part of a backup name: capitals, '_' and spaces become '-'."""
    lab = re.sub(r"[^A-Z0-9-]", "-", repo.upper()).strip("-")
    if not lab:
        raise BackupError(f"cannot make a device label from repository name {repo!r}")
    return lab


def make_name(when: dt.datetime, device: str, number: int) -> str:
    if not 0 < number < 1_000_000:
        raise BackupError(f"backup number {number} is outside 1..999999")
    return f"{when.astimezone().strftime('%Y%m%d')}_{device}_{number:06d}"


def parse_time(s: str) -> dt.datetime:
    s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
    return dt.datetime.fromisoformat(s)


def data_snapshots(snaps: list[dict]) -> list[dict]:
    """Data snapshots only (catalog snapshots dropped), oldest first."""
    out = [s for s in snaps if CATALOG_TAG not in (s.get("tags") or [])]
    return sorted(out, key=lambda s: parse_time(s["time"]))


def diff(prev: dict[str, tuple[int, int]], cur: dict[str, tuple[int, int]]) -> tuple[list, list]:
    """(added, gone) as sorted lists of (path, size, mtime). A changed size or mtime is GONE old + ADDED new."""
    added = sorted((p, *v) for p, v in cur.items() if prev.get(p) != v)
    gone = sorted((p, *v) for p, v in prev.items() if cur.get(p) != v)
    return added, gone


def _clean(p: str) -> str:
    return p.replace("\t", " ").replace("\n", " ")


def event_lines(name: str, device: str, added: list, gone: list) -> str:
    out = [f"{name}\tGONE\t{device}\t{_clean(p)}\t{s}\t{m}\n" for p, s, m in gone]
    out += [f"{name}\tADDED\t{device}\t{_clean(p)}\t{s}\t{m}\n" for p, s, m in added]
    return "".join(out)


def name_number(name: str) -> int:
    return int(name.rsplit("_", 1)[1])


def group_key(snap: dict) -> str:
    """restic's prune grouping (host + paths): one backup stream."""
    return snap.get("hostname", "") + "|" + "|".join(sorted(snap.get("paths") or []))


def name_line(name: str, snap: dict) -> str:
    """'#NAME' line: which folders a named backup covers, so `where` only counts backups of the same stream."""
    return "\t".join(["#NAME", name, snap.get("hostname", ""), *(_clean(p) for p in sorted(snap.get("paths") or []))]) + "\n"


def name_device(name: str) -> str:
    return name.split("_")[1]


def alive_line(when: dt.datetime, covered: int, names: list[str]) -> str:
    """'#ALIVE' line: every named data backup that still exists at this run (prune removes old ones), and the
    highest number this line covers. Names above it were issued later: `where` reports them as "not checked
    yet", never as pruned. Starts with '#' so plain readers skip it; `where` uses the last one."""
    return f"#ALIVE\t{when.isoformat(timespec='seconds')}\t{covered}\t{' '.join(sorted(names))}\n"


def where(lines, pattern: str, device: str | None = None) -> list[dict]:
    """Replay the catalog for paths containing `pattern` (case-insensitive). One result per file version:
    first backup that has it, the first backup without it ('' = still in the newest backup), and `held_by`:
    the backups that still exist and hold it (from the last #ALIVE line; empty = pruned away)."""
    pat = pattern.lower()
    found: dict[tuple, dict] = {}
    alive: list[str] | None = None
    covered = 0
    stream: dict[str, tuple] = {}                         # name -> (host, roots) from #NAME lines
    for ln in lines:
        if ln.startswith("#NAME\t"):
            f = ln.rstrip("\n").split("\t")
            stream[f[1]] = (f[2], tuple(f[3:]))
            continue
        if ln.startswith("#ALIVE\t"):
            _, _, cov, names = ln.rstrip("\n").split("\t", 3)
            alive, covered = names.split(), int(cov)
            continue
        if ln.startswith("#") or pat not in ln.lower():
            continue
        parts = ln.rstrip("\n").split("\t")
        if len(parts) != 6:
            continue
        name, ev, dev, path, size, mtime = parts
        if pat not in path.lower() or (device and dev != device.upper()):
            continue
        st_ = stream.get(name)                            # None for 2.2.0 lines without #NAME
        key = (dev, st_, path, size, mtime)               # review S1: a version belongs to one stream
        if ev == "ADDED":
            found[key] = {"device": dev, "path": path, "size": int(size), "mtime": int(mtime),
                          "first": name, "gone": "", "_stream": st_}
        elif ev == "GONE" and key in found:
            found[key]["gone"] = name
    for r in found.values():
        lo = name_number(r["first"])
        hi = name_number(r["gone"]) if r["gone"] else 10**9
        if alive is None or lo > covered:
            r["held_by"] = None                           # not checked yet: unknown, never "pruned"
            continue
        r["held_by"] = sorted((n for n in alive if name_device(n) == r["device"] and lo <= name_number(n) < hi
                               and stream.get(n) == r["_stream"]), key=name_number)
    for r in found.values():
        del r["_stream"]
    return sorted(found.values(), key=lambda r: (not r["held_by"], r["device"], r["path"], r["mtime"]))


# ---------- state ----------

def cat_dir() -> Path:
    return config.state_dir() / "catalog"


def catalog_path() -> Path:
    return cat_dir() / "catalog.tsv"


def _fresh_state() -> dict:
    return {"counter": 0, "catalog_bytes": 0, "devices": {}, "untagged": [], "catalog_snapshots": [],
            "catalog_bytes_backed_up": 0, "alive": [], "alive_by_repo": {}, "alive_covered": 0}


def _load_state() -> dict:
    p = cat_dir() / "state.json"
    if not p.exists():
        if catalog_path().exists() and catalog_path().stat().st_size > 0:
            raise BackupError(f"{p} is missing but {catalog_path()} is not empty: refusing to start over "
                              "(that would cut the catalog and reuse numbers). Run `catalog run --recover`.")
        return _fresh_state()
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError) as e:
        raise BackupError(f"cannot read catalog state {p}: {e}") from e


def _save_state(st: dict) -> None:
    p = cat_dir() / "state.json"
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(st, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def catalog_snapshot_ids() -> set[str]:
    """Full ids of the catalog snapshots this hub wrote (health skips these files in <repo>/snapshots/)."""
    p = cat_dir() / "state.json"
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text()).get("catalog_snapshots", []))
    except (OSError, ValueError) as e:
        raise BackupError(f"cannot read catalog state {p}: {e}") from e


def _live_path(dev: str, ref: str) -> Path:
    return cat_dir() / "live" / f"{dev}.{ref}.tsv"


def _read_live(p: Path) -> dict[str, tuple[int, int]]:
    out = {}
    with open(p, encoding="utf-8", errors="surrogateescape") as f:
        for ln in f:
            path, s, m = ln.rstrip("\n").rsplit("\t", 2)
            out[path] = (int(s), int(m))
    return out


def _write_live(p: Path, files: dict[str, tuple[int, int]]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
        for path in sorted(files):
            s, m = files[path]
            f.write(f"{_clean(path)}\t{s}\t{m}\n")
        f.flush()
        os.fsync(f.fileno())


# ---------- restic ----------

def _env(repo_root: Path, repo: str) -> dict | None:
    pw = hub_password_dir() / f"{repo}.pass"
    if not pw.is_file():
        return None
    return {"RESTIC_REPOSITORY": str(repo_root / repo), "RESTIC_PASSWORD_FILE": str(pw)}


def snapshots(restic: str, env: dict) -> list[dict]:
    r = run([restic, "snapshots", "--json", "--no-lock"], env=env, timeout=1800)
    if r.returncode != 0:
        raise BackupError(f"restic snapshots failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    return json.loads(r.stdout or "[]")


def latest_data_snapshot(restic: str, env: dict) -> dict | None:
    """Newest snapshot that is a real backup (catalog snapshots skipped). Used by drill and coverage-sync."""
    snaps = data_snapshots(snapshots(restic, env))
    return snaps[-1] if snaps else None


def listing(restic: str, env: dict, snap_id: str) -> dict[str, tuple[int, int]]:
    from .coverage import parse_ls_json  # reuse: one restic `ls --json` parser
    e = {**os.environ, **env}
    p = subprocess.Popen([restic, "ls", "--json", "--no-lock", snap_id], env=e,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="surrogateescape")
    assert p.stdout is not None and p.stderr is not None
    _, files = parse_ls_json(p.stdout)
    err = p.stderr.read()
    if p.wait() != 0:
        raise BackupError(f"restic ls {snap_id[:8]} failed (rc {p.returncode}): {err.strip()[-300:]}")
    return files


# ---------- the run ----------

def _repos(repo_root: Path) -> list[str]:
    return sorted(p.name for p in repo_root.iterdir() if p.is_dir() and (p / "config").is_file())


class SnapshotGone(BackupError):
    """The snapshot to tag no longer exists (pruned or removed) and nothing carries the name."""


def _set_mtime(env: dict, snap_id: str, t: float) -> None:
    f = Path(env["RESTIC_REPOSITORY"]) / "snapshots" / snap_id
    if not f.is_file():
        raise BackupError(f"snapshot file {f} not found: cannot set its time (health reads file times)")
    os.utime(f, (t, t))


def _tag(restic: str, env: dict, snap_id: str, name: str, when: str) -> None:
    """Add the name as a tag. restic rewrites the snapshot file (new id, file mtime = now), so the new file's
    mtime is set back to the snapshot's own time: health reads snapshot age from file mtimes."""
    snaps = snapshots(restic, env)
    tagged = [s for s in snaps if name in (s.get("tags") or [])]
    if not tagged and not any(s["id"] == snap_id for s in snaps):
        raise SnapshotGone(f"snapshot {snap_id[:8]} for {name} no longer exists (pruned?); name not applied")
    if not tagged:
        r = run([restic, "tag", "--retry-lock", "30m", "--add", name, snap_id], env=env, timeout=3600)
        if r.returncode != 0:
            raise BackupError(f"restic tag {name} on {snap_id[:8]} failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
        tagged = [s for s in snapshots(restic, env) if name in (s.get("tags") or [])]
    if len(tagged) != 1:
        raise BackupError(f"after tagging, {len(tagged)} snapshots carry {name} (expected 1)")
    _set_mtime(env, tagged[0]["id"], parse_time(when).timestamp())


def _max_number_in(lines) -> int:
    hi = 0
    for ln in lines:
        if ln.startswith("#"):
            continue
        name = ln.split("\t", 1)[0]
        if NAME_RE.match(name):
            hi = max(hi, name_number(name))
    return hi


def _repo_max_number(snaps: list[dict]) -> int:
    nums = [name_number(t) for s in snaps for t in (s.get("tags") or []) if NAME_RE.match(t)]
    return max(nums, default=0)


def catalog_run(first_run_latest_only: bool = True, recover: bool = False) -> int:
    """Name new data snapshots, extend the catalog, back the catalog up into every repository.
    Exit 0 all done; 1 something was skipped (missing password, a failed tag or catalog backup); 2 could not run."""
    hub = config.load().get("hub_local")
    if not hub:
        raise BackupError("not a hub: no [hub_local] in the config")
    repo_root = Path(hub["repo_root"])
    cdir = cat_dir()
    (cdir / "live").mkdir(parents=True, exist_ok=True)
    lock = open(cdir / "run.lock", "w")  # noqa: SIM115 -- held for the whole run (flock)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as e:
        raise BackupError("another catalog run is in progress") from e
    restic, problems, cat = restic_bin(), [], catalog_path()
    fresh = not (cdir / "state.json").exists()
    if recover and not fresh:
        raise BackupError("--recover is only for a missing state.json; state.json exists")
    if recover:
        # Keep every complete line of the catalog; numbering resumes above anything already used below.
        st = _fresh_state()
        if cat.exists():
            data = cat.read_bytes()
            keep = data[: data.rfind(b"\n") + 1]
            with open(cat, "r+b") as f:
                f.truncate(len(keep))                     # only a partial last line can be cut
            st["catalog_bytes"] = len(keep)
            st["counter"] = _max_number_in(keep.decode("utf-8", "surrogateescape").splitlines(True))
        print("catalog: recovering: devices restart from their newest snapshot; old catalog lines are kept")
    else:
        st = _load_state()
    if not cat.exists():
        cat.write_text(HEADER)
        st["catalog_bytes"] = st["catalog_bytes"] or len(HEADER.encode())
        _save_state(st)
    size = cat.stat().st_size
    if size > st["catalog_bytes"]:            # an uncommitted tail from a crashed run
        with open(cat, "r+b") as f:
            f.truncate(st["catalog_bytes"])
    elif size < st["catalog_bytes"]:
        raise BackupError(f"{cat} is shorter than the committed length {st['catalog_bytes']}: refusing to continue")

    envs = {r: _env(repo_root, r) for r in _repos(repo_root)}
    for repo in [r for r, e in envs.items() if e is None]:
        problems.append(f"{repo}: no hub-side password at {hub_password_dir() / (repo + '.pass')}")
    snap_cache: dict[str, list[dict]] = {}
    for repo, env in envs.items():
        if env is None:
            continue
        try:
            snap_cache[repo] = snapshots(restic, env)
        except BackupError as e:
            problems.append(f"{repo}: {e}")
    if recover and (problems or len(snap_cache) != len(envs)):
        raise BackupError("--recover needs every repository readable (the counter floor comes from all their tags): "
                          + "; ".join(problems))
    if fresh and not recover and any(CATALOG_TAG in (s.get("tags") or []) for v in snap_cache.values() for s in v):
        raise BackupError(
            "the catalog state is gone but the repositories already hold catalog snapshots: starting over would "
            "lose the history. Restore it: `restic dump <newest havnvard-catalog snapshot> <its _catalog.tsv path>` "
            f"> {cat}, then `python -m backup catalog run --recover`")
    if fresh or recover:                                  # never reissue a number some repo already carries
        st["counter"] = max([st["counter"], *(_repo_max_number(s) for s in snap_cache.values())])
        _save_state(st)

    for item in list(st["untagged"]):                     # retry tags a crash left behind
        snap_id, name, repo, when = item
        env = envs.get(repo)
        if env is None:
            problems.append(f"{repo}: tag retry {name}: no password")
            continue
        try:
            _tag(restic, env, snap_id, name, when)
            st["untagged"].remove(item)
            _save_state(st)
        except SnapshotGone as e:                         # reported once, then dropped
            problems.append(f"{repo}: tag retry {name}: {e}; dropped from the retry list")
            st["untagged"].remove(item)
            _save_state(st)
        except BackupError as e:
            problems.append(f"{repo}: tag retry {name}: {e}")

    named = 0
    for repo, env in envs.items():
        if env is None or repo not in snap_cache:
            continue
        dev = device_label(repo)
        # One stream per (host, paths): a repo may hold many (e.g. one per app on a server). Diffing across streams would
        # log every file as GONE and ADDED (review finding 9), so state and diffs are per stream.
        streams: dict[str, list[dict]] = {}
        for s in data_snapshots(snap_cache[repo]):
            streams.setdefault(group_key(s), []).append(s)
        rstate = st["devices"].setdefault(repo, {})
        for gk, snaps in sorted(streams.items()):
            dst = rstate.get(gk, {})
            last = parse_time(dst["last_time"]) if dst.get("last_time") else None
            todo = [s for s in snaps if last is None or parse_time(s["time"]) > last]
            if last is None and first_run_latest_only:
                todo = todo[-1:]   # older snapshots age out under prune; naming them would only burn numbers
            prev = _read_live(_live_path(repo, dst["live"])) if dst.get("live") else {}
            for s in todo:
                try:
                    cur = listing(restic, env, s["id"])
                except BackupError as e:
                    problems.append(f"{repo}: {e}")
                    break
                st["counter"] += 1
                name = make_name(parse_time(s["time"]), dev, st["counter"])
                added, gone = diff(prev, cur)
                ref = f"{st['counter']:06d}"
                _write_live(_live_path(repo, ref), cur)
                with open(cat, "a", encoding="utf-8", errors="surrogateescape") as f:
                    f.write(name_line(name, s) + event_lines(name, dev, added, gone))
                    f.flush()
                    os.fsync(f.fileno())
                old_live = dst.get("live")
                dst = {"last_time": s["time"], "last_name": name, "live": ref}
                rstate[gk] = dst
                st["catalog_bytes"] = cat.stat().st_size
                item = [s["id"], name, repo, s["time"]]
                st["untagged"].append(item)
                _save_state(st)                                   # commit point
                if old_live and _live_path(repo, old_live).is_file():
                    os.remove(_live_path(repo, old_live))
                prev = cur
                named += 1
                print(f"catalog: {name} = {repo} {gk} snapshot {s['id'][:8]} (+{len(added)} / -{len(gone)})")
                try:
                    _tag(restic, env, s["id"], name, s["time"])
                    st["untagged"].remove(item)
                    _save_state(st)
                except BackupError as e:
                    problems.append(f"{repo}: {e}")

    # Per repo: names that still exist. A repo this run could not read keeps its last known names, so a
    # partial view never marks anything pruned (review round 2, R1).
    by_repo = dict(st.get("alive_by_repo", {}))
    for repo, env in envs.items():
        if env is None or repo not in snap_cache:
            continue
        try:
            by_repo[repo] = sorted(t for s in data_snapshots(snapshots(restic, env)) for t in (s.get("tags") or [])
                                   if NAME_RE.match(t) and name_device(t) != "CATALOG")
        except BackupError as e:
            problems.append(f"{repo}: {e}")
    # names issued but not yet tagged (a failed tag, retried next run) still exist as snapshots: count them
    alive = sorted({n for names in by_repo.values() for n in names} | {it[1] for it in st["untagged"]})
    if alive != st.get("alive", []):     # a name issued but not yet tagged stays above `covered`: "not checked"
        with open(cat, "a", encoding="utf-8") as f:
            f.write(alive_line(dt.datetime.now(dt.timezone.utc), st["counter"], alive))
            f.flush()
            os.fsync(f.fileno())
        st.update(alive=alive, alive_by_repo=by_repo, alive_covered=st["counter"], catalog_bytes=cat.stat().st_size)
        _save_state(st)

    if st["catalog_bytes"] != st.get("catalog_bytes_backed_up"):
        st["counter"] += 1
        cname = make_name(dt.datetime.now(dt.timezone.utc), "CATALOG", st["counter"])
        _save_state(st)
        stage = cdir / "stage"
        stage.mkdir(exist_ok=True)
        for old in [p for p in stage.iterdir() if p.name.endswith("_catalog.tsv")]:
            os.remove(old)
        copy = stage / f"{cname}_catalog.tsv"
        with open(cat, "rb") as src, open(copy, "wb") as out:
            out.write(src.read(st["catalog_bytes"]))
        ok_all = True
        for repo, renv in envs.items():
            if renv is None:
                ok_all = False
                continue
            r = run([restic, "backup", "--json", "--retry-lock", "30m", "--host", repo, "--tag", CATALOG_TAG,
                     "--tag", cname, str(stage)], env=renv, timeout=7200)
            sid = None
            for ln in r.stdout.splitlines():
                try:
                    o = json.loads(ln)
                except ValueError:
                    continue
                if o.get("message_type") == "summary":
                    sid = o.get("snapshot_id")
            if r.returncode != 0 or not sid:
                ok_all = False
                problems.append(f"{repo}: catalog backup failed rc={r.returncode}: {r.stderr.strip()[-200:]}")
                continue
            st["catalog_snapshots"].append(sid)
            _save_state(st)
            # health must not depend on state.json: pin the catalog snapshot's file time to the newest DATA
            # snapshot's time (0 when there is none), so it can never make a dead device look fresh
            newest = data_snapshots(snap_cache.get(repo, []))
            try:
                _set_mtime(renv, sid, parse_time(newest[-1]["time"]).timestamp() if newest else 0)
            except BackupError as e:
                problems.append(f"{repo}: {e}")
        if ok_all:
            st["catalog_bytes_backed_up"] = st["catalog_bytes"]
            _save_state(st)
        print(f"catalog: {cname} backed up into {len(envs) - sum(e is None for e in envs.values())}/{len(envs)} repositories")
    print(f"catalog: {named} backup(s) named, catalog {st['catalog_bytes'] / 1e6:.1f} MB, {len(problems)} problem(s)")
    for p in problems:
        print(f"  PROBLEM {p}")
    return config.PROBLEM_EXIT if problems else 0


def run_where(pattern: str, device: str | None = None, catalog: str | None = None) -> int:
    p = Path(catalog) if catalog else catalog_path()
    if not p.is_file():
        raise BackupError(f"no catalog at {p}: run `catalog run` on the hub, or pass --catalog FILE")
    with open(p, encoding="utf-8", errors="surrogateescape") as f:
        hits = where(f, pattern, device)
    for h in hits:
        if h["held_by"] is None:
            state = f"from {h['first']}" + (f" until {h['gone']}" if h["gone"] else " on") + " (not checked against prune yet)"
        elif h["held_by"]:
            state = f"in {h['held_by'][-1]} (newest of {len(h['held_by'])} backup(s) that hold it)"
        else:
            state = f"was in {h['first']}" + (f" until {h['gone']}" if h["gone"] else "") + ": those backups are pruned"
        when = dt.datetime.fromtimestamp(h["mtime"], dt.timezone.utc).strftime("%Y-%m-%d")
        print(f"{h['device']}\t{h['path']}\t{h['size']} bytes\t{when}\t{state}")
    held = [h for h in hits if h["held_by"] or h["held_by"] is None]
    if not hits:
        print(f"where {pattern!r}: not in any named backup (the catalog starts at its first run; "
              "older unnamed snapshots are not listed)")
    else:
        print(f"where {pattern!r}: {len(hits)} file version(s), {len(held)} still restorable")
    return 0 if held else config.PROBLEM_EXIT
