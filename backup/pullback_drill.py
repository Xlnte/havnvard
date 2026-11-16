"""`pullback-drill` (HavnVard 3.3.13, INFRA-644 spec 3.6): prove, on a schedule, that a pullback works and wins.

On the hub, against one device's repository (the hub-side password; never touching the device):
1. pull a known TEST SET (a folder backed up on purpose, with a stored SHA-256 list) into a fresh scratch folder;
2. check SHA-256 X/N and the folder count;
3. forced contention: while that pullback runs, a real catalog-style exclusive step on the same repository (a name tag
   of the drill's own marker snapshot, the same `restic tag` the catalog uses) must yield (deferred), and the pullback
   must end with 0 FAILED;
4. concurrency: 20 parallel short pullbacks (one small file each, separate processes) while 50 "may I take the
   exclusive lock now?" checks run: every pullback writes and removes its own intent file, no intent file is read
   half-written, no check says "free" while a pullback is live, and the intent folder is empty at the end;
5. catch-up: after the pullbacks end, the deferred tag is applied and its deferral line gets done_at;
6. the report names what the drill does not prove (a pullback over the network from another computer);
7. report X/Y to the journal and the hub audit log, remove the scratch folder, raise/resolve `havnvard-pullback-drill`.
A drill that cannot run (hub down, test set missing, a step that errors) is a FAILED drill, never a skipped one.

The test set's SHA-256 list lives in state/drill-sets/<DEVICE>/<SET>.sha256 (`sha256sum` format, absolute paths);
`--hashes FILE` imports one. The marker snapshot (host `havnvard-drill`, tag `havnvard-drill-marker`) is the only thing
the drill ever adds to the repository; it is not a data backup (catalog.data_snapshots skips it) and its file time is
pinned to 0 so it never makes a device look fresh. Nothing is ever deleted from the repository.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import alerts, catalog, config, precedence
from .config import BackupError
from .util import restic_bin, run, sha256_file

KEY = "havnvard-pullback-drill"
PARALLEL = 20
CHECKS = 50
CHILD_TIMEOUT_S = 600
HOLD_S = 3.0          # lock leg: how long the drill's own exclusive tag is held paused in the pullback's way
NOT_COVERED = ("not covered by this drill: a pullback over the network from another computer (network loss "
               "mid-pullback); the test suite covers a cut stream (reported PARTIAL/FAILED, exit 1)")
_HASH_LINE = re.compile(r"^([0-9a-fA-F]{64}) [ *]?(/.*)$")


def result_path() -> Path:
    return config.state_dir() / "pullback-drill.json"


def set_path(device: str, name: str) -> Path:
    return config.state_dir() / "drill-sets" / precedence.safe_name(device) / f"{precedence.safe_name(name)}.sha256"


def import_hashes(device: str, name: str, src: str) -> int:
    """Store the test set's SHA-256 list (`sha256sum` output with absolute paths, or HASH<TAB>PATH)."""
    rows = []
    for i, ln in enumerate(Path(src).expanduser().read_text().splitlines(), 1):
        ln = ln.rstrip("\n")
        if not ln.strip() or ln.startswith("#"):
            continue
        m = _HASH_LINE.match(ln.replace("\t", " ", 1))
        if not m:
            raise BackupError(f"{src} line {i}: expected 'SHA256  /absolute/path', got {ln[:80]!r}")
        rows.append(f"{m[1].lower()}  {m[2]}\n")
    if not rows:
        raise BackupError(f"{src} holds no SHA-256 lines")
    p = set_path(device, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    config.atomic_write_text(p, "".join(rows))
    return len(rows)


def load_set(device: str, name: str) -> list[tuple[str, str]]:
    p = set_path(device, name)
    if not p.is_file():
        raise BackupError(f"test set {name} of {device} is missing: no SHA-256 list at {p} "
                          "(import it once with --hashes FILE)")
    out = []
    for ln in p.read_text().splitlines():
        m = _HASH_LINE.match(ln)
        if m:
            out.append((m[1], m[2]))
    if not out:
        raise BackupError(f"test set {name} of {device}: {p} holds no SHA-256 lines")
    return out


# ---------- the marker snapshot (the drill's own exclusive step) ----------

def _marker(restic: str, env: dict) -> dict | None:
    hits = [s for s in catalog.snapshots(restic, env) if catalog.DRILL_TAG in (s.get("tags") or [])]
    return sorted(hits, key=lambda s: catalog.parse_time(s["time"]))[-1] if hits else None


def ensure_marker(restic: str, env: dict) -> dict:
    """The drill's marker snapshot in this repository; made once (a tiny file, shared lock), then reused."""
    m = _marker(restic, env)
    if m:
        return m
    with tempfile.TemporaryDirectory(prefix="havnvard-drill-marker-") as td:
        f = Path(td) / "havnvard-drill-marker.txt"
        f.write_text("HavnVard pullback drill marker: the drill tags this snapshot to test that exclusive steps yield "
                     "to a pullback. Not a backup of anything.\n")
        r = run([restic, "backup", "--retry-lock", "2m", "--host", "havnvard-drill", "--tag", catalog.DRILL_TAG,
                 str(f)], env=env, timeout=600)
    if r.returncode != 0:
        raise BackupError(f"could not create the drill marker snapshot rc={r.returncode}: {r.stderr.strip()[-300:]}")
    m = _marker(restic, env)
    if not m:
        raise BackupError("the drill marker snapshot was written but is not listed")
    _pin(restic, env, m)
    return m


def markers_path() -> Path:
    return config.state_dir() / "drill-markers.json"


def marker_ids() -> set[str]:
    """Every snapshot id the drill marker ever had on this hub (review L11: health skips them, like catalog copies, so a
    crash before the file time is pinned can never make a device look freshly backed up)."""
    try:
        d = json.loads(markers_path().read_text())
    except (OSError, ValueError):
        return set()
    return {i for ids in (d.values() if isinstance(d, dict) else []) for i in ids if isinstance(i, str)}


def _remember(repo: str, snap_id: str) -> None:
    p = markers_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with config.file_lock(p):
        try:
            d = json.loads(p.read_text()) if p.is_file() else {}
        except (OSError, ValueError):
            d = {}
        ids = d.setdefault(repo, [])
        if snap_id not in ids:
            ids.append(snap_id)
        config.atomic_write_text(p, json.dumps(d))


def pin_all_markers(restic: str, env: dict, repo: str) -> int:
    """Re-review R3: EVERY snapshot tagged as the drill marker (a tag killed mid-way can leave an extra one with a fresh
    file time) is recorded for health's skip set and its file time pinned to 0. Returns how many."""
    ms = [s for s in catalog.snapshots(restic, env) if catalog.DRILL_TAG in (s.get("tags") or [])]
    for m in ms:
        _remember(repo, m["id"])
        catalog._set_mtime(env, m["id"], 0)
    return len(ms)


def _pin(restic: str, env: dict, m: dict | None = None) -> None:
    """Record the marker's current id (health skip set), then pin its file time to 0."""
    m = m or _marker(restic, env)
    if not m:
        return
    _remember(precedence.repo_label(env), m["id"])
    catalog._set_mtime(env, m["id"], 0)           # never makes the device look fresh (health reads file times)


EPOCH = "1970-01-01T00:00:00Z"


def tag_marker(restic: str, env: dict, repo: str, tag: str) -> bool:
    """The catalog-style exclusive step on the marker: tagged now (True) or deferred for a live pullback (False)."""
    m = _marker(restic, env)
    if not m:
        raise BackupError("the drill marker snapshot is gone")
    _remember(repo, m["id"])
    done = catalog.tag_or_defer(restic, env, repo, m["id"], tag, EPOCH, job="pullback-drill")
    if done:
        _pin(restic, env)
    return done


def catch_up(restic: str, env: dict, repo: str) -> list[dict]:
    """Apply every open deferral of the drill's own tag step on REPO (the same gate as the catalog) and mark it done."""
    done = []
    for o in precedence.open_deferrals(job="pullback-drill", repo=repo):
        if tag_marker(restic, env, repo, o["tag"]):
            done += precedence.mark_done(lambda x, o=o: x.get("job") == "pullback-drill" and x.get("repo") == repo
                                         and x.get("tag") == o["tag"], "tagged by the drill's catch-up")
    return done


# ---------- the drill ----------

def _folder_of(paths: list[str]) -> str:
    c = os.path.commonpath(paths)
    return os.path.dirname(c) if c in paths else c


def _main_case(device: str, folder: str, tset: list[tuple[str, str]], out: Path, restic: str, env: dict,
               tag: str, rep: dict) -> None:
    """Steps 1-3: the test set pulled back while a real exclusive tag step on the same repository must yield."""
    res: dict = {}
    decided = threading.Event()

    def contend():
        try:
            res["tagged"] = tag_marker(restic, env, device, tag)
        except BackupError as e:
            res["error"] = str(e)
        finally:
            decided.set()

    def on_start(_intent):
        threading.Thread(target=contend, name="havnvard-drill-contention", daemon=True).start()
        if not decided.wait(120):
            res["error"] = "the contention step did not decide within 120 s"

    stats: dict = {}
    rc = archive_pullback(paths=[folder], from_device=device, target=str(out), on_start=on_start, stats=stats)
    ok_hash, bad = 0, []
    for h, p in tset:
        f = out / p.lstrip("/")
        try:
            if sha256_file(f) == h:
                ok_hash += 1
            else:
                bad.append(f"{p}: SHA-256 differs")
        except OSError as e:
            bad.append(f"{p}: {e.strerror or e}")
    want_dirs = {os.path.dirname(p) for _, p in tset}
    got_dirs = sum(1 for d in want_dirs if (out / d.lstrip("/")).is_dir())
    rep["restored"] = (ok_hash, len(tset))
    rep["folders"] = (got_dirs, len(want_dirs))
    rep["pullback_rc"], rep["pullback_failed"] = rc, stats.get("failed", 0)
    rep["bad"] = bad[:20]
    rep["contention"] = ("error: " + res["error"]) if "error" in res else \
        ("yielded" if res.get("tagged") is False else "NOT exercised (the tag step did not see the pullback)")


def _lock_files(d: Path) -> set[str]:
    try:
        return {n for n in os.listdir(d) if re.fullmatch(r"[0-9a-f]{64}", n)}
    except OSError:
        return set()


def _resume(p: subprocess.Popen) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(p.pid, signal.SIGCONT)


def _die_with_parent(parent: int):
    """preexec_fn: the kernel SIGKILLs this child when the thread that started it dies, in any way, kill -9 included
    (Linux PR_SET_PDEATHSIG). A killed `restic tag` leaves its lock file with no live pid on this host, so restic and
    LockGate see it as stale at once. A tag killed mid-way can leave a duplicate MARKER snapshot: marker only, never
    device data, and it is excluded from data_snapshots like the marker itself."""
    import ctypes                               # re-review R4: resolved in the parent; the child only calls it
    prctl = ctypes.CDLL(None, use_errno=True).prctl

    def setup():
        if prctl(1, 9, 0, 0, 0) != 0:           # PR_SET_PDEATHSIG = 1, SIGKILL = 9
            os._exit(1)
        if os.getppid() != parent:              # the drill died before the death signal was armed
            os._exit(1)
    return setup


def hold_tag(restic: str, env: dict, snap_id: str, tag: str, locks: Path, errf, timeout: float = 60.0):
    """Start the drill's own exclusive `restic tag` (dies with the drill), wait for its lock file, pause it (SIGSTOP).
    Returns (process, True if the lock is now held). Must be called from the thread that lives as long as the hold
    (the death signal follows the creating thread): the drill calls it from the pullback's main thread."""
    before = _lock_files(locks)
    seen = set(before)
    p = subprocess.Popen([restic, "tag", "--retry-lock", "2m", "--add", tag, snap_id], env={**os.environ, **env},
                         stdout=subprocess.DEVNULL, stderr=errf, stdin=subprocess.DEVNULL,
                         preexec_fn=_die_with_parent(os.getpid()))  # noqa: PLW1509 - prctl must run in the child
    deadline = time.time() + timeout
    while time.time() < deadline and p.poll() is None:
        new = _lock_files(locks) - seen
        if new:
            os.kill(p.pid, signal.SIGSTOP)     # pause first (the tag holds its lock only briefly), then check it
            if any(_is_our_exclusive(restic, env, lid, p.pid) for lid in new):
                return p, True
            seen |= new                        # re-review R2: someone else's lock, or not exclusive: let it go on
            _resume(p)
        time.sleep(0.002)
    return p, False


def _is_our_exclusive(restic: str, env: dict, lock_id: str, pid: int) -> bool:
    r = run([restic, "cat", "lock", lock_id, "--no-lock"], env=env, timeout=60)
    if r.returncode != 0:
        return False
    try:
        rec = json.loads(r.stdout)
    except ValueError:
        return False
    return isinstance(rec, dict) and bool(rec.get("exclusive")) and int(rec.get("pid") or 0) == pid


def _lock_case(device: str, tset: list[tuple[str, str]], out: Path, restic: str, env: dict, stamp: str,
               rep: dict) -> None:
    """Review F1 (spec 3.3 + 3.6 step 3): a REAL exclusive restic lock already held when the pullback's restic call
    starts, the T4 failure mode. From on_start (intent written, before the first restic call) the drill starts its own
    `restic tag` on the marker WITHOUT the intent check, under a pullback-drill job record, waits for its lock file in
    locks/, and pauses that restic (SIGSTOP) for HOLD_S seconds, so the pullback must meet the lock. A timer and a
    finally always resume it (restic then finishes its tag). Pass = LockGate named the drill's step, GOT THE LOCK, and
    the pullback ended with 0 FAILED. Anything else, including the lock not being in the way, is a FAILED leg."""
    m = _marker(restic, env)
    lock_tag = f"havnvard-drill-lock-{stamp}"
    locks = Path(str(env.get("RESTIC_REPOSITORY", ""))) / "locks"
    st: dict = {}
    stack = contextlib.ExitStack()

    def on_start(_intent):
        if not m or not locks.is_dir():
            st["why"] = "no marker snapshot or no local locks/ folder"
            return
        if not sys.platform.startswith("linux"):
            st["why"] = ("not Linux: the paused tag step needs PR_SET_PDEATHSIG so a killed drill can never leave it "
                         "holding the lock; leg skipped")
            return
        stack.enter_context(precedence.job_record(device, "pullback-drill", f"drill lock step {lock_tag}"))
        errf = stack.enter_context(tempfile.TemporaryFile())
        p, held = hold_tag(restic, env, m["id"], lock_tag, locks, errf)
        st["proc"] = p
        if held:
            st["held"] = True
            t = threading.Timer(HOLD_S, _resume, args=(p,))
            t.daemon = True
            t.start()
        else:
            st["why"] = "the drill's tag finished before its lock could be held in the pullback's way (a race)"

    small = min(tset, key=lambda hp: (out.parent / "main" / hp[1].lstrip("/")).stat().st_size
                if (out.parent / "main" / hp[1].lstrip("/")).is_file() else 1 << 62)
    stats: dict = {}
    rc = None
    try:
        rc = archive_pullback(paths=[small[1]], from_device=device, target=str(out), on_start=on_start, stats=stats)
    finally:
        p = st.get("proc")
        if p is not None:
            _resume(p)
            try:
                st["tag_rc"] = p.wait(timeout=180)
            except subprocess.TimeoutExpired:
                st["tag_rc"] = "still running after 180 s"
        stack.close()
        with contextlib.suppress(BackupError, OSError):
            _pin(restic, env)
    got = [w for w in stats.get("lock_waits", []) if w.get("outcome") == "got the lock"
           and "pullback drill" in str(w.get("holder"))]
    if got and rc == 0 and stats.get("failed", 0) == 0:
        rep["lock_leg"] = (True, f"lock gate exercised: GOT THE LOCK after {got[0]['seconds']}s "
                                 f"(holder: {got[0]['holder']}), 0 FAILED")
    elif not st.get("held"):
        rep["lock_leg"] = (False, f"lock gate NOT exercised: {st.get('why', 'the lock was not held')}")
    else:
        rep["lock_leg"] = (False, f"lock gate FAILED: exit {rc}, {stats.get('failed')} FAILED, waits "
                                  f"{stats.get('lock_waits')}")
    if st.get("tag_rc") not in (None, 0):
        rep["lock_leg"] = (False, rep["lock_leg"][1] + f"; the drill's tag step ended rc={st['tag_rc']}")


def archive_pullback(**kw) -> int:
    from .archive import pullback
    return pullback(**kw)


def _concurrency_case(device: str, tset: list[tuple[str, str]], snap_id: str, scratch: Path, rep: dict,
                      parallel: int, checks: int) -> None:
    """Step 4: PARALLEL separate pullback processes of one small file each, while CHECKS gate checks run."""
    from .render import REPO_DIR
    small = sorted(tset, key=lambda hp: (os.path.getsize(scratch / "main" / hp[1].lstrip("/"))
                                         if (scratch / "main" / hp[1].lstrip("/")).is_file() else 1 << 62))
    picks = [small[i % len(small)] for i in range(parallel)]
    trace = scratch / "intent-trace.jsonl"
    env = dict(os.environ, **{precedence.TRACE_ENV: str(trace)})
    kids = []
    for i, (h, p) in enumerate(picks):
        tgt = scratch / f"c{i:02d}"
        tgt.mkdir()
        logf = open(scratch / f"c{i:02d}.log", "w")  # noqa: SIM115 -- closed after the child ends
        kids.append((subprocess.Popen([sys.executable, "-m", "backup", "pullback", "--from", device, "--snapshot",
                                       snap_id, p, "--target", str(tgt)], cwd=str(REPO_DIR), env=env, stdout=logf,
                                      stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL), logf, tgt, h, p))
    results = []                                    # (t0, t1, n_live, n_unreadable)
    deadline = time.time() + 60
    while time.time() < deadline and not trace.exists() and any(k[0].poll() is None for k in kids):
        time.sleep(0.01)                            # start checking once the first child has announced itself
    for _ in range(checks):
        t0 = time.time()
        live, unread = precedence.read_intents(device, seen_by="pullback-drill check")
        results.append((t0, time.time(), len(live), unread))
        time.sleep(0.02)
    codes = []
    for proc, logf, _tgt, _h, _p in kids:
        try:
            codes.append(proc.wait(timeout=CHILD_TIMEOUT_S))
        except subprocess.TimeoutExpired:
            proc.kill()
            codes.append(proc.wait())
        logf.close()
    pids = {k[0].pid for k in kids}
    ev = []
    if trace.exists():
        for ln in trace.read_text().splitlines():
            try:
                ev.append(json.loads(ln))
            except ValueError:
                rep.setdefault("trace_bad", 0)
                rep["trace_bad"] = rep["trace_bad"] + 1
    writes = {e["pid"]: e["t"] for e in ev if e.get("event") == "write" and e.get("pid") in pids}
    removes = {e["pid"]: e["t"] for e in ev if e.get("event") == "remove" and e.get("pid") in pids}
    both = [pid for pid in pids if pid in writes and pid in removes and writes[pid] <= removes[pid]]
    windows = [(writes[pid], removes[pid]) for pid in both]
    wrong_free = sum(1 for t0, t1, n, u in results if n == 0 and u == 0 and any(w <= t0 and t1 <= r for w, r in windows))
    during = sum(1 for t0, t1, _n, _u in results if any(w <= t0 and t1 <= r for w, r in windows))
    restored_ok = sum(1 for (_pr, _lf, tgt, h, p), c in zip(kids, codes, strict=True) if c == 0 and
                      (tgt / p.lstrip("/")).is_file() and sha256_file(tgt / p.lstrip("/")) == h)
    leftover = sorted(x.name for x in precedence.intent_dir(device).glob("*")) \
        if precedence.intent_dir(device).is_dir() else []
    rep["concurrency"] = {"pullbacks": parallel, "exit0": sum(1 for c in codes if c == 0), "restored": restored_ok,
                          "intents_written_removed": len(both), "half_read": sum(r[3] for r in results),
                          "wrong_free": wrong_free, "checks": len(results), "checks_during_live": during,
                          "leftover": leftover}


def _drill(device: str, set_name: str, hashes: str | None, scratch: str | None, parallel: int, checks: int) -> dict:
    from .drill import _canary, _env_for
    _canary()
    if hashes:
        n = import_hashes(device, set_name, hashes)
        print(f"pullback-drill: test set {set_name} of {device}: {n} SHA-256 line(s) stored at {set_path(device, set_name)}")
    tset = load_set(device, set_name)
    env, restic = _env_for(device), restic_bin()
    precedence.clear_dead_locks(restic, env, device, "pullback-drill")   # re-review R1: a killed earlier drill
    pinned = pin_all_markers(restic, env, device)                        # re-review R3
    before = len(catalog.snapshots(restic, env))
    had_marker = _marker(restic, env) is not None
    ensure_marker(restic, env)
    folder = _folder_of([p for _, p in tset])
    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    tag = f"havnvard-drill-{stamp}"
    rep: dict = {"device": device, "set": set_name, "folder": folder, "tag": tag, "markers_pinned": pinned}
    with tempfile.TemporaryDirectory(prefix="havnvard-pullback-drill-", dir=scratch) as td:
        tdp = Path(td)
        (tdp / "main").mkdir()
        rep["scratch"] = td
        try:
            _main_case(device, folder, tset, tdp / "main", restic, env, tag, rep)
            (tdp / "lockleg").mkdir()
            _lock_case(device, tset, tdp / "lockleg", restic, env, stamp, rep)
            from .archive import plan
            jobs = plan(restic, env, None, [folder], None, None, False)
            if not jobs:
                raise BackupError(f"no backup of {device} holds {folder}")
            _concurrency_case(device, tset, jobs[0][0]["id"], tdp, rep, parallel, checks)
        finally:
            # review F3: whatever happened above, the drill's own deferral is caught up now (never left for the
            # catalog, which cannot clear it); a catch-up that fails makes this a FAILED drill.
            try:
                rep["caught"] = catch_up(restic, env, device)
            except BackupError as e:
                rep["caught"], rep["catchup_error"] = [], str(e)
    rep["scratch_removed"] = not Path(rep["scratch"]).exists()
    mine = [o for o in rep["caught"] if o.get("tag") == tag]
    m = _marker(restic, env)
    rep["deferred"] = sum(1 for o in precedence._read_deferred()
                          if o.get("job") == "pullback-drill" and o.get("repo") == device and o.get("tag") == tag)
    rep["caught_up"] = len(mine) if m and tag in (m.get("tags") or []) else 0
    after_snaps = catalog.snapshots(restic, env)
    rep["snapshots"] = (before, len(after_snaps))
    rep["marker_created"] = not had_marker
    return rep


def _verdict(rep: dict) -> list[tuple[str, bool, str]]:
    c = rep.get("concurrency", {})
    x, n = rep["restored"]
    fx, fn = rep["folders"]
    b0, b1 = rep["snapshots"]
    return [
        ("SHA-256", x == n, f"{x}/{n} files match the stored SHA-256 list"),
        ("folders", fx == fn, f"{fx}/{fn} folders present"),
        ("pullback", rep["pullback_rc"] == 0 and rep["pullback_failed"] == 0,
         f"exit {rep['pullback_rc']}, {rep['pullback_failed']} FAILED"),
        ("contention", rep["contention"] == "yielded", f"the exclusive tag step {rep['contention']}"),
        ("catch-up", rep["deferred"] >= 1 and rep["caught_up"] == rep["deferred"] and not rep.get("catchup_error"),
         f"deferred {rep['deferred']}, caught up {rep['caught_up']}/{rep['deferred']}"
         + (f" ({rep['catchup_error']})" if rep.get("catchup_error") else "")),
        ("lock gate", *rep.get("lock_leg", (False, "lock gate leg did not run"))),
        ("concurrency pullbacks", c.get("exit0") == c.get("pullbacks") == c.get("restored"),
         f"{c.get('exit0')}/{c.get('pullbacks')} parallel pullbacks exit 0, {c.get('restored')} file(s) SHA-256 ok"),
        ("intents", c.get("intents_written_removed") == c.get("pullbacks"),
         f"{c.get('intents_written_removed')}/{c.get('pullbacks')} intent files written and removed"),
        ("half-read", c.get("half_read") == 0 and not rep.get("trace_bad"),
         f"{c.get('half_read')} intent file(s) read half-written"),
        ("free answers", c.get("wrong_free") == 0 and c.get("checks_during_live", 0) > 0,
         f"{c.get('wrong_free')} wrong 'free' answer(s) of {c.get('checks')} checks "
         f"({c.get('checks_during_live')} made while a pullback was live)"),
        ("intent folder", not c.get("leftover"), "empty at the end" if not c.get("leftover")
         else f"left: {', '.join(c['leftover'][:5])}"),
        ("scratch", rep.get("scratch_removed", False), "scratch folder removed"),
        ("never delete", b1 >= b0, f"snapshots before {b0}, after {b1} (nothing deleted)"),
    ]


def pullback_drill(device: str, set_name: str, hashes: str | None = None, scratch: str | None = None,
                   parallel: int = PARALLEL, checks: int = CHECKS) -> int:
    """Exit 0 the drill passed, 1 it FAILED (including: it could not run). Never a skip."""
    started = time.time()
    interrupted: BaseException | None = None
    old = None
    if threading.current_thread() is threading.main_thread():   # a systemd stop (SIGTERM) also records FAILED
        def _term(signum, frame):
            raise SystemExit(128 + signum)
        old = signal.signal(signal.SIGTERM, _term)
    try:
        rep = _drill(device, set_name, hashes, scratch, parallel, checks)
        verdict = _verdict(rep)
        failed_steps = [v for v in verdict if not v[1]]
        for name, ok, d in verdict:
            print(f"  {'OK    ' if ok else 'FAILED'} {name}: {d}")
        x, n = rep["restored"]
        summary = (f"drill: {x}/{n} restored, contention: "
                   + ("yielded+caught up" if rep["contention"] == "yielded" and rep["caught_up"] == rep["deferred"] >= 1
                      else rep["contention"])
                   + f", {rep['pullback_failed']} FAILED; deferred {rep['deferred']}, caught up "
                   f"{rep['caught_up']}/{rep['deferred']}; "
                   + rep.get("lock_leg", (False, "lock gate leg did not run"))[1]
                   + f"; {len(verdict) - len(failed_steps)}/{len(verdict)} checks passed")
        ok = not failed_steps
    except BackupError as e:
        ok, summary, verdict = False, f"drill could not run: {e}", []
    except OSError as e:          # a scratch disk or state-dir failure is a FAILED drill, never a skip
        ok, summary, verdict = False, f"drill could not run: {type(e).__name__}: {e}", []
    except BaseException as e:  # noqa: BLE001 - review F2: ANY crash, hang-kill (SIGTERM) or Ctrl-C is a FAILED drill:
        # recorded and alerted below, then SystemExit / KeyboardInterrupt are raised again
        ok, summary, verdict = False, f"drill crashed: {type(e).__name__}: {e}", []
        if isinstance(e, (SystemExit, KeyboardInterrupt)):
            interrupted = e
    print(NOT_COVERED)
    line = f"pullback-drill {device}/{set_name}: {'PASSED' if ok else 'FAILED'}: {summary}"
    print(line)
    rec = {"ok": ok, "at": precedence.iso(time.time()), "device": device, "set": set_name, "summary": summary,
           "seconds": round(time.time() - started), "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in verdict]}
    try:
        result_path().parent.mkdir(parents=True, exist_ok=True)
        config.atomic_write_text(result_path(), json.dumps(rec, sort_keys=True))
    except OSError as e:
        print(f"pullback-drill: WARNING result not saved to {result_path()}: {e}", file=sys.stderr)
        ok = False
    precedence.log("pullback_drill.result", device, hub_audit=True, ok=ok, summary=summary)
    if ok:
        alerts.resolve(KEY)
    else:
        sent, detail = alerts.fire(KEY, f"HavnVard {line}")
        print(f"alert: {detail}" if sent else f"ALERT NOT SENT: {detail} (health-relay raises it from the result)")
    if old is not None:
        signal.signal(signal.SIGTERM, old)
    if interrupted is not None:
        raise interrupted
    return 0 if ok else config.PROBLEM_EXIT


def render_units(out_dir: Path, device: str, set_name: str) -> list[Path]:
    """The weekly timer (Sunday 03:30). Rendered only: the hub owner enables it after seeing a drill report."""
    from .render import render_task
    from .util import systemd_arg
    cmd = f"pullback-drill --from {systemd_arg(device)} --set {systemd_arg(set_name)}"
    return render_task(out_dir, "havnvard-pullback-drill", f"HavnVard pullback drill ({device}/{set_name})", cmd,
                       "OnCalendar=Sun *-*-* 03:30:00\nRandomizedDelaySec=5m", success_exit="0", timeout="2h")
