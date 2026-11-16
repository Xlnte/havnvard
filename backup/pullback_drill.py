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

import datetime as dt
import json
import os
import re
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
    catalog._set_mtime(env, m["id"], 0)           # never makes the device look fresh (health reads file times)
    return m


EPOCH = "1970-01-01T00:00:00Z"


def tag_marker(restic: str, env: dict, repo: str, tag: str) -> bool:
    """The catalog-style exclusive step on the marker: tagged now (True) or deferred for a live pullback (False)."""
    m = _marker(restic, env)
    if not m:
        raise BackupError("the drill marker snapshot is gone")
    return catalog.tag_or_defer(restic, env, repo, m["id"], tag, EPOCH, job="pullback-drill")


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
    before = len(catalog.snapshots(restic, env))
    had_marker = _marker(restic, env) is not None
    ensure_marker(restic, env)
    folder = _folder_of([p for _, p in tset])
    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    tag = f"havnvard-drill-{stamp}"
    rep: dict = {"device": device, "set": set_name, "folder": folder, "tag": tag}
    with tempfile.TemporaryDirectory(prefix="havnvard-pullback-drill-", dir=scratch) as td:
        tdp = Path(td)
        (tdp / "main").mkdir()
        _main_case(device, folder, tset, tdp / "main", restic, env, tag, rep)
        from .archive import plan
        jobs = plan(restic, env, None, [folder], None, None, False)
        if not jobs:
            raise BackupError(f"no backup of {device} holds {folder}")
        _concurrency_case(device, tset, jobs[0][0]["id"], tdp, rep, parallel, checks)
        rep["scratch"] = td
    rep["scratch_removed"] = not Path(rep["scratch"]).exists()
    deferred = [o for o in precedence.open_deferrals(job="pullback-drill", repo=device) if o.get("tag") == tag]
    caught = catch_up(restic, env, device)
    mine = [o for o in caught if o.get("tag") == tag]
    m = _marker(restic, env)
    rep["deferred"] = len(deferred)
    rep["caught_up"] = sum(1 for _ in mine) if m and tag in (m.get("tags") or []) else 0
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
        ("catch-up", rep["deferred"] >= 1 and rep["caught_up"] == rep["deferred"],
         f"deferred {rep['deferred']}, caught up {rep['caught_up']}/{rep['deferred']}"),
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
                   f"{rep['caught_up']}/{rep['deferred']}; {len(verdict) - len(failed_steps)}/{len(verdict)} checks passed")
        ok = not failed_steps
    except BackupError as e:
        ok, summary, verdict = False, f"drill could not run: {e}", []
    except OSError as e:          # a scratch disk or state-dir failure is a FAILED drill, never a skip
        ok, summary, verdict = False, f"drill could not run: {type(e).__name__}: {e}", []
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
    return 0 if ok else config.PROBLEM_EXIT


def render_units(out_dir: Path, device: str, set_name: str) -> list[Path]:
    """The weekly timer (Sunday 03:30). Rendered only: the hub owner enables it after seeing a drill report."""
    from .render import render_task
    from .util import systemd_arg
    cmd = f"pullback-drill --from {systemd_arg(device)} --set {systemd_arg(set_name)}"
    return render_task(out_dir, "havnvard-pullback-drill", f"HavnVard pullback drill ({device}/{set_name})", cmd,
                       "OnCalendar=Sun *-*-* 03:30:00\nRandomizedDelaySec=5m", success_exit="0", timeout="2h")
