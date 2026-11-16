"""Pullback precedence (HavnVard 3.3.13, INFRA-644; spec runbooks/20261116-havnvard-pullback-precedence, v1.0).

A pullback is a person getting lost files back. It must never fail because a housekeeping job held the backup open.

3.1 Announce   A pullback writes one INTENT file per repository it reads: state/intent/<repo>/<host>-<pid>.json, atomic
               (temp + fsync + rename), heartbeat every 30 s, removed on any exit (finally + SIGTERM/SIGINT).
               Stale = pid gone on this host, heartbeat older than 5 min, or another boot id. An unreadable file is live
               for 5 min (it may be mid-write on another filesystem), then stale. Stale files are removed (logged) by the
               next job that sees them, so a crash or power loss blocks nothing for more than 5 min.
3.2 Yield      Every HavnVard step that takes an EXCLUSIVE restic lock checks for a live intent right before the step.
               The catalog's name tag defers (state/deferred.jsonl) and the next run catches up; prune / forget / key
               removal refuse to start ("nothing was changed"). A deferral not caught up in time is OVERDUE (health
               PROBLEM, alert `havnvard-yield-overdue`).
3.3 Get past   A pullback that meets an exclusive lock names the holder (restic's lock text + the job's own record in
               state/jobs/), retries up to 2 min for the catalog's 1-s tag, runs `restic unlock` for a STALE lock (stale
               locks only: never --remove-all, never data), and waits up to 10 min for a prune or an unknown holder
               (a line every minute, one hub notice after 2 min), then gives up: those files are FAILED, exit 1.
               It never removes a live lock.
3.5 Log        Every intent start/end, lock met, stale unlock, deferral and catch-up goes to stdout/stderr (the journal)
               and to state/precedence-log.jsonl; deferrals, stale unlocks and stale intents also get a hub audit row.

Standard library only. Paths are HavnVard's own state files; nothing here touches a backed-up file or a snapshot.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import getpass
import json
import os
import re
import signal
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path

from . import config
from .config import BackupError

HEARTBEAT_S = 30
STALE_S = 5 * 60                 # an intent whose heartbeat is older than this is stale
UNREADABLE_LIVE_S = 5 * 60       # an unreadable intent file counts as live this long (by its file time)
RESTIC_STALE_S = 30 * 60         # restic's own stale age for a lock it did not refresh
CATALOG_WAIT_S = 2 * 60          # the catalog's name tag holds the lock ~1 s; it yields after its current step
OTHER_WAIT_S = 10 * 60           # a prune or a lock HavnVard does not know
NOTICE_AFTER_S = 2 * 60          # then one notice on the hub page
LINE_EVERY_S = 60                # a visible line while waiting
POLL_S = 5.0                     # how often the pullback asks restic again
OVERDUE_AFTER_RUN_S = 15 * 60    # after the first catalog run that started after the pullback ended has finished
OVERDUE_NO_RUN_S = 75 * 60       # no catalog run started (or none finished) this long after the pullback ended
OVERDUE_LIVE_S = 3 * 60 * 60     # AC7 (review F4): deferred this long while the pullback is STILL live = overdue
DONE_KEEP_DAYS = 30              # done deferral lines older than this are trimmed
RUNS_KEEP = 500                  # catalog run history kept for the overdue rule
TRACE_ENV = "HAVNVARD_INTENT_TRACE"   # the drill's concurrency case: every intent write/remove appended here

JOB_WORDS = {"catalog": "hub catalog's name tag", "prune": "backup delete", "forget": "backup delete",
             "key-remove": "key removal", "pullback-drill": "pullback drill's tag step"}


# ---------- small helpers ----------

def _now() -> float:
    return time.time()


def iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


def hhmm(t: float) -> str:
    return dt.datetime.fromtimestamp(t).astimezone().strftime("%Y-%m-%d %H:%M")


def host() -> str:
    return socket.gethostname()


def user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return str(os.getuid())


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                      # exists, belongs to someone else
    except (OSError, ValueError, OverflowError):
        return False
    return True


def _stat_fields(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text()
    except (OSError, ValueError):
        return []
    return raw[raw.rfind(")") + 2:].split()     # fields after "pid (comm)": state, ppid, ...


def proc_start(pid: int) -> str:
    f = _stat_fields(pid)
    return f[19] if len(f) > 19 else ""          # field 22 of /proc/PID/stat: start time in clock ticks


def parent_pid(pid: int) -> int | None:
    f = _stat_fields(pid)
    try:
        return int(f[1]) if len(f) > 1 else None
    except ValueError:
        return None


def span(seconds: float) -> str:
    """'2 min', '10 min', '45 s'."""
    return f"{seconds / 60:.0f} min" if seconds >= 60 else f"{seconds:.0f} s"


def safe_name(repo: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(repo)) or "_"


def repo_label(env: dict, fallback: str | None = None) -> str:
    """The name intents and job records use for a repository: the device name (= hub repository folder name)."""
    if fallback:
        return fallback
    r = str(env.get("RESTIC_REPOSITORY", "")).rstrip("/")
    return r.rsplit("/", 1)[-1] or "repository"


def _remove_own(path: Path) -> bool:
    """Remove one of HavnVard's OWN state files (an intent or job record). Never a backed-up file."""
    try:
        os.unlink(path)  # HavnVard's own intent/job state file (allowlisted in test_crosshost_verify)
        return True
    except FileNotFoundError:
        return False


def _append_jsonl(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with config.file_lock(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())


def log_path() -> Path:
    return config.state_dir() / "precedence-log.jsonl"


def log(action: str, target: str, hub_audit: bool = False, **detail) -> None:
    """One log line (journal via stderr + state/precedence-log.jsonl); with hub_audit also a hub audit row
    (accounts.db on the hub only: never created on a device). A failure to log is printed, never hidden."""
    rec = {"at": iso(_now()), "action": action, "target": target, "host": host(), "pid": os.getpid(), **detail}
    print(f"havnvard {action} {target}: " + ", ".join(f"{k}={v}" for k, v in detail.items()), file=sys.stderr)
    try:
        _append_jsonl(log_path(), rec)
    except OSError as e:
        print(f"havnvard: WARNING could not write {log_path()}: {e}", file=sys.stderr)
    if hub_audit:
        hub_audit_row(action, target, **detail)


def hub_audit_row(action: str, target: str, **detail) -> bool:
    """A row in the hub's append-only audit log, when this machine is a hub that has one."""
    try:
        from .accounts import Accounts, default_path
        if not config.load().get("hub_local") or not default_path().is_file():
            return False
        Accounts().log_event(action, target, **detail)
        return True
    except (BackupError, OSError, ValueError, sqlite3.Error) as e:   # printed with its type; the job goes on
        print(f"havnvard: WARNING hub audit row {action} not written: {type(e).__name__}: {e}", file=sys.stderr)
        return False


def _trace(event: str, rec: dict, path: Path) -> None:
    t = os.environ.get(TRACE_ENV)
    if not t:
        return
    try:
        _append_jsonl(Path(t), {"event": event, "t": _now(), "pid": os.getpid(), "id": rec.get("id"),
                                "path": str(path)})
    except OSError as e:
        print(f"havnvard: WARNING intent trace not written: {e}", file=sys.stderr)


# ---------- 3.1 intent files ----------

def intent_dir(repo: str | None = None) -> Path:
    d = config.state_dir() / "intent"
    return d / safe_name(repo) if repo else d


class Intent:
    """One pullback's announcement on one repository. start() before the first restic call, close() on any exit."""

    def __init__(self, repo: str, what: str):
        self.repo = repo
        self.path = intent_dir(repo) / f"{safe_name(host())}-{os.getpid()}.json"
        t = _now()
        self.rec = {"id": f"{host()}-{os.getpid()}-{t:.3f}", "pid": os.getpid(), "host": host(), "user": user(),
                    "started_at": t, "heartbeat_at": t, "what": what, "boot_id": boot_id(),
                    "proc_start": proc_start(os.getpid()), "repo": repo}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.closed = False

    @property
    def id(self) -> str:
        return self.rec["id"]

    def _write(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.rec["heartbeat_at"] = _now()
            config.atomic_write_text(self.path, json.dumps(self.rec, sort_keys=True))

    def _beat(self) -> None:
        while not self._stop.wait(HEARTBEAT_S):
            try:
                self._write()
            except OSError as e:     # loud: a pullback whose heartbeat stops looks stale to others after 5 min
                print(f"havnvard pullback: WARNING heartbeat not written to {self.path}: {e}", file=sys.stderr)

    def start(self) -> "Intent":
        d = self.path.parent
        d.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(d, 0o700)
        self._write()
        _trace("write", self.rec, self.path)
        log("intent.start", self.repo, user=self.rec["user"], what=self.rec["what"], file=str(self.path))
        self._thread = threading.Thread(target=self._beat, name="havnvard-intent-heartbeat", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self.closed:
            return
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=10)
        with self._lock:
            self.closed = True
            removed = _remove_own(self.path)
        _trace("remove", self.rec, self.path)
        end = _now()
        note_pullback_end(self.id, end)
        log("intent.end", self.repo, user=self.rec["user"], removed=removed, seconds=round(end - self.rec["started_at"]))


@contextlib.contextmanager
def announce(repo: str, what: str, on_start=None):
    """Intent for the duration of the block. SIGTERM ends the block like Ctrl-C does, so `finally` removes the file."""
    it = Intent(repo, what)
    old = None
    if threading.current_thread() is threading.main_thread():
        def _term(signum, frame):
            raise SystemExit(128 + signum)
        old = signal.signal(signal.SIGTERM, _term)
    try:
        it.start()
        if on_start is not None:
            on_start(it)
        yield it
    finally:
        try:
            it.close()
        finally:
            if old is not None:
                signal.signal(signal.SIGTERM, old)


def stale_reason(rec: dict, now: float | None = None) -> str | None:
    now = _now() if now is None else now
    try:
        hb, pid = float(rec["heartbeat_at"]), int(rec["pid"])
    except (KeyError, TypeError, ValueError):
        return "unparsable"
    if now - hb > STALE_S:
        return f"heartbeat {now - hb:.0f} s old (limit {STALE_S} s)"
    if rec.get("host") == host():
        b = boot_id()
        if rec.get("boot_id") and b and rec["boot_id"] != b:
            return "the computer restarted since"
        if not pid_alive(pid):
            return f"process {pid} is gone"
        if rec.get("proc_start") and proc_start(pid) and proc_start(pid) != rec["proc_start"]:
            return f"process {pid} is gone (its number was reused)"
    return None


def read_intents(repo: str, now: float | None = None, remove_stale: bool = True,
                 seen_by: str = "") -> tuple[list[dict], int]:
    """(live intents on REPO, how many of them are unreadable-but-young). Stale ones are removed and logged
    (remove_stale), or just skipped (health reads without changing anything)."""
    now = _now() if now is None else now
    d = intent_dir(repo)
    if not d.is_dir():
        return [], 0
    live, unreadable = [], 0
    for p in sorted(d.glob("*.json")):
        try:
            mtime = p.stat().st_mtime
            rec = json.loads(p.read_text())
            if not isinstance(rec, dict):
                raise ValueError("not an object")
        except FileNotFoundError:
            continue                                     # removed between listing and reading: that pullback ended
        except (OSError, ValueError) as e:
            if now - mtime < UNREADABLE_LIVE_S:
                unreadable += 1
                live.append({"path": str(p), "unreadable": True, "user": "?", "host": "?", "pid": 0,
                             "started_at": mtime, "heartbeat_at": mtime, "what": f"unreadable intent file ({e})"})
            elif remove_stale and _remove_own(p):
                log("intent.stale_removed", repo, hub_audit=True, file=str(p), why=f"unreadable for over "
                    f"{UNREADABLE_LIVE_S} s", seen_by=seen_by)
            continue
        why = stale_reason(rec, now)
        if why is None:
            live.append({**rec, "path": str(p)})
        elif remove_stale and _remove_own(p):
            note_pullback_end(rec.get("id", ""), float(rec.get("heartbeat_at") or mtime))
            log("intent.stale_removed", repo, hub_audit=True, file=str(p), why=why, user=rec.get("user"),
                pid=rec.get("pid"), seen_by=seen_by)
    return live, unreadable


def describe_intent(i: dict) -> str:
    if i.get("unreadable"):
        return f"a pullback (intent file {Path(i['path']).name} is being written)"
    return f"a pullback for {i.get('user')} (pid {i.get('pid')} on {i.get('host')}) running since {hhmm(i['started_at'])}"


class PullbackLive(BackupError):
    """An exclusive-lock job refused to start: a pullback is reading this repository."""


def refuse_if_pullback(repo: str, job: str, changed: str = "") -> None:
    """3.2: prune / forget / key removal never start while a pullback is live. `changed` says what an earlier,
    additive step of the same command already did (default: nothing was changed)."""
    live, _ = read_intents(repo, seen_by=job)
    if live:
        i = live[0]
        log("yield.refused", repo, job=job, pullback=i.get("id", i.get("path")), user=i.get("user"))
        raise PullbackLive(f"{describe_intent(i)} on {repo}; {changed or 'nothing was changed'}; run the "
                           f"{JOB_WORDS.get(job, job)} again when it ends")


# ---------- job records (who holds an exclusive lock, for the pullback's WAITING line) ----------

def jobs_dir(repo: str) -> Path:
    return config.state_dir() / "jobs" / safe_name(repo)


@contextlib.contextmanager
def job_record(repo: str, job: str, what: str):
    """Record which HavnVard job is about to take an exclusive lock on REPO (a pullback names it to the person)."""
    p = jobs_dir(repo) / f"{safe_name(host())}-{os.getpid()}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    config.atomic_write_text(p, json.dumps({"job": job, "user": user(), "host": host(), "pid": os.getpid(),
                                            "started_at": _now(), "what": what}))
    try:
        yield
    finally:
        _remove_own(p)


def find_job(repo: str, lock_pid: int) -> dict | None:
    """The live HavnVard job record whose process is the restic lock holder or its parent."""
    d = jobs_dir(repo)
    if not d.is_dir():
        return None
    cands = {int(lock_pid)}
    pp = parent_pid(lock_pid)
    if pp:
        cands.add(pp)
    for p in sorted(d.glob("*.json")):
        try:
            rec = json.loads(p.read_text())
            pid = int(rec["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if rec.get("host") == host() and pid in cands and pid_alive(pid):
            return rec
    return None


# ---------- 3.2 deferrals ----------

def deferred_path() -> Path:
    return config.state_dir() / "deferred.jsonl"


def _read_deferred() -> list[dict]:
    p = deferred_path()
    if not p.is_file():
        return []
    out = []
    for ln in p.read_text().splitlines():
        try:
            o = json.loads(ln)
        except ValueError:
            print(f"havnvard: WARNING unreadable line in {p} kept as it is: {ln[:120]!r}", file=sys.stderr)
            o = {"_raw": ln}
        out.append(o)
    return out


def _write_deferred(lines: list[dict]) -> None:
    text = "".join((o["_raw"] if "_raw" in o else json.dumps(o, sort_keys=True)) + "\n" for o in lines)
    config.atomic_write_text(deferred_path(), text)


def _trim(lines: list[dict], now: float) -> list[dict]:
    keep = DONE_KEEP_DAYS * 86400
    return [o for o in lines if not (o.get("done_at") and now - float(o["done_at"]) > keep)]


def defer(job: str, repo: str, snapshot: str, tag: str, intent: dict, now: float | None = None) -> dict:
    """Record that JOB did not take its exclusive step on REPO now. One open line per (job, repo, tag)."""
    now = _now() if now is None else now
    p = deferred_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    reason = describe_intent(intent)
    fields = {"pullback": intent.get("id", intent.get("path")), "pullback_user": intent.get("user"),
              "pullback_started_at": intent.get("started_at"), "pullback_heartbeat_at": intent.get("heartbeat_at"),
              "pullback_ended_at": None, "reason": reason}
    with config.file_lock(p):
        lines = _read_deferred()
        line = next((o for o in lines if not o.get("done_at") and o.get("job") == job and o.get("repo") == repo
                     and o.get("tag") == tag), None)
        if line is None:
            line = {"job": job, "repo": repo, "snapshot": snapshot, "tag": tag, "deferred_at": now, "done_at": None}
            lines.append(line)
        line.update(fields)
        _write_deferred(_trim(lines, now))
    log("yield.deferred", repo, hub_audit=True, job=job, snapshot=snapshot[:8], tag=tag, reason=reason)
    return dict(line)


def open_deferrals(job: str | None = None, repo: str | None = None) -> list[dict]:
    return [o for o in _read_deferred() if "_raw" not in o and not o.get("done_at")
            and (job is None or o.get("job") == job) and (repo is None or o.get("repo") == repo)]


def mark_done(pred, note: str, now: float | None = None) -> list[dict]:
    """Set done_at on every open line pred(line) accepts; trim done lines older than 30 days. Returns those lines."""
    now = _now() if now is None else now
    p = deferred_path()
    if not p.is_file():
        return []
    done = []
    with config.file_lock(p):
        lines = _read_deferred()
        for o in lines:
            if "_raw" not in o and not o.get("done_at") and pred(o):
                o["done_at"], o["done_note"] = now, note
                done.append(dict(o))
        _write_deferred(_trim(lines, now))
    for o in done:
        print(f"{o['job']}: caught up {o['tag']} on {o['repo']} (deferred at {hhmm(o['deferred_at'])}, done now)")
        log("yield.caught_up", o["repo"], job=o["job"], tag=o["tag"], deferred_at=iso(o["deferred_at"]), note=note)
    return done


def note_pullback_end(intent_id: str, ended_at: float) -> None:
    p = deferred_path()
    if not intent_id or not p.is_file():
        return
    try:
        with config.file_lock(p):
            lines = _read_deferred()
            hit = False
            for o in lines:
                if "_raw" not in o and not o.get("done_at") and o.get("pullback") == intent_id \
                        and not o.get("pullback_ended_at"):
                    o["pullback_ended_at"] = ended_at
                    hit = True
            if hit:
                _write_deferred(lines)
    except OSError as e:
        print(f"havnvard: WARNING could not record the pullback's end in {p}: {e}", file=sys.stderr)


# ---------- catalog run history (the overdue rule follows the real catalog run) ----------

def runs_path() -> Path:
    return config.state_dir() / "catalog-runs.json"


def catalog_runs() -> list[dict]:
    p = runs_path()
    try:
        runs = json.loads(p.read_text()) if p.is_file() else []
    except (OSError, ValueError) as e:
        raise BackupError(f"cannot read {p}: {e}") from e
    return runs if isinstance(runs, list) else []


def _save_run(update) -> None:
    p = runs_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with config.file_lock(p):
        try:
            runs = catalog_runs()
        except BackupError as e:      # a damaged history must not stop the catalog: start a new one, loudly
            print(f"havnvard: WARNING {e}; starting a new catalog run history", file=sys.stderr)
            runs = []
        update(runs)
        config.atomic_write_text(p, json.dumps(runs[-RUNS_KEEP:]))


def record_catalog_start(t: float | None = None) -> float:
    t = _now() if t is None else t
    _save_run(lambda runs: runs.append({"started_at": t, "finished_at": None}))
    return t


def record_catalog_finish(started: float, t: float | None = None, failed: bool = False) -> None:
    t = _now() if t is None else t

    def upd(runs):
        for r in runs:
            if r.get("started_at") == started:
                r["finished_at"] = t
                if failed:
                    r["failed"] = True
    _save_run(upd)


def overdue(now: float | None = None) -> tuple[list[tuple[dict, str]], int]:
    """([(open deferral, why it is overdue)], number of open deferrals). Spec 3.2: overdue when the first catalog run
    that started after the pullback ended finished more than 15 min ago without catching it up, or when no catalog
    run started (or the one that started has not finished) within 75 min of the pullback's end. Read-only."""
    now = _now() if now is None else now
    # review F3: the drill's own deferrals are judged by the drill (alert havnvard-pullback-drill), not here: the catalog
    # run this alert tells the owner to start cannot catch them up.
    opened = [o for o in open_deferrals() if o.get("job") != "pullback-drill"]
    runs = catalog_runs()
    out = []
    for o in opened:
        end = o.get("pullback_ended_at")
        if not end:
            live, _ = read_intents(o["repo"], remove_stale=False)     # alive NOW, whatever `now` is asked about
            mine = [i for i in live if i.get("id") == o.get("pullback")]
            if mine:
                # review F4 / AC7: a pullback that hangs keeps its heartbeat, so it never goes stale; after 3 h of
                # deferred name tags that is a problem the owner must see.
                if now - float(o["deferred_at"]) > OVERDUE_LIVE_S:
                    i = mine[0]
                    out.append((o, f"pullback for {i.get('user')} (pid {i.get('pid')}) running since "
                                   f"{hhmm(float(i['started_at']))}, {o['job']} step {o['tag']} on {o['repo']} deferred "
                                   f"for over {OVERDUE_LIVE_S // 3600} h; check intent/ for a stuck pullback"))
                continue                                  # still running and not yet 3 h: nothing is late yet
            end = float(o.get("pullback_heartbeat_at") or o["deferred_at"])
        after = sorted((r for r in runs if float(r.get("started_at") or 0) > float(end)),
                       key=lambda r: r["started_at"])
        what = f"{o['job']} step {o['tag']} on {o['repo']} deferred at {hhmm(o['deferred_at'])}"
        if not after:
            if now > end + OVERDUE_NO_RUN_S:
                out.append((o, f"{what}: no catalog run has started since the pullback ended at {hhmm(end)} "
                               f"(limit {OVERDUE_NO_RUN_S // 60} min)"))
            continue
        first = after[0]
        if first.get("failed"):
            if now > float(first["finished_at"]) + OVERDUE_AFTER_RUN_S:
                out.append((o, f"{what}: the catalog run started {hhmm(first['started_at'])} FAILED at "
                               f"{hhmm(first['finished_at'])} without catching it up"))
        elif first.get("finished_at"):
            if now > float(first["finished_at"]) + OVERDUE_AFTER_RUN_S:
                out.append((o, f"{what}: the catalog run started {hhmm(first['started_at'])} finished "
                               f"{hhmm(first['finished_at'])} without catching it up"))
        elif now > float(first["started_at"]) + OVERDUE_NO_RUN_S:
            out.append((o, f"{what}: the catalog run started {hhmm(first['started_at'])} has not finished"))
    return out, len(opened)


# ---------- 3.3 the pullback gets past an exclusive lock ----------

class Locked(BackupError):
    """restic refused to start because another process holds a conflicting lock (restic exit 11)."""

    def __init__(self, stderr: str):
        self.stderr = plain(stderr)
        super().__init__(self.stderr.strip()[-400:])


LOCK_RE = re.compile(
    r"repository is already locked (?P<excl>exclusively )?by PID (?P<pid>\d+) on (?P<host>\S+) by (?P<user>.+?) "
    r"\(UID (?P<uid>\d+), GID \d+\)"
    r"(?:\s*lock was created at (?P<created>[^(\n]+?) \((?P<age>[^)\n]*) ago\))?"
    r"(?:\s*storage ID (?P<sid>[0-9a-f]+))?")
_DUR_RE = re.compile(r"([0-9.]+)(h|ms|us|µs|ns|m|s)")
_DUR_S = {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


def plain(stderr: str) -> str:
    """restic's error text; with --json restic prints it as {"message_type":"exit_error","message":...}."""
    out = []
    for ln in (stderr or "").splitlines():
        if ln.lstrip().startswith("{"):
            try:
                o = json.loads(ln)
                if isinstance(o, dict) and isinstance(o.get("message"), str):
                    out.append(o["message"])
                    continue
            except ValueError:
                pass
        out.append(ln)
    return "\n".join(out)


def lock_conflict(stderr: str) -> bool:
    """A lock held by someone else (not, for example, a read-only lock folder: that is a plain failure)."""
    return "already locked" in (stderr or "")


def _go_duration(s: str | None) -> float | None:
    if not s:
        return None
    parts = _DUR_RE.findall(s)
    return sum(float(n) * _DUR_S[u] for n, u in parts) if parts else None


def parse_lock(stderr: str) -> dict | None:
    m = LOCK_RE.search(plain(stderr))
    if not m:
        return None
    return {"pid": int(m["pid"]), "host": m["host"], "user": m["user"], "exclusive": bool(m["excl"]),
            "created": (m["created"] or "").strip(), "age_s": _go_duration(m["age"]), "sid": m["sid"] or ""}


class LockGate:
    """Runs one pullback's restic calls; a lock refusal is waited out, unlocked (stale only) or given up on (3.3)."""

    def __init__(self, restic: str, env: dict, repo: str, notice=None, out=print, sleep=time.sleep):
        self.restic, self.env, self.repo = restic, env, repo
        self.notice, self.out, self.sleep = notice, out, sleep
        self.gave_up: dict | None = None
        self.waits: list[dict] = []
        self.unlocks = 0

    def classify(self, lk: dict | None) -> tuple[str, str]:
        if lk is None:
            return "foreign", "a restic lock whose holder restic did not name"
        mine = lk["host"] == host()
        if mine and not pid_alive(lk["pid"]):
            return "stale", f"a lock left by process {lk['pid']} of user {lk['user']} on {lk['host']}, which is gone"
        if mine:
            rec = find_job(self.repo, lk["pid"])
            if rec:
                word = JOB_WORDS.get(rec.get("job"), rec.get("job"))
                desc = f"the {word} {rec.get('user')} started at {hhmm(float(rec['started_at']))} on {rec.get('host')}"
                return ("catalog" if rec.get("job") in ("catalog", "pullback-drill") else "job"), desc
        if lk.get("age_s") is not None and lk["age_s"] > RESTIC_STALE_S:
            return "stale", (f"a lock of process {lk['pid']} of user {lk['user']} on {lk['host']} not refreshed for "
                             f"{lk['age_s'] / 60:.0f} min")
        since = f" since {lk['created']}" if lk.get("created") else ""
        return "foreign", f"a restic lock held by process {lk['pid']} of user {lk['user']} on {lk['host']}{since}"

    def _unlock(self, desc: str, lk: dict | None) -> None:
        from .util import run
        r = run([self.restic, "unlock"], env=self.env, timeout=300)     # stale locks only; never --remove-all
        self.unlocks += 1
        ok = r.returncode == 0
        self.out(f"pullback: STALE LOCK on {self.repo}: {desc}; ran `restic unlock` (removes stale locks only, never "
                 f"data){'' if ok else f' -- it failed rc={r.returncode}: {r.stderr.strip()[-200:]}'}")
        log("pullback.stale_unlock", self.repo, hub_audit=True, holder=desc, rc=r.returncode,
            lock_pid=(lk or {}).get("pid"), lock_host=(lk or {}).get("host"))

    def _can_do(self, kind: str) -> str:
        if kind == "job":
            return ("it will go on by itself; to stop that job now, ask the hub owner; or press Ctrl-C and run the "
                    "same pullback again later: files already back are left alone")
        return ("it will go on by itself; if it does not, ask the hub owner who holds it; or press Ctrl-C and run "
                "the same pullback again later: files already back are left alone")

    def run(self, fn, files: list[str] | None = None, whole: bool = True):
        """fn() runs one restic call and raises Locked on a lock refusal. Returns fn()'s result, or raises
        BackupError (GAVE UP) naming the holder. A live lock is never removed."""
        t0 = last_line = None
        noticed = False
        desc = ""
        stale_tries = 0
        while True:
            try:
                res = fn()
            except Locked as e:
                lk = parse_lock(e.stderr)
                kind, desc = self.classify(lk)
                if self.gave_up and (lk is None or lk.get("sid") == self.gave_up.get("sid")):
                    raise BackupError(f"not tried: still locked by {desc} (gave up on it earlier in this pullback); "
                                      "no lock was removed") from e
                if kind == "stale" and stale_tries < 3:
                    stale_tries += 1
                    self._unlock(desc, lk)
                    continue
                if kind == "stale":
                    kind = "foreign"                     # restic kept it: it is not stale to restic, so wait
                now = _now()
                limit = CATALOG_WAIT_S if kind == "catalog" else OTHER_WAIT_S
                if t0 is None:
                    t0 = last_line = now
                    self._first_lines(desc, limit, files or [], whole, kind)
                waited = now - t0
                if waited >= limit:
                    self.out(f"pullback: GAVE UP after {waited:.0f}s waiting for {desc} (lock on {self.repo}); "
                             "no lock was removed")
                    self.gave_up = {"sid": (lk or {}).get("sid", ""), "desc": desc}
                    self.waits.append({"holder": desc, "seconds": round(waited), "outcome": "gave up"})
                    log("pullback.lock_gave_up", self.repo, holder=desc, seconds=round(waited), files=len(files or []))
                    said = next((ln.strip() for ln in e.stderr.splitlines() if "already locked" in ln), "")
                    raise BackupError(f"GAVE UP after {waited:.0f}s waiting for {desc} (lock on {self.repo}); "
                                      f"no lock was removed; run the same pullback again later (restic: {said})") from e
                if kind != "catalog" and not noticed and waited >= NOTICE_AFTER_S:
                    noticed = True
                    self._leave_notice(desc, t0)
                if now - last_line >= LINE_EVERY_S:
                    last_line = now
                    self.out(f"pullback: still waiting for {desc} to finish, {span(waited)} of {span(limit)}; "
                             f"{self._can_do(kind)}")
                self.sleep(max(0.05, min(POLL_S, limit - waited)))
                continue
            if t0 is not None:
                waited = _now() - t0
                self.out(f"pullback: GOT THE LOCK after {waited:.0f}s")
                self.waits.append({"holder": desc, "seconds": round(waited), "outcome": "got the lock"})
                log("pullback.lock_got", self.repo, seconds=round(waited))
            return res

    def _first_lines(self, desc: str, limit: float, files: list[str], whole: bool, kind: str) -> None:
        self.out(f"STATUS: WAITING for {desc} (lock on {self.repo})")
        self.out(f"pullback: WAITING for {desc} (lock on {self.repo}); retrying for up to {span(limit)}")
        if files:
            eg = ", ".join(files[:2])
            self.out(f"pullback: {len(files)} file(s) (e.g. {eg}) wait for this lock; "
                     + ("your whole pullback waits" if whole else "the rest of your pullback goes on"))
        else:
            self.out("pullback: your whole pullback waits")
        if kind != "catalog":
            self.out(f"pullback: {self._can_do(kind)}")
        log("pullback.lock_met", self.repo, holder=desc, limit_s=int(limit), files=len(files))

    def _leave_notice(self, desc: str, since: float) -> None:
        text = (f"{user()}'s pullback is waiting for {desc} (lock on {self.repo}) since {hhmm(since)}. "
                "It goes on by itself when the lock is released, and gives up after "
                f"{OTHER_WAIT_S // 60} min.")
        try:
            sent = (self.notice or leave_notice_for(self.repo))("pullback_waiting", text)
        except (BackupError, OSError, ValueError, RuntimeError, sqlite3.Error) as e:   # printed; the wait goes on
            sent = f"NOT left: {type(e).__name__}: {e}"
        self.out(f"pullback: notice for the hub owner: {sent}")
        log("pullback.wait_notice", self.repo, holder=desc, result=str(sent))


def leave_notice_for(repo: str):
    """Review F5: where a waiting notice can really reach the hub owner. On a hub that has a hub page (accounts.db),
    straight onto that page under the device's name; on an enrolled device, through the check-in queue
    (checkin.report_notice). A hub with no hub page cannot show it and says so, instead of queueing it for a check-in
    that never comes."""
    hub = config.load().get("hub_local")
    if hub:
        def on_hub(kind: str, text: str) -> str:
            from .accounts import Accounts, default_path
            if not default_path().is_file():
                return "NOT left: this hub has no hub page (no accounts.db); the lines above are the only record"
            try:
                nid = Accounts().add_notice(repo, kind, text)
            except (BackupError, sqlite3.Error, OSError) as e:
                return f"NOT left on the hub page: {type(e).__name__}: {e}"
            return f"left on the hub page (notice {nid}, computer {repo})"
        return on_hub
    from .checkin import report_notice
    return report_notice
