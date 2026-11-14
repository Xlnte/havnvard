"""HavnVard schedules (3.3.0, INFRA-576): one schedule per computer, kept on the hub.

Computers check in every few minutes and ask "am I due?" (`checkin`), so a change on the Schedules page takes effect at
the next check-in without logging in to the laptop. Modes:
* interval       - every N minutes, counted from the last run's START
* constant_loop  - the next run starts `min_gap_s` after the last one ENDS; run lengths are recorded (owner ruling 20261113).
                   After failures the gap doubles (2x, 4x ...) up to 60 min, so a broken run never loops hot.
* manual         - runs only when started by hand
* paused         - never due
A run the device could not report while the hub was unreachable is reported later (`report_late`), with its real times.
A check-in that could not reach the hub is NOT a backup run (F9): it is reported later as a missed check-in
(`report_missed_checkin`) and never moves the next backup, the back-off or the run statistics.
A run whose end is never reported (lid closed, hub blip) is marked failed with reason 'stale' after STALE bound (F5), so
scheduling never stops for good; a late end report for it still lands (`run_end`).
Same SQLite file as the accounts (the hub's state dir). Nothing here deletes anything.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import statistics
from pathlib import Path

from .config import BackupError

MODES = ("interval", "constant_loop", "manual", "paused")
BACKOFF_CAP = dt.timedelta(minutes=60)
CHECKIN_EVERY_S = 300
STALE_DEFAULT = dt.timedelta(hours=24)     # no run length recorded yet
STALE_MIN = dt.timedelta(hours=1)          # never sooner than this, however short the runs are
STALE_PREFIX = "stale:"
MISSED = "missed:"                          # checkin.reason prefix of a check-in that never reached the hub


class NotFound(BackupError):
    """No such run for this computer (the device API answers 404)."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS schedule (device TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK (mode IN ('interval','constant_loop','manual','paused')),
    every_min INTEGER, min_gap_s INTEGER NOT NULL DEFAULT 60, only_on_ac INTEGER NOT NULL DEFAULT 0,
    updated_by INTEGER, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run (id INTEGER PRIMARY KEY, device TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'backup',
    started_at TEXT NOT NULL, ended_at TEXT, duration_s REAL, exit_code INTEGER,
    status TEXT NOT NULL CHECK (status IN ('running','completed','failed','cancelled')),
    snapshot_id TEXT, error TEXT, reported_via TEXT NOT NULL DEFAULT 'checkin' CHECK (reported_via IN ('checkin','late')));
CREATE INDEX IF NOT EXISTS run_device_started ON run(device, started_at);
CREATE TABLE IF NOT EXISTS checkin (id INTEGER PRIMARY KEY, device TEXT NOT NULL, at TEXT NOT NULL, due INTEGER NOT NULL,
    reason TEXT, client_version TEXT);
CREATE INDEX IF NOT EXISTS checkin_device_at ON checkin(device, at);
"""


def _utc(t: dt.datetime | None) -> dt.datetime:
    t = t or dt.datetime.now(dt.timezone.utc)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return _utc(t).astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _parse(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


class Schedules:
    def __init__(self, path: str | os.PathLike | None = None):
        from .accounts import default_path
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        con = self._con()
        try:
            con.executescript(SCHEMA)
        finally:
            con.close()

    def _con(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        return con

    def _exec(self, sql: str, args=()) -> int:
        con = self._con()
        try:
            return con.execute(sql, args).lastrowid
        finally:
            con.close()

    def _rows(self, sql: str, args=()) -> list[dict]:
        con = self._con()
        try:
            return [dict(r) for r in con.execute(sql, args)]
        finally:
            con.close()

    # ---------- schedule ----------
    def set(self, actor: int | None, device: str, mode: str, every_min: int | None = None, min_gap_s: int = 60,
            only_on_ac: bool = False, now: dt.datetime | None = None) -> None:
        if mode not in MODES:
            raise BackupError(f"mode must be one of {', '.join(MODES)}")
        if mode == "interval" and (not every_min or every_min < 1):
            raise BackupError("interval mode needs every_min of 1 or more")
        if min_gap_s < 0:
            raise BackupError("min_gap_s cannot be negative")
        self._exec("INSERT INTO schedule(device, mode, every_min, min_gap_s, only_on_ac, updated_by, updated_at) "
                   "VALUES (?,?,?,?,?,?,?) ON CONFLICT(device) DO UPDATE SET mode=excluded.mode, "
                   "every_min=excluded.every_min, min_gap_s=excluded.min_gap_s, only_on_ac=excluded.only_on_ac, "
                   "updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                   (device, mode, every_min, min_gap_s, int(only_on_ac), actor, _iso(_utc(now))))

    def get(self, device: str) -> dict | None:
        r = self._rows("SELECT * FROM schedule WHERE device=?", (device,))
        return r[0] if r else None

    # ---------- runs ----------
    def run_start(self, device: str, kind: str = "backup", now: dt.datetime | None = None) -> int:
        return self._exec("INSERT INTO run(device, kind, started_at, status) VALUES (?,?,?, 'running')",
                          (device, kind, _iso(_utc(now))))

    def run_end(self, device: str, run_id: int, exit_code: int, snapshot_id: str | None = None,
                error: str | None = None, now: dt.datetime | None = None) -> None:
        """End THIS computer's open run (F4: a computer can never end or rewrite another computer's run). An open run
        is 'running', or one the hub marked failed as stale (its real end report, arriving late, still lands)."""
        r = self._rows("SELECT started_at FROM run WHERE id=? AND device=? AND (status='running' OR "
                       "(status='failed' AND exit_code IS NULL AND error LIKE ?))", (run_id, device, STALE_PREFIX + "%"))
        if not r:
            raise NotFound(f"no open run {run_id} for {device}")
        end = _utc(now)
        dur = (end - _parse(r[0]["started_at"])).total_seconds()
        # restic exit 3 = snapshot saved but some source files unreadable: the run completed (legacy SuccessExitStatus=3)
        status = "completed" if exit_code in (0, 3) else "failed"
        self._exec("UPDATE run SET ended_at=?, duration_s=?, exit_code=?, status=?, snapshot_id=?, error=? "
                   "WHERE id=? AND device=?",
                   (_iso(end), dur, exit_code, status, snapshot_id, (error or "")[:500] or None, run_id, device))

    def report_missed_checkin(self, device: str, at: dt.datetime, error: str | None = None) -> int:
        """F9: a check-in that could not reach the hub, reported later. Kept for the record; it is not a run."""
        return self._exec("INSERT INTO checkin(device, at, due, reason, client_version) VALUES (?,?,0,?,NULL)",
                          (device, _iso(_utc(at)), (MISSED + " " + (error or "hub unreachable"))[:300]))

    def stale_after(self, device: str) -> dt.timedelta:
        """How long a run may stay open: 2x the longest recorded run (at least STALE_MIN), or STALE_DEFAULT when no
        run length is recorded yet."""
        d = [r["duration_s"] for r in self._runs(device) if r["duration_s"] is not None]
        return max(2 * dt.timedelta(seconds=max(d)), STALE_MIN) if d else STALE_DEFAULT

    def expire_stale(self, device: str, now: dt.datetime | None = None) -> int:
        """F5: a run still 'running' past `stale_after` becomes failed with reason 'stale' (no length recorded, so the
        run statistics stay true). Returns how many were marked."""
        now = _utc(now)
        bound = self.stale_after(device)
        n = 0
        for r in self._rows("SELECT id, started_at FROM run WHERE device=? AND status='running'", (device,)):
            if now - _parse(r["started_at"]) > bound:
                n += 1
                self._exec("UPDATE run SET status='failed', ended_at=?, error=? WHERE id=? AND status='running'",
                           (_iso(now), f"{STALE_PREFIX} no end report within {bound}; marked failed by the hub so "
                                       "backups keep being scheduled", r["id"]))
        return n

    def report_late(self, device: str, started_at: dt.datetime, ended_at: dt.datetime, exit_code: int,
                    error: str | None = None, snapshot_id: str | None = None) -> int:
        s, e = _utc(started_at), _utc(ended_at)
        return self._exec("INSERT INTO run(device, started_at, ended_at, duration_s, exit_code, status, snapshot_id, "
                          "error, reported_via) VALUES (?,?,?,?,?,?,?,?, 'late')",
                          (device, _iso(s), _iso(e), (e - s).total_seconds(), exit_code,
                           "completed" if exit_code in (0, 3) else "failed", snapshot_id, (error or "")[:500] or None))

    def _runs(self, device: str) -> list[dict]:
        return self._rows("SELECT * FROM run WHERE device=? ORDER BY started_at, id", (device,))

    # ---------- due ----------
    def next_due(self, device: str, now: dt.datetime | None = None) -> dt.datetime | None:
        """When the next run is due; None = never (manual, paused, no schedule) or a run is still going (a run open
        longer than `stale_after` is marked failed first, F5)."""
        sch = self.get(device)
        if not sch or sch["mode"] in ("manual", "paused"):
            return None
        self.expire_stale(device, now)
        runs = self._runs(device)
        if any(r["status"] == "running" for r in runs):
            return None
        done = [r for r in runs if r["status"] != "running"]
        if not done:
            return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        last = done[-1]
        if sch["mode"] == "interval":
            return _parse(last["started_at"]) + dt.timedelta(minutes=sch["every_min"])
        fails = 0
        for r in reversed(done):
            if r["status"] != "failed":
                break
            fails += 1
        gap = dt.timedelta(seconds=sch["min_gap_s"] or 0)
        if fails:
            gap = min(max(gap, dt.timedelta(seconds=1)) * (2 ** fails), BACKOFF_CAP)
        return _parse(last["ended_at"] or last["started_at"]) + gap

    def checkin(self, device: str, client_version: str | None = None, now: dt.datetime | None = None) -> dict:
        now = _utc(now)
        sch = self.get(device)
        if not sch:
            due, reason = False, "no schedule set for this computer on the hub"
        elif sch["mode"] == "paused":
            due, reason = False, "paused"
        elif sch["mode"] == "manual":
            due, reason = False, "manual: runs only when started by hand"
        else:
            nd = self.next_due(device, now)
            if nd is None:
                due, reason = False, "a run is still going"
            elif nd <= now:
                due, reason = True, "due now"
            else:
                due, reason = False, f"next run at {_iso(nd)}"
        self._exec("INSERT INTO checkin(device, at, due, reason, client_version) VALUES (?,?,?,?,?)",
                   (device, _iso(now), int(due), reason, client_version))
        etag = hashlib.sha256(json.dumps(sch or {}, sort_keys=True).encode()).hexdigest()[:16]
        return {"due": due, "reason": reason, "next_checkin_s": CHECKIN_EVERY_S, "schedule_etag": etag,
                "schedule": sch}

    # ---------- page data ----------
    def stats(self, device: str, days: int = 7) -> dict:
        d = [r["duration_s"] for r in self._runs(device) if r["duration_s"] is not None]
        if not d:
            return {"runs": 0, "last_s": None, "median_s": None, "max_s": None}
        return {"runs": len(d), "last_s": round(d[-1]), "median_s": round(statistics.median(d)), "max_s": round(max(d))}

    def overview(self, now: dt.datetime | None = None) -> list[dict]:
        now = _utc(now)
        out = []
        for sch in self._rows("SELECT * FROM schedule ORDER BY device"):
            dev = sch["device"]
            self.expire_stale(dev, now)
            runs = [r for r in self._runs(dev) if r["status"] != "running"]
            last = runs[-1] if runs else None
            ck = self._rows("SELECT at FROM checkin WHERE device=? AND (reason IS NULL OR reason NOT LIKE ?) "
                            "ORDER BY at DESC LIMIT 1", (dev, MISSED + "%"))
            last_ck = ck[0]["at"] if ck else None
            limit = dt.timedelta(minutes=2 * (sch["every_min"] or 60)) if sch["mode"] == "interval" else dt.timedelta(hours=2)
            if sch["mode"] == "paused":
                health = "paused"
            elif not last_ck or now - _parse(last_ck) > limit:
                health = "silent"
            elif last and last["status"] == "failed":
                health = "failed"
            else:
                nd = self.next_due(dev, now)
                health = "late" if nd is not None and now - nd > limit / 2 else "ok"
            nd = self.next_due(dev, now)
            out.append({"device": dev, "mode": sch["mode"], "every_min": sch["every_min"], "min_gap_s": sch["min_gap_s"],
                        "last_started_at": last["started_at"] if last else None,
                        "last_duration_s": last["duration_s"] if last else None,
                        "last_status": last["status"] if last else None,
                        "last_reported_via": last["reported_via"] if last else None,
                        "last_checkin_at": last_ck, "next_due": _iso(nd) if nd and nd.year > 1 else ("now" if nd else None),
                        "health": health, **{f"stat_{k}": v for k, v in self.stats(dev).items()}})
        return out
