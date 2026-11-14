"""HavnVard 3.3.0 schedules (INFRA-576): per-computer schedule on the hub, devices check in and ask "am I due",
constant loop with run lengths recorded. Throwaway SQLite in tmp dirs only."""
from __future__ import annotations

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup import schedules  # noqa: E402
from backup.config import BackupError  # noqa: E402

T0 = dt.datetime(2026, 11, 14, 2, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def s(tmp_path):
    return schedules.Schedules(tmp_path / "accounts.db")


def m(n):
    return T0 + dt.timedelta(minutes=n)


def test_interval_due_when_never_run_then_after_the_interval(s):
    s.set(None, "air2017", mode="interval", every_min=60)
    assert s.checkin("air2017", now=T0)["due"] is True                       # never ran: due now
    rid = s.run_start("air2017", now=m(1))
    s.run_end("air2017", rid, exit_code=0, snapshot_id="abc12345", now=m(3))
    c = s.checkin("air2017", now=m(30))
    assert c["due"] is False and c["reason"].startswith("next run at")
    assert s.checkin("air2017", now=m(62))["due"] is True                    # 60 min after the last START
    assert s.checkin("air2017", now=m(30))["schedule_etag"]


def test_constant_loop_min_gap_failure_backoff_and_run_lengths(s):
    s.set(None, "spark", mode="constant_loop", min_gap_s=60)
    rid = s.run_start("spark", now=T0)
    assert s.checkin("spark", now=m(5))["due"] is False                      # a run is still going
    s.run_end("spark", rid, exit_code=0, now=m(10))
    assert s.checkin("spark", now=m(10) + dt.timedelta(seconds=30))["due"] is False
    assert s.checkin("spark", now=m(11))["due"] is True                      # next starts when the last ends + gap
    # failures back off (2x, 4x ... the gap), capped at 60 min: a broken run must not loop hot
    t = m(11)
    gaps = []
    for _ in range(8):
        r = s.run_start("spark", now=t)
        s.run_end("spark", r, exit_code=1, now=t + dt.timedelta(seconds=10))
        gaps.append(s.next_due("spark") - (t + dt.timedelta(seconds=10)))
        t = s.next_due("spark")
    assert gaps[0] == dt.timedelta(seconds=120) and gaps[1] == dt.timedelta(seconds=240)
    assert max(gaps) == dt.timedelta(minutes=60)
    st = s.stats("spark")
    assert st["runs"] == 9 and st["last_s"] == 10 and st["median_s"] == 10 and st["max_s"] == 600


def test_paused_manual_and_late_reports_and_overview(s):
    s.set(None, "pafpad", mode="paused")
    assert s.checkin("pafpad", now=T0) == {**s.checkin("pafpad", now=T0), "due": False, "reason": "paused"}
    s.set(None, "pafpad", mode="manual")
    assert s.checkin("pafpad", now=T0)["reason"] == "manual: runs only when started by hand"
    with pytest.raises(BackupError, match="mode"):
        s.set(None, "pafpad", mode="sometimes")
    with pytest.raises(BackupError, match="every_min"):
        s.set(None, "pafpad", mode="interval", every_min=0)
    # a run the device could not report while the hub was down arrives later, marked late, with its real times
    s.report_late("pafpad", started_at=m(-120), ended_at=m(-119), exit_code=1, error="hub unreachable")
    ov = {r["device"]: r for r in s.overview(now=T0)}
    assert ov["pafpad"]["last_status"] == "failed" and ov["pafpad"]["last_reported_via"] == "late"
    assert ov["pafpad"]["last_checkin_at"]
    # never checked in: shows as silent, not as fine
    s.set(None, "trigkey", mode="interval", every_min=60)
    assert {r["device"]: r for r in s.overview(now=T0)}["trigkey"]["health"] == "silent"
