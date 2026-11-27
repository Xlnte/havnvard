"""INFRA-692: a scheduled tier A/E run that verified 0 files is 'blocked' (with a reason), never 'completed'.
Source-level check (finalize_run needs Postgres; the repo's other finalize test reads the source the same way)."""
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "src" / "havnvard_bitrot" / "repository.py").read_text()
FIN = SRC.split("def finalize_run", 1)[1].split("\n    def ", 1)[0]


def test_empty_scheduled_run_is_blocked_before_completed():
    i_empty = FIN.index("completed == 0 and not pending and not remaining_due and tier in (Tier.A, Tier.E)")
    i_blocked = FIN.index('status = "blocked"')
    i_completed = FIN.index('status = "completed"\n')
    assert i_empty < i_blocked < i_completed


def test_reason_is_returned_for_the_alert():
    assert '"error": error' in FIN and "INFRA-692" in FIN
