from datetime import datetime,timedelta,timezone

import pytest

from havnvard_bitrot.policy import candidate_predicate_sql,due_for_tier
from havnvard_bitrot.types import Tier

NOW = datetime(2026,7,26,tzinfo=timezone.utc)


def test_tier_a_is_unverified_current_baseline():
    assert due_for_tier(Tier.A,NOW-timedelta(days=2),None,now=NOW)
    assert not due_for_tier(Tier.A,NOW-timedelta(days=2),NOW-timedelta(days=1),now=NOW)


def test_tier_b_window_and_monthly_recheck():
    baseline = NOW-timedelta(days=15)
    assert due_for_tier(Tier.B,baseline,None,now=NOW)
    assert not due_for_tier(Tier.B,baseline,NOW-timedelta(days=5),now=NOW)
    assert due_for_tier(Tier.B,baseline,NOW-timedelta(days=31),now=NOW)


def test_tier_c_closes_31_to_90_day_gap():
    assert due_for_tier(Tier.C,NOW-timedelta(days=40),None,now=NOW)
    assert "31 days" in candidate_predicate_sql(Tier.C)


def test_tier_e_only_critical():
    assert due_for_tier(Tier.E,NOW-timedelta(days=100),None,is_critical=True,now=NOW)
    assert not due_for_tier(Tier.E,NOW-timedelta(days=100),None,is_critical=False,now=NOW)


def test_tier_d_uses_stabilization_queue():
    sql = candidate_predicate_sql(Tier.D)
    assert "hash_baseline_stabilizations" in sql
    assert "due_at<=now()" in sql
