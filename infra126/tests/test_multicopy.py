from datetime import datetime,timezone

from havnvard_bitrot.multicopy import decide_copies
from havnvard_bitrot.types import CopyEvidence

NOW = datetime.now(timezone.utc)


def e(source,hash_value):
    return CopyEvidence("live_host",source,hash_value,NOW)


def test_one_copy_is_insufficient():
    assert decide_copies([e("spark","a")]).state == "insufficient_evidence"


def test_two_copies_match():
    decision = decide_copies([e("spark","a"),e("nas","a")])
    assert decision.state == "all_agree"
    assert decision.authoritative_hash == "a"


def test_two_copy_mismatch_is_unresolvable():
    decision = decide_copies([e("spark","a"),e("nas","b")])
    assert decision.state == "two_copy_conflict"
    assert decision.authoritative_hash is None


def test_three_copy_majority_identifies_odd_source_without_proving_corruption():
    decision = decide_copies([e("spark","b"),e("nas","a"),e("restic","a")])
    assert decision.state == "majority_odd_copy"
    assert decision.authoritative_hash == "a"
    assert decision.odd_sources == ("spark",)
    assert "does not prove corruption" in decision.reason


def test_three_way_split_escalates():
    decision = decide_copies([e("spark","a"),e("nas","b"),e("restic","c")])
    assert decision.state == "three_way_split"


def test_multiple_snapshots_from_one_repository_count_as_one_vote():
    from datetime import datetime,timezone,timedelta
    now=datetime.now(timezone.utc)
    decision=decide_copies([
        CopyEvidence("live_host","spark","b"*64,now),
        CopyEvidence("restic_snapshot","restic-repo","a"*64,now-timedelta(days=1)),
        CopyEvidence("restic_snapshot","restic-repo","a"*64,now),
    ])
    assert decision.state=="two_copy_conflict"
