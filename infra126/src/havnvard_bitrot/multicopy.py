from __future__ import annotations

from collections import defaultdict

from .types import CopyDecision, CopyEvidence


def decide_copies(evidence: list[CopyEvidence]) -> CopyDecision:
    # One independent source gets one vote. Multiple snapshots from the same
    # repository cannot manufacture a majority. Prefer the newest observation.
    latest: dict[str, CopyEvidence] = {}
    for item in evidence:
        if not item.sha256:
            continue
        current=latest.get(item.source_id)
        if current is None or (item.captured_at is not None and (current.captured_at is None or item.captured_at>current.captured_at)):
            latest[item.source_id]=item
    usable = list(latest.values())
    if len(usable) < 2:
        return CopyDecision("insufficient_evidence", None, reason="fewer than two hash observations")
    groups: dict[str, list[CopyEvidence]] = defaultdict(list)
    for item in usable:
        groups[item.sha256].append(item)
    if len(groups) == 1:
        only_hash = next(iter(groups))
        return CopyDecision("all_agree", only_hash, reason=f"{len(usable)} copies agree")
    if len(usable) == 2:
        return CopyDecision("two_copy_conflict", None, tuple(item.source_id for item in usable), "two copies differ; no authoritative version")
    ranked = sorted(groups.items(), key=lambda pair: len(pair[1]), reverse=True)
    top_hash, top_items = ranked[0]
    if len(top_items) >= 2 and len(top_items) > len(ranked[1][1]):
        odd = tuple(item.source_id for hash_value, items in ranked[1:] for item in items if hash_value != top_hash)
        return CopyDecision("majority_odd_copy", top_hash, odd, "majority agreement identifies an odd copy but does not prove corruption")
    return CopyDecision("three_way_split", None, tuple(item.source_id for item in usable), "no hash majority")
