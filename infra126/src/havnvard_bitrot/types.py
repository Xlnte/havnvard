from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Tier(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"


class ItemState(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    HASHING = "hashing"
    MATCHED = "matched"
    DIVERGED = "diverged"
    ACCEPTED_DRIFT = "accepted_drift"
    UNREADABLE = "unreadable"
    CHANGED_DURING_HASH = "changed_during_hash"
    STALE_BASELINE = "stale_baseline"
    MISSING = "missing"
    FAILED = "failed"
    SKIPPED = "skipped"


class HashOutcome(StrEnum):
    HASHED = "hashed"
    UNREADABLE = "unreadable"
    CHANGED_DURING_HASH = "changed_during_hash"
    MISSING = "missing"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class TierPolicy:
    tier: Tier
    target_days: int
    cadence: str
    description: str
    scheduled: bool = True


@dataclass(frozen=True)
class FileCandidate:
    item_id: int
    run_id: str
    host: str
    path: str
    inode: int | None
    baseline_hash: str
    baseline_hashed_at: datetime | None
    baseline_mtime_ns: int | None
    baseline_size: int | None
    is_critical: bool = False
    baseline_metadata_trusted: bool = False


@dataclass(frozen=True)
class HashResult:
    item_id: int
    path: str
    status: HashOutcome
    sha256: str | None
    size: int | None
    mtime_ns: int | None
    inode: int | None
    duration_ms: int
    error: str | None = None


@dataclass(frozen=True)
class Classification:
    score: int
    divergence_type: str
    reason: str
    explicit_mutable_rule: bool
    explicit_immutable_rule: bool
    auto_accept_baseline: bool


@dataclass(frozen=True)
class CopyEvidence:
    source_kind: str
    source_id: str
    sha256: str
    captured_at: datetime | None = None


@dataclass(frozen=True)
class CopyDecision:
    state: str
    authoritative_hash: str | None
    odd_sources: tuple[str, ...] = ()
    reason: str = ""


@dataclass
class RunSummary:
    run_id: str
    host: str
    tier: str
    checked: int = 0
    matched: int = 0
    diverged: int = 0
    accepted_drift: int = 0
    errors: int = 0
    missing: int = 0
    changed_during_hash: int = 0
    stale_baseline: int = 0
    # Excluded-by-POLICY (INFRA-281). Deliberately a separate field from
    # `errors`: policy exclusions must never influence run status, while a
    # genuine read failure still must.
    excluded_by_policy: int = 0
    path_exclusions: list[dict] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
