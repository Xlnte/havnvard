from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Iterable

from .types import Classification


@dataclass(frozen=True)
class RegistryPattern:
    pattern: str
    score: int
    reason: str
    is_regex: bool = False
    pattern_kind: str = "mutable"  # mutable | immutable | neutral


DEFAULT_PATTERNS: tuple[RegistryPattern, ...] = (
    RegistryPattern(r"^/var/log/", 99, "log path", True, "mutable"),
    RegistryPattern(r"^/var/tmp/", 97, "temporary path", True, "mutable"),
    RegistryPattern(r"^/tmp/", 97, "temporary path", True, "mutable"),
    RegistryPattern("*.sqlite", 98, "SQLite database", False, "mutable"),
    RegistryPattern("*.sqlite3", 98, "SQLite database", False, "mutable"),
    RegistryPattern("*.db", 98, "database file", False, "mutable"),
    RegistryPattern(r"/\.config/(google-chrome|chromium)/", 96, "browser profile", True, "mutable"),
    RegistryPattern(r"/\.git/", 95, "Git worktree metadata", True, "mutable"),
    RegistryPattern(r"^/etc/hostname$", 10, "immutable system identity", True, "immutable"),
    RegistryPattern(r"^/etc/(passwd|group|shadow|gshadow)$", 15, "security-sensitive account database", True, "immutable"),
    RegistryPattern(r"^/(boot|usr/bin|usr/lib|bin|lib)/", 10, "immutable system path", True, "immutable"),
)


def _pattern_match(path: str, patterns: Iterable[RegistryPattern]) -> RegistryPattern | None:
    for entry in patterns:
        matched = bool(re.search(entry.pattern, path)) if entry.is_regex else fnmatch.fnmatch(path, entry.pattern)
        if matched:
            return entry
    return None


def classify_divergence(
    path: str,
    old_mtime_ns: int | None,
    new_mtime_ns: int | None,
    old_size: int | None,
    new_size: int | None,
    *,
    is_critical: bool = False,
    metadata_trusted: bool = True,
    patterns: Iterable[RegistryPattern] = DEFAULT_PATTERNS,
    auto_accept_threshold: int = 90,
) -> Classification:
    """Classify a hash mismatch without pretending that heuristics prove corruption.

    Explicit immutable patterns remain suspicious even when metadata changed. Explicit
    mutable patterns are trusted only when metadata also shows a real write. Frozen
    metadata always overrides a mutable-path guess because it is the strongest bit-rot
    signal available without filesystem checksums.
    """
    matched = _pattern_match(path, patterns)
    explicit_mutable = bool(matched and matched.pattern_kind == "mutable")
    explicit_immutable = bool(matched and matched.pattern_kind == "immutable")
    score = matched.score if matched else 50
    reasons = [matched.reason] if matched else ["no registry match"]

    metadata_known = metadata_trusted and None not in (old_mtime_ns, new_mtime_ns, old_size, new_size)
    if not metadata_trusted:
        reasons.append("baseline metadata is untrusted; metadata forensics disabled")
    mtime_same = metadata_known and (old_mtime_ns // 1_000_000_000) == (new_mtime_ns // 1_000_000_000)
    size_same = metadata_known and old_size == new_size

    if metadata_known and mtime_same and size_same:
        score = min(score, 5)
        reasons.append("hash changed while mtime and size remained unchanged")
    elif metadata_known and mtime_same and not size_same:
        score = min(score, 5)
        reasons.append("size changed while mtime remained unchanged")
    elif metadata_known and not mtime_same and size_same:
        if explicit_immutable:
            score = min(score, 20)
        elif explicit_mutable:
            score = min(score, 80)
        else:
            score = 55
        reasons.append("mtime changed while size remained unchanged")
    elif metadata_known and not mtime_same and not size_same:
        if explicit_immutable:
            score = min(score, 25)
            reasons.append("immutable-path rule overrides changed metadata")
        elif explicit_mutable:
            score = max(score, 90)
            reasons.append("explicit mutable path and metadata both changed")
        else:
            score = 90
            reasons.append("mtime and size changed")
    else:
        reasons.append("metadata incomplete; confidence reduced")

    if is_critical:
        score = min(score, 15)
        reasons.append("critical-path override")

    if score < 30:
        divergence_type = "unconfirmed_corruption"
    elif score >= 80:
        divergence_type = "legitimate_drift"
    else:
        divergence_type = "unclassified"

    auto_accept = (
        explicit_mutable
        and score >= auto_accept_threshold
        and divergence_type == "legitimate_drift"
        and not is_critical
        and metadata_known
        and not mtime_same
    )
    return Classification(
        score=score,
        divergence_type=divergence_type,
        reason="; ".join(reasons),
        explicit_mutable_rule=explicit_mutable,
        explicit_immutable_rule=explicit_immutable,
        auto_accept_baseline=auto_accept,
    )
