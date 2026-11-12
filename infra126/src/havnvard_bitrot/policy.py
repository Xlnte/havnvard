from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .types import Tier, TierPolicy


# Tier C begins after Tier B's 31-day window. Its SLA is 90 days. This removes
# the otherwise-unmanaged 31-90 day gap while retaining quarterly cadence.
POLICIES: dict[Tier, TierPolicy] = {
    Tier.A: TierPolicy(Tier.A, 7, "weekly", "Current baseline is 0-7 days old and has not yet been re-verified"),
    Tier.B: TierPolicy(Tier.B, 30, "monthly", "Current baseline is 7-31 days old and is due monthly"),
    Tier.C: TierPolicy(Tier.C, 90, "quarterly", "Current baseline is older than 31 days and is due every 90 days"),
    Tier.D: TierPolicy(Tier.D, 1, "event-driven", "Accepted mutable baseline awaiting stabilization", scheduled=False),
    Tier.E: TierPolicy(Tier.E, 1, "daily", "Critical/load-bearing paths"),
}


def due_for_tier(
    tier: Tier,
    baseline_hashed_at: datetime,
    last_verified_at: datetime | None,
    *,
    is_critical: bool = False,
    now: datetime | None = None,
) -> bool:
    now = now or datetime.now(timezone.utc)
    age = now - baseline_hashed_at
    since_verified = None if last_verified_at is None else now - last_verified_at
    verified_current_baseline = last_verified_at is not None and last_verified_at >= baseline_hashed_at
    if tier == Tier.E:
        return is_critical and (last_verified_at is None or since_verified >= timedelta(days=1))
    if is_critical:
        return False
    if tier == Tier.A:
        return age <= timedelta(days=7) and not verified_current_baseline
    if tier == Tier.B:
        return timedelta(days=7) < age <= timedelta(days=31) and (
            not verified_current_baseline or since_verified >= timedelta(days=30)
        )
    if tier == Tier.C:
        return age > timedelta(days=31) and (
            not verified_current_baseline or since_verified >= timedelta(days=90)
        )
    return False


def candidate_predicate_sql(tier: Tier) -> str:
    baseline_time = "COALESCE(f.hashed_at,f.first_hashed_at)"
    critical = "EXISTS (SELECT 1 FROM diskaudit.infra126_critical_files c WHERE c.host=f.host AND c.path=f.path)"
    verified_current = f"f.last_verified_at IS NOT NULL AND f.last_verified_at >= {baseline_time}"
    if tier == Tier.E:
        return f"{critical} AND (f.last_verified_at IS NULL OR f.last_verified_at < now() - interval '1 day' OR NOT ({verified_current}))"
    noncritical = f"NOT ({critical})"
    if tier == Tier.A:
        return f"{noncritical} AND {baseline_time} >= now() - interval '7 days' AND NOT ({verified_current})"
    if tier == Tier.B:
        return (
            f"{noncritical} AND {baseline_time} < now() - interval '7 days' "
            f"AND {baseline_time} >= now() - interval '31 days' "
            f"AND (NOT ({verified_current}) OR f.last_verified_at < now() - interval '30 days')"
        )
    if tier == Tier.C:
        return (
            f"{noncritical} AND {baseline_time} < now() - interval '31 days' "
            f"AND (NOT ({verified_current}) OR f.last_verified_at < now() - interval '90 days')"
        )
    if tier == Tier.D:
        file_key_expr = "(md5(f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')) || md5('infra126:' || f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')))"
        return (
            "EXISTS (SELECT 1 FROM diskaudit.hash_baseline_stabilizations s "
            f"WHERE s.file_key={file_key_expr} AND s.state='pending' AND s.due_at<=now() "
            "AND s.accepted_hash=f.content_sha256)"
        )
    raise ValueError(f"unsupported tier: {tier}")


def exclusion_predicate_sql(exclusions, host: str) -> tuple[str, list[str]]:
    """SQL fragment excluding INFRA-281 policy paths, plus its bind params.

    Returns ("", []) when nothing applies to this host, so callers can skip the
    clause entirely rather than emitting a vacuous `AND TRUE`. starts_with() is
    used instead of LIKE so no caller has to escape % or _ inside a real path.
    """
    prefixes = [item.prefix for item in exclusions or () if item.applies_to(host)]
    if not prefixes:
        return "", []
    clauses = " OR ".join("starts_with(f.path, %s)" for _ in prefixes)
    return f"NOT ({clauses})", prefixes
