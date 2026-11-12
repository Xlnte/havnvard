"""HavnVard — canonical-copy ("best place to keep") ranking algorithm.

Owner's rule (verbatim): "best select 'best' place leave it, based on all
other files in one location[s] possible" -- i.e. prefer the location that
CONSOLIDATES survivors rather than scattering them, and show the reasoning
so the recommendation is auditable, never just a bare verdict.

Read-only / advisory only: this module never deletes or moves anything. It
only labels each copy in a duplicate group KEEP or CANDIDATE and explains
why, for a human to review (and, if they agree, export a manifest for the
separate not-yet-built FERJA cleanup process).

Precedence (highest first), per the 2026-07-25 build brief:
  1. load_bearing_paths / critical_patterns match -> automatic KEEP, never a
     candidate, full stop -- regardless of every other rule below.
  2. DATED SNAPSHOT SERIES: paths that are identical except for an embedded
     YYYYMMDD-shaped date component (the common backup-tree shape) -> keep
     the NEWEST dated snapshot (the live restore point); mark the rest
     reclaimable. Detected explicitly (see detect_dated_snapshot_series),
     never silently assumed -- this rule only fires when it demonstrably
     holds across every remaining candidate in the group.
  3. SIBLING CONSOLIDATION: otherwise, prefer the directory that already
     holds the most OTHER duplicated files on this host (computed honestly
     from diskaudit.files, not guessed) -- concentrating cleanup instead of
     fragmenting it.
  4. Prefer a non-deprecated path (diskaudit.decommissioned_path_patterns)
     over one under a decommissioned/dead-system prefix, as a tie-break.
  5. Final tie-breakers: oldest mtime (longest-lived location), then
     shortest path, then lexicographic (fully deterministic).

Invariant: at least one copy is always KEEP. The last remaining copy in a
group is never recommended for deletion.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

_DATE_TOKEN_RE = re.compile(r"\d{8}")
_DATE_MASK = "\x00DATE\x00"


def _normalize_for_snapshot(path: str) -> str:
    return _DATE_TOKEN_RE.sub(_DATE_MASK, path)


def _date_tokens(path: str) -> list[str]:
    return _DATE_TOKEN_RE.findall(path)


def _parse_date_token(tok: str) -> datetime | None:
    try:
        return datetime.strptime(tok, "%Y%m%d")
    except ValueError:
        return None


def _best_date_token(path: str) -> tuple[datetime, str] | None:
    """Of every 8-digit run in path that parses as a real YYYYMMDD date,
    return the (parsed, raw) pair for the latest one. A path may contain
    more than one 8-digit run (e.g. a hostname that happens to be numeric);
    we only trust runs that actually parse as calendar dates."""
    parsed = [(_parse_date_token(t), t) for t in _date_tokens(path)]
    parsed = [p for p in parsed if p[0] is not None]
    if not parsed:
        return None
    return max(parsed, key=lambda x: x[0])


def detect_dated_snapshot_series(paths: list[str]) -> bool:
    """True iff every path in `paths` becomes byte-identical once every
    8-digit run is masked out, AND at least two distinct real dates are
    actually present across the group (so a coincidental, never-varying
    8-digit substring -- e.g. a fixed serial number -- can't false-positive
    this). This is a labelled HEURISTIC shown in the UI, never asserted as
    proof."""
    if len(paths) < 2:
        return False
    if len({_normalize_for_snapshot(p) for p in paths}) != 1:
        return False
    dated = [_best_date_token(p) for p in paths]
    if not all(dated):
        return False
    return len({d[1] for d in dated}) > 1


def dirname_of(path: str) -> str:
    return re.sub(r"/[^/]+$", "", path)


def rank_group(rows: list[dict[str, Any]], sibling_counts: dict[str, int]) -> dict[str, Any]:
    """rows: per-copy dicts with at least path, size_bytes, inode, nlink,
    mtime, is_load_bearing, is_critical, is_decommissioned.
    sibling_counts: dirpath -> count of OTHER duplicated files (any group,
    excluding this one) already resident in that directory on this host.

    Returns {"dated_snapshot": bool, "keep_path": str|None,
             "headline": str, "annotated": [row + verdict + reason + reclaim_bytes, ...]}.
    Never mutates `rows`; never touches the filesystem.
    """
    if not rows:
        return {"dated_snapshot": False, "keep_path": None, "headline": "", "annotated": []}

    work = [dict(r) for r in rows]
    for r in work:
        r["dirpath"] = dirname_of(r["path"])
        r["sibling_count"] = sibling_counts.get(r["dirpath"], 0)
    work.sort(key=lambda r: r["path"])  # deterministic base order

    protected_paths = {r["path"] for r in work if r.get("is_load_bearing") or r.get("is_critical")}
    candidates = [r for r in work if r["path"] not in protected_paths]

    annotated: list[dict[str, Any]] = []
    for r in work:
        if r["path"] in protected_paths:
            is_lb = bool(r.get("is_load_bearing"))
            why = ("load-bearing path (referenced by a live system -- diskaudit.load_bearing_paths)"
                   if is_lb else
                   "critical-protected path (matches diskaudit.critical_patterns)")
            annotated.append({**r, "verdict": "KEEP",
                               "reason": f"Protected: {why}. Never a deletion candidate regardless of any other rule."})

    dated_snapshot = False
    keep_row: dict[str, Any] | None = None

    if candidates:
        if detect_dated_snapshot_series([r["path"] for r in candidates]):
            dated = [(r, _best_date_token(r["path"])) for r in candidates]
            dated = [(r, d) for r, d in dated if d is not None]
            if dated:
                dated_snapshot = True
                keep_row, keep_date = max(
                    dated, key=lambda rd: (rd[1][0], rd[0].get("mtime") or rd[1][0], -len(rd[0]["path"]))
                )
                n = len(candidates)
                for r in candidates:
                    if r is keep_row:
                        annotated.append({**r, "verdict": "KEEP",
                                           "reason": (f"Newest of {n} dated backup snapshots in this series "
                                                      f"(series date {keep_date[1]}) -- kept as the live restore point.")})
                    else:
                        tok = _best_date_token(r["path"])
                        tokstr = tok[1] if tok else "?"
                        annotated.append({**r, "verdict": "CANDIDATE",
                                           "reason": (f"Superseded snapshot in the same dated-backup series "
                                                      f"(dated {tokstr}); byte-identical to the kept copy at "
                                                      f"{keep_row['path']}.")})

        if keep_row is None:
            max_sib = max(r["sibling_count"] for r in candidates)
            sib_tied = [r for r in candidates if r["sibling_count"] == max_sib]
            used_decom_tiebreak = False
            used_mtime_tiebreak = False
            tied = sib_tied
            if len(tied) > 1:
                non_decom = [r for r in tied if not r.get("is_decommissioned")]
                if non_decom and len(non_decom) < len(tied):
                    used_decom_tiebreak = True
                    tied = non_decom
            if len(tied) > 1:
                used_mtime_tiebreak = True
                tied.sort(key=lambda r: (r.get("mtime") or datetime.max, len(r["path"]), r["path"]))
            keep_row = tied[0]

            other_counts = sorted((r["sibling_count"] for r in candidates if r is not keep_row), reverse=True)
            second = other_counts[0] if other_counts else 0
            tie_note = ""
            if used_decom_tiebreak:
                tie_note += " Tie-break: preferred over an equally-consolidated copy under a decommissioned/dead-system prefix."
            if used_mtime_tiebreak:
                tie_note += " Tie-break: oldest mtime (longest-lived location) among otherwise-tied candidates."
            for r in candidates:
                if r is keep_row:
                    annotated.append({**r, "verdict": "KEEP",
                                       "reason": (f"Consolidation: this directory already holds {r['sibling_count']} "
                                                  f"other duplicated files on this host (next-best directory holds "
                                                  f"{second}) -- keeping the survivor here concentrates cleanup "
                                                  f"instead of scattering it." + tie_note)})
                else:
                    annotated.append({**r, "verdict": "CANDIDATE",
                                       "reason": (f"Reclaimable -- canonical copy consolidated at "
                                                  f"{keep_row['path']} ({keep_row['sibling_count']} other duplicated "
                                                  f"files there vs {r['sibling_count']} here).")})

    # Per-row reclaim_bytes: hardlink-honest. A CANDIDATE sharing an inode
    # with the kept copy, or with another already-counted candidate, frees
    # ZERO bytes on its own -- never render a reclaim figure that implies
    # otherwise (non-negotiable).
    inode_seen: set = set()
    keep_inode = keep_row["inode"] if keep_row else None
    annotated.sort(key=lambda r: r["path"])
    for r in annotated:
        if r["verdict"] == "KEEP":
            r["reclaim_bytes"] = 0
            continue
        if keep_inode is not None and r["inode"] == keep_inode:
            r["reclaim_bytes"] = 0
            r["reason"] += " Same inode as the kept copy -- hardlinked, frees 0 bytes."
        elif r["inode"] in inode_seen:
            r["reclaim_bytes"] = 0
            r["reason"] += " Shares an inode with another listed candidate (already counted there) -- frees 0 bytes here."
        else:
            r["reclaim_bytes"] = r["size_bytes"] or 0
            inode_seen.add(r["inode"])

    if not candidates:
        headline = "Every copy in this group is protected (load-bearing/critical) -- no reclaim candidates."
    elif dated_snapshot:
        headline = f"Dated-snapshot series detected -- kept the newest snapshot at {keep_row['path']}."
    else:
        headline = f"Kept {keep_row['path']} (sibling-consolidation: {keep_row['sibling_count']} related files already there)."

    return {
        "dated_snapshot": dated_snapshot,
        "keep_path": keep_row["path"] if keep_row else None,
        "headline": headline,
        "annotated": annotated,
    }
