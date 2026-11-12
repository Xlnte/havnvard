"""Shared filter/pagination/URL-state helpers for the three HavnVard UI views
(dedup, cleanup, backup). One dataset, one interaction model -- per the build
brief ("common UI... not three bespoke pages"): all three views share this
module for parsing query params, building sort-toggle links, building
prev/next page links, and building export links, so behavior (URL-param
state, page-size clamping, sort whitelisting) can't drift between views even
though each view's own SQL/columns differ.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlencode

from . import config

# ---------------------------------------------------------------------------
# Evidence-strength ladder + classification taxonomy — single source of truth
# shared by dedup.py/cleanup.py (SQL WHERE clauses) and the templates (legend/
# badges), so the two can never drift apart. Must stay in sync with
# migrations/20260725_diskaudit_dedup_classification_evidence_v1.sql, which
# computes diskaudit.mv_dedup_groups_by_host.evidence_level/classification.
#
# (level, key, label, available, description) — strongest to weakest.
# `available=False` for byte_identical: no cmp-based tool is wired yet, so it
# always has 0 rows today. Kept in the model rather than silently omitted,
# per the owner's explicit instruction not to pretend a level doesn't exist.
EVIDENCE_LEVELS: list[tuple[int, str, str, bool, str]] = [
    (1, "byte_identical", "Byte-identical",
     False, "Byte-for-byte compared (cmp). NOT YET AVAILABLE — no byte-compare tool is wired up."),
    (2, "sha256_both", "SHA-256 (both sides)",
     True, "Full SHA-256 computed independently on both copies (crosshost-sha256)."),
    (3, "sha256_rdfind", "SHA-256 (rdfind)",
     True, "rdfind's size → head-bytes → tail-bytes → full-SHA256 pipeline, single host."),
    (4, "same_inode", "Same inode (hardlink)",
     True, "Certainly the same data — but NOT a duplicate. Reclaims ZERO bytes."),
    (5, "path_size_mtime", "Path+size+mtime guess",
     True, "Heuristic: same path/size/mtime elsewhere, not byte- or hash-compared."),
    (6, "size_only", "Size-only guess",
     True, "Weak heuristic: size match only."),
    (7, "none", "Not checked",
     True, "Never checked — not proof the file has no duplicate."),
]
EVIDENCE_LEVEL_BY_NUM: dict[int, tuple[str, str, bool, str]] = {
    lvl: (key, label, available, desc) for lvl, key, label, available, desc in EVIDENCE_LEVELS
}

# (key, label, description) — display order matches the SQL CASE precedence in
# the migration (most operationally sensitive first: a group is worst-case
# classified, never labeled more casually than its most sensitive member).
CLASSIFICATIONS: list[tuple[str, str, str]] = [
    ("decommissioned", "Decommissioned",
     "Matches a known dead/removed system (diskaudit.decommissioned_path_patterns)."),
    ("load_bearing", "Load-bearing",
     "Actively referenced by a live cron/systemd/thoth.census entry (diskaudit.load_bearing_paths)."),
    ("os_system", "OS/system",
     "Matches a known OS- or QNAP-system-managed path pattern (diskaudit.critical_patterns / file_category_patterns)."),
    ("application", "Application",
     "Matches a known registered application/module path pattern (diskaudit.critical_patterns)."),
    ("cache_temp", "Cache/temp",
     "Derived/regenerable cache or temp data (diskaudit.file_category_patterns)."),
    ("user_data", "User data",
     "Recognized human-content area (diskaudit.file_category_patterns)."),
    ("unknown", "Unknown",
     "No classification rule matched this path yet."),
]
CLASSIFICATION_KEYS: list[str] = [c[0] for c in CLASSIFICATIONS]
# The one-click "exclude OS/app" ask (defect 1) — every classification except
# the two an operator would want out of the way when hunting real dedup waste.
CLASSIFICATION_KEYS_EXCLUDING_OS_APP: list[str] = [
    c for c in CLASSIFICATION_KEYS if c not in ("os_system", "application")
]

PROVENANCE_LABELS: dict[str, str] = {
    "nas-native": "NAS-native (QNAP BusyBox sha256sum)",
    "local": "Local (this machine)",
    "trigkey-agent": "trigkey-agent",
    "rdfind-pipeline": "rdfind pipeline (local, no cross-host agent)",
    "inode-stat": "Inode stat (no hashing needed)",
    "mixed": "Mixed — members disagree on provenance",
}


def parse_csv(v: str | None) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]


def parse_multi(qp, key: str) -> list[str]:
    """Accepts either repeated same-name query params (?host=a&host=b -- how a
    <select multiple>/checkbox group submits via HTMX/native form GET) or a
    single comma-joined value (?host=a,b -- how our own generated links encode
    it). Always returns a flat, de-duplicated list; never raw enough to reach
    SQL un-whitelisted (callers still validate/filter against a known set)."""
    values = qp.getlist(key) if hasattr(qp, "getlist") else ([qp[key]] if key in qp else [])
    out: list[str] = []
    for v in values:
        out.extend(parse_csv(v))
    seen = set()
    deduped = []
    for x in out:
        if x not in seen:
            seen.add(x)
            deduped.append(x)
    return deduped


def parse_int(v: str | None) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except ValueError:
        return None


def parse_tristate(v: str | None) -> bool | None:
    """'true'/'1'/'yes' -> True, 'false'/'0'/'no' -> False, else None (any)."""
    if v is None or v == "" or v.lower() == "any":
        return None
    return v.lower() in ("true", "1", "yes", "y")


@dataclass
class Page:
    page: int
    page_size: int
    total: int

    @property
    def page_count(self) -> int:
        return max(1, -(-self.total // self.page_size))

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def clamp_page_size(v: str | None) -> int:
    n = parse_int(v) or config.DEFAULT_PAGE_SIZE
    return max(1, min(n, config.MAX_PAGE_SIZE))


def clamp_page(v: str | None) -> int:
    n = parse_int(v) or 1
    return max(1, n)


def build_url(base: str, qp: dict, **overrides) -> str:
    merged = dict(qp)
    merged.update({k: str(v) for k, v in overrides.items() if v is not None})
    merged = {k: v for k, v in merged.items() if v not in (None, "")}
    qs = urlencode(merged)
    return f"{base}?{qs}" if qs else base


def sort_links(base: str, qp: dict, sortable: tuple[str, ...], cur_sort: str | None) -> dict[str, dict]:
    """Precomputes each sortable column's toggle URL + current-direction arrow."""
    cur_col, cur_dir = (None, None)
    if cur_sort:
        parts = cur_sort.split(":", 1)
        cur_col = parts[0]
        cur_dir = parts[1] if len(parts) > 1 else "desc"
    out = {}
    for key in sortable:
        new_dir = "asc" if (key == cur_col and cur_dir == "desc") else "desc"
        out[key] = {
            "url": build_url(base, qp, sort=f"{key}:{new_dir}", page=1),
            "icon": ("▲" if cur_dir == "asc" else "▼") if key == cur_col else "",
        }
    return out


def parse_sort(v: str | None, whitelist: dict[str, str], default: str) -> tuple[str, str]:
    """Returns (real_column, direction) — direction always 'asc'|'desc', column
    always resolved through the whitelist map (never raw user text -> SQL)."""
    if v:
        parts = v.split(":", 1)
        col = parts[0]
        direction = (parts[1].lower() if len(parts) > 1 else "desc")
        direction = "asc" if direction == "asc" else "desc"
        if col in whitelist:
            return whitelist[col], direction
    return whitelist[default], "desc"
