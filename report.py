#!/usr/bin/env python3
"""diskaudit (HavnVard) — crosshost_verify markdown report renderer.

Invoked via `crosshost_verify.py report [--out-dir DIR]` (see that file's
`main()`). Never runs standalone from cron/systemd -- it is a reporting VIEW
over data that `hash`/`match` have already written into Postgres, not a
second source of truth. Per this repo's `feedback_data_into_rdbms` /
`feedback_ground_truth_protocol` convention: the durable, queryable record is
diskaudit.files (content_sha256, duplicate_group_id, inode/nlink, ...) and
diskaudit.integrity_checks -- these markdown files are a disposable,
regeneratable RENDERING of that DB data for a human to read, not the record
of truth themselves. Re-running `report` at any time re-renders current
state; nothing here is authoritative if it disagrees with a fresh query.

Renders three files per run, all under reports/ (gitignored -- see
.gitignore):
    dedup_report_<UTC-timestamp>.md
    nas_integrity_report_<UTC-timestamp>.md
    cleanup_candidates_<UTC-timestamp>.md

HARD CONSTRAINT: every recommendation in every report is phrased as a
CANDIDATE for the owner (the operator) to review -- "candidate for possible removal
on <host>", "consider", "may be safe to" -- never an instruction, and this
module never deletes/moves/renames anything itself. It only reads from
Postgres and writes new .md files under out_dir.

Inode-aware accounting (see crosshost_verify.py's hash_local_host
docstring): on a single host, rows sharing the same `inode` are guaranteed
to be byte-identical BY CONSTRUCTION (that's what a hardlink is) -- they are
the same physical copy on disk, occupying `size_bytes` ONCE, not once per
path. Treating hardlinked rows as independent duplicates would grossly
overstate "reclaimable space" (server-1 alone carries ~2M hardlinked file
rows). Every space calculation below first collapses each (host, inode)
pair down to a single physical copy before computing anything.
"""
from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# small shared helpers
# ---------------------------------------------------------------------------

import havnvard_site as _site  # noqa: E402  (3.0.0)

# Path prefix -> owning-app label for reports. Site data ([report] app_prefixes = [["/srv/app1", "App 1"], ...]);
# the generic entries below always apply after the site's own. Longest/most specific prefixes first.
_APP_PREFIXES = [tuple(p) for p in (_site.section("report").get("app_prefixes") or [])] + [
    ("/var/lib/postgresql", "PostgreSQL data files (live DB -- do not touch)"),
    ("/var/lib/docker", "Docker"),
    ("/var/lib/snapd", "snapd/snap packages"),
]


def _owning_app(path: str) -> str:
    for prefix, label in _APP_PREFIXES:
        if path.startswith(prefix):
            return label
    return "(unclassified)"


def _fmt_gb(n_bytes) -> str:
    return f"{int(n_bytes) / 1e9:,.2f} GB"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write(out_dir: str, name: str, body: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w") as f:
        f.write(body)
    return path


# ---------------------------------------------------------------------------
# 1. dedup report -- inode-aware, groups files sharing duplicate_group_id
#    (set by crosshost_verify.py's `match` subcommand, reusing dedup.py's
#    duplicate_group_id/dedup_tool/dedup_method convention)
# ---------------------------------------------------------------------------

_DEDUP_GROUPS_SQL = """
    SELECT duplicate_group_id, host, path, size_bytes, inode, nlink,
           mtime, hashed_at, still_exists
    FROM diskaudit.files
    WHERE duplicate_group_id IS NOT NULL AND still_exists
    ORDER BY duplicate_group_id, host, path
"""


def _collapse_by_inode(rows):
    """rows: list of (host, path, size_bytes, inode, nlink, mtime, hashed_at)
    for ONE duplicate_group_id. Returns list of "physical copies": one entry
    per distinct (host, inode) -- or per path, for rows with inode NULL
    (can't prove hardlink-ness without an inode; treated conservatively as
    its own physical copy) -- each carrying its representative path plus a
    count of how many sibling paths on that host share the same inode.
    """
    by_key: dict[tuple, list] = defaultdict(list)
    for host, path, size_bytes, inode, nlink, mtime, hashed_at in rows:
        key = (host, inode) if inode is not None else (host, ("_path", path))
        by_key[key].append((path, size_bytes, mtime, hashed_at))

    physical = []
    for (host, _inode_or_path), paths in by_key.items():
        paths.sort()
        rep_path, size_bytes, mtime, hashed_at = paths[0]
        physical.append({
            "host": host,
            "representative_path": rep_path,
            "size_bytes": size_bytes,
            "sibling_hardlink_paths": len(paths) - 1,
            "all_paths": [p[0] for p in paths],
            "mtime": mtime,
            "hashed_at": hashed_at,
        })
    return physical


def render_dedup_report(conn, out_dir: str) -> tuple[str, dict]:
    with conn.cursor() as cur:
        cur.execute(_DEDUP_GROUPS_SQL)
        rows = cur.fetchall()

    groups: dict[str, list] = defaultdict(list)
    for group_id, host, path, size_bytes, inode, nlink, mtime, hashed_at, _still in rows:
        groups[group_id].append((host, path, size_bytes, inode, nlink, mtime, hashed_at))

    lines = []
    lines.append("# HavnVard cross-host dedup report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(
        "Every group below shares one SHA-256 content hash "
        "(`diskaudit.files.duplicate_group_id`, set by `crosshost_verify.py match`). "
        "**Inode-aware**: on a single host, paths sharing the same inode are hardlinks -- "
        "the SAME bytes on disk, counted ONCE below, never as independent duplicates. "
        "\"Reclaimable space\" only ever counts genuinely separate physical copies."
    )
    lines.append("")
    lines.append(
        "**These are candidates for the operator's review only.** Nothing in this report is an "
        "instruction to delete/move anything, and HavnVard itself never does so."
    )
    lines.append("")

    total_groups = len(groups)
    total_reclaimable_same_host = 0
    total_verified_backed_up_bytes = 0
    group_summaries = []

    for group_id, group_rows in groups.items():
        physical = _collapse_by_inode(group_rows)
        hosts_present = sorted({p["host"] for p in physical})
        size_bytes = physical[0]["size_bytes"] if physical else 0

        # Reclaimable-on-same-host: for any host with >1 physical (non-hardlinked)
        # copy of this content, all-but-one of those physical copies is reclaimable.
        by_host_count = defaultdict(int)
        for p in physical:
            by_host_count[p["host"]] += 1
        reclaimable_here = sum(max(0, n - 1) * size_bytes for n in by_host_count.values())
        total_reclaimable_same_host += reclaimable_here

        verified_on_nas = _site.nas_host() in hosts_present
        if verified_on_nas and len(hosts_present) >= 2:
            # every physical copy NOT on nas-1 is a candidate: nas already
            # holds a cryptographically-verified copy of this content.
            non_nas_physical = sum(1 for p in physical if p["host"] != _site.nas_host())
            total_verified_backed_up_bytes += non_nas_physical * size_bytes

        group_summaries.append({
            "group_id": group_id,
            "size_bytes": size_bytes,
            "hosts": hosts_present,
            "physical_copies": len(physical),
            "logical_paths": sum(1 + p["sibling_hardlink_paths"] for p in physical),
            "reclaimable_same_host": reclaimable_here,
            "verified_on_nas": verified_on_nas,
            "physical": physical,
        })

    group_summaries.sort(key=lambda g: g["reclaimable_same_host"] + (g["size_bytes"] if g["verified_on_nas"] else 0), reverse=True)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Duplicate-content groups: **{total_groups:,}**")
    lines.append(f"- Reclaimable via same-host consolidation (true duplicates, hardlinks excluded): **{_fmt_gb(total_reclaimable_same_host)}**")
    lines.append(f"- Content already verified present on NAS, extra source-side copies (candidate cleanup, NOT hardlink-collapsed): **{_fmt_gb(total_verified_backed_up_bytes)}**")
    lines.append("")
    lines.append(
        "Context (independently verified 2026-07-25 against live diskaudit.files -- "
        "see runbook): one server alone carried ~2,020,483 hardlinked file rows out of "
        "~5,424,882 total regular files. A naive byte-sum over all rows sharing a size/hash "
        "massively overstates reclaimable space by counting each hardlinked path as if it "
        "were an independent copy. The figures above are already hardlink-corrected."
    )
    lines.append("")

    lines.append("## Top groups by candidate impact")
    lines.append("")
    lines.append("| size | hosts | physical copies | logical paths | reclaimable (same-host) | verified on NAS | app |")
    lines.append("|---|---|---|---|---|---|---|")
    for g in group_summaries[:200]:
        app = _owning_app(g["physical"][0]["representative_path"])
        lines.append(
            f"| {_fmt_gb(g['size_bytes'])} | {', '.join(g['hosts'])} | {g['physical_copies']} | "
            f"{g['logical_paths']} | {_fmt_gb(g['reclaimable_same_host'])} | "
            f"{'yes' if g['verified_on_nas'] else 'no'} | {app} |"
        )
    lines.append("")
    if len(group_summaries) > 200:
        lines.append(f"_({len(group_summaries) - 200:,} additional lower-impact groups not shown -- query `diskaudit.files` directly for the full set.)_")
        lines.append("")

    body = "\n".join(lines)
    path = _write(out_dir, f"dedup_report_{_ts()}.md", body)
    return path, {
        "total_groups": total_groups,
        "reclaimable_same_host_bytes": total_reclaimable_same_host,
        "verified_backed_up_bytes": total_verified_backed_up_bytes,
    }


# ---------------------------------------------------------------------------
# 2. NAS integrity report -- reads diskaudit.integrity_checks
# ---------------------------------------------------------------------------

def render_nas_integrity_report(conn, out_dir: str) -> tuple[str, dict]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT verdict, count(*), coalesce(sum(size_bytes), 0) "
            "FROM diskaudit.integrity_checks GROUP BY verdict ORDER BY verdict"
        )
        verdict_counts = cur.fetchall()

        cur.execute(
            """
            SELECT spark_host, spark_path, nas_path, size_bytes, sha_source, sha_dest, checked_at, notes
            FROM diskaudit.integrity_checks WHERE verdict = 'mismatch'
            ORDER BY size_bytes DESC NULLS LAST LIMIT 100
            """
        )
        mismatches = cur.fetchall()

        cur.execute(
            """
            SELECT spark_host, spark_path, size_bytes, checked_at
            FROM diskaudit.integrity_checks WHERE verdict = 'missing_dest'
            ORDER BY size_bytes DESC NULLS LAST LIMIT 200
            """
        )
        missing = cur.fetchall()

        cur.execute(
            """
            SELECT spark_host, spark_path, size_bytes, notes
            FROM diskaudit.integrity_checks WHERE verdict IN ('unreadable_source', 'unreadable_dest')
            ORDER BY spark_host, spark_path LIMIT 200
            """
        )
        unreadable = cur.fetchall()

    lines = []
    lines.append("# HavnVard NAS integrity report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(
        f"**Answers: \"is my {', '.join(_site.source_hosts())} data genuinely intact on the NAS?\"** "
        "Every row here is cryptographic (SHA-256) evidence, not a filename/size heuristic. "
        "A `match` verdict proves the source and NAS copies were bit-identical **at the "
        "moment both were hashed** -- it does NOT guarantee against later bit rot, a "
        "subsequent overwrite on either side, or silent corruption after the check. "
        "Re-run `crosshost_verify.py hash` + `match` periodically for fresh evidence, "
        "not a one-time guarantee."
    )
    lines.append("")

    lines.append("## Verdict summary")
    lines.append("")
    lines.append("| verdict | count | total size |")
    lines.append("|---|---|---|")
    for verdict, count, total_bytes in verdict_counts:
        lines.append(f"| {verdict} | {count:,} | {_fmt_gb(total_bytes)} |")
    lines.append("")

    lines.append("## Mismatches (same name+size on NAS, different content hash) -- investigate manually")
    lines.append("")
    lines.append(
        "Not asserted as proven corruption: could be genuine drift/staleness, OR simply an "
        "unrelated file that happens to share a basename and size. Ordered by size, capped at 100."
    )
    lines.append("")
    if mismatches:
        lines.append("| host | source path | nas path | size | source sha | nas sha | checked_at |")
        lines.append("|---|---|---|---|---|---|---|")
        for host, spath, npath, size_bytes, sha_s, sha_d, checked_at, _notes in mismatches:
            lines.append(
                f"| {host} | {spath} | {npath} | {_fmt_gb(size_bytes or 0)} | "
                f"`{(sha_s or '')[:12]}...` | `{(sha_d or '')[:12]}...` | {checked_at} |"
            )
    else:
        lines.append("_None found._")
    lines.append("")

    lines.append(f"## Missing on NAS (no matching content hash found on {_site.nas_host()}) -- capped at 200 by size")
    lines.append("")
    lines.append(
        "Caveat: checked only against the NAS candidate set hashed so far "
        "(size >= 1MB and shared with >=2 hosts). A smaller/unique-sized file "
        "genuinely on the NAS but never entering the candidate set would also show here -- "
        "this is a statement about the CROSS-HOST CANDIDATE SET, not a full NAS inventory diff."
    )
    lines.append("")
    if missing:
        lines.append("| host | path | size | checked_at |")
        lines.append("|---|---|---|---|")
        for host, path, size_bytes, checked_at in missing:
            lines.append(f"| {host} | {path} | {_fmt_gb(size_bytes or 0)} | {checked_at} |")
    else:
        lines.append("_None found._")
    lines.append("")

    lines.append("## Unreadable during hashing (permission-denied or vanished) -- capped at 200")
    lines.append("")
    lines.append(
        "Not a tool bug: sampled paths are typically permission-restricted system/other-user "
        "files (e.g. live PostgreSQL WAL/base files, another user's home directory) that the "
        "scanning account genuinely cannot -- and in the case of a live DB's files, should not -- "
        "read directly. These files were never scored for cross-host integrity; they are not "
        "\"missing\", they are \"unverified\"."
    )
    lines.append("")
    if unreadable:
        lines.append("| host | path | size | notes |")
        lines.append("|---|---|---|---|")
        for host, path, size_bytes, notes in unreadable:
            lines.append(f"| {host} | {path} | {_fmt_gb(size_bytes or 0)} | {notes or ''} |")
    else:
        lines.append("_None found._")
    lines.append("")

    body = "\n".join(lines)
    path = _write(out_dir, f"nas_integrity_report_{_ts()}.md", body)
    return path, {"verdict_counts": {v: (c, int(b)) for v, c, b in verdict_counts}}


# ---------------------------------------------------------------------------
# 3. cleanup / movement CANDIDATE list -- recommendations only, never
#    instructions; HavnVard performs none of these actions itself
# ---------------------------------------------------------------------------

_CLEANUP_CANDIDATES_SQL = """
    SELECT f.host, f.path, f.size_bytes, f.inode, f.mtime,
           ic.verdict, ic.checked_at
    FROM diskaudit.files f
    JOIN diskaudit.integrity_checks ic
        ON ic.spark_host = f.host AND ic.spark_path = f.path
    WHERE f.still_exists AND f.host != %s
      AND ic.verdict = 'match'
    ORDER BY f.size_bytes DESC
    LIMIT 500
"""


def render_cleanup_candidates(conn, out_dir: str) -> tuple[str, dict]:
    with conn.cursor() as cur:
        cur.execute(_CLEANUP_CANDIDATES_SQL, (_site.nas_host(),))
        rows = cur.fetchall()

    lines = []
    lines.append("# HavnVard cleanup / movement CANDIDATE list")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(
        "**RECOMMENDATIONS ONLY -- not instructions.** Every row below is a file on "
        f"{' or '.join(_site.source_hosts())} whose content has been cryptographically verified "
        f"(SHA-256 match) to also exist on {_site.nas_host()} as of the `checked_at` timestamp. "
        "That makes it a *candidate* the operator may choose to review for local cleanup -- "
        "HavnVard never deletes, moves, renames, or overwrites any of these files itself, "
        "and this list carries no authority to do so. Treat `checked_at` as a point-in-time "
        "fact: re-verify before actually acting if much time has passed."
    )
    lines.append("")
    lines.append(f"Total candidates: {len(rows):,}")
    lines.append("")
    lines.append("| host | path | size | verified match on NAS as of |")
    lines.append("|---|---|---|---|")
    for host, path, size_bytes, _inode, _mtime, verdict, checked_at in rows:
        lines.append(f"| {host} | {path} | {_fmt_gb(size_bytes or 0)} | {checked_at} |")
    lines.append("")

    body = "\n".join(lines)
    path = _write(out_dir, f"cleanup_candidates_{_ts()}.md", body)
    return path, {"candidate_count": len(rows)}


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def generate_all(conn, out_dir: str) -> dict:
    """Renders all three reports. Read-only against every scanned filesystem;
    the only writes performed are new .md files under out_dir (created if
    missing) -- no scanned path is ever touched."""
    dedup_path, dedup_stats = render_dedup_report(conn, out_dir)
    integrity_path, integrity_stats = render_nas_integrity_report(conn, out_dir)
    cleanup_path, cleanup_stats = render_cleanup_candidates(conn, out_dir)

    print(f"[report] dedup report:      {dedup_path}", file=__import__("sys").stderr)
    print(f"[report] integrity report:  {integrity_path}", file=__import__("sys").stderr)
    print(f"[report] cleanup candidates: {cleanup_path}", file=__import__("sys").stderr)

    return {
        "dedup_report": dedup_path,
        "nas_integrity_report": integrity_path,
        "cleanup_candidates": cleanup_path,
        "dedup_stats": dedup_stats,
        "integrity_stats": integrity_stats,
        "cleanup_stats": cleanup_stats,
    }


if __name__ == "__main__":
    import sys as _sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import crosshost_verify as _cv  # noqa: E402
    _conn = __import__("psycopg").connect(_cv.get_dsn(), autocommit=False)
    try:
        result = generate_all(_conn, out_dir=_cv.REPORTS_DIR)
        print(result, file=_sys.stderr)
    finally:
        _conn.close()
