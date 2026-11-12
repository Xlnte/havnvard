"""View — GROUP DETAIL: drill-down into one duplicate group on one host.

Route: /havnvard/group/{duplicate_group_id}?host=<host>  (host required --
duplicate_group_id alone is not a unique key; the same content hash can be
a group independently on more than one host -- see
diskaudit.mv_dedup_groups_by_host's (duplicate_group_id, host) unique key).

Lists every surviving copy (diskaudit.files, still_exists, file_type =
'regular') in the group: full path, size, inode, nlink, mtime, atime,
classification badge (diskaudit.v_file_status), evidence level
(content_sha256 presence + dedup_tool/method), and a KEEP/CANDIDATE
recommendation with an auditable reason -- see ../keeper.py for the ranking
algorithm itself (kept separate: this module is I/O, keeper.py is pure
logic, easy to unit-test/reason about independently).

Read-only. Never mutates diskaudit.files or any scanned filesystem. The
only "action" available is an export (CSV/JSON) of this group's manifest,
for the separate not-yet-built P5/FERJA authorized cleanup process -- same
constraint as the DEDUP/CLEANUP views.

Performance note (measured live 2026-07-25): the group's own member rows
come back in under 1ms via idx_diskaudit_files_dup_group. The "sibling
consolidation" directory-population count is the expensive part -- for a
server-1 group it costs ~2s (a scan bounded by duplicate_group_id IS NOT
NULL, which is only ~30% selective on that host: ~3M of ~4.46M spark rows
already carry a duplicate_group_id, so no index materially narrows it).
For nas-1/agent-1 (the hosts the worked backup-snapshot example lives
on) it is sub-second. Acceptable for a human-triggered, rarely-clicked
detail page -- NOT acceptable for the paginated list views, which is why
those stay on the indexed materialized view instead.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response

from .. import config, keeper
from ..db import pool
from ..formatting import human_bytes, human_count
from ..templates import templates

router = APIRouter()

# diskaudit.v_file_status.file_status -> (css badge suffix, short label). See
# migrations/20260718_diskaudit_classification_v1.sql for the authoritative
# CASE that produces these six values -- kept as an explicit map (not a slug
# transform) so an unrecognized future value renders as "unknown" rather than
# a broken/blank badge.
_STATUS_BADGE = {
    "load-bearing": ("protected", "Load-bearing"),
    "critical-protected": ("protected", "Critical-protected"),
    "orphaned-decommissioned-system": ("decommissioned", "Decommissioned"),
    "possibly-obsolete": ("obsolete", "Possibly obsolete"),
    "stale": ("stale", "Stale"),
    "active": ("active", "Active"),
}


async def _group_totals(conn, duplicate_group_id: str, host: str) -> dict | None:
    row = await conn.fetchrow(
        "SELECT duplicate_group_id, host, file_count, distinct_inode_count, size_bytes, "
        "reclaimable_bytes, hash_proven, sample_path, newest_mtime "
        "FROM diskaudit.mv_dedup_groups_by_host WHERE duplicate_group_id = $1 AND host = $2",
        duplicate_group_id, host,
    )
    return dict(row) if row else None


async def _member_rows(conn, duplicate_group_id: str, host: str) -> list[dict]:
    rows = await conn.fetch(
        "SELECT f.path, f.size_bytes, f.inode, f.nlink, f.mtime, f.atime, f.owner_name, "
        "       f.content_sha256, f.dedup_tool, f.dedup_method, f.hash_source, "
        "       vfs.file_status, vfs.is_load_bearing, vfs.is_critical, vfs.is_decommissioned, "
        "       vfs.is_atime_old, vfs.computed_at AS status_computed_at "
        "FROM diskaudit.files f "
        "LEFT JOIN diskaudit.v_file_status vfs ON vfs.host = f.host AND vfs.path = f.path "
        "WHERE f.host = $1 AND f.duplicate_group_id = $2 AND f.still_exists AND f.file_type = 'regular' "
        "ORDER BY f.path",
        host, duplicate_group_id,
    )
    return [dict(r) for r in rows]


async def _sibling_counts(conn, host: str, duplicate_group_id: str, dirpaths: list[str]) -> dict[str, int]:
    """How many OTHER duplicated files (any group, excluding this one) already
    live in each candidate directory on this host -- the honest, computed
    basis for the sibling-consolidation rule. See module docstring for the
    query-shape performance note."""
    if not dirpaths:
        return {}
    same_dir = [f"{d}/%" for d in dirpaths]
    sub_dir = [f"{d}/%/%" for d in dirpaths]
    rows = await conn.fetch(
        "SELECT regexp_replace(path, '/[^/]+$', '') AS dirpath, count(*) AS n "
        "FROM diskaudit.files "
        "WHERE host = $1 AND duplicate_group_id IS NOT NULL AND duplicate_group_id <> $2 "
        "  AND still_exists AND file_type = 'regular' "
        "  AND path LIKE ANY($3::text[]) AND NOT (path LIKE ANY($4::text[])) "
        "GROUP BY 1",
        host, duplicate_group_id, same_dir, sub_dir,
    )
    return {r["dirpath"]: int(r["n"]) for r in rows}


async def _load(conn, duplicate_group_id: str, host: str) -> dict:
    totals = await _group_totals(conn, duplicate_group_id, host)
    if totals is None:
        raise HTTPException(status_code=404, detail="No such duplicate group on that host.")
    members = await _member_rows(conn, duplicate_group_id, host)
    dirpaths = sorted({keeper.dirname_of(m["path"]) for m in members})
    sib = await _sibling_counts(conn, host, duplicate_group_id, dirpaths)
    ranked = keeper.rank_group(members, sib)

    for r in ranked["annotated"]:
        r["size_h"] = human_bytes(r["size_bytes"])
        r["reclaim_h"] = human_bytes(r["reclaim_bytes"])
        r["evidence"] = ("hash-proven (SHA-256)" if r.get("content_sha256")
                          else (f"{r['dedup_tool']}/{r['dedup_method']} (no content hash on this copy)"
                                if r.get("dedup_tool") else "no evidence recorded"))
        r["evidence_badge"] = "hash-proven" if r.get("content_sha256") else "guess"
        status_key = r.get("file_status")
        suffix, label = _STATUS_BADGE.get(status_key, ("unknown", status_key or "Unclassified"))
        r["status_badge"] = suffix
        r["status_label"] = label
        r["is_protected_row"] = suffix == "protected"

    checked_sum = sum(r["reclaim_bytes"] for r in ranked["annotated"])
    return {
        "totals": totals,
        "totals_size_h": human_bytes(totals["size_bytes"]),
        "totals_reclaim_h": human_bytes(totals["reclaimable_bytes"]),
        "is_hardlink_only": totals["distinct_inode_count"] == 1,
        "ranked": ranked,
        "checked_sum_h": human_bytes(checked_sum),
        "reclaim_matches": checked_sum == totals["reclaimable_bytes"],
    }


def _ctx(request: Request, duplicate_group_id: str, host: str, data: dict) -> dict:
    return {
        "request": request,
        "active_tab": "dedup",
        "duplicate_group_id": duplicate_group_id,
        "host": host,
        "human_count": human_count,
        "human_bytes": human_bytes,
        "back_url": f"/havnvard/dedup?host={host}",
        "export_csv": f"/havnvard/group/{duplicate_group_id}/export.csv?host={host}",
        "export_json": f"/havnvard/group/{duplicate_group_id}/export.json?host={host}",
        **data,
    }


@router.get("/havnvard/group/{duplicate_group_id}")
async def group_detail(duplicate_group_id: str, request: Request, host: str = Query(...)):
    if host not in config.ALL_HOSTS:
        raise HTTPException(status_code=400, detail=f"Unknown host {host!r}")
    p = pool()
    async with p.acquire() as conn:
        data = await _load(conn, duplicate_group_id, host)
    return templates.TemplateResponse("group_detail.html", _ctx(request, duplicate_group_id, host, data))


@router.get("/havnvard/group/{duplicate_group_id}/export.csv")
async def group_detail_export_csv(duplicate_group_id: str, host: str = Query(...)):
    if host not in config.ALL_HOSTS:
        raise HTTPException(status_code=400, detail=f"Unknown host {host!r}")
    p = pool()
    async with p.acquire() as conn:
        data = await _load(conn, duplicate_group_id, host)
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["duplicate_group_id", "host", "path", "size_bytes", "inode", "nlink", "mtime", "atime",
                "file_status", "evidence", "verdict", "reason", "reclaim_bytes"])
    for r in data["ranked"]["annotated"]:
        w.writerow([duplicate_group_id, host, r["path"], r["size_bytes"], r["inode"], r["nlink"],
                    r["mtime"], r["atime"], r.get("file_status") or "", r["evidence"], r["verdict"],
                    r["reason"], r["reclaim_bytes"]])
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": f"attachment; filename=havnvard_group_{duplicate_group_id[:16]}_{host}.csv"})


@router.get("/havnvard/group/{duplicate_group_id}/export.json")
async def group_detail_export_json(duplicate_group_id: str, host: str = Query(...)):
    if host not in config.ALL_HOSTS:
        raise HTTPException(status_code=400, detail=f"Unknown host {host!r}")
    p = pool()
    async with p.acquire() as conn:
        data = await _load(conn, duplicate_group_id, host)
    import json as _json
    payload = {
        "duplicate_group_id": duplicate_group_id,
        "host": host,
        "dated_snapshot_series": data["ranked"]["dated_snapshot"],
        "keep_path": data["ranked"]["keep_path"],
        "headline": data["ranked"]["headline"],
        "group_reclaimable_bytes": data["totals"]["reclaimable_bytes"],
        "is_hardlink_only": data["is_hardlink_only"],
        "copies": data["ranked"]["annotated"],
    }
    return Response(content=_json.dumps(payload, default=str), media_type="application/json",
                     headers={"Content-Disposition": f"attachment; filename=havnvard_group_{duplicate_group_id[:16]}_{host}.json"})
