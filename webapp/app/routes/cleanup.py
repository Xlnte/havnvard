"""View B — CLEANUP: files on the server + agent-1 that have duplicates elsewhere
in the same host's duplicate_group_id (candidates to remove -- never removed
by this app).

Per-file rows from diskaudit.files, enriched via a join to
diskaudit.mv_dedup_groups_by_host (same host + duplicate_group_id) so every
row carries its group's hardlink-aware reclaim figure and hash-proven flag
without recomputing either. By default, pure hardlink-only groups
(distinct_inode_count = 1, i.e. every "duplicate" is actually the same inode
via st_nlink) are EXCLUDED from the default listing because removing any path
in such a set frees zero bytes -- they are informational only and shown solely
via the "include hardlink-only sets" toggle, always carrying the hardlink
caveat badge.

KPI totals are computed at GROUP granularity (one reclaim figure counted once
per (duplicate_group_id, host), never once per file row) -- summing per file
row would double/triple count the same reclaimable bytes for every member of
a multi-file group.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from .. import common, config
from ..db import pool
from ..formatting import human_bytes, human_count
from ..templates import templates

router = APIRouter()

_SORT_MAP = {
    "size": "f.size_bytes",
    "reclaim": "g.reclaimable_bytes",
    "mtime": "f.mtime",
    "path": "f.path",
}
_SORTABLE = tuple(_SORT_MAP.keys())


def _filters(qp) -> dict:
    host = common.parse_multi(qp, "host") or list(config.SOURCE_HOSTS)
    host = [h for h in host if h in config.SOURCE_HOSTS] or list(config.SOURCE_HOSTS)
    return {
        "host": host,
        "q": (qp.get("q") or "").strip() or None,
        "size_min": common.parse_int(qp.get("size_min")),
        "hash_proven": common.parse_tristate(qp.get("hash_proven")),
        "include_hardlink_only": common.parse_tristate(qp.get("include_hardlink_only")) or False,
        "sort": qp.get("sort") or "reclaim:desc",
        "page": common.clamp_page(qp.get("page")),
        "page_size": common.clamp_page_size(qp.get("page_size")),
    }


def _group_where(f: dict, params: list, alias: str = "g") -> str:
    """Predicate expressed purely in terms of mv_dedup_groups_by_host columns
    (aliased g) -- valid at both group granularity (KPI) and joined granularity
    (file rows), since size_bytes/hash_proven are identical for every member of
    a content-duplicate group."""
    clauses = [f"{alias}.host = ANY(${len(params) + 1})"]
    params.append(f["host"])
    if f["size_min"] is not None:
        params.append(f["size_min"])
        clauses.append(f"{alias}.size_bytes >= ${len(params)}")
    if f["hash_proven"] is not None:
        params.append(f["hash_proven"])
        clauses.append(f"{alias}.hash_proven = ${len(params)}")
    if not f["include_hardlink_only"]:
        clauses.append(f"{alias}.distinct_inode_count > 1")
    return " AND ".join(clauses)


async def _kpi(conn, f: dict) -> dict:
    params: list = []
    where = _group_where(f, params, "g")
    row = await conn.fetchrow(
        f"SELECT count(*) AS groups, coalesce(sum(reclaimable_bytes),0) AS reclaim, "
        f"coalesce(sum(file_count),0) AS candidate_files "
        f"FROM diskaudit.mv_dedup_groups_by_host g WHERE {where}",
        *params,
    )
    return dict(row)


async def _rows(conn, f: dict) -> tuple[list[dict], int]:
    params: list = []
    gwhere = _group_where(f, params, "g")
    fclauses = [
        "f.still_exists", "f.file_type = 'regular'", "f.duplicate_group_id IS NOT NULL",
    ]
    if f["q"]:
        params.append(f"%{f['q']}%")
        fclauses.append(f"f.path ILIKE ${len(params)}")
    fwhere = " AND ".join(fclauses)
    col, direction = common.parse_sort(f["sort"], _SORT_MAP, "reclaim")

    base = (
        "FROM diskaudit.files f "
        "JOIN diskaudit.mv_dedup_groups_by_host g "
        "  ON g.duplicate_group_id = f.duplicate_group_id AND g.host = f.host "
        f"WHERE {fwhere} AND {gwhere}"
    )
    total = await conn.fetchval(f"SELECT count(*) {base}", *params)
    params2 = list(params) + [f["page_size"], (f["page"] - 1) * f["page_size"]]
    sql = (
        f"SELECT f.host, f.path, f.size_bytes, f.inode, f.nlink, f.mtime, f.duplicate_group_id, "
        f"g.file_count AS group_file_count, g.distinct_inode_count AS group_distinct_inodes, "
        f"g.reclaimable_bytes AS group_reclaimable_bytes, g.hash_proven, "
        f"g.classification, g.evidence_level, g.evidence_level_label, g.evidence_provenance "
        f"{base} "
        f"ORDER BY {col} {direction} NULLS LAST, f.duplicate_group_id, f.host, f.path "
        f"LIMIT ${len(params2) - 1} OFFSET ${len(params2)}"
    )
    rows = await conn.fetch(sql, *params2)
    out = []
    # Alternating per-GROUP row banding (owner ask, 2026-07-25: "all the files
    # separate slightly different ROW colors... row duplicated file" -- every
    # row belonging to the same duplicate_group_id shares a tint; the tint
    # flips on the next group). Ties on the primary sort column are common
    # (reclaimable_bytes/size_bytes are identical across a group's members),
    # which is exactly why duplicate_group_id was added to ORDER BY above --
    # without it, a group's rows could interleave with another's and this
    # transition-count would band mid-group. Never the only signal for
    # anything meaningful: banding is decorative grouping, not a verdict --
    # verdicts/classification stay as explicit text badges elsewhere.
    prev_group = None
    band = 0
    for r in rows:
        d = dict(r)
        d["is_hardlink_only"] = d["group_distinct_inodes"] == 1
        d["size_h"] = human_bytes(d["size_bytes"])
        d["group_reclaim_h"] = human_bytes(d["group_reclaimable_bytes"])
        d["provenance_label"] = common.PROVENANCE_LABELS.get(d["evidence_provenance"], d["evidence_provenance"])
        if d["duplicate_group_id"] != prev_group:
            band ^= 1
            prev_group = d["duplicate_group_id"]
        d["band_class"] = "band-a" if band == 0 else "band-b"
        out.append(d)
    return out, int(total)


@router.get("/havnvard/cleanup")
async def cleanup_page(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        rows, total = await _rows(conn, f)
        kpi = await _kpi(conn, f)
    return templates.TemplateResponse("cleanup.html", _ctx(request, f, rows, total, kpi))


@router.get("/havnvard/cleanup/table")
async def cleanup_table(request: Request):
    if request.headers.get("HX-Request") != "true":
        from fastapi.responses import RedirectResponse
        qs = request.url.query
        return RedirectResponse(f"/havnvard/cleanup?{qs}" if qs else "/havnvard/cleanup", status_code=303)
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        rows, total = await _rows(conn, f)
        kpi = await _kpi(conn, f)
    resp = templates.TemplateResponse("_cleanup_table.html", _ctx(request, f, rows, total, kpi))
    qs = request.url.query
    resp.headers["HX-Push-Url"] = f"/havnvard/cleanup?{qs}" if qs else "/havnvard/cleanup"
    return resp


def _ctx(request: Request, f: dict, rows: list[dict], total: int, kpi: dict) -> dict:
    qp = {
        "host": ",".join(f["host"]),
        "q": f["q"] or "",
        "size_min": f["size_min"] if f["size_min"] is not None else "",
        "hash_proven": ("true" if f["hash_proven"] is True else "false" if f["hash_proven"] is False else "any"),
        "include_hardlink_only": "true" if f["include_hardlink_only"] else "false",
        "sort": f["sort"],
        "page_size": f["page_size"],
    }
    page = common.Page(page=f["page"], page_size=f["page_size"], total=total)
    return {
        "request": request,
        "active_tab": "cleanup",
        "rows": rows,
        "total": total,
        "human_count": human_count,
        "human_bytes": human_bytes,
        "kpi": kpi,
        "f": f,
        "qp": qp,
        "source_hosts": config.SOURCE_HOSTS,
        # Classification/evidence are read-only display here (defect 1 ask is
        # satisfied by surfacing dedup.py's already-computed group columns via
        # the existing join) -- the filterable ladder/classification UI lives
        # on the DEDUP view; CLEANUP keeps its existing hash_proven filter.
        "classification_map": {key: (label, desc) for key, label, desc in common.CLASSIFICATIONS},
        "provenance_labels": common.PROVENANCE_LABELS,
        "sort_links": common.sort_links("/havnvard/cleanup/table", qp, _SORTABLE, f["sort"]),
        "page_count": page.page_count,
        "prev_url": common.build_url("/havnvard/cleanup/table", qp, page=max(1, f["page"] - 1)),
        "next_url": common.build_url("/havnvard/cleanup/table", qp, page=f["page"] + 1),
        "export_csv": common.build_url("/havnvard/cleanup/export.csv", qp),
        "export_json": common.build_url("/havnvard/cleanup/export.json", qp),
    }


def _export_sql(f: dict, params: list) -> str:
    gwhere = _group_where(f, params, "g")
    fclauses = ["f.still_exists", "f.file_type = 'regular'", "f.duplicate_group_id IS NOT NULL"]
    if f["q"]:
        params.append(f"%{f['q']}%")
        fclauses.append(f"f.path ILIKE ${len(params)}")
    fwhere = " AND ".join(fclauses)
    col, direction = common.parse_sort(f["sort"], _SORT_MAP, "reclaim")
    params.append(config.EXPORT_ROW_CAP)
    return (
        f"SELECT f.host, f.path, f.size_bytes, f.inode, f.nlink, f.mtime, f.duplicate_group_id, "
        f"g.file_count AS group_file_count, g.distinct_inode_count AS group_distinct_inodes, "
        f"g.reclaimable_bytes AS group_reclaimable_bytes, g.hash_proven, "
        f"g.classification, g.evidence_level, g.evidence_level_label, g.evidence_provenance "
        f"FROM diskaudit.files f JOIN diskaudit.mv_dedup_groups_by_host g "
        f"  ON g.duplicate_group_id = f.duplicate_group_id AND g.host = f.host "
        f"WHERE {fwhere} AND {gwhere} "
        f"ORDER BY {col} {direction} NULLS LAST, f.duplicate_group_id, f.host, f.path LIMIT ${len(params)}"
    )


@router.get("/havnvard/cleanup/export.csv")
async def cleanup_export_csv(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        params: list = []
        sql = _export_sql(f, params)
        rows = await conn.fetch(sql, *params)
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "path", "size_bytes", "inode", "nlink", "mtime", "duplicate_group_id",
                "group_file_count", "group_distinct_inodes", "group_reclaimable_bytes",
                "hash_proven", "classification", "evidence_level", "evidence_level_label",
                "evidence_provenance", "caveat"])
    for r in rows:
        caveat = "HARDLINK SET — deleting a path frees 0 bytes" if r["group_distinct_inodes"] == 1 else ""
        w.writerow([r["host"], r["path"], r["size_bytes"], r["inode"], r["nlink"], r["mtime"],
                    r["duplicate_group_id"], r["group_file_count"], r["group_distinct_inodes"],
                    r["group_reclaimable_bytes"], r["hash_proven"], r["classification"],
                    r["evidence_level"], r["evidence_level_label"], r["evidence_provenance"], caveat])
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": "attachment; filename=havnvard_cleanup_candidates.csv"})


@router.get("/havnvard/cleanup/export.json")
async def cleanup_export_json(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        params: list = []
        sql = _export_sql(f, params)
        rows = await conn.fetch(sql, *params)
    import json as _json
    payload = [dict(r) for r in rows]
    for d in payload:
        d["mtime"] = d["mtime"].isoformat() if d["mtime"] else None
        d["reclaim_caveat"] = ("HARDLINK SET — deleting a path frees 0 bytes"
                                if d["group_distinct_inodes"] == 1 else None)
    return Response(content=_json.dumps(payload, default=str), media_type="application/json",
                     headers={"Content-Disposition": "attachment; filename=havnvard_cleanup_candidates.json"})
