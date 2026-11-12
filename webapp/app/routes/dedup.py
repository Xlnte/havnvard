"""View A — DEDUP: duplicate groups for all three devices (server-1, agent-1,
nas-1), one row per (duplicate_group_id, host).

Source: diskaudit.mv_dedup_groups_by_host (materialized, indexed — see
migrations/20260725_diskaudit_havnvard_ui_mv.sql +
migrations/20260725_diskaudit_dedup_classification_evidence_v1.sql). Read-only,
never mutates anything. Hardlink-aware: reclaimable_bytes is already computed as
GREATEST(distinct_inode_count-1,0)*size_bytes — a pure hardlink set
(distinct_inode_count=1) always shows reclaimable=0, never a false-positive
"space to reclaim".

Classification + evidence-strength ladder (owner report, 2026-07-25, three
defects): every group now carries `classification` (OS/system, application,
load-bearing, cache/temp, user data, decommissioned, unknown — worst-case wins
across every member file) and a 7-level `evidence_level` (byte_identical ..
none) plus a separate `evidence_provenance` axis (who computed it). See
app/common.py EVIDENCE_LEVELS / CLASSIFICATIONS for the shared taxonomy used by
both this route and the templates.
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from .. import common, config
from ..db import pool
from ..formatting import human_bytes, human_count
from ..templates import templates

router = APIRouter()

_SORT_MAP = {
    "reclaimable": "reclaimable_bytes",
    "size": "size_bytes",
    "file_count": "file_count",
    "distinct_inodes": "distinct_inode_count",
    "evidence": "evidence_level",
}
_SORTABLE = tuple(_SORT_MAP.keys())

_SELECT_COLS = (
    "duplicate_group_id, host, file_count, distinct_inode_count, size_bytes, "
    "reclaimable_bytes, hash_proven, sample_path, newest_mtime, "
    "classification, evidence_level, evidence_level_label, evidence_provenance"
)


def _filters(qp) -> dict:
    ev_levels = [int(x) for x in common.parse_multi(qp, "evidence_level") if x.isdigit()]
    return {
        "host": common.parse_multi(qp, "host") or list(config.ALL_HOSTS),
        "q": (qp.get("q") or "").strip() or None,
        "size_min": common.parse_int(qp.get("size_min")),
        "min_file_count": common.parse_int(qp.get("min_file_count")),
        # Exact-set ladder filter (checkbox group, e.g. "just levels 2 and 3").
        "evidence_level": ev_levels or None,
        # Convenience "at least this strong" cumulative threshold — lower
        # number = stronger, so "at least N" means evidence_level <= N.
        "evidence_at_least": common.parse_int(qp.get("evidence_at_least")),
        "provenance": common.parse_multi(qp, "provenance") or None,
        # Classification exclude/include multi-select. None == no filter
        # (every classification shown) -- this is how "any" is distinguished
        # from "user explicitly picked every box".
        "classification": common.parse_multi(qp, "classification") or None,
        "sort": qp.get("sort") or "reclaimable:desc",
        "page": common.clamp_page(qp.get("page")),
        "page_size": common.clamp_page_size(qp.get("page_size")),
    }


def _where(f: dict, params: list, *, exclude: tuple[str, ...] = ()) -> str:
    """Builds the WHERE clause. `exclude` lets the KPI breakdown panels compute
    "what would each bucket look like under every OTHER current filter" (e.g.
    the classification breakdown ignores the classification filter itself, so
    a user can see every bucket's count while already filtered to one)."""
    clauses = []
    if f["host"]:
        params.append(f["host"])
        clauses.append(f"host = ANY(${len(params)})")
    if f["q"]:
        params.append(f"%{f['q']}%")
        clauses.append(f"sample_path ILIKE ${len(params)}")
    if f["size_min"] is not None:
        params.append(f["size_min"])
        clauses.append(f"size_bytes >= ${len(params)}")
    if f["min_file_count"] is not None:
        params.append(f["min_file_count"])
        clauses.append(f"file_count >= ${len(params)}")
    if "evidence_level" not in exclude and f["evidence_level"]:
        params.append(f["evidence_level"])
        clauses.append(f"evidence_level = ANY(${len(params)})")
    if "evidence_at_least" not in exclude and f["evidence_at_least"] is not None:
        params.append(f["evidence_at_least"])
        clauses.append(f"evidence_level <= ${len(params)}")
    if "provenance" not in exclude and f["provenance"]:
        params.append(f["provenance"])
        clauses.append(f"evidence_provenance = ANY(${len(params)})")
    if "classification" not in exclude and f["classification"]:
        params.append(f["classification"])
        clauses.append(f"classification = ANY(${len(params)})")
    return " AND ".join(clauses) if clauses else "true"


async def _kpi(conn, f: dict) -> dict:
    params: list = []
    where = _where(f, params)
    row = await conn.fetchrow(
        f"SELECT count(*) AS groups, coalesce(sum(reclaimable_bytes),0) AS reclaim, "
        f"coalesce(sum(file_count),0) AS files, "
        f"count(*) FILTER (WHERE hash_proven) AS hash_proven_groups "
        f"FROM diskaudit.mv_dedup_groups_by_host WHERE {where}",
        *params,
    )
    kpi = dict(row)

    # Classification breakdown -- ignores the classification filter itself so
    # every bucket's count/reclaim under the *other* current filters is always
    # visible (this is what makes "exclude OS/app in one click" legible: you
    # can see exactly how much each bucket is worth before excluding it).
    cparams: list = []
    cwhere = _where(f, cparams, exclude=("classification",))
    crows = await conn.fetch(
        f"SELECT classification, count(*) AS groups, coalesce(sum(reclaimable_bytes),0) AS reclaim "
        f"FROM diskaudit.mv_dedup_groups_by_host WHERE {cwhere} GROUP BY classification",
        *cparams,
    )
    by_class = {r["classification"]: {"groups": r["groups"], "reclaim": r["reclaim"]} for r in crows}
    kpi["by_classification"] = [
        {"key": key, "label": label, "desc": desc,
         "groups": by_class.get(key, {}).get("groups", 0),
         "reclaim": by_class.get(key, {}).get("reclaim", 0)}
        for key, label, desc in common.CLASSIFICATIONS
    ]

    # Evidence-level breakdown -- ignores the evidence filters for the same reason.
    eparams: list = []
    ewhere = _where(f, eparams, exclude=("evidence_level", "evidence_at_least"))
    erows = await conn.fetch(
        f"SELECT evidence_level, count(*) AS groups, coalesce(sum(reclaimable_bytes),0) AS reclaim "
        f"FROM diskaudit.mv_dedup_groups_by_host WHERE {ewhere} GROUP BY evidence_level",
        *eparams,
    )
    by_level = {r["evidence_level"]: {"groups": r["groups"], "reclaim": r["reclaim"]} for r in erows}
    kpi["by_evidence_level"] = [
        {"level": lvl, "key": key, "label": label, "available": available, "desc": desc,
         "groups": by_level.get(lvl, {}).get("groups", 0),
         "reclaim": by_level.get(lvl, {}).get("reclaim", 0)}
        for lvl, key, label, available, desc in common.EVIDENCE_LEVELS
    ]
    return kpi


async def _rows(conn, f: dict) -> tuple[list[dict], int]:
    params: list = []
    where = _where(f, params)
    col, direction = common.parse_sort(f["sort"], _SORT_MAP, "reclaimable")
    total = await conn.fetchval(f"SELECT count(*) FROM diskaudit.mv_dedup_groups_by_host WHERE {where}", *params)
    params2 = list(params) + [f["page_size"], (f["page"] - 1) * f["page_size"]]
    sql = (
        f"SELECT {_SELECT_COLS} "
        f"FROM diskaudit.mv_dedup_groups_by_host WHERE {where} "
        f"ORDER BY {col} {direction} NULLS LAST, duplicate_group_id "
        f"LIMIT ${len(params2) - 1} OFFSET ${len(params2)}"
    )
    rows = await conn.fetch(sql, *params2)
    out = []
    for r in rows:
        d = dict(r)
        d["is_hardlink_only"] = d["distinct_inode_count"] == 1
        d["reclaim_h"] = human_bytes(d["reclaimable_bytes"])
        d["size_h"] = human_bytes(d["size_bytes"])
        d["group_id_short"] = d["duplicate_group_id"][:16] + "…"
        d["provenance_label"] = common.PROVENANCE_LABELS.get(d["evidence_provenance"], d["evidence_provenance"])
        out.append(d)
    return out, int(total)


@router.get("/havnvard/dedup")
async def dedup_page(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        rows, total = await _rows(conn, f)
        kpi = await _kpi(conn, f)
    return templates.TemplateResponse("dedup.html", _ctx(request, f, rows, total, kpi))


@router.get("/havnvard/dedup/table")
async def dedup_table(request: Request):
    if request.headers.get("HX-Request") != "true":
        from fastapi.responses import RedirectResponse
        qs = request.url.query
        return RedirectResponse(f"/havnvard/dedup?{qs}" if qs else "/havnvard/dedup", status_code=303)
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        rows, total = await _rows(conn, f)
        kpi = await _kpi(conn, f)
    resp = templates.TemplateResponse("_dedup_table.html", _ctx(request, f, rows, total, kpi))
    qs = request.url.query
    resp.headers["HX-Push-Url"] = f"/havnvard/dedup?{qs}" if qs else "/havnvard/dedup"
    return resp


def _ctx(request: Request, f: dict, rows: list[dict], total: int, kpi: dict) -> dict:
    # Built from the parsed/normalized filter dict (not raw request.query_params)
    # so multi-valued fields (host, evidence_level, provenance, classification)
    # always round-trip as one comma-joined param in generated links -- see
    # common.parse_multi.
    qp = {
        "host": ",".join(f["host"]),
        "q": f["q"] or "",
        "size_min": f["size_min"] if f["size_min"] is not None else "",
        "min_file_count": f["min_file_count"] if f["min_file_count"] is not None else "",
        "evidence_level": ",".join(str(x) for x in f["evidence_level"]) if f["evidence_level"] else "",
        "evidence_at_least": f["evidence_at_least"] if f["evidence_at_least"] is not None else "",
        "provenance": ",".join(f["provenance"]) if f["provenance"] else "",
        "classification": ",".join(f["classification"]) if f["classification"] else "",
        "sort": f["sort"],
        "page_size": f["page_size"],
    }
    page = common.Page(page=f["page"], page_size=f["page_size"], total=total)
    base = "/havnvard/dedup/table"
    return {
        "request": request,
        "active_tab": "dedup",
        "rows": rows,
        "total": total,
        "human_count": human_count,
        "human_bytes": human_bytes,
        "kpi": kpi,
        "f": f,
        "qp": qp,
        "all_hosts": config.ALL_HOSTS,
        "evidence_levels": common.EVIDENCE_LEVELS,
        "classifications": common.CLASSIFICATIONS,
        # key -> (label, desc) lookup for per-row badges -- plain tuples aren't
        # indexable via Jinja's selectattr('0', ...), so the route pre-builds
        # this dict rather than asking the template to search CLASSIFICATIONS.
        "classification_map": {key: (label, desc) for key, label, desc in common.CLASSIFICATIONS},
        "provenance_labels": common.PROVENANCE_LABELS,
        "all_provenance": list(common.PROVENANCE_LABELS.keys()),
        "sort_links": common.sort_links(base, qp, _SORTABLE, f["sort"]),
        "page_count": page.page_count,
        "prev_url": common.build_url(base, qp, page=max(1, f["page"] - 1)),
        "next_url": common.build_url(base, qp, page=f["page"] + 1),
        "export_csv": common.build_url("/havnvard/dedup/export.csv", qp),
        "export_json": common.build_url("/havnvard/dedup/export.json", qp),
        # One-click "exclude OS/system + application" -- defect 1's exact ask.
        "exclude_os_app_url": common.build_url(
            base, qp, classification=",".join(common.CLASSIFICATION_KEYS_EXCLUDING_OS_APP), page=1
        ),
        "clear_classification_url": common.build_url(base, qp, classification="", page=1),
    }


@router.get("/havnvard/dedup/export.csv")
async def dedup_export_csv(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        params: list = []
        where = _where(f, params)
        col, direction = common.parse_sort(f["sort"], _SORT_MAP, "reclaimable")
        params.append(config.EXPORT_ROW_CAP)
        rows = await conn.fetch(
            f"SELECT {_SELECT_COLS} "
            f"FROM diskaudit.mv_dedup_groups_by_host WHERE {where} "
            f"ORDER BY {col} {direction} NULLS LAST, duplicate_group_id LIMIT ${len(params)}",
            *params,
        )
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["duplicate_group_id", "host", "file_count", "distinct_inode_count",
                "size_bytes", "reclaimable_bytes", "hash_proven", "sample_path", "newest_mtime",
                "classification", "evidence_level", "evidence_level_label", "evidence_provenance",
                "caveat"])
    for r in rows:
        caveat = "HARDLINK SET — deleting a path frees 0 bytes" if r["distinct_inode_count"] == 1 else ""
        w.writerow([r["duplicate_group_id"], r["host"], r["file_count"], r["distinct_inode_count"],
                    r["size_bytes"], r["reclaimable_bytes"], r["hash_proven"], r["sample_path"],
                    r["newest_mtime"], r["classification"], r["evidence_level"],
                    r["evidence_level_label"], r["evidence_provenance"], caveat])
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": "attachment; filename=havnvard_dedup_groups.csv"})


@router.get("/havnvard/dedup/export.json")
async def dedup_export_json(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        params: list = []
        where = _where(f, params)
        col, direction = common.parse_sort(f["sort"], _SORT_MAP, "reclaimable")
        params.append(config.EXPORT_ROW_CAP)
        rows = await conn.fetch(
            f"SELECT {_SELECT_COLS} "
            f"FROM diskaudit.mv_dedup_groups_by_host WHERE {where} "
            f"ORDER BY {col} {direction} NULLS LAST, duplicate_group_id LIMIT ${len(params)}",
            *params,
        )
    import json as _json
    payload = [dict(r) for r in rows]
    for d in payload:
        d["newest_mtime"] = d["newest_mtime"].isoformat() if d["newest_mtime"] else None
        d["reclaim_caveat"] = ("HARDLINK SET — deleting a path frees 0 bytes"
                                if d["distinct_inode_count"] == 1 else None)
    return Response(content=_json.dumps(payload, default=str), media_type="application/json",
                     headers={"Content-Disposition": "attachment; filename=havnvard_dedup_groups.json"})
