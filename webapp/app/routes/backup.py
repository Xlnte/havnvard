"""View C — BACKUP: files on the server + agent-1 NOT safely on the NAS (candidates
to copy).

Primary source: diskaudit.backup_coverage (host, path, classification,
match_method) -- the concurrent agent's coverage table, landed live during
this build (confirmed via to_regclass() 2026-07-25: table + backup_scope_rules
both exist). classification IN ('NOT_BACKED_UP','BACKED_UP_UNVERIFIED',
'EXCLUDED') with match_method IN ('none','path_size_mtime') observed so far --
no 'hash_proven'/'restic_snapshot_listing' rows yet, and only agent-1 has been
evaluated (server-1: 0 rows) as of this build. The KPI banner surfaces that
per-host evaluation gap explicitly so it never reads as "spark is all safe".

Fallback source (used only if backup_coverage is ever absent, e.g. schema
rolled back): diskaudit.integrity_checks -- a much narrower, hash-proven-only
sample (~23k rows total vs 8.5M+ files) produced by crosshost_verify.py.
Never silently mixed with the primary source; the view banner states which
source is active.

Every row here is read-only evidence about a file's backup status. This view
NEVER offers delete/move -- see FEATURES.md "Absolute constraint".
"""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from .. import common, config
from ..db import pool, table_exists
from ..formatting import human_bytes, human_count
from ..templates import templates

router = APIRouter()

_COVERAGE_TABLE = "diskaudit.backup_coverage"

_SORT_MAP_COVERAGE = {
    "size": "size_bytes",
    "checked_at": "checked_at",
    "path": "path",
}
_SORT_MAP_FALLBACK = {
    "size": "size_bytes",
    "checked_at": "checked_at",
    "path": "spark_path",
}

_DEFAULT_CLASSIFICATIONS = ("NOT_BACKED_UP", "BACKED_UP_UNVERIFIED")
_ALL_CLASSIFICATIONS = ("NOT_BACKED_UP", "BACKED_UP_UNVERIFIED", "EXCLUDED", "BACKED_UP_VERIFIED")

_FALLBACK_VERDICTS = ("missing_dest", "mismatch", "unreadable_source", "unreadable_dest")


def _filters(qp) -> dict:
    host = common.parse_multi(qp, "host") or list(config.SOURCE_HOSTS)
    host = [h for h in host if h in config.SOURCE_HOSTS] or list(config.SOURCE_HOSTS)
    classification = common.parse_multi(qp, "classification") or list(_DEFAULT_CLASSIFICATIONS)
    return {
        "host": host,
        "classification": classification,
        "q": (qp.get("q") or "").strip() or None,
        "size_min": common.parse_int(qp.get("size_min")),
        "sort": qp.get("sort") or "size:desc",
        "page": common.clamp_page(qp.get("page")),
        "page_size": common.clamp_page_size(qp.get("page_size")),
    }


# ---------------------------------------------------------------- primary ---

def _where_coverage(f: dict, params: list) -> str:
    clauses = []
    params.append(f["host"])
    clauses.append(f"host = ANY(${len(params)})")
    if f["classification"]:
        params.append(f["classification"])
        clauses.append(f"classification = ANY(${len(params)})")
    if f["q"]:
        params.append(f"%{f['q']}%")
        clauses.append(f"path ILIKE ${len(params)}")
    if f["size_min"] is not None:
        params.append(f["size_min"])
        clauses.append(f"size_bytes >= ${len(params)}")
    return " AND ".join(clauses)


def _evidence_level(match_method: str | None) -> str:
    if match_method in ("hash_proven", "restic_snapshot_listing"):
        return "hash_proven"
    if match_method == "path_size_mtime":
        return "guess"
    return "no_evidence"


async def _rows_coverage(conn, f: dict) -> tuple[list[dict], int]:
    params: list = []
    where = _where_coverage(f, params)
    col, direction = common.parse_sort(f["sort"], _SORT_MAP_COVERAGE, "size")
    total = await conn.fetchval(f"SELECT count(*) FROM diskaudit.backup_coverage WHERE {where}", *params)
    params2 = list(params) + [f["page_size"], (f["page"] - 1) * f["page_size"]]
    sql = (
        f"SELECT host, path, size_bytes, inode, nlink, classification, match_method, "
        f"matched_nas_host, matched_nas_path, matched_restic_target, checked_at, notes "
        f"FROM diskaudit.backup_coverage WHERE {where} "
        f"ORDER BY {col} {direction} NULLS LAST, host, path "
        f"LIMIT ${len(params2) - 1} OFFSET ${len(params2)}"
    )
    rows = await conn.fetch(sql, *params2)
    out = []
    for r in rows:
        d = dict(r)
        d["evidence"] = _evidence_level(d["match_method"])
        d["size_h"] = human_bytes(d["size_bytes"])
        out.append(d)
    return out, int(total)


async def _kpi_coverage(conn, f: dict) -> dict:
    params: list = []
    where = _where_coverage(f, params)
    row = await conn.fetchrow(
        f"SELECT count(*) AS candidates, coalesce(sum(size_bytes),0) AS at_risk_bytes "
        f"FROM diskaudit.backup_coverage WHERE {where}", *params,
    )
    kpi = dict(row)
    # Coverage-completeness banner: how many rows exist per source host in
    # backup_coverage at all (any classification), vs how many still_exists
    # files diskaudit.files has for that host -- makes an unevaluated host
    # (e.g. server-1 mid-build) visibly obvious rather than reading as "all
    # safe".
    per_host = await conn.fetch(
        "SELECT host, count(*) AS evaluated FROM diskaudit.backup_coverage "
        "WHERE host = ANY($1) GROUP BY host", list(config.SOURCE_HOSTS),
    )
    evaluated = {r["host"]: r["evaluated"] for r in per_host}
    universe = await conn.fetch(
        "SELECT host, count(*) AS total FROM diskaudit.files "
        "WHERE host = ANY($1) AND still_exists AND file_type = 'regular' GROUP BY host",
        list(config.SOURCE_HOSTS),
    )
    total_files = {r["host"]: r["total"] for r in universe}
    kpi["coverage_by_host"] = [
        {
            "host": h,
            "evaluated": evaluated.get(h, 0),
            "total": total_files.get(h, 0),
            "pct": round(100.0 * evaluated.get(h, 0) / total_files[h], 1) if total_files.get(h) else 0.0,
        }
        for h in config.SOURCE_HOSTS
    ]
    return kpi


# --------------------------------------------------------------- fallback ---

def _where_fallback(f: dict, params: list) -> str:
    clauses = []
    params.append(f["host"])
    clauses.append(f"spark_host = ANY(${len(params)})")
    params.append(list(_FALLBACK_VERDICTS))
    clauses.append(f"verdict = ANY(${len(params)})")
    if f["q"]:
        params.append(f"%{f['q']}%")
        clauses.append(f"spark_path ILIKE ${len(params)}")
    if f["size_min"] is not None:
        params.append(f["size_min"])
        clauses.append(f"size_bytes >= ${len(params)}")
    return " AND ".join(clauses)


async def _rows_fallback(conn, f: dict) -> tuple[list[dict], int]:
    """Narrow, hash-proven-only sample from integrity_checks. Latest check per
    (spark_host, spark_path) via DISTINCT ON, since a path can be re-checked."""
    params: list = []
    where = _where_fallback(f, params)
    col, direction = common.parse_sort(f["sort"], _SORT_MAP_FALLBACK, "size")
    base = (
        f"SELECT DISTINCT ON (spark_host, spark_path) spark_host, spark_path, size_bytes, "
        f"verdict, checked_at, notes "
        f"FROM diskaudit.integrity_checks WHERE {where} "
        f"ORDER BY spark_host, spark_path, checked_at DESC"
    )
    total = await conn.fetchval(f"SELECT count(*) FROM ({base}) s", *params)
    params2 = list(params) + [f["page_size"], (f["page"] - 1) * f["page_size"]]
    sql = (
        f"SELECT * FROM ({base}) s ORDER BY {col} {direction} NULLS LAST, spark_path "
        f"LIMIT ${len(params2) - 1} OFFSET ${len(params2)}"
    )
    rows = await conn.fetch(sql, *params2)
    out = []
    for r in rows:
        d = dict(r)
        d["host"] = d.pop("spark_host")
        d["path"] = d.pop("spark_path")
        d["classification"] = d["verdict"]
        # match/mismatch had both hashes computed and compared -> proven evidence.
        # missing_dest/unreadable_* had no comparison possible -> no evidence either way.
        d["evidence"] = "hash_proven" if d["verdict"] in ("match", "mismatch") else "no_evidence"
        d["match_method"] = "hash_proven" if d["evidence"] == "hash_proven" else "none"
        d["size_h"] = human_bytes(d["size_bytes"])
        out.append(d)
    return out, int(total)


async def _kpi_fallback(conn, f: dict) -> dict:
    params: list = []
    where = _where_fallback(f, params)
    row = await conn.fetchrow(
        f"SELECT count(*) AS candidates, coalesce(sum(size_bytes),0) AS at_risk_bytes "
        f"FROM diskaudit.integrity_checks WHERE {where}", *params,
    )
    kpi = dict(row)
    total_checked = await conn.fetchval(
        "SELECT count(DISTINCT (spark_host, spark_path)) FROM diskaudit.integrity_checks WHERE spark_host = ANY($1)",
        list(config.SOURCE_HOSTS),
    )
    universe = await conn.fetch(
        "SELECT host, count(*) AS total FROM diskaudit.files "
        "WHERE host = ANY($1) AND still_exists AND file_type = 'regular' GROUP BY host",
        list(config.SOURCE_HOSTS),
    )
    total_files = sum(r["total"] for r in universe) or 1
    kpi["coverage_by_host"] = None
    kpi["sample_pct"] = round(100.0 * total_checked / total_files, 3)
    kpi["total_checked"] = total_checked
    kpi["total_files"] = total_files
    return kpi


# ------------------------------------------------------------------ views ---

async def _load(conn, f: dict) -> tuple[str, list[dict], int, dict]:
    if await table_exists(conn, _COVERAGE_TABLE):
        rows, total = await _rows_coverage(conn, f)
        kpi = await _kpi_coverage(conn, f)
        return "coverage", rows, total, kpi
    rows, total = await _rows_fallback(conn, f)
    kpi = await _kpi_fallback(conn, f)
    return "fallback", rows, total, kpi


@router.get("/havnvard/backup")
async def backup_page(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        source, rows, total, kpi = await _load(conn, f)
    return templates.TemplateResponse("backup.html", _ctx(request, f, source, rows, total, kpi))


@router.get("/havnvard/backup/table")
async def backup_table(request: Request):
    if request.headers.get("HX-Request") != "true":
        from fastapi.responses import RedirectResponse
        qs = request.url.query
        return RedirectResponse(f"/havnvard/backup?{qs}" if qs else "/havnvard/backup", status_code=303)
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        source, rows, total, kpi = await _load(conn, f)
    resp = templates.TemplateResponse("_backup_table.html", _ctx(request, f, source, rows, total, kpi))
    qs = request.url.query
    resp.headers["HX-Push-Url"] = f"/havnvard/backup?{qs}" if qs else "/havnvard/backup"
    return resp


def _ctx(request: Request, f: dict, source: str, rows: list[dict], total: int, kpi: dict) -> dict:
    qp = {
        "host": ",".join(f["host"]),
        "classification": ",".join(f["classification"]),
        "q": f["q"] or "",
        "size_min": f["size_min"] if f["size_min"] is not None else "",
        "sort": f["sort"],
        "page_size": f["page_size"],
    }
    sort_map = _SORT_MAP_COVERAGE if source == "coverage" else _SORT_MAP_FALLBACK
    page = common.Page(page=f["page"], page_size=f["page_size"], total=total)
    return {
        "request": request,
        "active_tab": "backup",
        "rows": rows,
        "total": total,
        "source": source,
        "human_count": human_count,
        "human_bytes": human_bytes,
        "kpi": kpi,
        "f": f,
        "qp": qp,
        "source_hosts": config.SOURCE_HOSTS,
        "all_classifications": _ALL_CLASSIFICATIONS,
        "sort_links": common.sort_links("/havnvard/backup/table", qp, tuple(sort_map.keys()), f["sort"]),
        "page_count": page.page_count,
        "prev_url": common.build_url("/havnvard/backup/table", qp, page=max(1, f["page"] - 1)),
        "next_url": common.build_url("/havnvard/backup/table", qp, page=f["page"] + 1),
        "export_csv": common.build_url("/havnvard/backup/export.csv", qp),
        "export_json": common.build_url("/havnvard/backup/export.json", qp),
    }


@router.get("/havnvard/backup/export.csv")
async def backup_export_csv(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        if await table_exists(conn, _COVERAGE_TABLE):
            params: list = []
            where = _where_coverage(f, params)
            col, direction = common.parse_sort(f["sort"], _SORT_MAP_COVERAGE, "size")
            params.append(config.EXPORT_ROW_CAP)
            rows = await conn.fetch(
                f"SELECT host, path, size_bytes, classification, match_method, "
                f"matched_nas_host, matched_nas_path, checked_at "
                f"FROM diskaudit.backup_coverage WHERE {where} "
                f"ORDER BY {col} {direction} NULLS LAST LIMIT ${len(params)}", *params,
            )
            header = ["host", "path", "size_bytes", "classification", "match_method",
                      "matched_nas_host", "matched_nas_path", "checked_at", "evidence"]
            data = [[r["host"], r["path"], r["size_bytes"], r["classification"], r["match_method"],
                     r["matched_nas_host"], r["matched_nas_path"], r["checked_at"],
                     _evidence_level(r["match_method"])] for r in rows]
        else:
            params: list = []
            where = _where_fallback(f, params)
            col, direction = common.parse_sort(f["sort"], _SORT_MAP_FALLBACK, "size")
            base = (
                f"SELECT DISTINCT ON (spark_host, spark_path) spark_host, spark_path, size_bytes, "
                f"verdict, checked_at FROM diskaudit.integrity_checks WHERE {where} "
                f"ORDER BY spark_host, spark_path, checked_at DESC"
            )
            params.append(config.EXPORT_ROW_CAP)
            rows = await conn.fetch(f"SELECT * FROM ({base}) s ORDER BY {col} {direction} NULLS LAST LIMIT ${len(params)}", *params)
            header = ["host", "path", "size_bytes", "verdict", "checked_at", "evidence"]
            data = [[r["spark_host"], r["spark_path"], r["size_bytes"], r["verdict"], r["checked_at"],
                     "hash_proven" if r["verdict"] in ("match", "mismatch") else "no_evidence"] for r in rows]
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(data)
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": "attachment; filename=havnvard_backup_candidates.csv"})


@router.get("/havnvard/backup/export.json")
async def backup_export_json(request: Request):
    f = _filters(request.query_params)
    p = pool()
    async with p.acquire() as conn:
        source, rows, _total, _kpi = await _load(conn, {**f, "page": 1, "page_size": config.EXPORT_ROW_CAP})
    import json as _json
    payload = []
    for d in rows:
        e = dict(d)
        if e.get("checked_at"):
            e["checked_at"] = e["checked_at"].isoformat()
        payload.append(e)
    return Response(content=_json.dumps(payload, default=str), media_type="application/json",
                     headers={"Content-Disposition": "attachment; filename=havnvard_backup_candidates.json"})
