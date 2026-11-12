"""Health check + census landing. Mirrors the house pattern's /health route."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..db import pool, table_exists

router = APIRouter()


@router.get("/havnvard/health")
async def health():
    try:
        p = pool()
        async with p.acquire() as conn:
            await conn.fetchval("SELECT 1")
            coverage_live = await table_exists(conn, "diskaudit.backup_coverage")
        return JSONResponse({"status": "ok", "db": "ok", "backup_coverage_table": coverage_live})
    except Exception as exc:  # noqa: BLE001 — health endpoint reports, never raises 500
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)
