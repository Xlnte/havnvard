"""HavnVard UI (diskaudit webapp) — FastAPI app entrypoint.

Stack: FastAPI + Jinja2 + HTMX SSR. No client-side JS framework, no build
step, no CDN assets (htmx.min.js served from /static). Binds 127.0.0.1:9108;
fronted by Caddy Tailnet-only at :9457 (see webapp/systemd/ and the Caddyfile
block added alongside this app).

Strictly read-only against every diskaudit.* table/view -- no route in this
app issues INSERT/UPDATE/DELETE, and no template renders a delete/move
control anywhere (see FEATURES.md "Absolute constraint").

Run: uvicorn app.main:app --host 127.0.0.1 --port 9108   (from webapp/ dir)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

try:   # optional shared chrome (forge_core); the UI works without it (3.0.0)
    from forge_core.router import chrome_router
except ImportError:
    chrome_router = None

from .db import close_pool, init_pool
from .routes import backup, cleanup, dedup, group_detail, health

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_pool()
    try:
        yield
    finally:
        await close_pool()


app = FastAPI(title="HavnVard", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(__file__.rsplit("/main.py", 1)[0] + "/static")), name="static")

app.include_router(dedup.router)
app.include_router(cleanup.router)
app.include_router(group_detail.router)
app.include_router(backup.router)
app.include_router(health.router)
if chrome_router is not None:
    app.include_router(chrome_router)  # GET /chrome/modules.json — forge_core nav data (INFRA-51)


@app.get("/")
async def root():
    return RedirectResponse("/havnvard/dedup")
