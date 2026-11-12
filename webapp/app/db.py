"""HavnVard UI — asyncpg pool against the inventory database, schema diskaudit.

POSTGRES_URL comes from havnvard_site (env, or the site file's env_file). Never inline the
credential, never log it. This app is strictly READ-ONLY against every
diskaudit.* table/view -- it has no INSERT/UPDATE/DELETE path anywhere
(matches the "never mutates a scanned file" constraint one layer up: it also
never mutates the audit data describing those files).
"""
from __future__ import annotations
import functools
import time

import asyncpg

_POOL: asyncpg.Pool | None = None

# Cache of live to_regclass() schema probes (concurrent agent is actively adding
# tables to this schema right now -- see routes/backup.py). Short TTL so a table
# that lands mid-session is picked up without a restart, but we don't re-probe
# on every single request.
_SCHEMA_PROBE_CACHE: dict[str, tuple[bool, float]] = {}
_SCHEMA_PROBE_TTL_S = 30.0


@functools.lru_cache(maxsize=1)
def db_url() -> str:
    import havnvard_site  # noqa: PLC0415  (repo root is on sys.path; see webapp/app/config.py)
    return havnvard_site.require_dsn()


async def init_pool(min_size: int = 2, max_size: int = 10) -> asyncpg.Pool:
    global _POOL
    if _POOL is None:
        _POOL = await asyncpg.create_pool(
            db_url(), min_size=min_size, max_size=max_size,
            server_settings={"search_path": "diskaudit, public"},
        )
    return _POOL


async def close_pool() -> None:
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None


def pool() -> asyncpg.Pool:
    if _POOL is None:
        raise RuntimeError("DB pool not initialized — call init_pool() at app startup")
    return _POOL


async def table_exists(conn: asyncpg.Connection, qualified_name: str) -> bool:
    """Cached to_regclass() probe -- e.g. table_exists(conn, 'diskaudit.backup_coverage').

    Used so the BACKUP view degrades gracefully instead of 500ing while the
    concurrent backup_coverage/backup_scope_rules migration is still landing.
    """
    now = time.monotonic()
    cached = _SCHEMA_PROBE_CACHE.get(qualified_name)
    if cached is not None and (now - cached[1]) < _SCHEMA_PROBE_TTL_S:
        return cached[0]
    exists = bool(await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", qualified_name))
    _SCHEMA_PROBE_CACHE[qualified_name] = (exists, now)
    return exists
