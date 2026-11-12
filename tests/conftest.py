"""Shared fixtures for the nas_trigkey_dedup suite (INFRA-520).

`nd_schema` builds a THROWAWAY schema per pytest session: LIKE-copies of the live
diskaudit table shapes (no data, own identity sequences) plus the 1.4.0 migration
applied to it. The migration is therefore tested as a FILE, and production gets no
test rows, no DDL and no locks beyond a momentary catalog read. The crosshost
tests keep their own `conn` fixture (live DB, rolled back) in test_crosshost_verify.py.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest
import psycopg

# 3.0.0 test isolation, set BEFORE any HavnVard module is imported:
#  * every test reads the generic tests/site.test.toml, never the operator's /etc/havnvard/site.toml;
#  * database tests run ONLY against HAVNVARD_TEST_DSN (a scratch database you create; see tests/README.md).
#    POSTGRES_URL is overridden for the whole session, so code under test that opens its own connection
#    can never reach a production database by accident.
_HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["HAVNVARD_SITE"] = os.path.join(_HERE, "site.test.toml")
TEST_DSN = os.environ.get("HAVNVARD_TEST_DSN", "")
os.environ["POSTGRES_URL"] = TEST_DSN or "postgresql://no-test-db@127.0.0.1:1/unset"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crosshost_verify as cv  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(REPO_ROOT, "migrations")
_COPIED = ("scan_runs", "dedup_runs", "files", "run_heartbeats", "dedup_worker_status", "backup_runs",
           "scan_errors", "files_staging")  # last two: scan.merge + load_nas_inventory tests (1.4.2)


@pytest.fixture(autouse=True)
def _isolate_havnvard_config(tmp_path, monkeypatch):
    """Every test gets its own HavnVard config and state dirs. Without this, a backup test that did not ask for
    `hubenv` wrote its [nas] section into the operator's real ~/.config/havnvard/backup.toml (found 20261111)."""
    monkeypatch.setenv("HAVNVARD_CONFIG_DIR", str(tmp_path / "_iso_cfg"))
    monkeypatch.setenv("HAVNVARD_STATE_DIR", str(tmp_path / "_iso_state"))


def connect_retry(autocommit=False, attempts=20, delay=1.0):
    """psycopg.connect that rides out a momentarily full connection table (the live DB shares ~100 slots with
    other services); a real outage still fails after ~attempts*delay seconds."""
    import time  # noqa: PLC0415
    if not TEST_DSN:
        pytest.skip("database test: set HAVNVARD_TEST_DSN to a scratch database (see tests/README.md)")
    last = None
    for _ in range(attempts):
        try:
            return psycopg.connect(TEST_DSN, autocommit=autocommit)
        except psycopg.OperationalError as e:
            last = e
            time.sleep(delay)
    raise last


def rewrite(sql: str, schema: str) -> str:
    return sql.replace("diskaudit.", schema + ".")


@pytest.fixture(scope="session")
def nd_schema():
    schema = "diskaudit_t_" + uuid.uuid4().hex[:8]
    try:
        admin = connect_retry(autocommit=True)
    except psycopg.OperationalError as e:
        pytest.skip(f"diskaudit DB not reachable in this environment: {e}")
        return
    try:
        with admin.cursor() as cur:
            cur.execute(f"CREATE SCHEMA {schema}")
            for t in _COPIED:
                cur.execute(f"CREATE TABLE {schema}.{t} (LIKE diskaudit.{t} INCLUDING ALL)")
            with open(os.path.join(MIGRATIONS, "20261109_diskaudit_nas_dedup_v3.sql"), encoding="utf-8") as f:
                cur.execute(rewrite(f.read(), schema))
            # 1.4.3: files_staging.scan_id (not yet in production until the deployer applies it)
            with open(os.path.join(MIGRATIONS, "20261109_diskaudit_files_staging_scan_id_v1.sql"), encoding="utf-8") as f:
                cur.execute(rewrite(f.read(), schema))
        yield schema
    finally:
        with admin.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        admin.close()


@pytest.fixture
def gconn_factory(nd_schema):
    """Returns a factory of GuardedConns on the throwaway schema; closes them at teardown."""
    from _dbguard import GuardedConn  # noqa: PLC0415
    made = []

    def factory():
        c = GuardedConn(connect_retry(), nd_schema)
        made.append(c)
        return c

    yield factory
    for c in made:
        try:
            c.rollback()
            c.close()
        except psycopg.Error:
            pass


@pytest.fixture
def gconn(gconn_factory):
    return gconn_factory()
