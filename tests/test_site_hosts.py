"""Site-file-driven rows and the generic NAS-orphan view (INFRA-563, INFRA-562, 3.3.9).

* init_site_hosts.py makes site_hosts + hash_verification_sla rows from the site file (tests/site.test.toml: 3 hosts);
* validate_live.py expects hosts x 4 SLA rows, not a literal 12;
* v_nas_orphans reads the NAS host from site_hosts, so a site whose NAS is not called nas-1 gets the check.
Database tests build the baseline into a throwaway schema on the scratch database only.
"""
from __future__ import annotations

import importlib.util
import os
import uuid

import psycopg
import pytest

from conftest import REPO_ROOT, connect_retry

import init_site_hosts as ish


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vl = _load("validate_live", "infra126/scripts/validate_live.py")
TIERS = ("A", "B", "C", "E")


# ---- pure ---------------------------------------------------------------------------------------------

def test_rows_come_from_the_site_file():
    assert ish.site_host_rows() == [("server-1", "source"), ("agent-1", "source"), ("nas-1", "nas")]
    sla = ish.sla_rows()
    assert len(sla) == 3 * 4 and {t for _, t, _, _ in sla} == set(TIERS)
    assert {(t, d, m) for _, t, d, m in sla} == {("A", 7, "weekly"), ("B", 30, "monthly"), ("C", 90, "quarterly"), ("E", 1, "daily")}


def test_validate_live_expects_hosts_times_four():
    two = ("h1", "h2")
    ok = {(h, t) for h in two for t in TIERS}
    assert vl.sla_failures(ok, two) == []                                  # 8 rows is right for 2 hosts (was: "expected 12")
    assert vl.sla_failures(ok, ("h1", "h2", "h3"))                          # a host with no rows fails
    assert vl.sla_failures(ok - {("h2", "E")}, two)                         # a missing tier fails
    assert vl.sla_failures(ok | {("gone", "A")}, two)                       # a row for a host the site file lacks fails
    assert "expected 8 " in vl.sla_failures(ok - {("h2", "E")}, two)[0]


def test_validate_live_reads_the_test_site_file():
    assert vl.site_hosts() == ("server-1", "agent-1", "nas-1")


# ---- database (scratch only) -----------------------------------------------------------------------------

class _Shim:
    """Rewrites `diskaudit.` to a throwaway schema, so init_site_hosts.apply() runs unchanged."""
    def __init__(self, conn, schema):
        self._c, self._s = conn, schema

    def cursor(self):
        outer = self

        class Cur:
            def __init__(self):
                self._cur = outer._c.cursor()

            def execute(self, q, p=None):
                self._cur.execute(q.replace("diskaudit.", outer._s + "."), p)
                return self

            def __getattr__(self, n):
                return getattr(self._cur, n)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self._cur.close()
        return Cur()


@pytest.fixture
def schema():
    name = "diskaudit_s_" + uuid.uuid4().hex[:8]
    conn = connect_retry(autocommit=True)
    with open(os.path.join(REPO_ROOT, "schema", "baseline.sql"), encoding="utf-8") as f:
        sql = f.read().replace("CREATE SCHEMA diskaudit;", f"CREATE SCHEMA {name};").replace("diskaudit.", name + ".")
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        yield name, conn
    finally:
        with conn.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {name} CASCADE")
        conn.close()


def test_init_creates_rows_is_idempotent_and_keeps_tuned_values(schema):
    name, conn = schema
    with conn.cursor() as cur:
        cur.execute(f"INSERT INTO {name}.hash_verification_sla (host,tier,target_recheck_days,schedule_mode) "
                    "VALUES ('server-1','A',3,'daily')")                       # an operator-tuned row
    assert ish.apply(_Shim(conn, name)) == {"site_hosts": 3, "hash_verification_sla": 11}
    assert ish.apply(_Shim(conn, name)) == {"site_hosts": 0, "hash_verification_sla": 0}
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {name}.hash_verification_sla")
        assert cur.fetchone()[0] == 12
        cur.execute(f"SELECT target_recheck_days FROM {name}.hash_verification_sla WHERE host='server-1' AND tier='A'")
        assert cur.fetchone()[0] == 3
        cur.execute(f"SELECT host FROM {name}.site_hosts WHERE role='nas'")
        assert cur.fetchall() == [("nas-1",)]


def _file(cur, name, host, path, grp, scan):
    cur.execute(f"INSERT INTO {name}.files (host,path,file_type,first_seen_scan_id,last_seen_scan_id,duplicate_group_id) "
                "VALUES (%s,%s,'regular',%s,%s,%s)", (host, path, scan, scan, grp))


def test_nas_orphans_takes_the_nas_from_site_hosts(schema):
    name, conn = schema
    with conn.cursor() as cur:
        cur.execute(f"INSERT INTO {name}.scan_runs (host, root_path, dry_run, status) VALUES ('_test_h','/x',true,'running') "
                    "RETURNING scan_id")
        sid = cur.fetchone()[0]
        _file(cur, name, "vault", "/a/only-on-nas", None, sid)     # never deduped: orphan
        _file(cur, name, "vault", "/a/copied", 7, sid)
        _file(cur, name, "pc", "/b/copied", 7, sid)                # copy on another host: not an orphan
        _file(cur, name, "pc", "/b/pc-only", None, sid)            # not on the NAS: never listed
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="init_site_hosts"):
            cur.execute(f"SELECT count(*) FROM {name}.v_nas_orphans")  # not configured raises, never "no orphans"
        cur.execute(f"INSERT INTO {name}.site_hosts (host,role) VALUES ('pc','source')")
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            cur.execute(f"SELECT count(*) FROM {name}.v_nas_orphans")  # a source row alone is not a NAS
        cur.execute(f"DELETE FROM {name}.site_hosts")
        cur.execute(f"INSERT INTO {name}.site_hosts (host,role) VALUES ('vault','nas'),('pc','source')")
        cur.execute(f"SELECT host, path FROM {name}.v_nas_orphans")
        assert cur.fetchall() == [("vault", "/a/only-on-nas")]     # works for a NAS that is not called nas-1


def test_baseline_view_names_no_host_and_migration_matches_it():
    with open(os.path.join(REPO_ROOT, "schema", "baseline.sql"), encoding="utf-8") as f:
        text = f.read()
    start = text.index("CREATE VIEW diskaudit.v_nas_orphans")
    view = text[start:text.index(";", start)]
    assert "site_hosts" in view and "nas-1" not in view
    with open(os.path.join(REPO_ROOT, "migrations", "20261116_diskaudit_site_hosts_v1.sql"), encoding="utf-8") as f:
        mig = f.read()
    assert "BEGIN;" in mig and "SET LOCAL lock_timeout = '5s';" in mig and "COMMIT;" in mig


def test_migration_applies_on_top_of_the_baseline_twice(schema):
    name, conn = schema
    with open(os.path.join(REPO_ROOT, "migrations", "20261116_diskaudit_site_hosts_v1.sql"), encoding="utf-8") as f:
        sql = f.read().replace("diskaudit.", name + ".")
    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(sql)
        cur.execute(f"INSERT INTO {name}.site_hosts (host,role) VALUES ('vault','nas')")
        cur.execute(f"SELECT count(*) FROM {name}.v_nas_orphans")
        assert cur.fetchone()[0] == 0


def test_rollback_file_needs_the_nas_host_and_names_no_host():
    with open(os.path.join(REPO_ROOT, "migrations", "20261116_diskaudit_site_hosts_v1_rollback.sql"), encoding="utf-8") as f:
        rb = f.read()
    assert "\\if :{?nas_host}" in rb and "RAISE EXCEPTION" in rb and "\\set ON_ERROR_STOP on" in rb
    assert "f.host = :'nas_host'" in rb and "nas-1" not in rb
    assert rb.index("CREATE OR REPLACE VIEW") < rb.index("DROP TABLE IF EXISTS diskaudit.site_hosts")
