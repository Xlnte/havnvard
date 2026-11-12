"""schema/baseline.sql: the one-file install for a new site (INFRA-557).

* the committed baseline carries no site names (same check the generator runs);
* the generator refuses a dump that would leak a site name, and strips host defaults;
* on a scratch database, the baseline builds the whole schema in a throwaway schema with no other system's tables.
"""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import uuid

import pytest

from conftest import REPO_ROOT, connect_retry

BASELINE = os.path.join(REPO_ROOT, "schema", "baseline.sql")
_spec = importlib.util.spec_from_file_location("mbs", os.path.join(REPO_ROOT, "scripts", "make_baseline_schema.py"))
mbs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mbs)


def _baseline() -> str:
    with open(BASELINE, encoding="utf-8") as f:
        return f.read()


def test_committed_baseline_has_no_site_names():
    assert mbs.leaks(_baseline(), []) == []


def test_committed_baseline_is_complete():
    text = _baseline()
    assert text.startswith("-- HavnVard database schema: baseline")
    assert "CREATE SCHEMA diskaudit;" in text
    assert "\\restrict" not in text
    assert not re.search(r"host text DEFAULT", text)
    assert "INSERT INTO diskaudit.backup_scope_rules" in text  # seed appended


_DUMP = """--
-- Name: files; Type: TABLE; Schema: diskaudit; Owner: -
--

CREATE TABLE diskaudit.files (
    host text DEFAULT 'myhost'::text NOT NULL
);

--
-- Name: v_x; Type: VIEW; Schema: diskaudit; Owner: -
--

CREATE VIEW diskaudit.v_x AS SELECT 1 WHERE 'HOSTNAME' = 'a';

--
-- Name: v_nas_orphans; Type: VIEW; Schema: diskaudit; Owner: -
--

CREATE VIEW diskaudit.v_nas_orphans AS SELECT 1;

--
-- Name: TABLE files; Type: COMMENT; Schema: diskaudit; Owner: -
--

COMMENT ON TABLE diskaudit.files IS 'scanned on zebra-box by Zed, see /home/someone/runbooks/x.md';
"""


# A made-up site's private rules (the real ones live in the operator's private file, never in the repo).
RULES = [("zebra-box", "server-1"), (r"\bZed\b", "the operator"), ("okapi-nas", None)]


def test_generator_strips_defaults_drops_host_view_and_rewrites_comments():
    out = mbs.build(_DUMP.replace("HOSTNAME", "generic"), RULES)
    assert "host text NOT NULL" in out
    assert "v_nas_orphans" not in out
    assert "scanned on server-1 by the operator, see the project runbook" in out
    assert mbs.leaks(out, RULES) == []


def test_generator_refuses_a_site_name_in_code():
    out = mbs.build(_DUMP.replace("HOSTNAME", "okapi-nas"), RULES)
    assert mbs.leaks(out, RULES)  # a name inside a view body is code, never silently rewritten


def test_site_rules_file_format(tmp_path):
    f = tmp_path / "rules.txt"
    f.write_text("# comment\n\nzebra-box => server-1\nokapi-nas\n", encoding="utf-8")
    assert mbs.read_site_rules(str(f)) == [("zebra-box", "server-1"), ("okapi-nas", None)]


def test_baseline_builds_schema_on_scratch_database():
    """Applies the baseline into a throwaway schema; no thoth.*, no migrations, no live table copies."""
    schema = "diskaudit_b_" + uuid.uuid4().hex[:8]
    sql = _baseline().replace("CREATE SCHEMA diskaudit;", f"CREATE SCHEMA {schema};").replace("diskaudit.", schema + ".")
    conn = connect_retry(autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute("SELECT count(*) FILTER (WHERE c.relkind='r'), count(*) FILTER (WHERE c.relkind IN ('v','m')) "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s", (schema,))
            tables, views = cur.fetchone()
            text = _baseline()
            assert tables == len(re.findall(r"(?m)^CREATE (?:UNLOGGED )?TABLE ", text))
            assert views == len(re.findall(r"(?m)^CREATE (?:MATERIALIZED )?VIEW ", text))
            cur.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname=%s AND c.relkind='m' AND NOT c.relispopulated", (schema,))
            assert cur.fetchone()[0] == 0  # materialized views are readable right after install
            cur.execute("SELECT column_default FROM information_schema.columns WHERE table_schema=%s "
                        "AND column_name='host' AND column_default IS NOT NULL", (schema,))
            defaults = [r[0] for r in cur.fetchall()]
            assert all(d.startswith("'*'") for d in defaults), defaults  # no site gets a silent default host
            cur.execute(f"SELECT count(*) FROM {schema}.mutable_file_registry WHERE host = '*'")
            assert cur.fetchone()[0] >= 20  # bit-rot mutable/immutable rules seeded for every host
            cur.execute(f"SELECT count(*) FROM {schema}.backup_scope_rules WHERE host_pattern <> '%'")
            assert cur.fetchone()[0] == 0  # seed rules are host-generic
            cur.execute(f"INSERT INTO {schema}.scan_runs (host, root_path, dry_run, status) "
                        "VALUES ('_test_h', '/x', true, 'running') RETURNING scan_id")
            assert cur.fetchone()[0] is not None
            with pytest.raises(Exception):
                cur.execute(f"INSERT INTO {schema}.scan_runs (root_path, dry_run, status) VALUES ('/x', true, 'running')")
    finally:
        with conn.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        conn.close()


def test_leak_check_is_case_insensitive():
    rules = RULES + [(r"\bzebra\b(?!-agent)", None)]
    for name in ("ZEBRA-BOX", "Okapi-NAS", "Plane INFRA-98", "/home/Zed"):
        assert mbs.leaks(f"COMMENT ON TABLE t IS '{name}';", rules), name
    assert mbs.leaks("zebra_path text, idx_x_zebra, 'zebra-agent'", rules) == []  # code contract names allowed


def test_refusal_never_empties_the_output_file(tmp_path):
    dump = tmp_path / "dump.sql"
    dump.write_text(_DUMP.replace("HOSTNAME", "okapi-nas"), encoding="utf-8")
    rules = tmp_path / "rules.txt"
    rules.write_text("okapi-nas\n", encoding="utf-8")
    out = tmp_path / "baseline.sql"
    out.write_text("previous good baseline", encoding="utf-8")
    r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "scripts", "make_baseline_schema.py"), str(dump),
                        "--site-names", str(rules), "-o", str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and "refusing" in r.stderr
    assert out.read_text(encoding="utf-8") == "previous good baseline"


def test_load_bearing_census_is_skipped_without_thoth():
    """A new site has no thoth.census: the refresh logs a skip instead of failing every timer run."""
    import refresh_load_bearing_paths as rlb  # noqa: PLC0415
    conn = connect_retry(autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('thoth.census') IS NOT NULL")
            if cur.fetchone()[0]:
                pytest.skip("scratch database has a thoth.census table")
        assert rlb.scan_census(conn) is rlb.CENSUS_SKIPPED
    finally:
        conn.close()
