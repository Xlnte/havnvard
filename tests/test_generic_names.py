"""3.3.11 (INFRA-565 / INFRA-566): generic file, column and value names instead of the original site's.

* nas_host_dedup.py is the real tool; nas_trigkey_dedup.py is a deprecated shim that forwards to it;
* no code or baseline names the old spark_* columns or the 'investigate_spark' value;
* the 20261117 migration upgrades an old-shaped schema (rows kept, CHECK moved, default changed, legacy views),
  is idempotent, and leaves a fresh baseline unchanged.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid

import pytest

from conftest import REPO_ROOT, connect_retry

MIGRATION = os.path.join(REPO_ROOT, "migrations", "20261117_diskaudit_generic_names_v1.sql")
OLD_VERDICTS = ("'benign','suspicious','confirmed_corruption','investigate_spark',"
                "'investigate_nas','investigate_restic','unresolved'")


def _run(script, *args):
    return subprocess.run([sys.executable, os.path.join(REPO_ROOT, script), *args],
                          capture_output=True, text=True, timeout=60, cwd=REPO_ROOT)


def test_shim_forwards_arguments_and_exit_code_and_warns():
    new = _run("nas_host_dedup.py")                       # no --host / --export: the tool's own usage error
    old = _run("nas_trigkey_dedup.py")
    assert new.returncode == old.returncode != 0
    assert "DEPRECATED" in old.stderr and "nas_host_dedup.py" in old.stderr
    assert "DEPRECATED" not in new.stderr
    assert old.stderr.replace(next(l for l in old.stderr.splitlines() if "DEPRECATED" in l) + "\n", "") == new.stderr
    help_old, help_new = _run("nas_trigkey_dedup.py", "--help"), _run("nas_host_dedup.py", "--help")
    assert help_old.returncode == help_new.returncode == 0 and help_old.stdout == help_new.stdout


def test_shim_import_keeps_the_old_module_api():
    sys.path.insert(0, REPO_ROOT)
    try:
        import nas_host_dedup  # noqa: PLC0415
        import nas_trigkey_dedup  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    assert nas_trigkey_dedup.main is nas_host_dedup.main
    assert nas_trigkey_dedup.KNOWN_HOSTS == nas_host_dedup.KNOWN_HOSTS


def test_no_unit_or_doc_runs_the_old_name_except_the_shim_and_history():
    allowed = {"nas_trigkey_dedup.py", "CHANGELOG.md", os.path.join("tests", "test_generic_names.py"), os.path.join("tests", "README.md")}
    bad = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "__pycache__", "node_modules"}]
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), REPO_ROOT)
            if rel in allowed or rel.startswith(("migrations" + os.sep, os.path.join("infra126", "spec"), os.path.join("infra126", "docs"))) or not f.endswith((".py", ".sh", ".md", ".service", ".timer", ".yaml", ".toml", ".sql")):
                continue
            with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                if "nas_trigkey_dedup" in fh.read():
                    bad.append(rel)
    assert bad == []


def test_code_and_baseline_use_no_old_names():
    pat = re.compile(r"spark_(host|path|files|bytes)|investigate_spark|find-scan-20260718")
    bad = []
    for root, dirs, files in os.walk(REPO_ROOT):
        rel_root = os.path.relpath(root, REPO_ROOT)
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "__pycache__", "node_modules", "migrations", "spec"}]
        for f in files:
            rel = os.path.join(rel_root, f)
            if not f.endswith((".py", ".sql", ".sh", ".html", ".json")) or f == "test_generic_names.py":
                continue
            if rel.startswith(os.path.join(".", "infra126", "migrations")):
                continue                                  # history files (FILE-5, PAF's call)
            with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                if pat.search(fh.read()):
                    bad.append(rel)
    assert bad == [], bad


@pytest.fixture
def old_shape():
    """A throwaway schema built from the baseline, then put back into the pre-3.3.11 shape, with an old-value row."""
    name = "diskaudit_g_" + uuid.uuid4().hex[:8]
    conn = connect_retry(autocommit=True)
    with open(os.path.join(REPO_ROOT, "schema", "baseline.sql"), encoding="utf-8") as f:
        sql = f.read().replace("CREATE SCHEMA diskaudit;", f"CREATE SCHEMA {name};").replace("diskaudit.", name + ".")
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute(f"""
                ALTER TABLE {name}.integrity_checks RENAME COLUMN source_host TO spark_host;
                ALTER TABLE {name}.integrity_checks RENAME COLUMN source_path TO spark_path;
                ALTER INDEX {name}.idx_diskaudit_integrity_checks_source RENAME TO idx_diskaudit_integrity_checks_spark;
                ALTER TABLE {name}.report_snapshots RENAME COLUMN local_files TO spark_files;
                ALTER TABLE {name}.report_snapshots RENAME COLUMN local_bytes TO spark_bytes;
                ALTER TABLE {name}.corruption_suspects DROP CONSTRAINT corruption_suspects_operator_verdict_check;
                ALTER TABLE {name}.corruption_suspects ADD CONSTRAINT corruption_suspects_operator_verdict_check
                    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY[{OLD_VERDICTS}]));
                ALTER TABLE {name}.hash_divergences DROP CONSTRAINT hash_divergences_operator_verdict_check;
                ALTER TABLE {name}.hash_divergences ADD CONSTRAINT hash_divergences_operator_verdict_check
                    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY[{OLD_VERDICTS}]));
                ALTER TABLE {name}.git_repo_roots ALTER COLUMN discovered_via SET DEFAULT 'find-scan-20260718';
                INSERT INTO {name}.integrity_checks (spark_path, spark_host, verdict) VALUES ('/a', '_test_h', 'match');
                INSERT INTO {name}.report_snapshots (snap_date, spark_files, spark_bytes) VALUES ('2026-01-01', 7, 9);
                INSERT INTO {name}.corruption_suspects (file_key, host, path, first_divergence_at,
                       last_seen_divergence_at, operator_verdict)
                    VALUES (repeat('a',64), '_test_h', '/a', now(), now(), 'investigate_spark');""")
        yield name, conn
    finally:
        with conn.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {name} CASCADE")
        conn.close()


def _migrate(cur, name):
    with open(MIGRATION, encoding="utf-8") as f:
        cur.execute(f.read().replace("diskaudit.", name + ".").replace("'diskaudit'", f"'{name}'"))


def test_migration_upgrades_an_old_shaped_schema_and_is_idempotent(old_shape):
    name, conn = old_shape
    with conn.cursor() as cur:
        for _ in range(2):                                # second run = no-op
            _migrate(cur, name)
        cur.execute(f"SELECT source_host, source_path FROM {name}.integrity_checks")
        assert cur.fetchall() == [("_test_h", "/a")]
        cur.execute(f"SELECT local_files, local_bytes FROM {name}.report_snapshots")
        assert cur.fetchall() == [(7, 9)]
        cur.execute(f"SELECT operator_verdict FROM {name}.corruption_suspects")
        assert cur.fetchall() == [("investigate_server",)]
        cur.execute(f"INSERT INTO {name}.git_repo_roots (repo_root) VALUES ('/r') RETURNING discovered_via")
        assert cur.fetchone()[0] == "manual"
        with pytest.raises(Exception):                    # the old value is no longer accepted
            cur.execute(f"UPDATE {name}.corruption_suspects SET operator_verdict='investigate_spark'")
        # legacy views keep the old column names for old readers
        cur.execute(f"SELECT spark_host, spark_path FROM {name}.v_integrity_checks_legacy_names")
        assert cur.fetchall() == [("_test_h", "/a")]
        cur.execute(f"SELECT spark_files, spark_bytes FROM {name}.v_report_snapshots_legacy_names")
        assert cur.fetchall() == [(7, 9)]
        cur.execute("SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace "
                    "WHERE n.nspname=%s AND conname='hash_divergences_operator_verdict_check'", (name,))
        assert "investigate_server" in cur.fetchone()[0]


def test_migration_on_a_fresh_baseline_changes_nothing_but_adds_the_legacy_views(old_shape):
    name, conn = old_shape
    with conn.cursor() as cur:
        _migrate(cur, name)
        cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_schema=%s "
                    "AND column_name IN ('spark_host','spark_path','spark_files','spark_bytes') AND table_name NOT LIKE 'v\\_%%'", (name,))
        assert cur.fetchone()[0] == 0


def test_generator_keeps_the_legacy_views_out_of_the_baseline():
    text = open(os.path.join(REPO_ROOT, "schema", "baseline.sql"), encoding="utf-8").read()
    assert "legacy_names" not in text and "spark" not in text.lower()
