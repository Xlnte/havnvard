from __future__ import annotations

import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_no_forbidden_scanned_file_mutation_primitives_in_python():
    forbidden=("os.remove(","os.unlink(","os.rename(","shutil.move(","Path.unlink(",".unlink(")
    sources="\n".join(p.read_text(errors="ignore") for base in [ROOT/"src",ROOT/"scripts",ROOT/"web"] for p in base.rglob("*.py"))
    for token in forbidden:
        assert token not in sources


def test_no_pkill_f_in_executable_surfaces():
    paths=[]
    for base in [ROOT/"bin",ROOT/"scripts",ROOT/"systemd"]:
        paths.extend(p for p in base.rglob("*") if p.is_file())
    sources="\n".join(p.read_text(errors="ignore") for p in paths)
    assert "pkill -f" not in sources


def test_nas_scratch_is_not_tmp():
    env=(ROOT/"config/infra126.env.example").read_text()
    assert "/share/CACHEDEV1_DATA/.diskaudit_scratch/infra126" in env
    assert '"scratch_dir":"/tmp' not in env


def test_migration_has_no_public_update_grant():
    sql="\n".join(p.read_text() for p in (ROOT/"migrations").glob("*.sql"))
    assert "GRANT SELECT, UPDATE ON diskaudit.files TO PUBLIC" not in sql
    assert " TO PUBLIC" not in sql.upper()


def test_concurrent_indexes_are_outside_transaction():
    sql=(ROOT/"migrations/002_infra126_indexes_concurrently.sql").read_text().upper()
    assert "CREATE INDEX CONCURRENTLY" in sql
    assert "BEGIN;" not in sql


def test_remote_helper_emits_hashed_not_hashing():
    script=(ROOT/"bin/remote_hash_batch.sh").read_text()
    assert '"status":"hashed"' in script
    assert '"status":"hashing"' not in script


def test_four_grafana_panels_present():
    dashboard=json.loads((ROOT/"grafana/infra126_dashboard.json").read_text())
    assert len(dashboard["panels"])==4


def test_all_timers_use_explicit_utc_when_calendar_based():
    for path in (ROOT/"systemd").glob("*.timer"):
        text=path.read_text()
        if "OnCalendar=" in text:
            assert " UTC" in text


def test_cross_host_votes_require_explicit_copy_links():
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "Never assume equal paths on different hosts are copies" in repository
    assert "hash_copy_links" in repository


def test_ui_exports_assurance_age_and_divergence_fields():
    blueprint=(ROOT/"web/infra126_blueprint.py").read_text()
    for field in ["hashed_at","last_verified_at","hash_age_days","mutable_score","divergence_count_4w"]:
        assert field in blueprint


def test_critical_file_sync_does_not_scan_full_inventory_in_one_transaction():
    script=(ROOT/"scripts/sync_critical_files.py").read_text()
    assert "--input" in script
    assert "executemany" in script
    assert "JOIN diskaudit.files" not in script
    assert "CREATE TEMP TABLE" not in script
    assert "refresh_generation" in script


def test_critical_file_sync_refuses_accidental_empty_generation():
    script=(ROOT/"scripts/sync_critical_files.py").read_text()
    assert "refusing to replace the critical-file registry with an empty generation" in script
    assert "--allow-empty" in script


def test_restic_copy_evidence_requires_passing_repository_check():
    script=(ROOT/"scripts/restic_hash_copy.py").read_text()
    assert "backup_verification_state" in script
    assert "repository_verified" in script
    assert 'evidence_state="verified" if repository_verified else "unverified"' in script
