from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CORE=(ROOT/"migrations/001_infra126_core.sql").read_text()
VIEWS=(ROOT/"migrations/003_infra126_views_and_functions.sql").read_text()


def test_required_tables_exist():
    for table in [
        "hash_verification_sla","hash_verification_runs","hash_verification_items",
        "hash_observations","hash_divergences","mutable_file_registry",
        "corruption_suspects","hash_copy_evidence","hash_baseline_stabilizations",
    ]:
        assert f"CREATE TABLE IF NOT EXISTS diskaudit.{table}" in CORE


def test_initial_hash_and_reverification_are_distinct():
    assert "first_hashed_at" in CORE
    assert "last_verified_at" in CORE
    assert "last_baseline_accepted_at" in CORE
    assert "verification_count" in CORE
    assert "baseline_revision_count" in CORE


def test_sla_seed_is_12_scheduled_rows():
    seed_lines=[line for line in CORE.splitlines() if "('server-1'" in line or "('nas-1'" in line or "('agent-1'" in line]
    assert sum(line.count("('server-1'")+line.count("('nas-1'")+line.count("('agent-1'") for line in seed_lines)==12


def test_mutable_registry_has_at_least_20_seed_rules():
    section=CORE.split("INSERT INTO diskaudit.mutable_file_registry",1)[1].split("ON CONFLICT",1)[0]
    assert section.count("('*'")>=20


def test_view_uses_last_verified_not_initial_hash_for_assurance_age():
    assert "days_since_last_verification" in VIEWS
    assert "last_verified_at" in VIEWS
    assert "baseline_only" not in VIEWS.lower()  # status is stored, not presented as verified


def test_operator_verdict_constraints_do_not_put_null_inside_in_list():
    assert ", NULL" not in CORE
    assert "operator_verdict IS NULL OR" in CORE


def test_preflight_rejects_known_prototype_shapes():
    preflight=(ROOT/"migrations/000_preflight.sql").read_text()
    for table,column in [
        ("hash_verification_sla","schedule_mode"),
        ("hash_verification_runs","remaining_due_count"),
        ("hash_verification_items","lease_expires_at"),
        ("hash_divergences","decision_state"),
        ("mutable_file_registry","score"),
        ("corruption_suspects","file_key"),
    ]:
        assert table in preflight
        assert column in preflight


def test_alert_delivery_uses_atomic_lease_columns():
    assert "delivery_state" in CORE
    assert "delivery_lease_until" in CORE
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "delivery_lease_until < now()" in repository
    assert "def mark_alert_failed" in repository


def test_hash_baseline_metadata_is_persisted_separately_from_inventory_metadata():
    core=(ROOT/"migrations/001_infra126_core.sql").read_text()
    backfill=(ROOT/"migrations/004_backfill_existing_hashes.sql").read_text()
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    for column in ["hash_baseline_mtime_ns","hash_baseline_size","hash_baseline_inode","hash_baseline_metadata_trusted"]:
        assert column in core
    assert "hash_baseline_metadata_trusted = FALSE" in backfill
    assert "AND mtime IS NOT NULL" in backfill
    assert "AND size_bytes IS NOT NULL" in backfill
    assert "AND inode IS NOT NULL" in backfill
    assert "f.hash_baseline_mtime_ns" in repository
    assert "f.mtime" not in repository.split("def enqueue_candidates",1)[1].split("def count_due_excluding_run",1)[0]

def test_live_copy_vote_requires_successful_current_baseline_verification():
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "f.last_verified_at >= COALESCE(f.hashed_at,f.first_hashed_at)" in repository


def test_operator_review_is_persisted_to_divergence_history():
    views=(ROOT/"migrations/003_infra126_views_and_functions.sql").read_text()
    assert "infra126_sync_suspect_review" in views
    assert "UPDATE diskaudit.hash_divergences" in views
    assert "trg_infra126_sync_suspect_review" in views


def test_host_specific_registry_rules_override_global_rules_at_same_priority():
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "CASE WHEN host=%s THEN 0 ELSE 1 END" in repository


def test_sla_next_schedule_uses_calendar_function_not_completion_drift():
    views=(ROOT/"migrations/003_infra126_views_and_functions.sql").read_text()
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "infra126_next_scheduled" in views
    assert "date_trunc('quarter'" in views
    assert "next_scheduled_at=diskaudit.infra126_next_scheduled" in repository
    assert "now()+interval '30 days'" not in repository

def test_tier_e_sla_has_tighter_overdue_grace():
    monitor=(ROOT/"src/havnvard_bitrot/monitor.py").read_text()
    assert "WHEN 'E' THEN interval '1 hour'" in monitor


def test_skipped_due_file_prevents_successful_run_status():
    repository=(ROOT/"src/havnvard_bitrot/repository.py").read_text()
    assert "'stale_baseline','skipped'" in repository
