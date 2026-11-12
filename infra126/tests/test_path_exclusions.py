"""INFRA-281 -- path exclusions are configuration, are REPORTED, and never
masquerade as either coverage or failure.

The defect these guard against: a verifier that quietly ignores part of the
filesystem is a silent failure (docs/STANDARDS/SILENT_FAILURE_STANDARD.md), and
is a worse bug than the noisy-error one it replaces.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from havnvard_bitrot.config import DEFAULT_EXCLUSIONS, PathExclusion, load_settings
from havnvard_bitrot.policy import exclusion_predicate_sql
from havnvard_bitrot.types import Tier
from havnvard_bitrot.verifier import VerificationService
from havnvard_bitrot.waitingroom import WaitingRoomGate

from test_verifier import FakeRepository, Sink, candidate_for, settings

POSTGRES_URL = "postgresql://role:password@127.0.0.1:5432/havnvard"


def _env(monkeypatch, value: str | None) -> None:
    monkeypatch.setenv("POSTGRES_URL", POSTGRES_URL)
    monkeypatch.delenv("INFRA126_HOSTS_JSON", raising=False)
    if value is None:
        monkeypatch.delenv("INFRA126_EXCLUDE_PATH_PREFIXES", raising=False)
    else:
        monkeypatch.setenv("INFRA126_EXCLUDE_PATH_PREFIXES", value)


# --- configuration, not a hardcoded path -------------------------------------

def test_no_exclusions_by_default(monkeypatch):
    """3.0.0: exclusions are site settings; the shipped default excludes nothing."""
    _env(monkeypatch, None)
    assert load_settings().exclude_path_prefixes == ()
    assert DEFAULT_EXCLUSIONS == ()


def test_env_override_replaces_defaults_and_supports_multiple_forms(monkeypatch):
    _env(monkeypatch, "server-1:/home/Deprecated/,/everywhere/cache/")
    exclusions = load_settings().exclude_path_prefixes
    assert [(e.host, e.prefix) for e in exclusions] == [
        ("server-1", "/home/Deprecated/"),
        (None, "/everywhere/cache/"),
    ]


def test_env_override_accepts_json_objects_with_reasons(monkeypatch):
    _env(monkeypatch, json.dumps([{"host": "agent-1", "prefix": "/mnt/x/", "reason": "PLANE-1 why"}]))
    exclusion = load_settings().exclude_path_prefixes[0]
    assert (exclusion.host, exclusion.prefix, exclusion.reason) == ("agent-1", "/mnt/x/", "PLANE-1 why")


def test_empty_value_disables_exclusions_but_unset_keeps_defaults(monkeypatch):
    _env(monkeypatch, "")
    assert load_settings().exclude_path_prefixes == ()
    _env(monkeypatch, None)
    assert load_settings().exclude_path_prefixes == DEFAULT_EXCLUSIONS


@pytest.mark.parametrize("bad", ["home/olduser/", "/", '["relative/path"]'])
def test_unsafe_prefixes_are_rejected_loudly(monkeypatch, bad):
    _env(monkeypatch, bad)
    with pytest.raises(ValueError):
        load_settings()


# --- the SQL actually filters, per host --------------------------------------

def test_exclusion_sql_is_host_scoped_and_parameterised():
    exclusions = (PathExclusion("/home/olduser/", host="server-1", reason="unreadable old home"),)
    fragment, params = exclusion_predicate_sql(exclusions, "server-1")
    assert fragment == "NOT (starts_with(f.path, %s))"
    assert params == ["/home/olduser/"]
    assert exclusion_predicate_sql(exclusions, "agent-1") == ("", [])


def test_exclusion_sql_ors_multiple_prefixes():
    exclusions = (PathExclusion("/a/"), PathExclusion("/b/", host="agent-1"))
    fragment, params = exclusion_predicate_sql(exclusions, "agent-1")
    assert fragment.count("starts_with") == 2
    assert params == ["/a/", "/b/"]


def test_enqueue_and_due_count_share_one_exclusion_clause():
    """If enqueue skipped a path but the due-count still counted it, every run
    would finish completed_with_errors forever -- the exact bug INFRA-281 fixes."""
    source = Path(__file__).resolve().parents[1] / "src/havnvard_bitrot/repository.py"
    text = source.read_text()
    enqueue = text.split("def enqueue_candidates", 1)[1].split("def count_due_excluding_run", 1)[0]
    due = text.split("def count_due_excluding_run", 1)[1].split("def count_excluded_candidates", 1)[0]
    for block in (enqueue, due):
        assert "{exclusion_clause}" in block
        assert "*exclusion_params" in block


def test_read_failures_still_count_as_errors_in_run_status():
    """Excluded-by-policy must not fail a run; unreadable still must."""
    text = (Path(__file__).resolve().parents[1] / "src/havnvard_bitrot/repository.py").read_text()
    finalize = text.split("def finalize_run", 1)[1]
    errors_bucket = finalize.split("FROM diskaudit.hash_verification_items", 1)[0]
    assert "'unreadable','missing','failed','changed_during_hash','stale_baseline','skipped'" in errors_bucket
    assert "excluded" not in errors_bucket
    assert "elif errors or pending or remaining_due:" in finalize


# --- the run REPORTS the exclusion -------------------------------------------

def _service(tmp_path, repo):
    return VerificationService(repo, settings(tmp_path), Sink(), Sink(), WaitingRoomGate(None, None), Path("unused"))


def test_exclusions_are_reported_persisted_and_kept_out_of_the_error_tally(tmp_path, caplog):
    path = tmp_path / "stable.txt"
    path.write_text("stable")
    st = path.stat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    repo = FakeRepository(candidate_for(path, digest, st.st_mtime_ns, st.st_size))
    repo.exclusion_report = [{
        "prefix": "/home/olduser/", "host": "server-1", "reason": "INFRA-281 deprecated home",
        "due_excluded": 34, "inventory_files": 60931, "baselined_files": 34, "ever_verified_files": 0,
    }]
    with caplog.at_level("INFO"):
        summary = _service(tmp_path, repo).run("server-1", Tier.A)

    assert summary.excluded_by_policy == 34
    assert summary.path_exclusions == repo.exclusion_report
    assert summary.errors == 0, "a policy exclusion must never land in the error tally"
    assert summary.details["excluded_by_policy"] == 34
    assert repo.recorded_exclusions[1] == repo.exclusion_report, "must be persisted on the run row"
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "PATH EXCLUDED BY POLICY" in logged
    assert "/home/olduser/" in logged and "due_excluded=34" in logged


def test_unreadable_file_still_counts_as_an_error(tmp_path):
    """The other half of the contract: a genuine read failure must still be an
    error, so the run cannot report success over data it could not check."""
    path = tmp_path / "secret.bin"
    path.write_bytes(b"data")
    st = path.stat()
    os.chmod(path, 0o000)
    try:
        repo = FakeRepository(candidate_for(path, "0" * 64, st.st_mtime_ns, st.st_size))
        repo.record_result = lambda *a, **k: {"state": "unreadable", "alert": False}
        summary = _service(tmp_path, repo).run("server-1", Tier.A)
    finally:
        os.chmod(path, 0o600)
    assert summary.errors == 1
    assert summary.excluded_by_policy == 0
