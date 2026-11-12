-- Run with psql autocommit. CONCURRENTLY cannot run inside BEGIN/COMMIT.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_infra126_existing_hash
  ON diskaudit.files(host,path)
  WHERE content_sha256 IS NOT NULL AND first_hashed_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_infra126_due
  ON diskaudit.files(host,hashed_at,last_verified_at)
  INCLUDE(path,inode,content_sha256,first_hashed_at,hash_baseline_mtime_ns,hash_baseline_size,hash_baseline_metadata_trusted)
  WHERE still_exists AND file_type='regular' AND content_sha256 IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_infra126_attempt_status
  ON diskaudit.files(host,hash_status,last_hash_attempt_at)
  WHERE still_exists AND file_type='regular';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_infra126_items_claim
  ON diskaudit.hash_verification_items(run_id,state,item_id)
  INCLUDE(lease_expires_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_infra126_runs_heartbeat
  ON diskaudit.hash_verification_runs(status,last_heartbeat_at)
  WHERE status IN ('running','blocked');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hash_divergences_unresolved
  ON diskaudit.hash_divergences(host,created_at DESC)
  WHERE operator_verdict IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_corruption_suspects_unresolved
  ON diskaudit.corruption_suspects(host,last_seen_divergence_at DESC)
  WHERE operator_verdict IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hash_observations_path
  ON diskaudit.hash_observations(file_key,observed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hash_copy_evidence_latest
  ON diskaudit.hash_copy_evidence(logical_file_key,independent_source_id,captured_at DESC)
  WHERE verification_state='verified';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hash_stabilizations_due
  ON diskaudit.hash_baseline_stabilizations(state,due_at)
  WHERE state='pending';
