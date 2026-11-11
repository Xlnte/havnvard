-- HavnVard 2.1.0: link restic snapshots to backup coverage (spec 20261110 section 9 item 5, INFRA-112).
-- NOT APPLIED by the build. Apply by hand after Opus review:  psql -v ON_ERROR_STOP=1 -f this file  (additive, idempotent).
-- `python -m backup coverage-sync DEVICE` marks a NOT_BACKED_UP row BACKED_UP_UNVERIFIED (never VERIFIED: a listing
-- is not a SHA-256 compare; review R2-1) when the latest restic snapshot holds the same path + size + mtime.
BEGIN;
ALTER TABLE diskaudit.backup_coverage ADD COLUMN IF NOT EXISTS restic_snapshot_id  text;
ALTER TABLE diskaudit.backup_coverage ADD COLUMN IF NOT EXISTS restic_verified_at  timestamptz;
COMMENT ON COLUMN diskaudit.backup_coverage.restic_snapshot_id IS
  'restic snapshot id whose listing matched this file on path+size+mtime (set by backup coverage-sync)';
COMMIT;
-- "not backed up" report (backup not-backed-up): per-host, per-class, biggest first.
-- CONCURRENTLY, outside the transaction: the table holds ~5.7 M rows [measured 20261111]; a plain build blocks writers.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_backup_coverage_host_class_size
    ON diskaudit.backup_coverage (host, classification, size_bytes DESC);
