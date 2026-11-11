-- HavnVard 2.1.0: link restic snapshots to backup coverage (spec 20261110 section 9 item 5, INFRA-112).
-- NOT APPLIED by the build. Apply by hand after Opus review:  psql -f this file  (additive, idempotent).
-- `python -m backup coverage-sync DEVICE` marks a BACKED_UP_UNVERIFIED / NOT_BACKED_UP row BACKED_UP_VERIFIED
-- when the device's latest HavnVard restic snapshot holds the same path + size + mtime (to the second).
BEGIN;
ALTER TABLE diskaudit.backup_coverage ADD COLUMN IF NOT EXISTS restic_snapshot_id  text;
ALTER TABLE diskaudit.backup_coverage ADD COLUMN IF NOT EXISTS restic_verified_at  timestamptz;
COMMENT ON COLUMN diskaudit.backup_coverage.restic_snapshot_id IS
  'restic snapshot id whose listing matched this file on path+size+mtime (set by backup coverage-sync)';
-- "not backed up" report (backup not-backed-up): per-host, per-class, biggest first.
CREATE INDEX IF NOT EXISTS ix_backup_coverage_host_class_size
    ON diskaudit.backup_coverage (host, classification, size_bytes DESC);
COMMIT;
