-- diskaudit v3.1 — backup_coverage write-batching (same fix dedup_staging got
-- in 20260717_diskaudit_dedup_staging_v2.sql: COPY-into-staging + one
-- set-based INSERT ... ON CONFLICT, instead of one row at a time, at
-- server-1's ~5.7M-file scale).

BEGIN;

CREATE UNLOGGED TABLE IF NOT EXISTS diskaudit.backup_coverage_staging (
    host                    text NOT NULL,
    path                    text NOT NULL,
    size_bytes              bigint,
    inode                   bigint,
    nlink                   integer,
    classification          text NOT NULL,
    match_method            text,
    excluded_rule_id        bigint,
    matched_nas_host        text,
    matched_nas_path        text,
    matched_restic_target   text,
    run_id                  bigint,
    notes                   text
);
CREATE INDEX IF NOT EXISTS idx_diskaudit_backup_coverage_staging_host_path
    ON diskaudit.backup_coverage_staging (host, path);

COMMIT;
