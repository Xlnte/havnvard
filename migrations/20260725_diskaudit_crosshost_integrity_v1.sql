-- diskaudit v2 — cross-host content-hash verification (crosshost_verify.py)
-- Date: 2026-07-25 · Owner: the operator · Plan: crosshost NAS-integrity build
-- Runbook: /home/alice/runbooks/20260725-havnvard-crosshost-integrity/RUNBOOK.md
--
-- Adds the columns/tables needed to hash the cross-host candidate set (files
-- whose size_bytes appears on >=2 hosts, >=1MB) and record, per file, whether a
-- byte-identical copy was independently verified to exist on another host.
--
-- Additive + idempotent (safe to re-run). Does NOT alter or drop anything
-- existing -- dedup.py's rdfind-based duplicate_group_id/dedup_tool/dedup_method/
-- dedup_checked_at columns are untouched; this migration adds new, separate
-- content_sha256/hashed_at/hash_source columns that crosshost_verify.py owns.
-- The two systems interoperate through duplicate_group_id (see match subcommand)
-- but neither writes into the other's columns exclusively.

BEGIN;

-- 1. Cross-host content hash columns on diskaudit.files.
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS content_sha256 text;
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS hashed_at timestamptz;
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS hash_source text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'files_hash_source_check'
    ) THEN
        ALTER TABLE diskaudit.files ADD CONSTRAINT files_hash_source_check
            CHECK (hash_source IN ('local', 'nas-native', 'trigkey-agent'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_diskaudit_files_content_sha256
    ON diskaudit.files (content_sha256) WHERE content_sha256 IS NOT NULL;

-- 2. Per-file cross-host integrity verification log. Every row is evidence
-- collected AT ONE POINT IN TIME (checked_at) -- a 'match' verdict proves
-- bit-identity at time of test, it does NOT guarantee against later bit rot,
-- silent corruption, or a subsequent overwrite on either side. Re-verification
-- is a fresh row, not an update -- history is preserved (append-only), matching
-- this repo's "never destroy evidence" documentation convention.
CREATE TABLE IF NOT EXISTS diskaudit.integrity_checks (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    checked_at      timestamptz NOT NULL DEFAULT now(),
    -- "spark_*" naming per spec -- source side is server-1 OR agent-1 (both
    -- are "the machines whose data we want proven safe"); nas-1 is always
    -- the destination/backup side being checked against.
    spark_path      text NOT NULL,
    spark_host      text NOT NULL,
    nas_path        text,
    size_bytes      bigint,
    sha_source      text,
    sha_dest        text,
    verdict         text NOT NULL CHECK (
                        verdict IN ('match', 'mismatch', 'missing_dest',
                                    'unreadable_source', 'unreadable_dest')
                    ),
    notes           text
);

CREATE INDEX IF NOT EXISTS idx_diskaudit_integrity_checks_verdict
    ON diskaudit.integrity_checks (verdict);
CREATE INDEX IF NOT EXISTS idx_diskaudit_integrity_checks_spark
    ON diskaudit.integrity_checks (spark_host, spark_path);
CREATE INDEX IF NOT EXISTS idx_diskaudit_integrity_checks_checked_at
    ON diskaudit.integrity_checks (checked_at DESC);

-- 3. Run-tracking table for crosshost_verify.py's hash/match subcommands,
-- same shape/purpose as dedup_runs/backup_runs/scan_runs -- gives `match`/`hash`
-- runs a heartbeat home (run_heartbeats.run_id) and lets long hashing runs be
-- monitored/resumed the same way scan/dedup runs already are.
CREATE TABLE IF NOT EXISTS diskaudit.crosshost_verify_runs (
    run_id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subcommand                text NOT NULL CHECK (subcommand IN ('hash', 'match')),
    host                      text,  -- host being hashed; NULL for match (cross-host, no single host)
    started_at                timestamptz NOT NULL DEFAULT now(),
    finished_at               timestamptz,
    status                    text NOT NULL DEFAULT 'running'
                                CHECK (status IN ('running', 'completed', 'failed')),
    files_considered          bigint,
    files_hashed              bigint,
    files_skipped_unchanged   bigint,
    files_errored             bigint,
    groups_found              bigint,
    notes                     text
);

-- last_heartbeat_at/current_stage mirror scan_runs/dedup_runs/backup_runs so
-- heartbeat.py's write_heartbeat()/monitor.py's staleness check work
-- identically for crosshost_verify runs (see heartbeat.py's table_map).
-- Added via ALTER (not inline in the CREATE TABLE above) so this migration
-- stays idempotent even after crosshost_verify_runs already exists from an
-- earlier apply of this same file.
ALTER TABLE diskaudit.crosshost_verify_runs ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
ALTER TABLE diskaudit.crosshost_verify_runs ADD COLUMN IF NOT EXISTS current_stage text;

-- 4. Widen run_heartbeats.run_type to accept crosshost_verify runs (heartbeat.py
-- is reused as-is -- write_heartbeat(conn, "crosshost_verify", run_id, host, stage)).
ALTER TABLE diskaudit.run_heartbeats DROP CONSTRAINT IF EXISTS run_heartbeats_run_type_check;
ALTER TABLE diskaudit.run_heartbeats ADD CONSTRAINT run_heartbeats_run_type_check
    CHECK (run_type = ANY (ARRAY['scan'::text, 'dedup'::text, 'restic_backup'::text, 'crosshost_verify'::text]));

COMMIT;
