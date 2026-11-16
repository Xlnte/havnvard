-- HavnVard 3.3.11 (INFRA-565, FILE-4): generic names instead of the original deployment's. Idempotent.
--   integrity_checks.spark_host / spark_path        -> source_host / source_path   (+ index rename)
--   report_snapshots.spark_files / spark_bytes      -> local_files / local_bytes
--   operator_verdict value 'investigate_spark'      -> 'investigate_server' (corruption_suspects, hash_divergences;
--                                                      existing rows are updated, the CHECK is re-created)
--   git_repo_roots.discovered_via DEFAULT           -> 'manual' (existing rows keep their value)
-- NOT in this migration (follow-up, see the 3.3.11 report): the infra126_* tables, views, functions and indexes.
--
-- Deploy order: this migration and the 3.3.11 code go together, in a window with no scan / verify / report run.
-- 3.3.10 and older code names the old columns and fails on the renamed ones; 3.3.11 code names the new ones.
-- Read-only compatibility: two views keep the OLD column names for ad-hoc queries and old dashboards:
--   diskaudit.v_integrity_checks_legacy_names, diskaudit.v_report_snapshots_legacy_names.
-- A view cannot take writes the way the old columns did, so old WRITERS (3.3.10 crosshost_verify / verify_tree /
-- havnvard_report) must be upgraded together with this migration, on Spark AND on the agent host.
-- Apply: psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f <this file>
BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='integrity_checks' AND column_name='spark_host') THEN
        ALTER TABLE diskaudit.integrity_checks RENAME COLUMN spark_host TO source_host;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='integrity_checks' AND column_name='spark_path') THEN
        ALTER TABLE diskaudit.integrity_checks RENAME COLUMN spark_path TO source_path;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='report_snapshots' AND column_name='spark_files') THEN
        ALTER TABLE diskaudit.report_snapshots RENAME COLUMN spark_files TO local_files;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='report_snapshots' AND column_name='spark_bytes') THEN
        ALTER TABLE diskaudit.report_snapshots RENAME COLUMN spark_bytes TO local_bytes;
    END IF;
END $$;

ALTER INDEX IF EXISTS diskaudit.idx_diskaudit_integrity_checks_spark
    RENAME TO idx_diskaudit_integrity_checks_source;

-- operator_verdict: move the value, then the CHECK (rows first would violate the old CHECK's complement).
ALTER TABLE diskaudit.corruption_suspects DROP CONSTRAINT IF EXISTS corruption_suspects_operator_verdict_check;
UPDATE diskaudit.corruption_suspects SET operator_verdict = 'investigate_server' WHERE operator_verdict = 'investigate_spark';
ALTER TABLE diskaudit.corruption_suspects ADD CONSTRAINT corruption_suspects_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_server','investigate_nas','investigate_restic','unresolved']));
ALTER TABLE diskaudit.hash_divergences DROP CONSTRAINT IF EXISTS hash_divergences_operator_verdict_check;
UPDATE diskaudit.hash_divergences SET operator_verdict = 'investigate_server' WHERE operator_verdict = 'investigate_spark';
ALTER TABLE diskaudit.hash_divergences ADD CONSTRAINT hash_divergences_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_server','investigate_nas','investigate_restic','unresolved']));

ALTER TABLE diskaudit.git_repo_roots ALTER COLUMN discovered_via SET DEFAULT 'manual';

-- Read-only compatibility views (old column names). Not part of schema/baseline.sql (the generator drops them).
CREATE OR REPLACE VIEW diskaudit.v_integrity_checks_legacy_names AS
    SELECT id, checked_at, source_path AS spark_path, source_host AS spark_host, nas_path, size_bytes,
           sha_source, sha_dest, verdict, notes, basis, tree_run_id
      FROM diskaudit.integrity_checks;
CREATE OR REPLACE VIEW diskaudit.v_report_snapshots_legacy_names AS
    SELECT snap_date, total_files, total_bytes, local_files AS spark_files, local_bytes AS spark_bytes,
           nas_files, nas_bytes, dup_files, dup_groups, reclaimable_bytes, scan_errors, created_at
      FROM diskaudit.report_snapshots;
COMMIT;
-- Rollback (only while no 3.3.11 code runs; also restore 3.3.10 code): rename the columns back, rename the index back,
-- UPDATE ... 'investigate_spark' for both tables after re-creating the CHECK with the old value, ALTER COLUMN
-- discovered_via SET DEFAULT 'find-scan-20260718', DROP VIEW both *_legacy_names views.
