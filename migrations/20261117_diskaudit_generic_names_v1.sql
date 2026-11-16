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

-- operator_verdict: drop BOTH old CHECKs, move the value in both tables, then add both new CHECKs.
-- The infra126 trigger trg_infra126_sync_suspect_review copies a suspect's verdict onto its latest divergence on
-- UPDATE. It is switched off for the two UPDATEs (and back on only if it was on): with it on, the suspect UPDATE wrote
-- 'investigate_server' into hash_divergences while that table's old CHECK still stood and the whole migration failed
-- (3.3.11 review), and it would also copy a suspect verdict over a different divergence verdict. This is a rename only.
SELECT set_config('havnvard.m20261117_trg', COALESCE((
    SELECT t.tgenabled::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'diskaudit' AND c.relname = 'corruption_suspects'
       AND t.tgname = 'trg_infra126_sync_suspect_review'), 'absent'), true);
DO $$
BEGIN
    IF current_setting('havnvard.m20261117_trg') NOT IN ('absent', 'D') THEN
        ALTER TABLE diskaudit.corruption_suspects DISABLE TRIGGER trg_infra126_sync_suspect_review;
    END IF;
END $$;
ALTER TABLE diskaudit.corruption_suspects DROP CONSTRAINT IF EXISTS corruption_suspects_operator_verdict_check;
ALTER TABLE diskaudit.hash_divergences DROP CONSTRAINT IF EXISTS hash_divergences_operator_verdict_check;
UPDATE diskaudit.corruption_suspects SET operator_verdict = 'investigate_server' WHERE operator_verdict = 'investigate_spark';
UPDATE diskaudit.hash_divergences SET operator_verdict = 'investigate_server' WHERE operator_verdict = 'investigate_spark';
ALTER TABLE diskaudit.corruption_suspects ADD CONSTRAINT corruption_suspects_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_server','investigate_nas','investigate_restic','unresolved']));
ALTER TABLE diskaudit.hash_divergences ADD CONSTRAINT hash_divergences_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_server','investigate_nas','investigate_restic','unresolved']));
DO $$
BEGIN
    CASE current_setting('havnvard.m20261117_trg')      -- put back exactly the mode it had
        WHEN 'O' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE TRIGGER trg_infra126_sync_suspect_review;
        WHEN 'A' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE ALWAYS TRIGGER trg_infra126_sync_suspect_review;
        WHEN 'R' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE REPLICA TRIGGER trg_infra126_sync_suspect_review;
        ELSE NULL;                                         -- 'absent' or 'D': nothing was switched off
    END CASE;
END $$;

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
-- Rollback: migrations/20261117_diskaudit_generic_names_v1_rollback.sql (stop every writer first; restore 3.3.10 code on
-- Spark AND the agent host before any timer runs again).
