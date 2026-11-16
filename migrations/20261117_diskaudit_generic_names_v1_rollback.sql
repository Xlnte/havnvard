-- Rollback of 20261117_diskaudit_generic_names_v1.sql (HavnVard 3.3.11, INFRA-565). Puts the pre-3.3.11 names back:
--   integrity_checks.source_host / source_path -> spark_host / spark_path (+ index), report_snapshots.local_* -> spark_*,
--   operator_verdict 'investigate_server' -> 'investigate_spark' (rows + CHECKs), git_repo_roots.discovered_via DEFAULT
--   back to 'find-scan-20260718', and drops the two *_legacy_names views (they name the new columns).
-- Use only together with a return to 3.3.10 code on Spark AND the agent host: 3.3.11 code fails on the old names.
-- Stop every writer first (same list as the forward deploy). Idempotent.
--   psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/20261117_diskaudit_generic_names_v1_rollback.sql
BEGIN;
SET LOCAL lock_timeout = '5s';

DROP VIEW IF EXISTS diskaudit.v_integrity_checks_legacy_names;
DROP VIEW IF EXISTS diskaudit.v_report_snapshots_legacy_names;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='integrity_checks' AND column_name='source_host') THEN
        ALTER TABLE diskaudit.integrity_checks RENAME COLUMN source_host TO spark_host;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='integrity_checks' AND column_name='source_path') THEN
        ALTER TABLE diskaudit.integrity_checks RENAME COLUMN source_path TO spark_path;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='report_snapshots' AND column_name='local_files') THEN
        ALTER TABLE diskaudit.report_snapshots RENAME COLUMN local_files TO spark_files;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
               AND table_name='report_snapshots' AND column_name='local_bytes') THEN
        ALTER TABLE diskaudit.report_snapshots RENAME COLUMN local_bytes TO spark_bytes;
    END IF;
END $$;

ALTER INDEX IF EXISTS diskaudit.idx_diskaudit_integrity_checks_source
    RENAME TO idx_diskaudit_integrity_checks_spark;

-- Same trigger handling as the forward migration: a rename of the value only, no verdict copied between tables.
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
UPDATE diskaudit.corruption_suspects SET operator_verdict = 'investigate_spark' WHERE operator_verdict = 'investigate_server';
UPDATE diskaudit.hash_divergences SET operator_verdict = 'investigate_spark' WHERE operator_verdict = 'investigate_server';
ALTER TABLE diskaudit.corruption_suspects ADD CONSTRAINT corruption_suspects_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_spark','investigate_nas','investigate_restic','unresolved']));
ALTER TABLE diskaudit.hash_divergences ADD CONSTRAINT hash_divergences_operator_verdict_check
    CHECK (operator_verdict IS NULL OR operator_verdict = ANY (ARRAY['benign','suspicious','confirmed_corruption',
           'investigate_spark','investigate_nas','investigate_restic','unresolved']));
DO $$
BEGIN
    CASE current_setting('havnvard.m20261117_trg')
        WHEN 'O' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE TRIGGER trg_infra126_sync_suspect_review;
        WHEN 'A' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE ALWAYS TRIGGER trg_infra126_sync_suspect_review;
        WHEN 'R' THEN ALTER TABLE diskaudit.corruption_suspects ENABLE REPLICA TRIGGER trg_infra126_sync_suspect_review;
        ELSE NULL;
    END CASE;
END $$;

ALTER TABLE diskaudit.git_repo_roots ALTER COLUMN discovered_via SET DEFAULT 'find-scan-20260718';
COMMIT;
