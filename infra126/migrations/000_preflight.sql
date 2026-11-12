-- Read-only preflight. Run before 001.
DO $$
DECLARE
  missing TEXT[];
  incompatible TEXT[] := ARRAY[]::TEXT[];
BEGIN
  IF current_setting('server_version_num')::int < 120000 THEN
    RAISE EXCEPTION 'INFRA-126 requires PostgreSQL 12 or newer';
  END IF;

  SELECT array_agg(required.column_name ORDER BY required.column_name)
  INTO missing
  FROM (VALUES
    ('host'),('path'),('inode'),('content_sha256'),('hashed_at'),
    ('mtime'),('size_bytes'),('still_exists'),('file_type')
  ) AS required(column_name)
  WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.columns c
    WHERE c.table_schema='diskaudit' AND c.table_name='files'
      AND c.column_name=required.column_name
  );
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'diskaudit.files is missing required columns: %', missing;
  END IF;

  -- Refuse to silently layer the rebuild over any earlier prototype. CREATE
  -- TABLE IF NOT EXISTS cannot upgrade an incompatible table definition safely.
  IF to_regclass('diskaudit.hash_verification_sla') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='hash_verification_sla' AND column_name='schedule_mode'
  ) THEN incompatible := array_append(incompatible,'hash_verification_sla'); END IF;

  IF to_regclass('diskaudit.hash_verification_runs') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='hash_verification_runs' AND column_name='remaining_due_count'
  ) THEN incompatible := array_append(incompatible,'hash_verification_runs'); END IF;

  IF to_regclass('diskaudit.hash_verification_items') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='hash_verification_items' AND column_name='lease_expires_at'
  ) THEN incompatible := array_append(incompatible,'hash_verification_items'); END IF;

  IF to_regclass('diskaudit.hash_divergences') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='hash_divergences' AND column_name='decision_state'
  ) THEN incompatible := array_append(incompatible,'hash_divergences'); END IF;

  IF to_regclass('diskaudit.mutable_file_registry') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='mutable_file_registry' AND column_name='score'
  ) THEN incompatible := array_append(incompatible,'mutable_file_registry'); END IF;

  IF to_regclass('diskaudit.corruption_suspects') IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns WHERE table_schema='diskaudit'
      AND table_name='corruption_suspects' AND column_name='file_key'
  ) THEN incompatible := array_append(incompatible,'corruption_suspects'); END IF;

  IF cardinality(incompatible) > 0 THEN
    RAISE EXCEPTION 'Older incompatible INFRA-126 prototype tables exist: %. Export them and create a reviewed upgrade migration before applying the rebuild.', incompatible;
  END IF;
END $$;
