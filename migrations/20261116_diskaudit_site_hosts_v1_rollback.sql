-- Rollback of 20261116_diskaudit_site_hosts_v1.sql (HavnVard 3.3.9, INFRA-562). Puts back the single-host v_nas_orphans
-- (same columns, same rows as before 3.3.9) and drops diskaudit.site_hosts and its guard function.
-- The NAS host is YOUR site's NAS ([hosts] nas in the site file); it is a psql variable so no host name is committed:
--   psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -v nas_host=<your NAS host> -f migrations/20261116_diskaudit_site_hosts_v1_rollback.sql
-- Do NOT use migrations/20260718_diskaudit_backup_coverage_v2.sql for this: in the published repo it names a placeholder host,
-- so its view would silently match no files. Without -v nas_host this file stops with an error; it never guesses a host.
\set ON_ERROR_STOP on
\if :{?nas_host}
\else
DO $$BEGIN RAISE EXCEPTION 'rollback: pass -v nas_host=<your NAS host>'; END$$;
\endif
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE VIEW diskaudit.v_nas_orphans AS
SELECT
    f.host,
    f.path,
    f.size_bytes,
    f.duplicate_group_id,
    f.inode,
    f.mtime
FROM diskaudit.files f
WHERE f.host = :'nas_host'
  AND f.still_exists
  AND f.file_type = 'regular'
  AND NOT EXISTS (
      SELECT 1
      FROM diskaudit.files other
      WHERE other.duplicate_group_id = f.duplicate_group_id
        AND other.host <> :'nas_host'
        AND other.still_exists
        AND f.duplicate_group_id IS NOT NULL
  );

COMMENT ON VIEW diskaudit.v_nas_orphans IS
  'Live regular files on the NAS host with no content-identical copy (matching duplicate_group_id) confirmed on any '
  'other host -- includes files never deduped (duplicate_group_id IS NULL). Single-host form restored by the 3.3.9 rollback.';

DROP FUNCTION IF EXISTS diskaudit.site_nas_hosts_configured();
DROP TABLE IF EXISTS diskaudit.site_hosts;

COMMIT;
