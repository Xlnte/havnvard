-- HavnVard 3.3.9 (INFRA-562): a generic NAS-orphan view.
-- diskaudit.site_hosts says which hosts are NAS hosts (and which are backup sources). It is filled from the site file by
--   python3 init_site_hosts.py          (also creates the hash_verification_sla rows, INFRA-563)
-- v_nas_orphans keeps its name and columns but no longer names one host: it reads the NAS hosts from site_hosts.
-- Until site_hosts has a 'nas' row, reading the view raises an error naming init_site_hosts.py (review 3.3.9: an empty
-- result would read as "no orphans"); it never guesses a host. Run init_site_hosts.py right after applying this file.
-- Idempotent. Apply: psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f <this file>
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS diskaudit.site_hosts (
    host     text PRIMARY KEY,
    role     text NOT NULL CHECK (role IN ('source', 'nas')),
    added_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE diskaudit.site_hosts IS
  'The site file''s hosts and their role: source = a machine whose files need a backup, nas = a NAS (the backup target). '
  'Filled by init_site_hosts.py; read by v_nas_orphans.';

-- Raises when no NAS host is configured, so "not configured" can never look like "no orphans".
CREATE OR REPLACE FUNCTION diskaudit.site_nas_hosts_configured() RETURNS boolean
LANGUAGE plpgsql STABLE AS $fn$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM diskaudit.site_hosts WHERE role = 'nas') THEN
        RAISE EXCEPTION 'v_nas_orphans: diskaudit.site_hosts has no nas row, so the NAS host is unknown (not "no orphans")'
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'Run python3 init_site_hosts.py; it reads the NAS host from the site file.';
    END IF;
    RETURN true;
END
$fn$;

CREATE OR REPLACE VIEW diskaudit.v_nas_orphans AS
SELECT
    f.host,
    f.path,
    f.size_bytes,
    f.duplicate_group_id,
    f.inode,
    f.mtime
FROM diskaudit.files f
JOIN diskaudit.site_hosts n ON n.host = f.host AND n.role = 'nas'
WHERE diskaudit.site_nas_hosts_configured()
  AND f.still_exists
  AND f.file_type = 'regular'
  AND NOT EXISTS (
      SELECT 1
      FROM diskaudit.files other
      WHERE other.duplicate_group_id = f.duplicate_group_id
        AND other.host <> f.host
        AND other.still_exists
        AND f.duplicate_group_id IS NOT NULL
  );

COMMENT ON VIEW diskaudit.v_nas_orphans IS
  'Live regular files on a NAS host (diskaudit.site_hosts, role nas) with no content-identical copy (matching '
  'duplicate_group_id) confirmed on any other host -- includes files never deduped (duplicate_group_id IS NULL). '
  'NOT limited to critical_patterns matches -- this is a whole-NAS reverse check. Deliberately unclassified: could be an '
  'intentional archive-only copy or a real single point of failure -- operator judgment call, not this view''s job. '
  'Raises (not empty) until site_hosts has a nas row: run init_site_hosts.py.';

COMMIT;
-- Rollback: migrations/20261116_diskaudit_site_hosts_v1_rollback.sql with -v nas_host=<your NAS host>.
