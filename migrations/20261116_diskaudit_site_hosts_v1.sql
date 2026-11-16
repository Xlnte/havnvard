-- HavnVard 3.3.9 (INFRA-562): a generic NAS-orphan view.
-- diskaudit.site_hosts says which hosts are NAS hosts (and which are backup sources). It is filled from the site file by
--   python3 init_site_hosts.py          (also creates the hash_verification_sla rows, INFRA-563)
-- v_nas_orphans keeps its name and columns but no longer names one host: it reads the NAS hosts from site_hosts.
-- Until site_hosts has a 'nas' row the view returns NO rows (it never guesses a host). Run init_site_hosts.py right after
-- applying this file. Idempotent. Apply: psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f <this file>
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
WHERE f.still_exists
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
  'Empty until site_hosts has a nas row (run init_site_hosts.py).';

COMMIT;
-- Rollback: restore the single-host view from migrations/20260718_diskaudit_backup_coverage_v2.sql (it names the original
-- NAS host), then DROP TABLE diskaudit.site_hosts;
