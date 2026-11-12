-- diskaudit -- HavnVard 1.4.3 per-scan staging. Date: 2026-11-09 -- Plane: INFRA-522 (R142-6), INFRA-518.
-- Additive and metadata-only: a nullable column with no default (PG16 does not rewrite the table).
-- Rows staged by 1.4.2 and earlier keep scan_id NULL; 1.4.3 clears them at the host's next scan start.
-- NOT applied by the implementer: the deployer applies it BEFORE switching /srv/diskaudit to 1.4.3
-- (1.4.3 scan.py/load_nas_inventory.py COPY into scan_id and fail without it).
-- Apply: psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -1 -f <this file>
BEGIN;
SET LOCAL lock_timeout = '5s';
ALTER TABLE diskaudit.files_staging ADD COLUMN IF NOT EXISTS scan_id bigint;
COMMENT ON COLUMN diskaudit.files_staging.scan_id IS
  '1.4.3: the scan_runs.scan_id that staged this row; merge reads only its own scan_id. NULL = staged by <= 1.4.2.';
COMMIT;
-- Rollback (only while no 1.4.3 scan runs): ALTER TABLE diskaudit.files_staging DROP COLUMN scan_id;
