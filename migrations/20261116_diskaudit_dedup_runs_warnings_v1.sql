-- HavnVard 3.3.8 (INFRA-567): a run records the warnings it started with (for example an empty
-- [nas] backup_tree_prefix, which turns off the "never keep a backup replica" keeper rule).
-- Idempotent. Owned by nas_trigkey_dedup.py. Backward compatible: <= 3.3.7 code never names the column and
-- gets the default, so apply this BEFORE deploying 3.3.8 code (3.3.8's INSERT names `warnings`).
-- Old rows get '{}' (constant default: PG 11+ adds it without a table rewrite; brief ACCESS EXCLUSIVE lock).
-- Apply: psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f <this file>
BEGIN;
-- Never queue behind a running dedup's open transaction on dedup_runs (a queued ACCESS EXCLUSIVE would block
-- every heartbeat and monitor read behind it). On a timeout: re-run when no dedup run is active.
SET LOCAL lock_timeout = '5s';
ALTER TABLE diskaudit.dedup_runs
    ADD COLUMN IF NOT EXISTS warnings text[] NOT NULL DEFAULT '{}';
COMMIT;
-- Rollback (only while no 3.3.8 code runs): ALTER TABLE diskaudit.dedup_runs DROP COLUMN warnings;
