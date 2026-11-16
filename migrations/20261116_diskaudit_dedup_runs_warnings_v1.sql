-- HavnVard 3.3.8 (INFRA-567): a run records the warnings it started with (for example an empty
-- [nas] backup_tree_prefix, which turns off the "never keep a backup replica" keeper rule).
-- Idempotent. Owned by nas_trigkey_dedup.py.
ALTER TABLE diskaudit.dedup_runs
    ADD COLUMN IF NOT EXISTS warnings text[] NOT NULL DEFAULT '{}';
