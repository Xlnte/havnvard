-- diskaudit v2 — dedup write-batching fix
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- write_groups() was doing one UPDATE per file (1.8M individual round-trips on the
-- /srv/apps test -- confirmed ~22 of the 78 total minutes, a real, measured cost).
-- Fix: same COPY-into-staging + set-based UPDATE...FROM pattern scan.py already uses.

BEGIN;

CREATE UNLOGGED TABLE IF NOT EXISTS diskaudit.dedup_staging (
    host                text NOT NULL,
    path                text NOT NULL,
    duplicate_group_id  text NOT NULL,
    dedup_tool          text NOT NULL,
    dedup_method        text NOT NULL,
    dedup_checked_at    timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_diskaudit_dedup_staging_host_path
    ON diskaudit.dedup_staging (host, path);

COMMIT;
