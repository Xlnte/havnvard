-- diskaudit v1 — whole-disk file inventory (log-only)
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- v1 is intentionally slim: just enough to record a monthly whole-disk file
-- inventory. No dedup-group column, no cabinet_reviews table — those land in
-- v2 once the log-only crawl has been running and proven out. Additive +
-- idempotent (safe to re-run).

BEGIN;

CREATE SCHEMA IF NOT EXISTS diskaudit;

-- One row per scan (monthly, or ad hoc dry-runs during development).
CREATE TABLE IF NOT EXISTS diskaudit.scan_runs (
    scan_id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    host           text NOT NULL DEFAULT 'server-1',
    root_path      text NOT NULL DEFAULT '/',
    files_scanned  bigint,
    dirs_scanned   bigint,
    bytes_scanned  bigint,
    errors_count   integer NOT NULL DEFAULT 0,
    status         text NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'completed', 'failed', 'dry_run')),
    dry_run        boolean NOT NULL DEFAULT false,
    notes          text
);

-- Living inventory keyed by path, upserted every scan (not append-per-run).
CREATE TABLE IF NOT EXISTS diskaudit.files (
    path                text NOT NULL PRIMARY KEY,
    file_type           text NOT NULL,   -- 'regular' | 'dir' | 'symlink' | 'other'
    symlink_target      text,
    size_bytes          bigint,
    mode                integer,
    uid                 integer,
    gid                 integer,
    owner_name          text,
    group_name          text,
    inode               bigint,
    nlink               integer,
    extension           text,
    mtime               timestamptz,
    atime               timestamptz,
    btime               timestamptz,     -- NULL if statx birthtime unsupported for this file
    first_seen_scan_id  bigint NOT NULL REFERENCES diskaudit.scan_runs (scan_id),
    last_seen_scan_id   bigint NOT NULL REFERENCES diskaudit.scan_runs (scan_id),
    still_exists        boolean NOT NULL DEFAULT true,
    disappeared_at      timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_diskaudit_files_size_atime
    ON diskaudit.files (size_bytes DESC, atime)
    WHERE still_exists AND file_type = 'regular';
CREATE INDEX IF NOT EXISTS idx_diskaudit_files_still_exists
    ON diskaudit.files (still_exists);
CREATE INDEX IF NOT EXISTS idx_diskaudit_files_extension
    ON diskaudit.files (extension);

-- Per-run error log (permission-denied, race ENOENT, etc.) — non-fatal, informational.
CREATE TABLE IF NOT EXISTS diskaudit.scan_errors (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id     bigint NOT NULL REFERENCES diskaudit.scan_runs (scan_id),
    path        text NOT NULL,
    error       text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- Staging table for bulk COPY load; truncated + reloaded fresh every scan.
-- UNLOGGED: no WAL overhead for a table that's rebuilt from scratch each run.
CREATE UNLOGGED TABLE IF NOT EXISTS diskaudit.files_staging (
    path            text NOT NULL,
    file_type       text NOT NULL,
    symlink_target  text,
    size_bytes      bigint,
    mode            integer,
    uid             integer,
    gid             integer,
    owner_name      text,
    group_name      text,
    inode           bigint,
    nlink           integer,
    extension       text,
    mtime           timestamptz,
    atime           timestamptz,
    btime           timestamptz
);
CREATE INDEX IF NOT EXISTS idx_diskaudit_files_staging_path ON diskaudit.files_staging (path);

COMMIT;
