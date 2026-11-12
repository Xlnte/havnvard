-- diskaudit v2 — multi-host (host,path) key + dedup columns
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- Fixes a real bug in the v1 schema: diskaudit.files.path was the sole PRIMARY KEY,
-- which breaks the moment a second host (the NAS) is added -- the same path string
-- could exist on both machines with unrelated content, and an upsert from one host
-- would silently clobber the other host's row for a coincidentally-identical path.
-- scan_runs.host already existed (built with this in mind); files itself did not.
--
-- Also adds the columns needed for rdfind-based duplicate detection (v2 Part A).
-- Additive + safe to re-run (IF NOT EXISTS / IF EXISTS guards throughout).

BEGIN;

-- 1. Add host to files, backfill existing v1 rows as server-1 (the only host so far).
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS host text;
UPDATE diskaudit.files SET host = 'server-1' WHERE host IS NULL;
ALTER TABLE diskaudit.files ALTER COLUMN host SET NOT NULL;
ALTER TABLE diskaudit.files ALTER COLUMN host SET DEFAULT 'server-1';

-- 2. Swap the primary key from (path) to (host, path).
ALTER TABLE diskaudit.files DROP CONSTRAINT IF EXISTS files_pkey;
ALTER TABLE diskaudit.files ADD CONSTRAINT files_pkey PRIMARY KEY (host, path);

-- 3. Dedup columns (rdfind-based, v2 Part A).
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS duplicate_group_id text;
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS dedup_tool text;
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS dedup_method text;
ALTER TABLE diskaudit.files ADD COLUMN IF NOT EXISTS dedup_checked_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_diskaudit_files_host ON diskaudit.files (host);
CREATE INDEX IF NOT EXISTS idx_diskaudit_files_dup_group
    ON diskaudit.files (duplicate_group_id) WHERE duplicate_group_id IS NOT NULL;

-- 4. Staging table needs the same host column + composite key for the merge to work.
ALTER TABLE diskaudit.files_staging ADD COLUMN IF NOT EXISTS host text;
UPDATE diskaudit.files_staging SET host = 'server-1' WHERE host IS NULL;
ALTER TABLE diskaudit.files_staging ALTER COLUMN host SET NOT NULL;
ALTER TABLE diskaudit.files_staging ALTER COLUMN host SET DEFAULT 'server-1';

-- 5. critical_patterns config table (v2 Part B, created now so it's available for both hosts
-- from day one -- the operator-editable list of "things that would hurt to lose").
CREATE TABLE IF NOT EXISTS diskaudit.critical_patterns (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pattern     text NOT NULL,       -- path prefix or LIKE pattern, e.g. '/srv/backups/%'
    label       text,                -- human-readable reason, e.g. 'DB backup dumps'
    source      text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'thoth_census')),
    added_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pattern)
);

-- Seed from thoth.census active-system paths (additive, safe to re-run).
INSERT INTO diskaudit.critical_patterns (pattern, label, source)
SELECT DISTINCT unnest(c.paths || ARRAY[c.primary_path]) || '%', c.name || ' (thoth.census)', 'thoth_census'
FROM thoth.census c
WHERE c.status = 'active' AND c.primary_path IS NOT NULL
ON CONFLICT (pattern) DO NOTHING;

INSERT INTO diskaudit.critical_patterns (pattern, label, source) VALUES
    ('/srv/backups/%', 'DB/CRM backup dumps', 'manual')
ON CONFLICT (pattern) DO NOTHING;

COMMIT;
