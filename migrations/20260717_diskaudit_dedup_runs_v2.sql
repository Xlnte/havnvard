-- diskaudit v2 — dedup_runs audit table (per-stage elimination counts from rdfind's 4-step pipeline)
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- Previously only the FINAL verdict (duplicate_group_id on diskaudit.files) was persisted.
-- This captures the full result of rdfind's 4-stage elimination (size -> first bytes ->
-- last bytes -> full checksum) for audit/debugging, one row per dedup.py invocation.

BEGIN;

CREATE TABLE IF NOT EXISTS diskaudit.dedup_runs (
    dedup_run_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host                    text NOT NULL,
    root_dirs               text[] NOT NULL,
    started_at              timestamptz NOT NULL DEFAULT now(),
    finished_at             timestamptz,
    dedup_tool              text NOT NULL DEFAULT 'rdfind',
    dedup_method            text NOT NULL DEFAULT 'sha256',
    total_files_considered  bigint,
    eliminated_unique_size  bigint,   -- stage 1: files with no size-match candidate
    eliminated_first_bytes  bigint,   -- stage 2
    eliminated_last_bytes   bigint,   -- stage 3
    eliminated_checksum     bigint,   -- stage 4: same size+first+last bytes but checksum differs
    duplicate_files_found   bigint,   -- files remaining after all 4 stages (genuine duplicates)
    duplicate_groups_found  bigint,
    status                  text NOT NULL DEFAULT 'running'
                              CHECK (status IN ('running', 'completed', 'failed')),
    raw_stdout              text      -- full rdfind stdout, for anything the parsed columns miss
);

COMMIT;
