-- diskaudit v2 — heartbeat/stage tracking + per-worker status + history log
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-98
--
-- Adds hang-detection infrastructure: a heartbeat + current-stage field on the two
-- existing run tables, per-worker granularity for the parallel dedup path (so a
-- monitor can tell WHICH of N concurrent workers is stuck, not just that the overall
-- run looks stale), and an append-only history log for retroactive analysis.

BEGIN;

ALTER TABLE diskaudit.scan_runs ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
ALTER TABLE diskaudit.scan_runs ADD COLUMN IF NOT EXISTS current_stage text;

ALTER TABLE diskaudit.dedup_runs ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
ALTER TABLE diskaudit.dedup_runs ADD COLUMN IF NOT EXISTS current_stage text;

CREATE TABLE IF NOT EXISTS diskaudit.dedup_worker_status (
    dedup_run_id      bigint NOT NULL REFERENCES diskaudit.dedup_runs (dedup_run_id),
    worker_idx        integer NOT NULL,
    bucket_file_count integer,
    bucket_bytes      bigint,
    current_stage     text,
    last_heartbeat_at timestamptz,
    status            text NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'failed')),
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    PRIMARY KEY (dedup_run_id, worker_idx)
);

-- Append-only heartbeat history (distinct from the single last_heartbeat_at above,
-- which is only ever the most recent value) -- lets a run's progress be reconstructed
-- retroactively (e.g. "which stage took the longest"), not just monitored live.
CREATE TABLE IF NOT EXISTS diskaudit.run_heartbeats (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_type     text NOT NULL CHECK (run_type IN ('scan', 'dedup')),
    run_id       bigint NOT NULL,
    worker_idx   integer,               -- NULL for scan_runs / the overall dedup_runs row
    host         text NOT NULL,
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    stage        text,
    note         text
);
CREATE INDEX IF NOT EXISTS idx_diskaudit_run_heartbeats_lookup
    ON diskaudit.run_heartbeats (run_type, run_id, heartbeat_at DESC);

COMMIT;
