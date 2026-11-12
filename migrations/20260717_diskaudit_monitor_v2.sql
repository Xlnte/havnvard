-- diskaudit v2 — monitor.py idempotency support
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-98
--
-- Adds alerted_at to the three run/worker-status tables monitor.py polls, so a
-- stale/failed condition is only ever alerted once per occurrence (a NEW
-- heartbeat after alerting resets eligibility -- see monitor.py's
-- `alerted_at IS NULL OR alerted_at < last_heartbeat_at` check).

BEGIN;

ALTER TABLE diskaudit.scan_runs ADD COLUMN IF NOT EXISTS alerted_at timestamptz;
ALTER TABLE diskaudit.dedup_runs ADD COLUMN IF NOT EXISTS alerted_at timestamptz;
ALTER TABLE diskaudit.dedup_worker_status ADD COLUMN IF NOT EXISTS alerted_at timestamptz;

COMMIT;
