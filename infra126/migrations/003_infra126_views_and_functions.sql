BEGIN;

CREATE OR REPLACE VIEW diskaudit.v_infra126_verification_age AS
SELECT
  f.host,
  f.path,
  f.inode,
  (md5(f.host || E'\n' || f.path || E'\n' || COALESCE(f.inode::text,'')) || md5('infra126:' || f.host || E'\n' || f.path || E'\n' || COALESCE(f.inode::text,''))) AS file_key,
  f.size_bytes,
  f.content_sha256,
  f.first_hash,
  f.first_hashed_at,
  f.hashed_at AS current_baseline_at,
  f.last_hash_attempt_at,
  f.last_verified_at,
  f.last_baseline_accepted_at,
  CASE WHEN f.first_hashed_at IS NULL THEN NULL ELSE floor(extract(epoch FROM (now()-f.first_hashed_at))/86400)::bigint END AS days_since_first_hash,
  CASE WHEN f.last_verified_at IS NULL THEN NULL ELSE floor(extract(epoch FROM (now()-f.last_verified_at))/86400)::bigint END AS days_since_last_verification,
  f.verification_count,
  f.baseline_revision_count,
  f.hash_divergence_count,
  f.hash_status,
  f.hash_error,
  f.hash_baseline_mtime_ns,
  f.hash_baseline_size,
  f.hash_baseline_inode,
  f.hash_baseline_metadata_trusted,
  EXISTS (SELECT 1 FROM diskaudit.infra126_critical_files c WHERE c.host=f.host AND c.path=f.path) AS is_critical
FROM diskaudit.files f
WHERE f.still_exists AND f.file_type='regular';

CREATE OR REPLACE VIEW diskaudit.v_infra126_sla_status AS
SELECT
  host,tier,target_recheck_days,schedule_mode,last_completed_at,last_successful_at,
  last_completed_status,last_run_id,last_successful_run_id,next_scheduled_at,
  files_total,files_on_time,files_pending,critical_overdue_count,pct_on_time,
  CASE
    WHEN files_total=0 THEN 'NO_ELIGIBLE_FILES'
    WHEN last_successful_at IS NULL THEN 'NEVER_SUCCESSFUL'
    WHEN next_scheduled_at IS NOT NULL AND next_scheduled_at < now() THEN 'OVERDUE'
    WHEN last_completed_status='completed_with_errors' THEN 'COMPLETED_WITH_ERRORS'
    ELSE 'ON_TIME'
  END AS sla_state
FROM diskaudit.hash_verification_sla;

-- Compatibility name requested in the original brief. This is intentionally a
-- normal view, not a materialized view, so operational status cannot go stale.
CREATE OR REPLACE VIEW diskaudit.v_sla_status AS
SELECT * FROM diskaudit.v_infra126_sla_status;

CREATE OR REPLACE FUNCTION diskaudit.infra126_next_scheduled(
  p_tier CHAR(1), p_after TIMESTAMPTZ DEFAULT now()
) RETURNS TIMESTAMPTZ LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_utc TIMESTAMP := p_after AT TIME ZONE 'UTC';
  v_candidate TIMESTAMP;
BEGIN
  CASE p_tier
    WHEN 'A' THEN
      v_candidate := date_trunc('week',v_utc)+interval '2 days 23 hours';
      IF v_candidate<=v_utc THEN v_candidate:=v_candidate+interval '7 days'; END IF;
    WHEN 'B' THEN
      v_candidate := date_trunc('month',v_utc)+interval '6 days 2 hours';
      IF v_candidate<=v_utc THEN v_candidate:=date_trunc('month',v_utc+interval '1 month')+interval '6 days 2 hours'; END IF;
    WHEN 'C' THEN
      v_candidate := date_trunc('quarter',v_utc)+interval '7 days 2 hours';
      IF v_candidate<=v_utc THEN v_candidate:=date_trunc('quarter',v_utc+interval '3 months')+interval '7 days 2 hours'; END IF;
    WHEN 'E' THEN
      v_candidate := date_trunc('day',v_utc)+interval '22 hours';
      IF v_candidate<=v_utc THEN v_candidate:=v_candidate+interval '1 day'; END IF;
    ELSE
      RETURN NULL;
  END CASE;
  RETURN v_candidate AT TIME ZONE 'UTC';
END $$;

UPDATE diskaudit.hash_verification_sla
SET next_scheduled_at=COALESCE(next_scheduled_at,diskaudit.infra126_next_scheduled(tier,now())),
    updated_at=now();

CREATE OR REPLACE FUNCTION diskaudit.infra126_refresh_sla(p_host TEXT, p_tier CHAR(1))
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
  v_total BIGINT := 0;
  v_on_time BIGINT := 0;
  v_pending BIGINT := 0;
  v_critical BIGINT := 0;
BEGIN
  WITH base AS (
    SELECT f.*,
           COALESCE(f.hashed_at,f.first_hashed_at) AS baseline_at,
           EXISTS (SELECT 1 FROM diskaudit.infra126_critical_files c WHERE c.host=f.host AND c.path=f.path) AS critical
    FROM diskaudit.files f
    WHERE f.host=p_host AND f.still_exists AND f.file_type='regular'
      AND f.content_sha256 IS NOT NULL AND f.first_hashed_at IS NOT NULL
  ), eligible AS (
    SELECT *,
      CASE p_tier
        WHEN 'A' THEN NOT critical AND baseline_at >= now()-interval '7 days'
        WHEN 'B' THEN NOT critical AND baseline_at < now()-interval '7 days' AND baseline_at >= now()-interval '31 days'
        WHEN 'C' THEN NOT critical AND baseline_at < now()-interval '31 days'
        WHEN 'E' THEN critical
        ELSE FALSE
      END AS is_eligible,
      CASE p_tier
        WHEN 'A' THEN last_verified_at IS NOT NULL AND last_verified_at >= baseline_at
        WHEN 'B' THEN last_verified_at IS NOT NULL AND last_verified_at >= baseline_at AND last_verified_at >= now()-interval '30 days'
        WHEN 'C' THEN last_verified_at IS NOT NULL AND last_verified_at >= baseline_at AND last_verified_at >= now()-interval '90 days'
        WHEN 'E' THEN last_verified_at IS NOT NULL AND last_verified_at >= baseline_at AND last_verified_at >= now()-interval '1 day'
        ELSE FALSE
      END AS is_on_time
    FROM base
  )
  SELECT count(*) FILTER (WHERE is_eligible),
         count(*) FILTER (WHERE is_eligible AND is_on_time),
         count(*) FILTER (WHERE is_eligible AND NOT is_on_time),
         count(*) FILTER (WHERE critical AND NOT is_on_time)
  INTO v_total,v_on_time,v_pending,v_critical
  FROM eligible;

  UPDATE diskaudit.hash_verification_sla
  SET files_total=COALESCE(v_total,0),
      files_on_time=COALESCE(v_on_time,0),
      files_pending=COALESCE(v_pending,0),
      critical_overdue_count=CASE WHEN p_tier='E' THEN COALESCE(v_critical,0) ELSE 0 END,
      pct_on_time=CASE WHEN COALESCE(v_total,0)=0 THEN 0 ELSE round(100.0*v_on_time/v_total,2) END,
      updated_at=now()
  WHERE host=p_host AND tier=p_tier;
END $$;

CREATE OR REPLACE FUNCTION diskaudit.infra126_sync_suspect_review()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.latest_divergence_id IS NOT NULL AND (
       NEW.operator_verdict IS DISTINCT FROM OLD.operator_verdict
    OR NEW.operator_action IS DISTINCT FROM OLD.operator_action
    OR NEW.notes IS DISTINCT FROM OLD.notes
  ) THEN
    UPDATE diskaudit.hash_divergences
    SET operator_verdict=NEW.operator_verdict
    WHERE divergence_id=NEW.latest_divergence_id;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_infra126_sync_suspect_review ON diskaudit.corruption_suspects;
CREATE TRIGGER trg_infra126_sync_suspect_review
AFTER UPDATE OF operator_verdict,operator_action,notes
ON diskaudit.corruption_suspects
FOR EACH ROW EXECUTE FUNCTION diskaudit.infra126_sync_suspect_review();

COMMIT;
