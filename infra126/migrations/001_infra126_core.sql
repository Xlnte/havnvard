-- INFRA-126 core schema.
-- Additive, idempotent, and intentionally free of large index builds/backfills.
BEGIN;

ALTER TABLE diskaudit.files
  ADD COLUMN IF NOT EXISTS first_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS first_hashed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_hash_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_baseline_accepted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS verification_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS baseline_revision_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS hash_divergence_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS hash_status TEXT,
  ADD COLUMN IF NOT EXISTS hash_error TEXT,
  ADD COLUMN IF NOT EXISTS hash_baseline_mtime_ns BIGINT,
  ADD COLUMN IF NOT EXISTS hash_baseline_size BIGINT,
  ADD COLUMN IF NOT EXISTS hash_baseline_inode BIGINT,
  ADD COLUMN IF NOT EXISTS hash_baseline_metadata_trusted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS diskaudit.hash_verification_sla (
  sla_id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL,
  tier CHAR(1) NOT NULL CHECK (tier IN ('A','B','C','E')),
  target_recheck_days INTEGER NOT NULL CHECK (target_recheck_days > 0),
  schedule_mode TEXT NOT NULL CHECK (schedule_mode IN ('daily','weekly','monthly','quarterly')),
  last_completed_at TIMESTAMPTZ,
  last_successful_at TIMESTAMPTZ,
  last_completed_status TEXT,
  last_run_id UUID,
  last_successful_run_id UUID,
  next_scheduled_at TIMESTAMPTZ,
  files_total BIGINT NOT NULL DEFAULT 0,
  files_on_time BIGINT NOT NULL DEFAULT 0,
  files_pending BIGINT NOT NULL DEFAULT 0,
  critical_overdue_count BIGINT NOT NULL DEFAULT 0,
  pct_on_time NUMERIC(6,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host,tier)
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_verification_runs (
  run_id UUID PRIMARY KEY,
  host TEXT NOT NULL,
  tier CHAR(1) NOT NULL CHECK (tier IN ('A','B','C','D','E')),
  status TEXT NOT NULL CHECK (status IN (
    'queued','running','blocked','completed','completed_with_errors','failed','cancelled'
  )),
  worker_id TEXT,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  candidate_count BIGINT NOT NULL DEFAULT 0,
  completed_count BIGINT NOT NULL DEFAULT 0,
  matched_count BIGINT NOT NULL DEFAULT 0,
  divergence_count BIGINT NOT NULL DEFAULT 0,
  error_count BIGINT NOT NULL DEFAULT 0,
  remaining_due_count BIGINT NOT NULL DEFAULT 0,
  blocked_seconds BIGINT NOT NULL DEFAULT 0,
  remote_pid BIGINT,
  remote_work_dir TEXT,
  recovery_command TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  last_heartbeat_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_verification_items (
  item_id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES diskaudit.hash_verification_runs(run_id) ON DELETE RESTRICT,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  inode BIGINT,
  file_key CHAR(64) NOT NULL,
  baseline_hash CHAR(64) NOT NULL,
  baseline_hashed_at TIMESTAMPTZ,
  baseline_mtime_ns BIGINT,
  baseline_size BIGINT,
  is_critical BOOLEAN NOT NULL DEFAULT FALSE,
  baseline_metadata_trusted BOOLEAN NOT NULL DEFAULT FALSE,
  state TEXT NOT NULL CHECK (state IN (
    'pending','leased','hashing','matched','diverged','accepted_drift',
    'unreadable','changed_during_hash','stale_baseline','missing','failed','skipped'
  )),
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  observed_hash CHAR(64),
  observed_size BIGINT,
  observed_mtime_ns BIGINT,
  observed_inode BIGINT,
  duration_ms BIGINT,
  error_text TEXT,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(run_id,file_key)
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_observations (
  observation_id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES diskaudit.hash_verification_runs(run_id) ON DELETE RESTRICT,
  item_id BIGINT NOT NULL REFERENCES diskaudit.hash_verification_items(item_id) ON DELETE RESTRICT,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  file_key CHAR(64) NOT NULL,
  baseline_hash CHAR(64),
  observed_hash CHAR(64),
  result_state TEXT NOT NULL,
  observed_size BIGINT,
  observed_mtime_ns BIGINT,
  observed_inode BIGINT,
  observed_at TIMESTAMPTZ NOT NULL,
  UNIQUE(run_id,item_id)
);

CREATE TABLE IF NOT EXISTS diskaudit.mutable_file_registry (
  registry_id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL DEFAULT '*',
  path_pattern TEXT NOT NULL,
  score SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
  reason TEXT NOT NULL,
  is_regex BOOLEAN NOT NULL DEFAULT FALSE,
  pattern_kind TEXT NOT NULL DEFAULT 'mutable' CHECK (pattern_kind IN ('mutable','immutable','neutral')),
  priority INTEGER NOT NULL DEFAULT 100,
  created_by TEXT NOT NULL DEFAULT 'SYSTEM',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host,path_pattern,reason)
);

-- Upgrade an earlier prototype safely if it created nullable global-host rows.
UPDATE diskaudit.mutable_file_registry SET host='*' WHERE host IS NULL;
ALTER TABLE diskaudit.mutable_file_registry ALTER COLUMN host SET DEFAULT '*';
ALTER TABLE diskaudit.mutable_file_registry ALTER COLUMN host SET NOT NULL;
ALTER TABLE diskaudit.mutable_file_registry ADD COLUMN IF NOT EXISTS pattern_kind TEXT NOT NULL DEFAULT 'mutable';

CREATE TABLE IF NOT EXISTS diskaudit.infra126_critical_paths (
  critical_path_id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL DEFAULT '*',
  path_pattern TEXT NOT NULL,
  is_regex BOOLEAN NOT NULL DEFAULT FALSE,
  source TEXT NOT NULL DEFAULT 'load_bearing_refresh',
  refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host,path_pattern,source)
);

CREATE TABLE IF NOT EXISTS diskaudit.infra126_critical_files (
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  file_key CHAR(64) NOT NULL,
  source TEXT NOT NULL DEFAULT 'load_bearing_refresh',
  refresh_generation TEXT NOT NULL DEFAULT 'bootstrap',
  refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(file_key)
);

ALTER TABLE diskaudit.infra126_critical_files
  ADD COLUMN IF NOT EXISTS refresh_generation TEXT NOT NULL DEFAULT 'bootstrap';

CREATE TABLE IF NOT EXISTS diskaudit.hash_divergences (
  divergence_id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES diskaudit.hash_verification_runs(run_id) ON DELETE RESTRICT,
  item_id BIGINT NOT NULL REFERENCES diskaudit.hash_verification_items(item_id) ON DELETE RESTRICT,
  tier CHAR(1) NOT NULL CHECK (tier IN ('A','B','C','D','E')),
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  inode BIGINT,
  file_key CHAR(64) NOT NULL,
  old_hash CHAR(64),
  new_hash CHAR(64) NOT NULL,
  old_hashed_at TIMESTAMPTZ,
  new_hashed_at TIMESTAMPTZ NOT NULL,
  mtime_old BIGINT,
  mtime_new BIGINT,
  size_old BIGINT,
  size_new BIGINT,
  divergence_type TEXT NOT NULL CHECK (divergence_type IN ('legitimate_drift','unconfirmed_corruption','unclassified')),
  mutable_score SMALLINT CHECK (mutable_score BETWEEN 0 AND 100),
  classifier_reason TEXT,
  decision_state TEXT NOT NULL CHECK (decision_state IN (
    'insufficient_evidence','all_agree','two_copy_conflict','majority_odd_copy','three_way_split'
  )),
  authoritative_hash CHAR(64),
  odd_sources TEXT[] NOT NULL DEFAULT '{}',
  operator_verdict TEXT CHECK (
    operator_verdict IS NULL OR operator_verdict IN (
      'benign','suspicious','confirmed_corruption','investigate_spark',
      'investigate_nas','investigate_restic','unresolved'
    )
  ),
  escalated_to_tg BOOLEAN NOT NULL DEFAULT FALSE,
  escalated_to_plane BOOLEAN NOT NULL DEFAULT FALSE,
  first_divergence_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_divergence_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(run_id,item_id)
);

CREATE TABLE IF NOT EXISTS diskaudit.corruption_suspects (
  suspect_id BIGSERIAL PRIMARY KEY,
  file_key CHAR(64) NOT NULL UNIQUE,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  inode BIGINT,
  first_divergence_at TIMESTAMPTZ NOT NULL,
  last_seen_divergence_at TIMESTAMPTZ NOT NULL,
  mutable_score SMALLINT CHECK (mutable_score BETWEEN 0 AND 100),
  decision_state TEXT,
  operator_action TEXT CHECK (
    operator_action IS NULL OR operator_action IN ('monitored','isolated','investigated','dismissed')
  ),
  operator_verdict TEXT CHECK (
    operator_verdict IS NULL OR operator_verdict IN (
      'benign','suspicious','confirmed_corruption','investigate_spark',
      'investigate_nas','investigate_restic','unresolved'
    )
  ),
  latest_divergence_id BIGINT REFERENCES diskaudit.hash_divergences(divergence_id) ON DELETE RESTRICT,
  escalated_to_plane BOOLEAN NOT NULL DEFAULT FALSE,
  plane_ticket_id TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_copy_links (
  logical_file_key CHAR(64) NOT NULL,
  logical_host TEXT NOT NULL,
  logical_path TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('live_host','restic_snapshot','qnap_snapshot','offsite')),
  independent_source_id TEXT NOT NULL,
  source_host TEXT,
  source_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(logical_file_key,source_kind,independent_source_id,source_path)
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_copy_evidence (
  evidence_id BIGSERIAL PRIMARY KEY,
  logical_file_key CHAR(64) NOT NULL,
  logical_host TEXT NOT NULL,
  logical_path TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('live_host','restic_snapshot','qnap_snapshot','offsite')),
  independent_source_id TEXT NOT NULL,
  source_path TEXT NOT NULL,
  snapshot_id TEXT,
  sha256 CHAR(64) NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verification_state TEXT NOT NULL CHECK (verification_state IN ('verified','unverified','failed','stale')),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(logical_file_key,source_kind,independent_source_id,sha256,captured_at)
);

CREATE TABLE IF NOT EXISTS diskaudit.backup_verification_state (
  restic_snapshot_id TEXT NOT NULL,
  host TEXT NOT NULL,
  verification_passed BOOLEAN NOT NULL,
  last_verified_at TIMESTAMPTZ,
  corrupt_count BIGINT NOT NULL DEFAULT 0,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY(restic_snapshot_id,host)
);

CREATE TABLE IF NOT EXISTS diskaudit.hash_baseline_stabilizations (
  stabilization_id BIGSERIAL PRIMARY KEY,
  file_key CHAR(64) NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  inode BIGINT,
  accepted_hash CHAR(64) NOT NULL,
  accepted_at TIMESTAMPTZ NOT NULL,
  due_at TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','stable','diverged','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(file_key,accepted_hash)
);

CREATE TABLE IF NOT EXISTS diskaudit.infra126_alert_events (
  fingerprint CHAR(64) PRIMARY KEY,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT,
  payload JSONB NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  last_sent_at TIMESTAMPTZ,
  send_count INTEGER NOT NULL DEFAULT 0,
  delivery_state TEXT NOT NULL DEFAULT 'idle' CHECK (delivery_state IN ('idle','sending','sent','failed')),
  delivery_lease_until TIMESTAMPTZ,
  last_error TEXT
);

ALTER TABLE diskaudit.infra126_alert_events
  ADD COLUMN IF NOT EXISTS delivery_state TEXT NOT NULL DEFAULT 'idle',
  ADD COLUMN IF NOT EXISTS delivery_lease_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_error TEXT;

INSERT INTO diskaudit.hash_verification_sla(host,tier,target_recheck_days,schedule_mode)
SELECT host,tier,target_days,mode
FROM (VALUES
  ('server-1','A',7,'weekly'),('server-1','B',30,'monthly'),('server-1','C',90,'quarterly'),('server-1','E',1,'daily'),
  ('nas-1','A',7,'weekly'),('nas-1','B',30,'monthly'),('nas-1','C',90,'quarterly'),('nas-1','E',1,'daily'),
  ('agent-1','A',7,'weekly'),('agent-1','B',30,'monthly'),('agent-1','C',90,'quarterly'),('agent-1','E',1,'daily')
) AS seed(host,tier,target_days,mode)
ON CONFLICT(host,tier) DO UPDATE
SET target_recheck_days=EXCLUDED.target_recheck_days,
    schedule_mode=EXCLUDED.schedule_mode,
    updated_at=now();

INSERT INTO diskaudit.mutable_file_registry(host,path_pattern,score,reason,is_regex,pattern_kind,priority)
VALUES
('*','^/var/log/',99,'system logs',true,'mutable',10),
('*','^/var/tmp/',97,'temporary files',true,'mutable',10),
('*','^/tmp/',97,'temporary files',true,'mutable',10),
('*','*.sqlite',98,'SQLite database',false,'mutable',20),
('*','*.sqlite3',98,'SQLite database',false,'mutable',20),
('*','*.db',98,'database file',false,'mutable',30),
('*','*.db-wal',99,'SQLite WAL',false,'mutable',20),
('*','*.db-shm',99,'SQLite shared memory',false,'mutable',20),
('*','/\.config/(google-chrome|chromium)/',96,'browser profile',true,'mutable',20),
('*','/\.cache/',96,'user cache',true,'mutable',30),
('*','/\.git/',95,'Git metadata',true,'mutable',30),
('*','^/run/',99,'runtime state',true,'mutable',10),
('*','^/var/run/',99,'runtime state',true,'mutable',10),
('*','^/var/lib/docker/',95,'container runtime data',true,'mutable',40),
('*','^/var/lib/postgresql/',99,'PostgreSQL data directory',true,'mutable',10),
('*','^/etc/hostname$',10,'host identity',true,'immutable',1),
('*','^/etc/(passwd|group|shadow|gshadow)$',15,'account database',true,'immutable',1),
('*','^/etc/(fstab|crypttab)$',10,'storage boot configuration',true,'immutable',1),
('*','^/boot/',10,'boot files',true,'immutable',1),
('*','^/(usr/)?(bin|sbin)/',10,'system executable',true,'immutable',2),
('*','^/(usr/)?lib/',10,'system library',true,'immutable',2),
('*','^/etc/systemd/system/',10,'systemd unit',true,'immutable',1),
('*','^/etc/cron',10,'scheduler configuration',true,'immutable',1)
ON CONFLICT(host,path_pattern,reason) DO UPDATE
SET score=EXCLUDED.score,is_regex=EXCLUDED.is_regex,
    pattern_kind=EXCLUDED.pattern_kind,priority=EXCLUDED.priority;

COMMIT;
