-- diskaudit — classification layer v1 (orphaned/stale/possibly-obsolete + load-bearing override)
-- Date: 2026-07-18 · Owner: the operator · Plan: witty-swinging-shore.md item #12 · Plane: INFRA-97
-- Runbook: /home/alice/runbooks/20260718-diskaudit-classification/README.md
--
-- Design spec (PRESCAB 10-VP cabinet, all VPs converged): pure mtime/atime age produces false
-- positives on cold-but-live files (a yearly cron script, a rarely-touched config). Fix: cross-
-- reference file paths against LIVE SYSTEM CONTEXT (systemd units, crontabs, thoth.census) to
-- build a "load-bearing override" that protects cold-but-live files from mislabeling, regardless
-- of age. That override is the highest-priority rule in the decision tree below.
--
-- Additive + safe re-run (IF NOT EXISTS / OR REPLACE / ON CONFLICT DO NOTHING throughout).
-- Never deletes anything, anywhere. Every status here is a label for human review only.

BEGIN;

-- ============================================================================================
-- 1. diskaudit.decommissioned_path_patterns — the operator-editable table of dead-system path prefixes.
--    Same shape/convention as diskaudit.critical_patterns (20260717_diskaudit_multihost_dedup_v2.sql):
--    a LIKE pattern, not hardcoded logic in a script. Seeded from CLAUDE.md's documented
--    [DEPRECATED]/[REMOVED] filesystem paths (Part II — MACHINE & SYSTEM FACTS, "Retired /
--    Inactive" + user-architecture table + key-file-paths sections).
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.decommissioned_path_patterns (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pattern             text NOT NULL,   -- LIKE pattern, e.g. '/home/carol/.oldapp/%'
    system_name         text NOT NULL,   -- human-readable dead system, e.g. 'OldApp'
    decommissioned_date date,            -- NULL where CLAUDE.md doesn't give an exact date
    notes               text,
    added_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pattern)
);

INSERT INTO diskaudit.decommissioned_path_patterns (pattern, system_name, decommissioned_date, notes) VALUES
    ('/home/carol/.oldapp/%', 'OldApp', '2026-04-24',
        'Decommissioned 2026-04-17, made inert 2026-04-24 (CLAUDE.md Part I §1b). DEPRECATED-20260424.txt marker files present. Instance config/master.key/backups all under this tree.'),
    ('/home/carol/oldapp/%', 'OldApp', '2026-04-24',
        'Second OldApp filesystem root retained for archival per CLAUDE.md; do not restart.'),
    ('/home/carol/agent-system/%', 'OldApp (agent system)', '2026-04-24',
        'Per-agent AgentGateway configs, skills, .env, todo — all decommissioned with OldApp.'),
    ('/home/erin/%', 'OldOperator', NULL,
        'Former rootless Docker AgentGateway operator, marked [DEPRECATED] in CLAUDE.md user-architecture table; no decommission date given.'),
    ('/opt/dgx-spark-vllm/vllm_env%', 'vLLM (disabled)', NULL,
        'Disabled vLLM virtualenv (CLAUDE.md "Retired / Inactive"); paired systemd unit below.'),
    ('/etc/systemd/system/vllm.service', 'vLLM (disabled)', NULL,
        'Disabled vLLM systemd unit file itself (exact-file pattern, no wildcard — CLAUDE.md "Retired / Inactive").'),
    ('/etc/systemd/system/oldapp.service.archived-20260424', 'OldApp', '2026-04-24',
        'Archived OldApp systemd unit (exact-file pattern) — CLAUDE.md Part I §1b.')
ON CONFLICT (pattern) DO NOTHING;

-- ============================================================================================
-- 2. diskaudit.load_bearing_refresh_runs — traceability log for refresh_load_bearing_paths.py.
--    Same shape as diskaudit.scan_runs/dedup_runs (started_at/finished_at/status). Required so
--    "why does load_bearing_paths have this entry" always has a queryable answer: which run,
--    when, from which exact source. (the operator: "we don't want a GREP going haywire and not knowing
--    where it is being fired from.")
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.load_bearing_refresh_runs (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host             text NOT NULL DEFAULT 'server-1',
    started_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    status           text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    sources_scanned  jsonb,   -- e.g. {"systemd_units": 42, "crontab_alice": 38, "crontab_bob": 1, "census_active": 16}
    paths_found      integer, -- total candidate (pattern, source) pairs extracted this run
    paths_upserted   integer, -- how many were new inserts vs. already-known (upserted) rows
    errors           jsonb,   -- [{"source": "...", "error": "..."}] — per-unit-file/per-user granularity
    note             text
);

-- ============================================================================================
-- 3. diskaudit.load_bearing_paths — protected-path table, POPULATED BY refresh_load_bearing_paths.py
--    (not hand-maintained). "source" is per-row provenance precise enough to answer "which exact
--    file/line produced this row" — e.g. 'systemd-unit:/etc/systemd/system/diskaudit-scan.service#ExecStart',
--    not a generic category like 'systemd'.
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.load_bearing_paths (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pattern              text NOT NULL,   -- LIKE pattern; exact-file patterns (no '%') are common and preferred where precision allows
    source               text NOT NULL,   -- precise provenance, e.g. 'systemd-unit:/etc/systemd/system/X.service#ExecStart', 'crontab:alice:L42', 'census:diskaudit#primary_path'
    last_verified_at     timestamptz NOT NULL DEFAULT now(),
    last_refresh_run_id  bigint REFERENCES diskaudit.load_bearing_refresh_runs(id),
    UNIQUE (pattern, source)
);

-- ============================================================================================
-- 4. diskaudit.classification_config — the operator-editable thresholds, so the age cutoff is a config
--    row, not a magic number buried in a view definition.
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.classification_config (
    key         text PRIMARY KEY,
    value       text NOT NULL,
    description text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO diskaudit.classification_config (key, value, description) VALUES
    ('stale_atime_threshold_days', '365',
     'atime age (days) beyond which a file is a possibly-obsolete/stale candidate, subject to the load-bearing/decommissioned/critical overrides. the operator-editable; re-read on every classification refresh, no code change needed to adjust.')
ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE FUNCTION diskaudit.classification_threshold_days() RETURNS integer AS $$
    SELECT value::integer FROM diskaudit.classification_config WHERE key = 'stale_atime_threshold_days';
$$ LANGUAGE sql STABLE;

-- ============================================================================================
-- 5. diskaudit.git_repo_roots — ground-truth list of git repo roots on server-1, for the
--    supplementary git-tracked-recency signal. Populated from a real
--    `find / -maxdepth 4 -name .git -type d` sweep on 2026-07-18 (72 repos found — this box has
--    far more git-tracked project directories than CLAUDE.md documents by name). the operator-editable
--    table, not a hardcoded list in a view — re-run the same find command and INSERT ... ON
--    CONFLICT DO NOTHING to pick up newly-created repos later.
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.git_repo_roots (
    repo_root      text PRIMARY KEY,
    discovered_via text NOT NULL DEFAULT 'find-scan-20260718',
    added_at       timestamptz NOT NULL DEFAULT now()
);

INSERT INTO diskaudit.git_repo_roots (repo_root, discovered_via) VALUES
    ('/home/alice', 'find-scan-20260718'),
    ('/home/alice/projects/app-a', 'find-scan-20260718'),
    ('/srv/apps/app-b', 'find-scan-20260718')
ON CONFLICT (repo_root) DO NOTHING;

COMMIT;

-- ============================================================================================
-- 6. diskaudit.mv_file_status — MATERIALIZED VIEW, refreshed on a schedule (see
--    diskaudit-classification-refresh.timer / refresh_file_status.py), NOT a live view.
--
--    Performance justification (measured live on this box, 2026-07-18, ~10.4M still-existing
--    regular files on server-1+nas-1 combined):
--      EXPLAIN ANALYZE of a single EXISTS-join against diskaudit.critical_patterns (37 real
--      pattern rows) took 31.7s wall time (Nested Loop Semi Join, 353.7M join-filter evaluations,
--      no index can help a dynamic LIKE-pattern-list join). The classification decision tree
--      below needs THREE such pattern-set joins per row (load_bearing_paths, decommissioned_-
--      path_patterns, critical_patterns) plus the atime/duplicate_group_id predicates — a live
--      view recomputing this on every Grafana panel load (5m auto-refresh, possibly multiple
--      panels, possibly multiple viewers) would mean repeated ~60-100s+ full-table scans hitting
--      Postgres continuously. That is not acceptable load for a dashboard data source shared with
--      other schemas on the same instance.
--
--      A materialized view pays this cost ONCE per refresh cycle (scheduled, off the interactive
--      path — see refresh cadence below) and turns every subsequent read (Grafana panel, ad hoc
--      psql query, the load-bearing sanity checks in the runbook) into a fast indexed lookup on
--      a ~10.4M-row table with no runtime joins. Given diskaudit.files itself only changes on a
--      monthly scan cadence (diskaudit-scan.timer, diskaudit-nas-crawl.timer both OnCalendar=
--      *-*-01), a materialized view that is at most a few days stale between refreshes is a
--      correct trade, not a compromise — the underlying data isn't more current than that anyway
--      between scans. A plain per-batch UPDATE'd column on diskaudit.files was considered and
--      rejected: it would require write access to an 11M-row hot table already carrying scan/
--      dedup merge traffic, for no benefit over a materialized view (same batch-cost profile,
--      more coupling to a table this task was explicitly told to leave alone).
-- ============================================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS diskaudit.mv_file_status AS
WITH threshold AS (
    SELECT diskaudit.classification_threshold_days() AS days
),
flagged AS (
    SELECT
        f.host,
        f.path,
        f.file_type,
        f.size_bytes,
        f.owner_name,
        f.mtime,
        f.atime,
        f.duplicate_group_id,
        (f.atime < now() - (t.days || ' days')::interval)               AS is_atime_old,
        (f.duplicate_group_id IS NOT NULL)                               AS is_duplicated,
        EXISTS (
            SELECT 1 FROM diskaudit.load_bearing_paths lbp
            WHERE f.path LIKE lbp.pattern
        )                                                                 AS is_load_bearing,
        EXISTS (
            SELECT 1 FROM diskaudit.decommissioned_path_patterns dpp
            WHERE f.path LIKE dpp.pattern
        )                                                                 AS is_decommissioned,
        EXISTS (
            SELECT 1 FROM diskaudit.critical_patterns cp
            WHERE f.path LIKE cp.pattern
        )                                                                 AS is_critical,
        (
            f.path ~* '\.bak(-|\.|$)'
            OR f.path ~* '_old(\.[a-z0-9]+)?$'
            OR f.path ~* '_deprecated(\.[a-z0-9]+)?$'
            OR f.path LIKE '%.DEPRECATED-%'
            OR f.path ~* '_v[0-9]+_old'
        )                                                                  AS is_legacy_naming
    FROM diskaudit.files f
    CROSS JOIN threshold t
    WHERE f.still_exists AND f.file_type = 'regular'
)
SELECT
    host,
    path,
    file_type,
    size_bytes,
    owner_name,
    mtime,
    atime,
    duplicate_group_id,
    is_legacy_naming,
    CASE
        WHEN is_load_bearing              THEN 'load-bearing'
        WHEN is_decommissioned            THEN 'orphaned-decommissioned-system'
        -- Deviation from the literal a-f spec, called out explicitly: an aged file that is also
        -- in critical_patterns (e.g. a DB backup dump, a census active-system path) is NOT
        -- "active" (it wasn't touched recently) but it is also explicitly protected the same way
        -- load-bearing paths are. Falling it through to 'active' would be dishonest (implies
        -- recent touch); folding it into 'stale'/'possibly-obsolete' would invite exactly the
        -- kind of accidental cleanup-candidate flagging the critical_patterns table exists to
        -- prevent. 'critical-protected' names the case honestly: old, but known-important.
        WHEN is_atime_old AND is_critical THEN 'critical-protected'
        WHEN is_atime_old AND is_duplicated THEN 'possibly-obsolete'
        WHEN is_atime_old                 THEN 'stale'
        ELSE 'active'
    END AS file_status,
    is_load_bearing,
    is_decommissioned,
    is_critical,
    is_duplicated,
    is_atime_old,
    now() AS computed_at
FROM flagged;

-- Unique index kept regardless of refresh mode (see function below) — useful for fast
-- (host, path) point lookups either way, and keeps REFRESH ... CONCURRENTLY available as a
-- manual escape hatch if the non-concurrent lock window ever becomes a real problem.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_file_status_host_path ON diskaudit.mv_file_status (host, path);
CREATE INDEX IF NOT EXISTS idx_mv_file_status_status ON diskaudit.mv_file_status (file_status);
CREATE INDEX IF NOT EXISTS idx_mv_file_status_status_host ON diskaudit.mv_file_status (file_status, host);

CREATE OR REPLACE FUNCTION diskaudit.refresh_file_status() RETURNS void AS $$
BEGIN
    -- Non-concurrent, by deliberate choice after live measurement (2026-07-18): the initial
    -- non-concurrent population of this MV (CREATE MATERIALIZED VIEW ... AS ..., a full rebuild)
    -- completed in under 2 minutes over ~10.4M rows. The first REFRESH ... CONCURRENTLY call —
    -- run right after refresh_load_bearing_paths.py populated load_bearing_paths for the first
    -- time, so a large fraction of rows genuinely changed is_load_bearing — was still running
    -- past 15 minutes before it finally completed (see runbook Test Results for the exact
    -- figure). CONCURRENTLY's row-by-row diff-and-apply against a real multi-million-row delta
    -- is dramatically more expensive than a plain rebuild-and-swap. Both callers of this
    -- function (diskaudit-load-bearing-refresh.timer, weekly 06:00; diskaudit-classification-
    -- refresh.timer, monthly 08:00) are unattended off-hours batch jobs, not something a human
    -- is watching a spinner for — a brief ACCESS EXCLUSIVE lock during a ~1-2 minute rebuild
    -- (any concurrent reader just waits, doesn't error) is a better trade than tying up Postgres
    -- for 15+ minutes to avoid a lock window nobody is actually contending for at 6am.
    REFRESH MATERIALIZED VIEW diskaudit.mv_file_status;
END;
$$ LANGUAGE plpgsql;

-- Thin, literally-named view per the spec ("diskaudit.v_file_status") — a transparent alias so
-- callers (Grafana panels, the runbook's sanity-check queries) can reference the name given in
-- the spec, while the header comment above and this comment make it unambiguous that the actual
-- computation lives in the materialized view and is only as fresh as the last refresh.
CREATE OR REPLACE VIEW diskaudit.v_file_status AS
SELECT * FROM diskaudit.mv_file_status;

-- ============================================================================================
-- 7. diskaudit.v_git_tracked_recency — supplementary signal, scoped to known repo roots only
--    (diskaudit.git_repo_roots, §5 above). This is a filesystem-mtime-based PROXY for git
--    activity, not real git-log data — SQL/views cannot invoke `git log`. It answers "how
--    recently was anything under this repo root touched on disk," which is a reasonable cold-
--    repo signal on its own, but is explicitly NOT wired into diskaudit.mv_file_status's main
--    file_status decision (per spec: "fine to ship as a separate supplementary signal/view if
--    that's cleaner"). A future enhancement could enrich this with real `git log -1 --format=%cI`
--    per repo via a small script (same pattern as refresh_load_bearing_paths.py) if the operator wants
--    true commit-recency instead of this mtime proxy.
-- ============================================================================================
CREATE OR REPLACE VIEW diskaudit.v_git_tracked_recency AS
SELECT
    g.repo_root,
    f.host,
    count(*)                       AS file_count,
    sum(f.size_bytes)              AS total_size_bytes,
    max(f.mtime)                   AS most_recent_mtime,
    max(f.atime)                   AS most_recent_atime,
    (now() - max(f.mtime))         AS mtime_age,
    (max(f.mtime) < now() - interval '180 days') AS looks_cold_180d
FROM diskaudit.git_repo_roots g
JOIN diskaudit.files f
    ON f.still_exists
    AND (f.path = g.repo_root OR f.path LIKE g.repo_root || '/%')
GROUP BY g.repo_root, f.host;

COMMENT ON MATERIALIZED VIEW diskaudit.mv_file_status IS
    'Classification of still-existing regular files by orphaned/stale/possibly-obsolete/load-bearing status. Refreshed by diskaudit.refresh_file_status() via diskaudit-classification-refresh.timer, NOT live. See /home/alice/runbooks/20260718-diskaudit-classification/README.md.';
COMMENT ON VIEW diskaudit.v_file_status IS
    'Thin alias for diskaudit.mv_file_status (spec-literal name). Freshness = last materialized-view refresh, not query time.';
COMMENT ON VIEW diskaudit.v_git_tracked_recency IS
    'Filesystem-mtime proxy for git-repo activity, scoped to diskaudit.git_repo_roots. NOT real git-log data. Supplementary signal only, not wired into file_status.';
