-- diskaudit — HavnVard dedup UI: classification badge + evidence-strength ladder
-- Date: 2026-07-25 · Owner: the operator · Runbook: /home/alice/runbooks/20260725-havnvard-dedup-ui-fixes/RUNBOOK.md
--
-- WHY: three defects on the live /havnvard/dedup view (owner report, 2026-07-25):
--   1. No OS/application/load-bearing classification badge — the machinery
--      (critical_patterns, load_bearing_paths, mv_file_status, decommissioned_path_patterns)
--      already exists and was simply never surfaced on this view. Worst on nas-1,
--      whose duplicate groups are full of QNAP system-generated artifacts
--      (@Recycle, @Recently-Snapshot, .qsync, .qpkg, .streams sidecar dirs, Thumbs.db,
--      .DS_Store) that critical_patterns had ZERO coverage for (verified: 0 of 37 rows
--      matched any NAS/QNAP path before this migration).
--   2. The evidence badge on the dedup view has no inline legend (unlike
--      _backup_table.html, which has one) — badges are unexplained.
--   3. hash_proven is a boolean, collapsing genuinely different evidence into "yes/no".
--      The data already carries dedup_tool (rdfind-parallel / crosshost-sha256) and
--      hash_source (nas-native / local / trigkey-agent) — this migration derives a
--      7-level evidence-strength ladder (byte_identical..none) plus a separate
--      provenance axis (who computed it), instead of a single boolean.
--
-- Additive + safe re-run (IF NOT EXISTS / OR REPLACE / ON CONFLICT DO NOTHING throughout).
-- Never deletes anything, anywhere. Does not touch diskaudit.files (short read-only
-- queries only — three dedup jobs are writing duplicate_group_id/dedup_checked_at live).

BEGIN;

-- ============================================================================================
-- 1. diskaudit.critical_patterns — add a `category` column so a matched pattern can be told
--    apart as 'application' (existing 37 thoth_census rows — server-hosted modules/apps) vs
--    'os_system' (new: QNAP system-managed directories on the NAS data share). Nullable-safe
--    default keeps every existing row + consumer (mv_file_status.is_critical) unchanged.
-- ============================================================================================
ALTER TABLE diskaudit.critical_patterns
    ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'application';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'critical_patterns_category_check'
    ) THEN
        ALTER TABLE diskaudit.critical_patterns
            ADD CONSTRAINT critical_patterns_category_check
            CHECK (category IN ('application', 'os_system'));
    END IF;
END $$;

-- New QNAP / NAS os_system + application coverage (data, not code — the operator's explicit
-- instruction). Inspected live 2026-07-25 against nas-1's actual crawled paths
-- (only /share/CACHEDEV1_DATA/* is reachable, QNAP firmware partition itself is not
-- crawled) — these are the QNAP-generated system/app directories actually present:
--   .qpkg (33 files)      — QNAP app-package install dir on the data volume
--   .qsync (16 files)     — Qsync sync-client state
--   @Recycle (33 files)   — QNAP-managed recycle bin (system-managed, not raw user delete)
--   @Recently-Snapshot (27 files) — QNAP snapshot cache directory
--   bkup_server (778,687 files, 946GB) — deliberate server app/DB backup archives, already
--   named/registered per-app in this same table (app-a, app-b, ...);
--   classified 'application' at the share level rather than duplicating every app name.
INSERT INTO diskaudit.critical_patterns (pattern, label, source, category) VALUES
    ('%/.qpkg/%',               'QNAP app-package install directory (QTS-managed)',            'manual', 'os_system'),
    ('%/.qsync/%',              'Qsync Central sync-client state directory (QTS-managed)',      'manual', 'os_system'),
    ('%/@Recycle/%',            'QNAP recycle bin (QTS-managed, not a raw user delete)',        'manual', 'os_system'),
    ('%/@Recently-Snapshot/%',  'QNAP snapshot cache directory (QTS-managed)',                  'manual', 'os_system'),
    ('/share/CACHEDEV1_DATA/bkup_server/%', 'server app/DB backup archives (NAS bkup_server share, deliberate, not stray dupes)', 'manual', 'application')
ON CONFLICT (pattern) DO NOTHING;

-- ============================================================================================
-- 2. diskaudit.file_category_patterns — new, same shape/convention as critical_patterns
--    (LIKE pattern, not hardcoded path logic in the app). Covers the two classification
--    buckets critical_patterns/load_bearing_paths were never meant to carry: cache/temp
--    (safe-to-regenerate derived data) and user_data (recognized human-content areas,
--    the affirmative "yes this is someone's actual data" bucket vs the residual 'unknown').
--    Deliberately NOT folded into critical_patterns: marking a recycle bin or thumbnail
--    cache "critical" (critical_patterns' actual semantics — "don't casually call this
--    stale/unknown") would be true; calling it load-bearing/protected would not be, and
--    this app has no delete path anyway (export-only) so the distinction is purely about
--    an honest label, not a protection guarantee.
-- ============================================================================================
CREATE TABLE IF NOT EXISTS diskaudit.file_category_patterns (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pattern   text NOT NULL,
    category  text NOT NULL CHECK (category IN ('os_system', 'cache_temp', 'user_data')),
    label     text,
    source    text NOT NULL DEFAULT 'manual' CHECK (source = ANY (ARRAY['manual'::text, 'thoth_census'::text])),
    added_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pattern, category)
);

INSERT INTO diskaudit.file_category_patterns (pattern, category, label, source) VALUES
    -- cache/temp: derived/sidecar data, safe to regenerate, never the original copy.
    ('%/.streams/%',   'cache_temp', 'QNAP AFP/Time-Machine resource-fork sidecar store (QTS-generated, derived from real files)', 'manual'),
    ('%/Thumbs.db',    'cache_temp', 'Windows thumbnail cache', 'manual'),
    ('%/.DS_Store',    'cache_temp', 'macOS Finder metadata', 'manual'),
    ('/tmp/%',         'cache_temp', 'Unix /tmp', 'manual'),
    ('/var/tmp/%',     'cache_temp', 'Unix /var/tmp', 'manual'),
    ('%/__pycache__/%','cache_temp', 'Python bytecode cache (regenerable)', 'manual'),
    ('%/.cache/%',     'cache_temp', 'XDG user cache directory (regenerable)', 'manual'),
    -- user_data: recognized human-content areas (NAS shares + server/agent-1 home dirs).
    ('/share/CACHEDEV1_DATA/homes/%',      'user_data', 'NAS per-user home share', 'manual'),
    ('/share/CACHEDEV1_DATA/Share1/%',   'user_data', 'NAS Share1 share', 'manual'),
    ('/share/CACHEDEV1_DATA/Public/%',     'user_data', 'NAS Public share', 'manual'),
    ('/share/CACHEDEV1_DATA/Multimedia/%', 'user_data', 'NAS Multimedia share', 'manual'),
    ('/share/CACHEDEV1_DATA/Download/%',   'user_data', 'NAS Download share', 'manual'),
    ('/share/CACHEDEV1_DATA/bittorrents/%','user_data', 'NAS bittorrents share', 'manual'),
    ('/share/CACHEDEV1_DATA/Recordings/%', 'user_data', 'NAS Recordings share', 'manual'),
    ('/share/CACHEDEV1_DATA/Web/%',        'user_data', 'NAS Web share', 'manual'),
    ('/home/alice/%',  'user_data', 'server alice home directory', 'manual'),
    ('/home/bob/%',    'user_data', 'server bob home directory', 'manual'),
    ('/home/carol/%',    'user_data', 'server carol home directory', 'manual'),
    ('/home/dave/%', 'user_data', 'server dave home directory', 'manual')
ON CONFLICT (pattern, category) DO NOTHING;

COMMIT;

-- ============================================================================================
-- 3. Recreate diskaudit.mv_dedup_groups_by_host (DROP + CREATE, same shape as the
--    20260725_diskaudit_havnvard_ui_mv.sql original) adding four columns:
--      classification        — worst-case-wins across every member file in the group:
--                               decommissioned > load_bearing > os_system > application >
--                               cache_temp > user_data > unknown. "Worst case wins" so a
--                               group is never mislabeled friendlier than its most
--                               sensitive member (verified 2026-07-25: 0 of nas-1's
--                               groups have members split across different top-level
--                               shares, so this is not a lossy approximation in practice).
--      evidence_level         — smallint 1..7, strongest to weakest:
--                               1 byte_identical (NOT IMPLEMENTED — no cmp-based tool
--                                 wired yet; always 0 rows, kept in the model on purpose
--                                 rather than silently omitted)
--                               2 sha256_both    (crosshost-sha256, hash proven both sides)
--                               3 sha256_rdfind  (rdfind-parallel pipeline, single host)
--                               4 same_inode     (hardlink — checked BEFORE 2/3 regardless
--                                 of whether a hash also happens to be present; a hardlink
--                                 reclaims zero bytes and must never be reported as if it
--                                 were a genuine second proven copy)
--                               5 path_size_mtime (heuristic — no data produces this today;
--                                 every current duplicate_group_id row has dedup_method
--                                 = 'sha256', verified 2026-07-25)
--                               6 size_only       (weaker heuristic — likewise 0 rows today)
--                               7 none            (never checked — likewise 0 rows today,
--                                 the view only covers files that already have a
--                                 duplicate_group_id)
--      evidence_level_label   — text label matching the ladder, for display without a
--                               Python-side lookup table drifting out of sync with SQL.
--      evidence_provenance    — separate axis: who computed it (nas-native BusyBox
--                               sha256sum / local NVMe / trigkey-agent / rdfind's own
--                               local pipeline / inode-stat for hardlinks / mixed for the
--                               ~34 groups, out of 689k, whose members disagree).
--    Refresh: REFRESH MATERIALIZED VIEW CONCURRENTLY diskaudit.mv_dedup_groups_by_host;
--    (unique index below still supports CONCURRENTLY, unchanged from the original).
-- ============================================================================================
DROP MATERIALIZED VIEW IF EXISTS diskaudit.mv_dedup_groups_by_host;

CREATE MATERIALIZED VIEW diskaudit.mv_dedup_groups_by_host AS
WITH members AS (
    SELECT
        f.duplicate_group_id,
        f.host,
        f.path,
        f.size_bytes,
        f.inode,
        f.mtime,
        f.content_sha256,
        f.dedup_tool,
        f.hash_source,
        -- Reused from mv_file_status (already computed, indexed on host+path) rather
        -- than re-scanning load_bearing_paths (443 patterns) / decommissioned_path_patterns
        -- (7 patterns) per row here -- avoids doubling that LIKE-scan cost.
        coalesce(mfs.is_load_bearing, false)   AS is_load_bearing,
        coalesce(mfs.is_decommissioned, false) AS is_decommissioned,
        -- category-aware critical-pattern match: small pattern sets (a handful of
        -- os_system rows, 37+ application rows) scanned directly so we know WHICH
        -- category matched, not just mv_file_status's plain is_critical boolean.
        EXISTS (
            SELECT 1 FROM diskaudit.critical_patterns cp
            WHERE cp.category = 'os_system' AND f.path LIKE cp.pattern
        ) AS is_os_system_critical,
        EXISTS (
            SELECT 1 FROM diskaudit.critical_patterns cp
            WHERE cp.category = 'application' AND f.path LIKE cp.pattern
        ) AS is_application_critical,
        EXISTS (
            SELECT 1 FROM diskaudit.file_category_patterns fcp
            WHERE fcp.category = 'os_system' AND f.path LIKE fcp.pattern
        ) AS is_os_system_extra,
        EXISTS (
            SELECT 1 FROM diskaudit.file_category_patterns fcp
            WHERE fcp.category = 'cache_temp' AND f.path LIKE fcp.pattern
        ) AS is_cache_temp,
        EXISTS (
            SELECT 1 FROM diskaudit.file_category_patterns fcp
            WHERE fcp.category = 'user_data' AND f.path LIKE fcp.pattern
        ) AS is_user_data
    FROM diskaudit.files f
    LEFT JOIN diskaudit.mv_file_status mfs ON mfs.host = f.host AND mfs.path = f.path
    WHERE f.duplicate_group_id IS NOT NULL AND f.still_exists AND f.file_type = 'regular'
)
SELECT
    m.duplicate_group_id,
    m.host,
    count(*)                                            AS file_count,
    count(DISTINCT m.inode)                             AS distinct_inode_count,
    max(m.size_bytes)                                   AS size_bytes,
    -- Hardlink-aware reclaim (correctness requirement, non-negotiable): reclaimable space
    -- is a function of DISTINCT PHYSICAL COPIES (inodes), not row count. A pure hardlink
    -- set (distinct_inode_count=1, any file_count) reclaims exactly zero bytes -- deleting
    -- one path frees nothing, the data is still referenced by the remaining links.
    GREATEST(count(DISTINCT m.inode) - 1, 0) * max(m.size_bytes) AS reclaimable_bytes,
    bool_and(m.content_sha256 IS NOT NULL)              AS hash_proven,
    (array_agg(m.path ORDER BY m.mtime ASC NULLS LAST))[1] AS sample_path,
    max(m.mtime)                                        AS newest_mtime,
    -- Classification: worst-case-wins across every member file. Priority order below is
    -- deliberate (most operationally sensitive first) -- a group is never labeled more
    -- casually than its most sensitive member.
    CASE
        WHEN bool_or(m.is_decommissioned)         THEN 'decommissioned'
        WHEN bool_or(m.is_load_bearing)            THEN 'load_bearing'
        WHEN bool_or(m.is_os_system_critical)
          OR bool_or(m.is_os_system_extra)         THEN 'os_system'
        WHEN bool_or(m.is_application_critical)    THEN 'application'
        WHEN bool_or(m.is_cache_temp)               THEN 'cache_temp'
        WHEN bool_or(m.is_user_data)                 THEN 'user_data'
        ELSE 'unknown'
    END AS classification,
    -- Evidence-strength ladder (1 strongest .. 7 weakest). same_inode is checked BEFORE
    -- the hash-tool branches on purpose -- see column comment above the MV definition.
    CASE
        WHEN count(DISTINCT m.inode) = 1 THEN 4
        WHEN bool_and(m.content_sha256 IS NOT NULL) AND bool_and(m.dedup_tool = 'crosshost-sha256') THEN 2
        WHEN bool_and(m.content_sha256 IS NOT NULL) AND bool_and(m.dedup_tool = 'rdfind-parallel')  THEN 3
        WHEN bool_and(m.content_sha256 IS NOT NULL) THEN 3  -- hashed via a mix of tools; never overclaim level 2
        ELSE 7
    END AS evidence_level,
    CASE
        WHEN count(DISTINCT m.inode) = 1 THEN 'same_inode'
        WHEN bool_and(m.content_sha256 IS NOT NULL) AND bool_and(m.dedup_tool = 'crosshost-sha256') THEN 'sha256_both'
        WHEN bool_and(m.content_sha256 IS NOT NULL) AND bool_and(m.dedup_tool = 'rdfind-parallel')  THEN 'sha256_rdfind'
        WHEN bool_and(m.content_sha256 IS NOT NULL) THEN 'sha256_rdfind'
        ELSE 'none'
    END AS evidence_level_label,
    -- Provenance (separate axis -- who computed it, independent of method strength).
    CASE
        WHEN count(DISTINCT m.inode) = 1 THEN 'inode-stat'
        WHEN bool_and(m.hash_source = 'nas-native')    THEN 'nas-native'
        WHEN bool_and(m.hash_source = 'local')          THEN 'local'
        WHEN bool_and(m.hash_source = 'trigkey-agent')  THEN 'trigkey-agent'
        WHEN bool_and(m.hash_source IS NULL) AND bool_and(m.dedup_tool = 'rdfind-parallel') THEN 'rdfind-pipeline'
        ELSE 'mixed'
    END AS evidence_provenance,
    now() AS refreshed_at
FROM members m
GROUP BY m.duplicate_group_id, m.host;

CREATE UNIQUE INDEX IF NOT EXISTS uq_mv_dedup_groups_by_host_group_host
    ON diskaudit.mv_dedup_groups_by_host (duplicate_group_id, host);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_reclaim
    ON diskaudit.mv_dedup_groups_by_host (host, reclaimable_bytes DESC);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_size
    ON diskaudit.mv_dedup_groups_by_host (host, size_bytes DESC);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_files
    ON diskaudit.mv_dedup_groups_by_host (host, file_count DESC);
-- New indexes for the new filters (classification exclude-in-one-click, evidence ladder).
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_classification
    ON diskaudit.mv_dedup_groups_by_host (host, classification);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_evidence
    ON diskaudit.mv_dedup_groups_by_host (host, evidence_level);

COMMENT ON MATERIALIZED VIEW diskaudit.mv_dedup_groups_by_host IS
  'HavnVard UI (webapp/) read-only cache of per-(duplicate_group_id, host) dedup groups,
   with classification (os_system/application/load_bearing/cache_temp/user_data/
   decommissioned/unknown) and a 7-level evidence-strength ladder + separate provenance
   axis (see 20260725_diskaudit_dedup_classification_evidence_v1.sql). Not wired to a
   refresh timer yet -- manual: REFRESH MATERIALIZED VIEW CONCURRENTLY
   diskaudit.mv_dedup_groups_by_host;';

COMMENT ON COLUMN diskaudit.mv_dedup_groups_by_host.classification IS
  'Worst-case-wins across every member file: decommissioned > load_bearing > os_system >
   application > cache_temp > user_data > unknown.';
COMMENT ON COLUMN diskaudit.mv_dedup_groups_by_host.evidence_level IS
  '1=byte_identical (not yet available) 2=sha256_both 3=sha256_rdfind 4=same_inode (hardlink,
   0 reclaim, checked before 2/3) 5=path_size_mtime 6=size_only 7=none. Strongest to weakest.';
COMMENT ON COLUMN diskaudit.mv_dedup_groups_by_host.evidence_provenance IS
  'Who computed the evidence: nas-native (QNAP BusyBox sha256sum) / local (server NVMe) /
   trigkey-agent / rdfind-pipeline (rdfind''s own local hashing, no cross-host agent) /
   inode-stat (same_inode groups -- no hash needed) / mixed (evidence_level 4 shows
   pipeline-tool disagreement -- true doubt, no rows have this today).';
