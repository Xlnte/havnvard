-- diskaudit — HavnVard UI support: materialized dedup-groups-by-host view
-- Date: 2026-07-25 · Owner: the operator · Runbook: /home/alice/runbooks/20260725-havnvard-ui/RUNBOOK.md
--
-- WHY: diskaudit.v_duplicate_groups_by_host (20260717 migration) is a plain view over
-- 8.5M diskaudit.files rows. Interactive pagination against it (WHERE host=$1 ORDER BY
-- reclaimable_bytes DESC LIMIT/OFFSET) re-aggregates the whole GROUP BY every request --
-- measured live 2026-07-25 at ~4s for a single 50-row page on server-1 alone, and a
-- naive count(*) at ~3.8s. Both are unusable for a server-rendered page a human clicks
-- through. This migration adds a MATERIALIZED copy of the same shape (additive only --
-- does not touch v_duplicate_groups_by_host/v_duplicate_groups, which stay the live-query
-- source of truth; this MV is a refreshable cache for the read-only HavnVard UI app) with
-- the indexes the UI's pagination/sort/filter actually needs, plus two columns the
-- existing view doesn't carry: hash_proven (true only if every row in the group has a
-- content_sha256 -- i.e. the group was formed by cross-host SHA-256 match, not just
-- rdfind's local-host heuristic) and sample_path (oldest-mtime member, for display).
--
-- Refresh: REFRESH MATERIALIZED VIEW CONCURRENTLY diskaudit.mv_dedup_groups_by_host;
-- (CONCURRENTLY needs the unique index below). No timer wired yet in this PR -- see
-- webapp/README.md "Data freshness" and FEATURES.md for the manual-refresh note; a
-- refresh timer is a named follow-up, not silently assumed.
--
-- Reclaim formula: uses the CORRECTED formula from 20260717_diskaudit_reclaimable_fix_v2.sql
-- (GREATEST(distinct_inode_count - 1, 0) * size_bytes) -- NOT the original, inverted
-- (file_count - distinct_inode_count) * size_bytes formula from the first 20260717 pass,
-- which was backwards (gave 0 for genuine separate-copy duplicates and overcounted pure
-- hardlink sets). Caught in review before this MV shipped -- verified against
-- v_duplicate_groups_by_host's live (corrected) output before trusting the formula here.

BEGIN;

DROP MATERIALIZED VIEW IF EXISTS diskaudit.mv_dedup_groups_by_host;

CREATE MATERIALIZED VIEW diskaudit.mv_dedup_groups_by_host AS
SELECT
    f.duplicate_group_id,
    f.host,
    count(*)                                          AS file_count,
    count(DISTINCT f.inode)                           AS distinct_inode_count,
    max(f.size_bytes)                                 AS size_bytes,
    -- Hardlink-aware reclaim (correctness requirement, non-negotiable): reclaimable space
    -- is a function of DISTINCT PHYSICAL COPIES (inodes), not row count. A pure hardlink
    -- set (distinct_inode_count=1, any file_count) reclaims exactly zero bytes -- deleting
    -- one path frees nothing, the data is still referenced by the remaining links.
    GREATEST(count(DISTINCT f.inode) - 1, 0) * max(f.size_bytes) AS reclaimable_bytes,
    bool_and(f.content_sha256 IS NOT NULL)            AS hash_proven,
    (array_agg(f.path ORDER BY f.mtime ASC NULLS LAST))[1] AS sample_path,
    max(f.mtime)                                      AS newest_mtime,
    now()                                              AS refreshed_at
FROM diskaudit.files f
WHERE f.duplicate_group_id IS NOT NULL AND f.still_exists AND f.file_type = 'regular'
GROUP BY f.duplicate_group_id, f.host;

CREATE UNIQUE INDEX IF NOT EXISTS uq_mv_dedup_groups_by_host_group_host
    ON diskaudit.mv_dedup_groups_by_host (duplicate_group_id, host);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_reclaim
    ON diskaudit.mv_dedup_groups_by_host (host, reclaimable_bytes DESC);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_size
    ON diskaudit.mv_dedup_groups_by_host (host, size_bytes DESC);
CREATE INDEX IF NOT EXISTS idx_mv_dedup_groups_by_host_host_files
    ON diskaudit.mv_dedup_groups_by_host (host, file_count DESC);

COMMENT ON MATERIALIZED VIEW diskaudit.mv_dedup_groups_by_host IS
  'HavnVard UI (webapp/) read-only cache of v_duplicate_groups_by_host + hash_proven +
   sample_path, indexed for interactive pagination. Refresh manually via
   REFRESH MATERIALIZED VIEW CONCURRENTLY diskaudit.mv_dedup_groups_by_host; -- see
   webapp/README.md. Never written to by anything except that REFRESH.';

COMMIT;
