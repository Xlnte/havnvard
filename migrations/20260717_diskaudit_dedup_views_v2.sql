-- diskaudit v2 — hardlink-aware duplicate-group views
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- duplicate_group_id (from dedup.py, a real content-hash) is stable across hosts and runs,
-- so a group can legitimately span both server and the NAS -- that's the basis for the v2
-- Part B backup-coverage view. But hardlinks (same inode) only mean anything WITHIN one
-- host/filesystem, so "reclaimable space" must be computed per-host, then summed -- naively
-- counting every row in a cross-host group as separately "wasted" would double-count a file
-- that's genuinely backed up (a good thing) as if it were wasted duplication (a bad thing).

BEGIN;

CREATE OR REPLACE VIEW diskaudit.v_duplicate_groups_by_host AS
SELECT
    duplicate_group_id,
    host,
    count(*)                    AS file_count,
    count(DISTINCT inode)       AS distinct_inode_count,
    max(size_bytes)             AS size_bytes,
    -- reclaimable = space wasted by genuinely separate copies, i.e. files beyond one-per-inode.
    -- Already-hardlinked duplicates (same inode) share physical storage and cost nothing extra.
    (count(*) - count(DISTINCT inode)) * max(size_bytes) AS reclaimable_bytes
FROM diskaudit.files
WHERE duplicate_group_id IS NOT NULL AND still_exists AND file_type = 'regular'
GROUP BY duplicate_group_id, host;

CREATE OR REPLACE VIEW diskaudit.v_duplicate_groups AS
SELECT
    duplicate_group_id,
    array_agg(DISTINCT host ORDER BY host) AS hosts,
    count(DISTINCT host)        AS host_count,
    sum(file_count)             AS total_file_count,
    max(size_bytes)             AS size_bytes,
    sum(reclaimable_bytes)      AS reclaimable_bytes_total
FROM diskaudit.v_duplicate_groups_by_host
GROUP BY duplicate_group_id;

COMMIT;
