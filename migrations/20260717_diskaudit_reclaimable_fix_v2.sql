-- diskaudit v2 — fix inverted reclaimable-space formula
-- Date: 2026-07-17 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- Bug found the hard way, using the first real full-disk dedup data: the original
-- formula (file_count - distinct_inode_count) * size_bytes is backwards.
--   - N files, all genuinely SEPARATE physical copies (all distinct inodes):
--     correct reclaimable = (N-1)*size (keep one, hardlink the rest).
--     Old formula gives (N-N)*size = 0 -- exactly wrong, this IS the case worth
--     reclaiming.
--   - N files already fully hardlinked together (1 distinct inode, already optimal):
--     correct reclaimable = 0 (nothing left to reclaim).
--     Old formula gives (N-1)*size -- overcounts space that isn't actually wasted.
-- Correct formula: reclaimable = (distinct_inode_count - 1) * size_bytes -- based on
-- how many separate PHYSICAL copies exist (inodes), not file_count vs inode_count.

BEGIN;

CREATE OR REPLACE VIEW diskaudit.v_duplicate_groups_by_host AS
SELECT
    duplicate_group_id,
    host,
    count(*)                    AS file_count,
    count(DISTINCT inode)       AS distinct_inode_count,
    max(size_bytes)             AS size_bytes,
    GREATEST(count(DISTINCT inode) - 1, 0) * max(size_bytes) AS reclaimable_bytes
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
