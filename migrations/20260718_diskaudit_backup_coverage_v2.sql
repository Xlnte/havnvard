-- diskaudit v2 — cross-host backup-coverage views (Dream feature #4/#5, design doc
-- witty-swinging-shore.md)
-- Date: 2026-07-18 · Owner: the operator · Plan: witty-swinging-shore.md · Plane: INFRA-97
--
-- Answers the actual question the operator asked for: for every file the operator considers "critical"
-- (per diskaudit.critical_patterns), does a content-identical copy (same
-- duplicate_group_id, still_exists=true) exist on a DIFFERENT host than the original?
--
-- Additive only: three new views, no data mutation, no changes to existing views/tables.
-- Follows this project's established convention (see 20260717_diskaudit_reclaimable_fix_v2.sql):
-- CREATE OR REPLACE VIEW inside BEGIN;/COMMIT;.
--
-- ---------------------------------------------------------------------------------------
-- Design notes / why it's built this way (kept here, not just in the runbook, since the
-- next person to touch this SQL needs the "why" next to the "what"):
--
-- 1. Current critical_patterns seeding (37 rows, from thoth.census + /srv/backups/%) is
--    FAR broader than "important config files" -- two patterns alone
--    (/srv/apps/crawler%, /srv/backups/%) each match ~2.6-2.7M rows, and the full
--    critical set is ~5.3M of the table's ~11.4M rows (~46%). This is real, measured data,
--    not a guess (see runbook). That means "one row per critical file" is inherently a
--    multi-million-row result set today -- no amount of indexing changes that, since the
--    view is only as narrow as the patterns the operator has defined. Not something this migration
--    changes; critical_patterns stays the operator-editable and untouched here.
--
-- 2. Because of (1), several "clever" approaches were tried and rejected before landing on
--    the design below (measured, not guessed -- see runbook for full numbers):
--    - Naive `EXISTS (... WHERE f.path LIKE cp.pattern)` full scan: ~11-12s for the
--      critical-file identification step alone. This turned out to be close to *optimal*
--      given the actual match volume (Postgres already picks a small-materialized-table
--      nested-loop-semi-join plan for this, which is the right shape).
--    - A custom `(path COLLATE "C")` prefix-range index + LATERAL per-pattern index scan:
--      faster to *find* matches (~7.8s) but requires a subsequent GROUP BY to de-duplicate
--      files matched by more than one overlapping pattern (e.g. heimdall's parent+evidence
--      patterns), and that GROUP BY spilled 1.3+ GB to disk sorting/hashing ~8M rows,
--      landing at 56s (sort-based) or 14s (hash-based, but only achievable by forcing
--      `enable_sort=off`, which is too fragile a hint to bake into a production view).
--      Net: more moving parts for a worse or barely-better result. Not used.
--    - Joining the cross-host coverage check against the pre-aggregated
--      `diskaudit.v_duplicate_groups` view (instead of the raw `files` table): correct,
--      and fine for a full unfiltered dump (~18.5s), but because that view is itself a
--      full-table GROUP BY with no matching index, ANY query against it -- including a
--      single-file lookup -- is forced to fully recompute the entire ~713k-group
--      aggregate first (~1-4s minimum, every time). Bad tradeoff for what will mostly be
--      targeted "is file X covered" lookups, not full dumps. Not used.
--    Conclusion: plain `EXISTS`/`LIKE` scan for "is this file critical" (matches Postgres's
--    own optimal plan), plus a per-file `LATERAL` lookup against the raw `files` table
--    (using the existing `idx_diskaudit_files_dup_group` index) for the cross-host check.
--    This makes targeted lookups (the common case: "is file X backed up") fast
--    (~1-1.2s, dominated by the one-time critical-file scan, not the coverage lookup),
--    at the cost of a full unfiltered view scan being slower (~100-120s) -- an acceptable
--    tradeoff since a full dump of 5.3M rows is an occasional report, not a hot path.
--
-- 3. No new indexes were needed. `idx_diskaudit_files_dup_group` (partial, WHERE
--    duplicate_group_id IS NOT NULL) already covers the cross-host lookup efficiently --
--    confirmed via EXPLAIN, not assumed. A candidate `(path COLLATE "C")` prefix index was
--    built and tested (see above) but dropped: it didn't survive contact with the
--    necessary de-duplication step, and would only add write overhead to future scan/dedup
--    runs for no net read benefit.
--
-- 4. Conservative-by-default: a critical file with duplicate_group_id IS NULL (never
--    deduped, or a true singleton) reports is_backed_up = false, covering_hosts = '{}' --
--    it is NEVER silently excluded from the view. "Unknown" is treated as "not confirmed
--    backed up," matching the explicit requirement in the task brief.
-- ---------------------------------------------------------------------------------------

BEGIN;

-- Helper view: every currently-live regular file that matches at least one
-- diskaudit.critical_patterns rule, on any host. One row per (host, path).
CREATE OR REPLACE VIEW diskaudit.v_critical_files AS
SELECT f.host, f.path, f.size_bytes, f.duplicate_group_id
FROM diskaudit.files f
WHERE f.still_exists
  AND f.file_type = 'regular'
  AND EXISTS (
      SELECT 1 FROM diskaudit.critical_patterns cp
      WHERE f.path LIKE cp.pattern
  );

COMMENT ON VIEW diskaudit.v_critical_files IS
  'Every live regular file matching a diskaudit.critical_patterns rule, any host. '
  'Helper view underlying diskaudit.v_backup_coverage -- current critical_patterns seeding '
  'matches ~46% of all files (2 broad thoth.census patterns dominate: heimdall evidence, '
  '/srv/backups/%), so this is expected to be a multi-million-row set, not a bug.';

-- The actual deliverable: for every critical file, does a content-identical copy
-- (same duplicate_group_id, still_exists=true) exist on at least one OTHER host?
CREATE OR REPLACE VIEW diskaudit.v_backup_coverage AS
SELECT
    cf.host,
    cf.path,
    cf.size_bytes,
    cf.duplicate_group_id,
    COALESCE(cov.covering_hosts, ARRAY[]::text[]) AS covering_hosts,
    (cf.duplicate_group_id IS NOT NULL AND cov.covering_hosts IS NOT NULL) AS is_backed_up
FROM diskaudit.v_critical_files cf
LEFT JOIN LATERAL (
    SELECT array_agg(DISTINCT g.host ORDER BY g.host) AS covering_hosts
    FROM diskaudit.files g
    WHERE g.duplicate_group_id = cf.duplicate_group_id
      AND g.host <> cf.host
      AND g.still_exists
      AND g.file_type = 'regular'
) cov ON cf.duplicate_group_id IS NOT NULL;

COMMENT ON VIEW diskaudit.v_backup_coverage IS
  'One row per critical file (diskaudit.critical_patterns). is_backed_up=true iff a '
  'content-identical (same duplicate_group_id) live copy exists on >=1 OTHER host. '
  'duplicate_group_id IS NULL (never deduped) or single-host-only both report '
  'is_backed_up=false, covering_hosts=''{}'' -- conservative by design, never silently '
  'excluded. As of 2026-07-18: nas-1 has not been deduped yet (0 of its files have a '
  'duplicate_group_id) and most NAS shares have not been crawled, so is_backed_up is '
  'expected to read false for effectively everything right now -- this is a data-coverage '
  'gap, not a view bug (confirmed: zero duplicate_group_id values currently span >1 host, '
  'system-wide). Coverage fills in automatically as NAS crawl+dedup work lands, since this '
  'is a live view, not a point-in-time report.';

-- Reverse check: files on nas-1 with no content-identical copy on any OTHER host.
-- Inherently ambiguous (intentional archive-only copy vs. real single point of failure) --
-- this view surfaces the fact, it does not classify or judge it.
CREATE OR REPLACE VIEW diskaudit.v_nas_orphans AS
SELECT
    f.host,
    f.path,
    f.size_bytes,
    f.duplicate_group_id,
    f.inode,
    f.mtime
FROM diskaudit.files f
WHERE f.host = 'nas-1'
  AND f.still_exists
  AND f.file_type = 'regular'
  AND NOT EXISTS (
      SELECT 1
      FROM diskaudit.files other
      WHERE other.duplicate_group_id = f.duplicate_group_id
        AND other.host <> 'nas-1'
        AND other.still_exists
        AND f.duplicate_group_id IS NOT NULL
  );

COMMENT ON VIEW diskaudit.v_nas_orphans IS
  'Live regular files on nas-1 with no content-identical copy (matching '
  'duplicate_group_id) confirmed on any other host -- includes files never deduped '
  '(duplicate_group_id IS NULL). NOT limited to critical_patterns matches -- this is a '
  'whole-NAS reverse check. Deliberately unclassified: could be an intentional '
  'archive-only copy or a real single point of failure -- operator judgment call, not '
  'this view''s job. As of 2026-07-18, NAS-side dedup has not run at all, so this '
  'currently returns ~100% of NAS regular files (781,120 of 781,120) -- expected given '
  'current data completeness, not a bug; will narrow as NAS dedup + remaining-share crawl '
  'work lands.';

COMMIT;
