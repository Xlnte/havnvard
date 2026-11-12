-- diskaudit — HavnVard 1.4.0 ONE-TIME reconciliation of stale within-host labels on nas-1 (HV-REQ-15).
-- Date: 2026-11-09 · Plane: INFRA-520 · Design §2.8 "One-time reconciliation".
--
-- Clears 'sha256-within-host' labels that are provably FALSE today:
--   (1) the row vanished from the NAS (still_exists = false)        -- baseline 15 rows
--   (2) the file was modified after its digest was taken (mtime > hashed_at)  -- baseline 2 rows
-- Labels from other tools (crosshost-sha256, rdfind) are out of this lane and untouched.
-- The remaining ~1.87 M legacy labels are ADVISORY and pre-1.4.0: each 1.4.0 publish replaces them
-- within its scope, and the delete script never reads them (DS-REQ-01).
--
-- One transaction, lock_timeout 5 s (HV-REQ-36). The two trailing counts are the HV-REQ-15 accept
-- checks: BOTH MUST BE 0.
SET lock_timeout = '5s';
BEGIN;

UPDATE diskaudit.files
   SET duplicate_group_id = NULL, dedup_tool = NULL, dedup_method = NULL, dedup_checked_at = now()
 WHERE host = 'nas-1' AND dedup_tool = 'sha256-within-host'
   AND duplicate_group_id IS NOT NULL AND NOT still_exists;

UPDATE diskaudit.files
   SET duplicate_group_id = NULL, dedup_tool = NULL, dedup_method = NULL, dedup_checked_at = now()
 WHERE host = 'nas-1' AND dedup_tool = 'sha256-within-host'
   AND duplicate_group_id IS NOT NULL AND still_exists AND content_sha256 IS NOT NULL AND mtime > hashed_at;

SELECT
  (SELECT count(*) FROM diskaudit.files WHERE host = 'nas-1' AND dedup_tool = 'sha256-within-host'
      AND duplicate_group_id IS NOT NULL AND NOT still_exists)                                   AS remaining_vanished_labelled,
  (SELECT count(*) FROM diskaudit.files WHERE host = 'nas-1' AND dedup_tool = 'sha256-within-host'
      AND duplicate_group_id IS NOT NULL AND still_exists AND content_sha256 IS NOT NULL
      AND mtime > hashed_at)                                                                     AS remaining_stale_labelled;

COMMIT;
RESET lock_timeout;
