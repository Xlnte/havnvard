-- Run after 001 and 002. Existing hashed rows become BASELINE_ONLY, not VERIFIED.
-- This can be rerun safely. It never changes content_sha256.

-- Historical hash state. Only rows missing one of these values are touched.
UPDATE diskaudit.files
SET first_hash = COALESCE(first_hash, content_sha256),
    first_hashed_at = COALESCE(first_hashed_at, hashed_at),
    hash_status = COALESCE(hash_status, 'baseline_only')
WHERE content_sha256 IS NOT NULL
  AND (first_hash IS NULL OR first_hashed_at IS NULL OR hash_status IS NULL);

-- Best-available metadata backfill. Existing inventory metadata is explicitly
-- untrusted because it may not have been captured at the exact hash time.
-- The predicates avoid rewriting rows forever when a source metadata field is NULL.
UPDATE diskaudit.files
SET hash_baseline_mtime_ns = COALESCE(
      hash_baseline_mtime_ns,
      CASE WHEN mtime IS NULL THEN NULL
           ELSE (EXTRACT(EPOCH FROM mtime) * 1000000000)::bigint
      END
    ),
    hash_baseline_size = COALESCE(hash_baseline_size, size_bytes),
    hash_baseline_inode = COALESCE(hash_baseline_inode, inode),
    hash_baseline_metadata_trusted = FALSE
WHERE content_sha256 IS NOT NULL
  AND NOT hash_baseline_metadata_trusted
  AND (
       (hash_baseline_mtime_ns IS NULL AND mtime IS NOT NULL)
    OR (hash_baseline_size IS NULL AND size_bytes IS NOT NULL)
    OR (hash_baseline_inode IS NULL AND inode IS NOT NULL)
  );
