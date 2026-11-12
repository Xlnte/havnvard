-- diskaudit — HavnVard 1.4.0 OPTIONAL indexes for the NAS dedup candidate query.
-- Date: 2026-11-09 · Plane: INFRA-520 · Design §4.1 commit 9 / §3.5.
--
-- GATED: apply ONLY if the scoped fixture acceptance run measures > 10 minutes wall clock
-- (HV-REQ-32). There is no (host, size_bytes) or (host, content_sha256) index today, so the
-- host-wide size prefilter is a seq scan over ~4.1 M NAS rows (24 s in run 39).
--
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block: run this file with psql
-- WITHOUT -1 / --single-transaction. CONCURRENTLY takes only SHARE UPDATE EXCLUSIVE, which does
-- not block the running dedup's writes (HV-REQ-36). NO lock_timeout here on purpose: a concurrent
-- build legitimately WAITS for every older transaction in the cluster to finish (it blocks nobody
-- while it waits), and a 5 s timeout would abort it whenever any long transaction exists.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_host_size_regular
    ON diskaudit.files (host, size_bytes) WHERE still_exists AND file_type = 'regular' AND size_bytes > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_host_sha_hashed
    ON diskaudit.files (host, content_sha256) WHERE content_sha256 IS NOT NULL;
