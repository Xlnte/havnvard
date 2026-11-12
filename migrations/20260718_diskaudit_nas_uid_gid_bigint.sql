-- diskaudit v2.1 — widen uid/gid from integer to bigint
-- Date: 2026-07-18 · Owner: the operator · Plane: INFRA-97
--
-- Fixes a real bug caught while loading real NAS data (nas-1, homes/ share):
-- a QNAP-internal thumbnail-cache directory (.@__thumb, under
-- homes/alice/bittorrents_paf/) is owned by uid=3701760710 -- a synthetic/
-- unmapped identity QNAP assigns internally, which is a legal 32-bit UNSIGNED
-- value (fits under 4294967295) but exceeds Postgres `integer`'s signed 4-byte
-- range (max 2147483647). The COPY into files_staging failed outright with
-- psycopg.errors.NumericValueOutOfRange, which would have aborted the entire
-- share load over a single row.
--
-- This is a latent schema bug in the ORIGINAL v1 design, not something
-- introduced by NAS support specifically -- server's own local uids have never
-- been large enough to trigger it, but any Linux/QNAP uid or gid is legally a
-- full unsigned 32-bit value, so `integer` was never wide enough in general.
-- bigint (8-byte signed) covers the full unsigned 32-bit range with room to
-- spare. Widening a column's numeric type is a safe, non-lossy operation for
-- every existing row (all current values are far smaller than either range's
-- limit) -- additive/safe to re-run.

BEGIN;

ALTER TABLE diskaudit.files ALTER COLUMN uid TYPE bigint;
ALTER TABLE diskaudit.files ALTER COLUMN gid TYPE bigint;
ALTER TABLE diskaudit.files_staging ALTER COLUMN uid TYPE bigint;
ALTER TABLE diskaudit.files_staging ALTER COLUMN gid TYPE bigint;

COMMIT;
