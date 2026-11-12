-- HavnVard 1.5.0 -- full-byte tree verification before deletion (verify_tree.py)
-- Date: 2026-11-10 · Plane INFRA-538 · Runbook: /home/alice/runbooks/20261110-havnvard-full-hash/
--
-- Additive + idempotent. Widens integrity_checks.verdict (adds extra_dest, not_verified),
-- adds integrity_checks.basis ('fresh' = both sides hashed in this run; 'stored' = a digest
-- read back from diskaudit.files) and tree_run_id, and creates tree_verifications (one row per
-- verify_tree run; deleted_at links each deletion to the VERIFIED run that allowed it).
-- Only a 'fresh' row may ever gate a deletion.

BEGIN;

-- Never queue behind a long writer on integrity_checks (crosshost/dedup runs).
SET LOCAL lock_timeout = '5s';

ALTER TABLE diskaudit.integrity_checks DROP CONSTRAINT IF EXISTS integrity_checks_verdict_check;
ALTER TABLE diskaudit.integrity_checks ADD CONSTRAINT integrity_checks_verdict_check CHECK (
    verdict IN ('match', 'mismatch', 'missing_dest', 'unreadable_source', 'unreadable_dest',
                'extra_dest', 'not_verified'));

ALTER TABLE diskaudit.integrity_checks ADD COLUMN IF NOT EXISTS basis text;
ALTER TABLE diskaudit.integrity_checks ADD COLUMN IF NOT EXISTS tree_run_id bigint;
ALTER TABLE diskaudit.integrity_checks DROP CONSTRAINT IF EXISTS integrity_checks_basis_check;
ALTER TABLE diskaudit.integrity_checks ADD CONSTRAINT integrity_checks_basis_check
    CHECK (basis IS NULL OR basis IN ('fresh', 'stored'));

CREATE TABLE IF NOT EXISTS diskaudit.tree_verifications (
    run_id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    purpose             text NOT NULL,
    local_host          text NOT NULL,
    local_path          text NOT NULL,
    nas_host            text NOT NULL,
    nas_path            text NOT NULL,
    files               bigint,
    bytes               bigint,
    canary_ok           boolean,
    verdict             text NOT NULL CHECK (verdict IN ('VERIFIED', 'MISMATCH', 'NOT_VERIFIED', 'CANARY_FAILED')),
    reason              text,
    hash_seconds_local  numeric,
    hash_seconds_nas    numeric,
    code_version        text,
    deleted_at          timestamptz,
    CONSTRAINT tree_verifications_delete_only_verified CHECK (deleted_at IS NULL OR verdict = 'VERIFIED')
);

CREATE INDEX IF NOT EXISTS idx_diskaudit_integrity_checks_tree_run
    ON diskaudit.integrity_checks (tree_run_id) WHERE tree_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_diskaudit_tree_verifications_local
    ON diskaudit.tree_verifications (local_path, started_at DESC);

COMMIT;
