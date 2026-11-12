-- diskaudit — HavnVard 1.4.0 NAS within-host dedup: bindings, per-run items, group snapshots
-- Date: 2026-11-09 · Owner: the operator · Plane: INFRA-519 (work) / INFRA-520 (source gaps)
-- Design: /home/alice/runbooks/20261109-havnvard-nas-dedup/20261109_ARCHITECTURE.md §2.2, 2.7, 2.8
--
-- ADDITIVE ONLY. Three new tables + ten-odd new dedup_runs columns. Nothing is dropped, renamed or
-- rewritten. ADD COLUMN IF NOT EXISTS / CREATE TABLE IF NOT EXISTS make it re-runnable.
--
-- HV-REQ-36 (no interference with a running dedup): every statement here is metadata-only
-- (ADD COLUMN with a constant/NULL default does not rewrite the table on PG16), and the whole file
-- runs under lock_timeout='5s' so it can never queue behind -- and thereby block -- a running dedup
-- run's short heartbeat UPDATEs for longer than 5 s. If it times out: retry, never raise the timeout.
-- Applied by the deployer (not by the build session) at design step D1.

SET lock_timeout = '5s';
BEGIN;

-- ---------------------------------------------------------------------------
-- dedup_runs: scope, code version, counts, failure reason (HV-REQ-12, 14, 23)
-- (scope itself lives in the existing root_dirs column: ARRAY[<abs dir>] for a scoped run)
-- ---------------------------------------------------------------------------
ALTER TABLE diskaudit.dedup_runs
    ADD COLUMN IF NOT EXISTS code_version        text,
    ADD COLUMN IF NOT EXISTS exclude_paths       text[]      NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS is_partial          boolean     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS excluded_zero_byte  bigint,
    ADD COLUMN IF NOT EXISTS files_hashed        bigint,
    ADD COLUMN IF NOT EXISTS files_inherited     bigint,
    ADD COLUMN IF NOT EXISTS files_reused        bigint,
    ADD COLUMN IF NOT EXISTS errors_by_reason    jsonb,
    ADD COLUMN IF NOT EXISTS transport_failures  integer,
    ADD COLUMN IF NOT EXISTS retries             integer,
    ADD COLUMN IF NOT EXISTS grouped_identities  bigint,
    ADD COLUMN IF NOT EXISTS bytes_reclaimable   bigint,
    ADD COLUMN IF NOT EXISTS failure_reason      text,
    ADD COLUMN IF NOT EXISTS published_at        timestamptz;

-- ---------------------------------------------------------------------------
-- dedup_digest_bindings: the stat a digest was computed against (HV-REQ-05..09)
-- Owned by nas_trigkey_dedup.py ONLY. bound_at is never refreshed on reuse/inherit (HV-REQ-07).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS diskaudit.dedup_digest_bindings (
    host            text        NOT NULL,
    path            text        NOT NULL,
    sha256          text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes      bigint      NOT NULL CHECK (size_bytes > 0),
    mtime           timestamptz NOT NULL,          -- whole seconds (BusyBox stat %Y)
    mtime_ns        bigint,                        -- reserved; NULL on the NAS
    st_ino          bigint      NOT NULL,
    st_dev          bigint      NOT NULL,
    nlink           integer     NOT NULL,
    bound_at        timestamptz NOT NULL,
    dedup_run_id    bigint      NOT NULL REFERENCES diskaudit.dedup_runs(dedup_run_id),
    inherited_from  text,                          -- representative path when stat-only inherited (hardlink sibling)
    PRIMARY KEY (host, path)
);
CREATE INDEX IF NOT EXISTS idx_dedup_bindings_identity ON diskaudit.dedup_digest_bindings (host, st_dev, st_ino);
CREATE INDEX IF NOT EXISTS idx_dedup_bindings_run      ON diskaudit.dedup_digest_bindings (dedup_run_id);

-- ---------------------------------------------------------------------------
-- dedup_run_items: per-path outcome of a run (HV-REQ-19, 23). Pruned (>30 days) at run start.
-- 'reused' and 'excluded_zero_byte' are legal values; the tool counts those two directly in the
-- run row (a per-path row for ~2.4 M reused files per weekly run would be wasted work).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS diskaudit.dedup_run_items (
    dedup_run_id    bigint NOT NULL REFERENCES diskaudit.dedup_runs(dedup_run_id),
    host            text   NOT NULL,
    path            text   NOT NULL,
    outcome         text   NOT NULL CHECK (outcome IN ('hashed','inherited','reused','error','excluded_zero_byte')),
    reason          text   CHECK (reason IN ('MISSING','UNREADABLE','UNSTABLE','NOT_REGULAR','NON_UTF8_PATH','UNSAFE_PATH','MALFORMED')),
    detail          text,
    PRIMARY KEY (dedup_run_id, host, path)
);

-- ---------------------------------------------------------------------------
-- Immutable per-run group snapshot -- the ONLY input of the operator delete script (HV-REQ-11, 27)
-- Append-only; pruned by the operator, never by the tool.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS diskaudit.dedup_group_snapshots (
    dedup_run_id        bigint      NOT NULL REFERENCES diskaudit.dedup_runs(dedup_run_id),
    host                text        NOT NULL,
    group_id            text        NOT NULL,                 -- the sha256
    size_bytes          bigint      NOT NULL,
    identity_count      integer     NOT NULL,
    member_count        integer     NOT NULL,
    keeper_path         text        NOT NULL,
    bytes_reclaimable   bigint      NOT NULL,
    code_version        text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dedup_run_id, group_id)
);

CREATE TABLE IF NOT EXISTS diskaudit.dedup_group_members (
    dedup_run_id            bigint      NOT NULL,
    group_id                text        NOT NULL,
    host                    text        NOT NULL,
    path                    text        NOT NULL,
    st_dev                  bigint      NOT NULL,
    st_ino                  bigint      NOT NULL,
    nlink                   integer     NOT NULL,
    size_bytes              bigint      NOT NULL,
    mtime                   timestamptz NOT NULL,
    sha256                  text        NOT NULL,
    bound_at                timestamptz NOT NULL,
    role                    text        NOT NULL CHECK (role IN ('keeper','keeper_link','victim','victim_link')),
    in_recycle_bin          boolean     NOT NULL,
    in_backup_tree          boolean     NOT NULL,
    links_outside_inventory boolean     NOT NULL,
    PRIMARY KEY (dedup_run_id, host, path),
    FOREIGN KEY (dedup_run_id, group_id) REFERENCES diskaudit.dedup_group_snapshots (dedup_run_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_dedup_group_members_group ON diskaudit.dedup_group_members (dedup_run_id, group_id, role);

COMMIT;
RESET lock_timeout;
