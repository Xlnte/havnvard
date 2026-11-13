-- HavnVard 3.2.0: offload records (INFRA-571). One row per file per offload: the SHA-256 read back out of the
-- archive snapshot and whether it matched the live file. NOT APPLIED by the build. Apply by hand after review:
--   psql -v ON_ERROR_STOP=1 -f this file      (additive, idempotent)
BEGIN;
CREATE TABLE IF NOT EXISTS diskaudit.archive_offload (
    host text NOT NULL,
    folder text NOT NULL,
    path text NOT NULL,
    size_bytes bigint,
    sha256 text,
    status text NOT NULL,
    snapshot_id text NOT NULL,
    archive_tag text NOT NULL,
    offloaded_at timestamp with time zone NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT archive_offload_pkey PRIMARY KEY (host, snapshot_id, path),
    CONSTRAINT archive_offload_status_check CHECK ((status = ANY (ARRAY['VERIFIED'::text, 'MISMATCH'::text, 'CHANGED'::text, 'MISSING_IN_SNAPSHOT'::text])))
);
COMMENT ON TABLE diskaudit.archive_offload IS 'HavnVard offload (python -m backup offload FOLDER): every file of an archive-tagged snapshot read back with restic dump and SHA-256 compared with the live file. Only VERIFIED rows are safe for the owner to delete from the device; HavnVard itself never deletes.';
CREATE INDEX IF NOT EXISTS ix_archive_offload_host_tag ON diskaudit.archive_offload (host, archive_tag);
COMMIT;
