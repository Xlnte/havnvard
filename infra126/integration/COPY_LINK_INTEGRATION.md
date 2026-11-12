# Copy-Link Integration

Equal paths on different hosts are not automatically copies. `/etc/hostname` is the simplest counterexample.

Populate `diskaudit.hash_copy_links` only from evidence that already proves a logical copy relationship, such as:

- an existing cross-host integrity check;
- backup coverage mapping;
- a known mirror job;
- a restic repository path mapping;
- a QNAP snapshot mapping.

Manual registration example:

```bash
python scripts/register_copy_link.py \
  --logical-host server-1 \
  --logical-path /srv/data/archive.tar.gz \
  --source-kind live_host \
  --source-id nas-1 \
  --source-host nas-1 \
  --source-path /share/Backup/spark/srv/data/archive.tar.gz
```

For bulk integration, write an `INSERT ... SELECT` adapter from the existing verified mapping table after inspecting its actual schema. Do not use `path LIKE '%name%'` matching.
