# Load-Bearing Refresh Hook

The existing `refresh_load_bearing_paths.py` process remains authoritative. INFRA-126 must not independently join hundreds of path patterns against the complete `diskaudit.files` table inside one long transaction.

After the existing refresh resolves exact files, emit JSON Lines containing:

```json
{"host":"server-1","path":"/etc/systemd/system/example.service","inode":12345,"source":"systemd"}
```

Then ingest the exact result in bounded transactions:

```bash
python scripts/sync_critical_files.py \
  --input /safe/runtime/path/load-bearing-exact-files.jsonl \
  --batch-size 500
```

The ingest uses a generation token. New rows are committed in small batches. Stale registry metadata is removed only after the new generation is fully committed. This removal affects only INFRA-126 database metadata; it never deletes, moves, renames, or overwrites scanned files.

The existing load-bearing refresh should call this hook only after its own output has passed validation. A failed or partial export must not replace the previous generation.
