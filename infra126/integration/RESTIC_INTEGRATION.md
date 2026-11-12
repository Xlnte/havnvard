# Restic Integration

Two distinct records are supported.

## Repository/snapshot integrity state

After the existing restic check process finishes:

```bash
python scripts/record_restic_check.py \
  --snapshot-id SNAPSHOT \
  --host server-1 \
  --passed \
  --corrupt-count 0 \
  --details-json '{"repository":"/path/to/repo"}'
```

## File-level independent evidence

For selected files:

```bash
python scripts/restic_hash_copy.py \
  --repository /path/to/repo \
  --snapshot SNAPSHOT \
  --snapshot-path /path/inside/snapshot \
  --logical-host server-1 \
  --logical-path /live/path \
  --source-id restic:spark-primary
```

`source-id` identifies the independent repository/source. Do not use each snapshot ID as a separate vote.


## Evidence gate

`restic_hash_copy.py` refuses to register voting evidence unless the same snapshot/backup-host has a passing `backup_verification_state` row with zero corrupt objects. Run `restic check`, record the result with `record_restic_check.py`, and only then hash individual snapshot files. An emergency `--allow-unverified-repository` override records the result as `unverified`; unverified evidence is excluded from multi-copy voting.
