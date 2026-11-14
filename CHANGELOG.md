# Changelog

Release notes from 3.3.2 on. Earlier releases: `git log --oneline` (each release commit carries its notes) and FEATURES.md.

## 3.3.2

NAS within-host dedup (`nas_trigkey_dedup.py`, `hash_stat_batch.sh`, `nas_dedup_core.py`), INFRA-520:

- **Racy-clean digests (G1).** `hash_stat_batch.sh` reads the hashing host's clock once per batch and reports a
  file whose mtime is within 2 s of that time, or in the future, as `UNSTABLE` instead of hashing it. A
  same-second rewrite keeps size and mtime, so such a digest could later look fresh while the bytes differ.
  `digest_is_fresh()` and the publish SQL also require `bound_at >= mtime + 2 s` (`RACY_MARGIN_S`), which
  re-hashes, once, any older binding taken inside that window. A file modified within 2 s of a batch start is
  grouped one run later.
- **`--path-prefix` (G4)** is accepted as an alias of `--path`.
- **`--publish-only` (G5):** no hashing and no ssh/scp; publishes groups from the digests already fresh (use
  after a killed long run). Not combinable with `--limit`.
- **`--dry-run`:** prints the plan (candidates, files and bytes to hash, fresh digests reused) and exits. No
  run row, no database write, no remote I/O. Opt-in: the default stays a live run, which never touches a file
  (it reads files and writes only database rows).
- Docs: module.yaml timer line no longer claims an `--exclude` the unit does not pass (excludes come from the
  site file).
