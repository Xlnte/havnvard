# Architecture

## Control plane

Every verification is represented by:

1. `hash_verification_runs`: run lifecycle, heartbeat, remote PID, recovery command, counters.
2. `hash_verification_items`: immutable snapshot of the comparison target plus lease/checkpoint state.
3. `hash_observations`: append-only result history for every attempt.
4. `hash_divergences`: append-only mismatch classification and multi-copy decision state.
5. `corruption_suspects`: current operator work queue.

The database transaction ends before any file is hashed. Workers claim short batches with `FOR UPDATE SKIP LOCKED`, commit, hash outside the transaction, and then persist each result in a short transaction.

The 64-character `file_key` is a deterministic lookup key built from host/path/inode using two salted MD5 values available in core PostgreSQL. It is not an integrity checksum; SHA-256 content hashes remain the integrity evidence.

## Data-plane safety

HavnVard reads files and records evidence. It does not delete, move, rename, restore, or overwrite scanned files.

Remote workers:

- operate only inside the configured scratch directory;
- write an exact PID and per-run token;
- update a heartbeat file during long hashes;
- can be terminated only by exact PID after token validation;
- never use `pkill -f`;
- never write to NAS `/tmp`.

## Baseline model

`first_hash` is immutable history. `content_sha256` is the active baseline. A successful exact match updates `last_verified_at`. An accepted mutable change updates the active baseline, increments `baseline_revision_count`, and queues Tier D stabilization. It does not masquerade as a successful match.

## Tier model

- A: baseline age 0-7 days; verify the newly created baseline.
- B: baseline age 7-31 days; verify monthly.
- C: baseline age over 31 days; verify every 90 days. This closes the 31-90 day policy gap.
- D: event-driven stabilization after a mutable baseline change.
- E: critical/load-bearing paths; verify daily.

## Divergence model

The classifier returns likelihood, not proof. Cross-host mtime comparisons are normalized to one-second precision because BusyBox `stat` does not reliably expose nanoseconds; raw observation timestamps are still retained.

- `<30`: unconfirmed corruption signal.
- `30-79`: unclassified/manual review.
- `>=80`: likely legitimate drift.

Only explicit mutable registry rules can auto-advance a baseline, and only when metadata shows a real write. Frozen metadata overrides a mutable path rule.

## Multi-copy model

Votes are counted by independent source, not by number of snapshots. Ten snapshots in one restic repository are one independent source, not ten votes.

- One source: insufficient evidence.
- Two matching sources: agreement.
- Two differing sources: unresolved conflict.
- Two of three independent sources agree: identify the odd copy for investigation.
- Three different hashes: unresolved split and highest-priority escalation.

A majority identifies inconsistency. It does not, by itself, prove corruption or prove which version is semantically correct.
