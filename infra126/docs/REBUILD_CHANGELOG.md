# Rebuild Changelog

## Rejected from the earlier prototype

- Treating `hashed_at` as proof of re-verification.
- Resuming only from `content_sha256 IS NULL`.
- Writing remote NAS work into `/tmp`.
- Using equal paths across hosts as proof that files are copies.
- Updating the baseline before preserving and comparing the prior hash.
- Auto-classifying a majority-vote odd copy as confirmed corruption.
- Letting changed metadata override an explicit immutable path.
- Updating `last_verified_at` when a mutable baseline was merely accepted.
- Broad `PUBLIC` update privileges.
- Large production indexes inside a migration transaction.
- A timer that depended on the venv command being accidentally present in `PATH`.
- Remote batches with no central heartbeat during a long hash.
- Stale operator verdicts remaining closed after a new divergence.
- A UI/report that counted initial agent-1 hashes as recent verification.

## Added

- frozen first hash and separate current baseline;
- baseline revision and stabilization semantics;
- runs, items, observations, leases, heartbeats, exact recovery commands;
- A/B/C/D/E implementation;
- persistent alert fingerprints;
- explicit copy-link model;
- latest-evidence-per-independent-source voting;
- restic integrity and file-evidence adapters;
- critical-path sync and Tier E escalation;
- production-safe staged migrations;
- verification UI, detail history, exports, and Grafana;
- deployment gates, controlled installer, rollback, and runbook;
- baseline-associated metadata with explicit trust state;
- live-copy voting only from current successfully re-verified baselines;
- operator-review synchronization into divergence history;
- 59 isolated tests.
