# INFRA-126 Rebuilt Implementation

Scheduled periodic re-hashing and divergence detection for HavnVard/diskaudit.

## Delivery status

This archive is a **complete implementation package for code review and controlled deployment**, not proof that the live the server/NAS/agent-1 environment has been changed or validated.

Package validation performed in the build sandbox:

- Python compilation: passed
- POSIX shell syntax: passed
- Grafana JSON parsing: passed
- Pytest: **59 passed**
- Static safety guard: passed

Live-machine gates remain explicit:

- PostgreSQL migrations must be reviewed and run on `havnvard`.
- Actual `diskaudit.files` column types and existing constraints must be confirmed.
- the server, NAS, and agent-1 hashing must be exercised against small test batches.
- HELM WaitingRoom, TG PRESI, and Plane command adapters must be connected.
- The HavnVard Flask blueprint and Grafana JSON must be integrated into the existing applications.
- systemd timers must not be enabled until the manual acceptance run passes.

## What was rebuilt

The previous prototype confused initial hashing with re-verification and had no durable run-item control plane. This version adds:

1. A frozen initial hash and a separate current baseline.
2. Separate timestamps for first hash, last attempt, successful re-verification, and accepted mutable baseline.
3. Durable verification runs and run items with leases, checkpoints, heartbeats, retries, and `SKIP LOCKED` claiming.
4. Tier A, B, C, D, and E selection logic.
5. Safe local and remote hashing with metadata-before/after checks.
6. NAS scratch enforcement outside `/tmp`.
7. Exact-PID remote recovery. No `pkill -f`.
8. Mutable/immutable classification that does not let changed metadata override an explicit immutable rule.
9. Two-copy conflict and three-copy majority decision states without falsely claiming mathematical proof of corruption.
10. Alert deduplication and adapters for TG PRESI and Plane.
11. Restic copy-evidence registration without duplicating restic's integrity checker.
12. SLA views, daily reporting, a HavnVard UI blueprint, CSV/JSON exports, and four Grafana panels.
13. Production-safe migration separation: tables, concurrent indexes, views/functions, then baseline backfill.
14. A Tier D stabilization queue after an accepted mutable baseline change.
15. A complete runbook, rollback plan, deployment gates, and acceptance matrix.

## Canonical semantics

- `first_hash`: the original SHA-256 baseline. Frozen.
- `content_sha256`: the current accepted comparison baseline.
- `first_hashed_at`: when the original baseline was created.
- `hashed_at`: when the current accepted baseline was created.
- `last_verified_at`: when a later re-hash exactly matched the current baseline.
- `last_baseline_accepted_at`: when a registered mutable file changed and the new baseline was accepted.
- `verification_count`: exact baseline matches only.
- `baseline_revision_count`: accepted mutable baseline changes.
- `hash_divergence_count`: all observed hash mismatches.

Initial hashes are **baseline-only**. They are not counted as successful re-verification.

## Source layout

- `migrations/`: staged PostgreSQL deployment
- `src/havnvard_bitrot/`: verification engine
- `bin/remote_hash_batch.sh`: BusyBox-compatible remote hashing worker
- `scripts/`: scheduled orchestration, restic evidence, SLA refresh, critical-path sync
- `systemd/`: A/B/C/D/E and monitor units
- `web/`: HavnVard verification blueprint and templates
- `grafana/`: four-panel dashboard JSON
- `integration/`: contracts for existing HavnVard/PRESI/Plane/HELM components
- `runbooks/`: operator procedures
- `tests/`: isolated tests and static safety checks
- `docs/`: comprehensive overview, architecture, acceptance, deployment, roadmap, related Plane/apps

## Start here

1. Read `docs/DEPLOYMENT_GATES.md`.
2. Read `INSTALLATION.md`.
3. Run `pytest -q`.
4. Review the migrations against the live schema.
5. Run a 10-item the server acceptance batch.
6. Run a 10-item NAS acceptance batch.
7. Validate alerts, reporting, UI, and Grafana.
8. Enable timers only after every live gate passes.
