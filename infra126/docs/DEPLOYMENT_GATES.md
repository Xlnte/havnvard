# Deployment Gates

## Gate 1: Package validation

- [x] Python compiles.
- [x] Remote shell script passes `sh -n`.
- [x] Grafana JSON parses.
- [x] 59 isolated tests pass.
- [x] Static guard finds no scanned-file delete/move/rename primitives.
- [x] No `pkill -f` exists in executable surfaces.

## Gate 2: Live schema review

- [ ] Confirm the production PostgreSQL version and verify the core `md5(text)` function is available.
- [ ] Confirm actual `diskaudit.files` types for `mtime`, `inode`, `size_bytes`, `hashed_at`, and `content_sha256`.
- [ ] Confirm no earlier prototype schema would be destructively replaced.
- [ ] Review query plans for A/B/C/E selectors.
- [ ] Confirm concurrent indexes complete without blocking scan workloads.

## Gate 3: Integration adapters

- [ ] TG command accepts JSON and delivers exactly once.
- [ ] Plane command accepts JSON and returns success only after ticket creation.
- [ ] HELM WaitingRoom commands correctly acquire/release P3 work.
- [ ] Existing HavnVard report includes the new assurance section.
- [ ] Existing monitor invokes INFRA-126 monitoring every five minutes.

## Gate 4: Remote execution

- [ ] NAS persistent scratch exists and has sufficient free space.
- [ ] Agent-1 scratch exists.
- [ ] SSH, SCP, `sha256sum`, `stat -c`, and `base64 -d` work on each target.
- [ ] A killed local worker leaves an exact remote PID and recovery command.
- [ ] Exact-PID recovery succeeds without affecting unrelated processes.

## Gate 5: Synthetic acceptance

- [ ] Stable test file re-hashes to `matched`.
- [ ] Frozen-metadata mismatch creates a suspect and TG alert.
- [ ] Registered mutable file creates accepted drift, then Tier D stabilization.
- [ ] Two-copy conflict remains unresolved.
- [ ] Three-source majority identifies the odd source without auto-restoring.
- [ ] Three-way split creates highest-priority escalation.
- [ ] Alert fingerprints prevent duplicate delivery.

## Gate 6: Operator visibility

- [ ] Verification-status route loads.
- [ ] CSV and JSON exports load.
- [ ] File detail shows observation history.
- [ ] Four Grafana panels render.
- [ ] Daily PRESI report distinguishes baseline-only from re-verified.

## Gate 7: Scheduling

- [ ] Manual A run completes without errors.
- [ ] Manual E run completes without errors.
- [ ] Monitor detects a synthetic stale heartbeat within five minutes.
- [ ] Timers show correct UTC next-run times.
- [ ] A/D/E enabled first.
- [ ] B/C enabled only after maintenance-window review.
