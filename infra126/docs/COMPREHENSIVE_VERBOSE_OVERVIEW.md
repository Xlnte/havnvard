# INFRA-126: Comprehensive Verbose Overview

## v1, v+1, and v+2 Roadmap

**Application:** HavnVard / `diskaudit`  
**Owner:** the operator  
**Rebuild date:** 2026-07-26  
**Package status:** Complete code-review and controlled-deployment package. Live deployment and live-machine acceptance remain pending.

---

## 1. Why INFRA-126 Exists

HavnVard already inventories files, identifies duplicates, evaluates backup coverage, and records SHA-256 hashes. Those capabilities answer whether two observed byte streams match. They do not prove that a file remained unchanged over time.

A single hash is a baseline. Bit-rot detection requires at least two observations at different times:

1. Hash a file and retain the result.
2. Hash the same logical file later.
3. Compare the new observation against the accepted baseline.
4. Preserve the result even when the file is unreadable, missing, replaced, or changed during hashing.
5. Distinguish likely legitimate modification from suspicious byte-level divergence.

The threat is not limited to cosmic rays. It includes media faults, controller problems, filesystem defects, accidental writes, tampering, broken copy jobs, and false assurance created by treating a one-time hash as a later verification.

The current ext4-based deployment does not provide end-to-end file-content checksumming and self-healing comparable to a correctly designed checksumming filesystem plus redundant independent copies. QNAP RAID parity scrubbing helps detect lower-level parity inconsistency, but it does not establish that an application file was semantically or historically correct when written.

INFRA-126 therefore creates a standing assurance loop rather than another one-shot scan.

---

## 2. Core Safety Model

HavnVard remains evidence-only with respect to scanned files.

It may:

- read file metadata;
- read bytes to calculate SHA-256;
- record observations, classifications, and operator decisions;
- create alerts and tickets;
- update database hash baselines for explicitly mutable files under controlled policy.

It may not:

- delete scanned files;
- move or rename scanned files;
- restore files;
- overwrite a scanned file;
- choose an authoritative copy and apply it automatically.

Future remediation belongs to FERJA, a separate component with explicit overwrite authority and an operator approval gate.

---

## 3. Corrected Hash Semantics

The rebuilt implementation separates concepts that the earlier prototype mixed together.

| Field | Meaning |
|---|---|
| `first_hash` | Original SHA-256 baseline. Frozen historical evidence. |
| `first_hashed_at` | Time the original baseline was created. |
| `content_sha256` | Current accepted comparison baseline. |
| `hashed_at` | Time the current accepted baseline was created. |
| `last_hash_attempt_at` | Latest attempted re-hash, whether successful or not. |
| `last_verified_at` | Latest later observation that exactly matched the current baseline. |
| `last_baseline_accepted_at` | Latest controlled mutable-file baseline advancement. |
| `verification_count` | Number of exact later matches. Initial hashing does not count. |
| `baseline_revision_count` | Number of accepted mutable baseline changes. |
| `hash_divergence_count` | Number of observed mismatches. |
| `hash_status` | Current operational state. |
| `hash_error` | Most recent hash error. |

### Baseline metadata pairing

Hash classification must compare against metadata captured with the hash baseline, not metadata from a later inventory scan. The rebuild therefore stores:

- `hash_baseline_mtime_ns`;
- `hash_baseline_size`;
- `hash_baseline_inode`;
- `hash_baseline_metadata_trusted`.

Existing hashes are backfilled with the best available inventory metadata but marked untrusted. Metadata-based corruption signals and automatic mutable-baseline advancement are disabled until a successful exact match or accepted baseline captures trusted metadata.

This prevents an ordinary inventory refresh from fabricating evidence about what the metadata looked like when the baseline hash was created.

---

## 4. Durable Verification Control Plane

Every run is persisted before hashing begins.

### `hash_verification_runs`

Tracks:

- host and tier;
- queued/running/blocked/completed/failed state;
- worker identity;
- candidate, completion, match, divergence, and error counts;
- central heartbeat;
- remote PID and scratch directory;
- exact token-validated recovery command;
- final error and remaining due work.

### `hash_verification_items`

Stores an immutable snapshot of the comparison target:

- host, path, and inode;
- deterministic logical file key;
- baseline hash and baseline timestamp;
- baseline-associated metadata and trust state;
- critical-path status;
- lease owner and expiration;
- retry count;
- observed result and completion state.

Workers claim bounded batches with `FOR UPDATE SKIP LOCKED`, commit immediately, hash outside the transaction, and persist results in short transactions. This avoids the prior failure mode where a long-running read transaction blocked vacuum for tens of minutes.

### `hash_observations`

Append-only operational evidence for every attempt, including matches and failures.

### `hash_divergences`

Append-only mismatch history with classification, copy decision, operator verdict, and escalation state.

### `corruption_suspects`

Current operator work queue for unresolved suspicious divergences. Operator verdicts are also synchronized to the corresponding divergence record so historical reviews are not lost when a later divergence reopens the current suspect.

---

## 5. Verification Tiers

### Tier A: Fresh baseline validation

- **Eligibility:** Current accepted baseline is 0-7 days old.
- **Due condition:** No later successful exact match exists for that baseline.
- **Cadence:** Weekly, Wednesday 23:00 UTC.
- **Purpose:** Confirm new baselines quickly while data is likely cache-warm.

Tier A is not a perpetual weekly re-hash of the same file. It validates a newly created baseline once. Older files move into the broader assurance tiers.

### Tier B: Monthly assurance

- **Eligibility:** Baseline age is greater than 7 days and no more than 31 days.
- **Due condition:** Baseline has never been verified or the latest verification is at least 30 days old.
- **Cadence:** Monthly, day 7 at 02:00 UTC, after the known day-6 QNAP scrub window.

### Tier C: Cold-data assurance

- **Eligibility:** Baseline age exceeds 31 days.
- **Due condition:** Baseline has never been verified or the latest verification is at least 90 days old.
- **Cadence:** Quarterly, Jan/Apr/Jul/Oct day 8 at 02:00 UTC.

Using 31 days rather than 90 days as the eligibility boundary closes the earlier unmanaged 31-90-day policy gap. The 90-day value remains the recheck SLA.

### Tier D: Mutable baseline stabilization

- **Eligibility:** A controlled mutable-file baseline change was accepted and its stabilization delay has elapsed.
- **Cadence:** Event-driven queue polled hourly.
- **Purpose:** Ensure the accepted baseline later produces an exact match rather than endlessly drifting.

An accepted mutable change does not count as verification. Only the later exact Tier D match increments `verification_count`.

### Tier E: Critical/load-bearing paths

- **Eligibility:** Resolved from HavnVard's load-bearing path registry.
- **Due condition:** No exact current-baseline match within one day.
- **Cadence:** Daily at 22:00 UTC.
- **Escalation:** Any divergence generates immediate TG PRESI and highest-priority Plane events.

---

## 6. Local and Remote Hashing

### the server local hashing

1. Read device, inode, size, and nanosecond mtime.
2. Stream the file through SHA-256 in bounded chunks.
3. Refresh the central run heartbeat during long reads.
4. Read metadata again.
5. Reject the observation as `changed_during_hash` if device, inode, size, or mtime changed.
6. Enforce a per-file timeout.

### NAS and agent-1 remote hashing

1. Refuse NAS `/tmp` as scratch space.
2. Create a unique run directory under persistent INFRA-126 scratch.
3. Transfer a base64 path manifest and BusyBox-compatible worker.
4. Start one exact remote PID.
5. Record a per-run token, PID, heartbeat, logs, results, and completion marker.
6. Poll from the server and refresh the database heartbeat.
7. On timeout, validate the token and terminate only the recorded PID.
8. Preserve the exact recovery command for operator review.

`pkill -f` is prohibited because it can match the recovery command itself or unrelated work.

---

## 7. Divergence Classification

A mismatch is evidence of change, not automatic proof of corruption.

### Explicit path rules

Examples:

| Path or pattern | Score | Meaning |
|---|---:|---|
| `/var/log/*` | 99 | Explicitly mutable |
| `/tmp/*`, `/var/tmp/*`, `/run/*` | 97-99 | Runtime or temporary state |
| `*.sqlite`, `*.sqlite3`, `*.db` | 98 | Database content expected to change |
| browser profiles and caches | 95-96 | Expected high churn |
| Git metadata | 95 | Mutable repository state |
| `/etc/hostname` | 10 | Explicitly immutable identity file |
| account, boot, executable, library, systemd, and cron paths | 10-15 | Sensitive or normally immutable infrastructure |

### Metadata forensics

Metadata is used only when it is trusted as baseline-associated evidence.

- Hash changed while mtime and size stayed unchanged: score at most 5.
- Size changed while mtime stayed unchanged: score at most 5.
- Mtime changed while size stayed unchanged: ambiguous unless an explicit rule applies.
- Mtime and size both changed:
  - explicit mutable path: likely legitimate drift;
  - explicit immutable path: remains suspicious;
  - unknown path: likely deliberate modification but not eligible for automatic baseline advancement.

### Outcome ranges

- **0-29:** `unconfirmed_corruption`; alert-worthy.
- **30-79:** `unclassified`; operator review or later evidence required.
- **80-100:** `legitimate_drift`; normally logged without a corruption alert.

### Automatic mutable baseline advancement

Allowed only when all conditions hold:

- an explicit mutable registry rule matched;
- trusted metadata shows a real write;
- score meets the configured threshold;
- file is not critical;
- independent-copy evidence does not identify the new hash as the odd version.

The new hash becomes the current baseline, history is retained, and Tier D stabilization is queued.

---

## 8. Multi-Copy Decision Logic

Cross-host voting is allowed only for explicitly linked logical copies. Equal path strings on different hosts do not prove that the files are copies. `/etc/hostname` demonstrates why automatic same-path voting would be dangerous.

A live linked copy may vote only when it has successfully re-verified its current baseline. A one-time or stale hash is not counted as current evidence.

Independent sources may include:

- current observed host;
- explicitly linked and currently verified live host;
- verified restic repository evidence;
- verified QNAP snapshot evidence;
- verified offsite evidence.

Multiple snapshots in one restic repository count as one independent source, not multiple votes.

### Decisions

- Fewer than two independent votes: `insufficient_evidence`.
- All votes equal: `all_agree`.
- Two independent votes differ: `two_copy_conflict`.
- Clear two-of-three or stronger majority: `majority_odd_copy`.
- No majority: `three_way_split`.

A majority identifies the odd source for investigation. It does not prove semantic correctness, prove corruption, or authorize restoration. Operator confirmation is still required.

---

## 9. Alerts and Escalation

### TG PRESI

Receives:

- low-score suspicious divergence;
- two-copy conflict;
- majority identifying the current host as the odd source;
- three-way split;
- Tier E divergence;
- stale or blocked verification run;
- overdue verification SLA;
- failed or incomplete run;
- operator-confirmed corruption.

### Plane

Receives highest-priority events for:

- Tier E divergence;
- low-score current host identified as the odd source by independent majority;
- three-way split;
- operator-confirmed corruption.

Alerts use persistent fingerprints and atomic delivery leases. A repeated five-minute monitor poll does not resend the same event inside its suppression window. Failed delivery releases the lease for a later retry.

---

## 10. Operator Visibility

### Daily PRESI report

Shows, per host:

- exact re-verification coverage within 7, 30, and 90 days;
- total baselined files;
- baseline-only files that have never been re-verified;
- open corruption suspects;
- monthly divergence count;
- Tier A/B/C/E SLA state, pending files, latest completion, latest successful run, and next due time.

### Grafana

The package includes four panels:

1. Verification age distribution by host.
2. Corruption suspects this month.
3. SLA attainment per host and tier.
4. Hash divergences by mutable score.

### HavnVard web UI

The supplied Flask blueprint adds:

- verification-status route;
- file observation and divergence history;
- CSV and JSON divergence exports;
- hash-age and status data contracts for integration into existing DEDUP/CLEANUP/BACKUP tabs.

The existing HavnVard application source was not provided, so registration and existing-tab modification remain a live repository integration gate rather than a falsely claimed completed deployment.

---

## 11. v1 and v+1 Delivery Position

The rebuilt archive contains code surfaces for Tier A, B, C, D, and E, monitoring, alerts, reporting, Grafana, UI, restic evidence, systemd scheduling, migrations, tests, and runbooks.

Deployment remains staged:

### Initial controlled deployment

1. Review live schema and prototype tables.
2. Apply migrations without enabling timers.
3. Connect TG PRESI, Plane, and HELM WaitingRoom adapters.
4. Run ten-item the server, NAS, and agent-1 Tier A batches.
5. Validate exact hash, divergence, failure, and alert behavior.
6. Enable Tier A, D, E, and monitoring first.
7. Enable Tier B and C only after maintenance-window review and observed Tier A/E stability.

This is stronger than labeling the earlier Tier A prototype “ready for deployment.” The package is ready for controlled live acceptance, not blind production activation.

---

## 12. v+2 Roadmap

### FERJA remediation

FERJA remains separate. A safe restore requires:

1. explicit operator approval identifying host, path, source, snapshot, expected hash, and expiration;
2. source re-hash immediately before use;
3. destination re-read and evidence revalidation;
4. copy to a new temporary destination;
5. hash validation before replacement;
6. atomic replacement only after approval;
7. rollback material;
8. final re-hash;
9. immutable audit record.

No remediation code is included in HavnVard.

### Predictive drive-failure correlation

Blocked by NAS SMART/RAID telemetry access. Practical scope is to correlate:

- per-drive SMART trends;
- RAID scrub errors and repairs;
- divergence spikes by volume/share and time window.

Do not promise exact file-to-physical-disk mapping or a guaranteed failure date on RAID5 without proving the QNAP block mapping.

### Continuous low-priority verification

Reuse the same durable run/item model with:

- token-bucket I/O throttling;
- HELM P3 admission and periodic yield;
- host/share fairness;
- priority for critical, never-verified, and overdue files;
- rolling throughput metrics;
- clean lease release on shutdown.

Scheduled tiers remain SLA backstops.

### Multi-device support

Windows, iOS, and Android agents should report through an authenticated ingestion API. They should not receive direct PostgreSQL credentials.

Platform work includes VSS/USN awareness on Windows, mobile background limits, scoped storage, battery/Wi-Fi gates, device-scoped credentials, replay protection, and server-side validation.

---

## 13. Success Criteria

Six-month targets:

- at least 90% Tier A attainment;
- at least 80% Tier B attainment;
- at least 50% Tier C attainment;
- 100% Tier E daily attainment;
- no initial hash misreported as re-verification;
- no silent failed verification runs;
- no unauthorized scanned-file mutation;
- no automatic restoration based only on majority vote;
- suspicious divergence surfaced within the applicable SLA window;
- alert volume controlled through classification and deduplication;
- live reports trusted because they distinguish baseline coverage, successful verification, accepted mutable revision, failure, and unresolved divergence.

---

## 14. Current Evidence and Limitations

The July 25 inventory and coverage figures in the source specification are historical inputs supplied for design. They have not been re-queried from the live database by this build environment.

Package-level validation proves that the code compiles, shell syntax parses, dashboard JSON parses, safety guards pass, and the isolated test suite passes. It does not prove:

- production PostgreSQL compatibility;
- live the server/NAS/agent-1 throughput;
- actual TG or Plane delivery;
- HELM WaitingRoom command compatibility;
- restic repository evidence;
- live Grafana rendering;
- systemd execution on the server;
- integration with the current HavnVard repository.

Those are explicit live deployment gates in `docs/DEPLOYMENT_GATES.md` and `runbooks/RUNBOOK.md`.


## HELM admission behavior

Scheduled verification requests P3 admission, retries every 30 seconds for a configurable 30-minute admission window, updates the run heartbeat while blocked, and fails loudly only after the window expires. P1 memory work is never displaced.
