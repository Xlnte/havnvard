# INFRA-126: Scheduled Periodic Re-Hashing for Bit-Rot Detection

## Rebuilt Canonical Specification

**Version:** 1.0 rebuilt  
**Date:** 2026-07-26  
**Application:** HavnVard / `diskaudit`  
**Owner:** the operator  
**Status:** Code-review and controlled-deployment package

---

## 1. Purpose

HavnVard already inventories files, finds duplicates, compares copies, and records SHA-256 hashes. A single hash is only a baseline. It cannot prove that the bytes remained unchanged later.

INFRA-126 adds a standing assurance loop:

1. select files due for re-verification;
2. hash them again;
3. compare the new result to the current accepted baseline;
4. preserve every observation;
5. classify mismatches without overstating certainty;
6. correlate independent copies;
7. alert on suspicious divergence, stale assurance, and failed jobs;
8. expose verification age and SLA status to the operator.

HavnVard remains read-only with respect to scanned files. Restoration and overwrite authority belongs to a future, separately governed FERJA component.

---

## 2. Threat model

INFRA-126 is designed to detect:

- silent media corruption;
- filesystem or controller faults that change file bytes;
- unexpected application or operator modification;
- tampering with load-bearing infrastructure;
- failed or stale verification jobs;
- false assurance caused by treating an initial hash as a later verification.

INFRA-126 does not prove semantic correctness. A file can be byte-stable and still be logically wrong. A majority of copies can agree and still contain an old or already-corrupt version.

---

## 3. Non-negotiable safety rules

1. HavnVard never deletes, moves, renames, restores, or overwrites scanned files.
2. `first_hash` is frozen historical evidence.
3. A successful re-verification requires a later hash that exactly matches the current accepted baseline.
4. Hash work occurs outside database transactions.
5. Database transactions are short and bounded.
6. Remote NAS work never uses `/tmp`.
7. Remote recovery uses an exact PID plus per-run token. `pkill -f` is prohibited.
8. A majority vote identifies an odd source; it does not automatically prove corruption.
9. An explicit immutable-path rule cannot be neutralized merely because mtime or size changed.
10. Initial baseline coverage and re-verification coverage are reported separately.
11. No timer is enabled until bounded live acceptance tests pass.
12. No production result is claimed from package-level tests alone.

---

## 4. Canonical data model

### 4.1 File-level state

- `first_hash`: original baseline, never changed.
- `first_hashed_at`: original baseline timestamp.
- `content_sha256`: current accepted comparison baseline.
- `hashed_at`: current baseline timestamp.
- `last_hash_attempt_at`: latest attempt, successful or not.
- `last_verified_at`: latest exact match against the current baseline.
- `last_baseline_accepted_at`: latest accepted mutable baseline change.
- `verification_count`: exact matches only.
- `baseline_revision_count`: accepted mutable baseline changes.
- `hash_divergence_count`: all mismatches.
- `hash_status`: current operational state.
- `hash_error`: most recent hashing error.
- `hash_baseline_mtime_ns`, `hash_baseline_size`, `hash_baseline_inode`: metadata captured with the accepted baseline.
- `hash_baseline_metadata_trusted`: whether metadata forensics may rely on that baseline metadata.

The 64-character `file_key` is a deterministic lookup key built from host/path/inode using two salted MD5 values available in core PostgreSQL. It is not an integrity checksum; SHA-256 content hashes remain the integrity evidence.

### 4.2 Run control plane

`hash_verification_runs` records:

- host and tier;
- lifecycle status;
- worker identity;
- candidate/completion/error counts;
- heartbeat;
- remote PID and scratch directory;
- exact recovery command;
- failure reason.

`hash_verification_items` records an immutable snapshot of:

- path and inode;
- baseline hash and timestamp;
- baseline-associated size, mtime, inode, and metadata-trust state;
- critical-path status;
- lease owner/expiry;
- attempt and result state.

Workers claim items using `FOR UPDATE SKIP LOCKED`, commit, and then hash outside the transaction.

### 4.3 Observation and divergence history

Every attempt produces a `hash_observations` row. Every mismatch produces a `hash_divergences` row. Current unresolved work is summarized in `corruption_suspects`.

---

## 5. Tier policy

### Tier A: Fresh baseline

- Eligibility: current baseline age 0-7 days.
- Due condition: no successful later match against that baseline.
- Cadence: weekly.
- Purpose: quickly validate newly created or newly accepted baselines.

### Tier B: Monthly assurance

- Eligibility: current baseline age 7-31 days.
- Due condition: no current-baseline verification or last verification older than 30 days.
- Cadence: monthly.

### Tier C: Cold-data assurance

- Eligibility: current baseline age over 31 days.
- Due condition: no current-baseline verification or last verification older than 90 days.
- Cadence: quarterly.

The 31-day threshold intentionally closes the unmanaged 31-90-day gap in the earlier draft.

### Tier D: Mutable-baseline stabilization

- Eligibility: accepted mutable baseline change whose stabilization delay has elapsed.
- Cadence: event-driven queue, polled hourly.
- Purpose: verify that an automatically accepted mutable baseline stabilizes and can later be matched exactly.

### Tier E: Critical paths

- Eligibility: paths resolved from the load-bearing registry.
- Due condition: no current-baseline verification within one day.
- Cadence: daily.
- Any divergence: immediate TG alert and highest-priority Plane escalation.

---

## 6. Hash execution

### Local

- read metadata before hashing;
- SHA-256 in bounded chunks;
- enforce per-file timeout;
- read metadata after hashing;
- reject result as `changed_during_hash` if device/inode/size/mtime changed.

### Remote

- create a unique persistent scratch directory;
- upload a base64 path manifest and BusyBox-compatible worker;
- launch one exact remote PID;
- write token, PID, heartbeat, results, logs, and completion marker;
- poll process and refresh the central run heartbeat;
- terminate only the exact PID after token validation on batch timeout;
- preserve recovery instructions if the local controller dies.

---

## 7. Divergence classification

Classification is a likelihood score, not a verdict.

### Path rules

Examples:

- `/var/log/*`: 99, explicit mutable.
- `*.sqlite`, `*.db`: 98, explicit mutable.
- browser/cache/runtime paths: 95-99, explicit mutable.
- `/etc/hostname`: 10, explicit immutable.
- account, boot, executable, library, systemd, and cron paths: 10-15, explicit immutable.

### Metadata trust

Metadata forensics uses metadata captured with the hash baseline, never the latest inventory metadata. Existing hashes are backfilled with best-available inventory metadata but marked untrusted until an exact match or accepted baseline captures trusted metadata. Untrusted metadata cannot trigger automatic mutable-baseline advancement.

### Metadata rules

- hash changed, mtime and size unchanged at one-second cross-host precision: score at most 5.
- size changed, mtime unchanged: score at most 5.
- mtime changed, size unchanged: ambiguous unless an explicit rule applies.
- mtime and size changed:
  - explicit mutable: high likelihood of legitimate drift;
  - explicit immutable: remains suspicious;
  - no explicit rule: likely legitimate modification but no automatic baseline acceptance.

### Baseline advancement

A new baseline can be automatically accepted only when:

- an explicit mutable rule matched;
- metadata shows a real write;
- the score meets the configured threshold;
- the file is not critical;
- multi-copy evidence does not identify the new candidate as the odd source.

Accepted changes preserve history, increment `baseline_revision_count`, and queue Tier D stabilization. They do not increment `verification_count` until a later exact match occurs.

---

## 8. Multi-copy decisions

Votes represent independent sources, not snapshots. Multiple snapshots in one restic repository are one independent source.

- fewer than two votes: `insufficient_evidence`;
- all hashes equal: `all_agree`;
- two votes differ: `two_copy_conflict`;
- one hash has a clear independent-source majority: `majority_odd_copy`;
- no majority: `three_way_split`.

A majority authorizes investigation, not restoration. Operator confirmation remains required before FERJA can act.

---

## 9. Alerts and escalation

### TG PRESI

- suspicious low-score divergence;
- two-copy conflict;
- candidate identified as odd by independent-source majority;
- three-way split;
- Tier E divergence;
- stale or blocked run;
- overdue SLA;
- failed or incomplete run;
- operator-confirmed corruption.

### Plane

- Tier E divergence;
- low-score candidate identified as odd by majority;
- three-way split;
- operator-confirmed corruption.

Alert fingerprints are persisted. Repeated monitor polls do not repeatedly send the same event inside the suppression window.

---

## 10. SLA and operator visibility

Per host and scheduled tier, the operator sees:

- eligible files;
- files on time;
- files pending;
- percent on time;
- last completed run;
- last successful run;
- next scheduled time;
- last run status;
- critical overdue count.

Baseline-only files are never shown as successfully re-verified.

The package includes:

- a verification status route;
- file-level observation and divergence history;
- CSV and JSON divergence exports;
- four Grafana panels;
- a daily text report section.

---

## 11. Scheduling

- Tier A: Wednesday 23:00 UTC, randomized delay up to 30 minutes.
- Tier B: day 7 at 02:00 UTC, after the known day-6 NAS scrub.
- Tier C: Jan/Apr/Jul/Oct day 8 at 02:00 UTC.
- Tier D: hourly queue poll.
- Tier E: daily 22:00 UTC.
- Monitor: every five minutes.

All hash work enters HELM WaitingRoom as P3.

---

## 12. Restic and RAID integration

INFRA-126 does not duplicate restic verification. It records restic check state and can hash selected snapshot files with `restic dump` to create independent copy evidence.

RAID scrub remains a separate lower-level integrity mechanism. Tier B/C schedules are staggered after the known scrub window. INFRA-127 remains the source for RAID scrub results.

---

## 13. v1, v+1, and v+2

### v1 operational minimum

- core schema;
- Tier A and Tier D;
- local/remote hashing;
- classification;
- run/item persistence;
- TG failure/corruption alerts;
- SLA report;
- bounded acceptance testing.

### v+1 included in this code package

- Tier B, C, and E selectors and units;
- monitor integration;
- Grafana dashboard;
- HavnVard UI blueprint;
- restic evidence adapters;
- critical-path synchronization.

Rollout remains gated even though code is present.

### v+2 roadmap

- FERJA remediation under explicit operator approval;
- aggregate SMART/RAID/divergence correlation;
- continuous throttled verification daemon;
- authenticated multi-device ingestion API and clients.

Exact file-to-physical-disk mapping on RAID5 and guaranteed drive-failure prediction are not promised without validating the QNAP block/storage architecture.

---

## 14. Acceptance

Package-level acceptance requires:

- all code compiles;
- shell and JSON validate;
- isolated test suite passes;
- static safety guard passes;
- migrations contain no public update grant;
- large indexes are concurrent and outside a transaction;
- timers use explicit UTC.

Live acceptance requires:

- reviewed migrations on the actual database;
- successful bounded the server/NAS/agent-1 runs;
- exact remote recovery test;
- TG and Plane delivery tests;
- Grafana and UI rendering;
- stale-heartbeat detection within five minutes;
- stable, immutable-divergence, mutable-drift, two-copy, majority, and split test cases.

No timer is enabled before live acceptance.


## HELM admission behavior

Scheduled verification requests P3 admission, retries every 30 seconds for a configurable 30-minute admission window, updates the run heartbeat while blocked, and fails loudly only after the window expires. P1 memory work is never displaced.
