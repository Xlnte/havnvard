# INFRA-126: Scheduled Periodic Re-Hashing for Bit-Rot Detection
## Consolidated Specification & Feature Design
**Generated:** 2026-07-25  
**For:** Implementation via Claude Code (or ChatGPT for code generation)  
**Scope:** HavnVard (technical name: diskaudit) v2 → v3 ecosystem  
**Related Plane Items:** 45 consolidated  
**Owner:** the operator (the owner)

---

## EXECUTIVE SUMMARY

**The Problem:**  
Silent data corruption — bit-rot, disk errors, filesystem issues — is undetected on this machine.
Today, HavnVard can prove files are byte-identical across hosts (cross-host dedup), but it cannot
detect when a single file's bytes change over time. Detection requires **comparison between two
points in time**. Every hash was taken today (`first_hash == last_hash`); nothing is verifiable yet.

**The Core Gap:**  
```
host         hashed   first_hash   last_hash    hashed >30d ago
nas-1    8,580   2026-07-25   2026-07-25         0        ← EXACTLY ZERO
server-1    8,687   2026-07-25   2026-07-25         0        ← EXACTLY ZERO
agent-1     158,285   2026-07-25   2026-07-25         0        ← EXACTLY ZERO
```

A standing assurance loop — periodic re-hashing + comparison against historical baseline — must
replace this one-shot snapshot.

**INFRA-126 Deliverable:**  
A requirements + acceptance-criteria spec (this document) for building that loop. Design the "what"
and "how would we know it works." Implementation follows, handled by an engineer with the machine
in front of them.

---

## PART I: EXISTING SUBSTRATE (What's Already Built)

### A. HavnVard Ecosystem Status (as of 2026-07-25)

| Component | Status | Runbook | Notes |
|-----------|--------|---------|-------|
| **Whole-disk inventory (the server)** | ✅ LIVE | 20260717-diskaudit-v1 | 10.7M rows, daily scan via `diskaudit-scan.timer` |
| **Whole-disk inventory (NAS)** | ✅ LIVE | 20260717-diskaudit-v2-dedup | 2.3M rows; native BusyBox crawl via SSH, ~29.3k files/sec |
| **Client agent (agent-1)** | ✅ LIVE | CLIENT_INSTALL.md | 380k rows; systemd-installed; autonomous scan |
| **Dedup detection (rdfind)** | ✅ LIVE | 20260717-diskaudit-v2-dedup | 689k groups found; 409.6 GB reclaimable identified |
| **NAS-only dedup** | ✅ LIVE (new 2026-07-25) | 20260725-havnvard-crosshost-integrity | `nas_trigkey_dedup.py` for hosts without rdfind |
| **Cross-host SHA-256 verification** | ✅ LIVE (new 2026-07-25) | 20260725-havnvard-crosshost-integrity | `crosshost_verify.py`; 0.3% of server-1 files, 0.1% of agent-1 in candidate set |
| **File-status classification** | ✅ LIVE | 20260718-diskaudit-classification | Labels: active / load-bearing / stale / possibly-obsolete / orphaned |
| **Load-bearing override** | ✅ LIVE | 20260718-diskaudit-classification | 443 patterns; protects cold-but-live infrastructure |
| **Backup coverage (critical patterns)** | ✅ LIVE | 20260718-diskaudit-backup-coverage | Scoped to 27 rules; shows if critical files have copies elsewhere |
| **Backup coverage (complete universe)** | ✅ LIVE (new 2026-07-25) | 20260725-havnvard-backup-coverage | `backup_coverage.py`; every file classified: `BACKED_UP_VERIFIED` / `BACKED_UP_UNVERIFIED` / `NOT_BACKED_UP` / `EXCLUDED` |
| **Health monitoring** | ✅ LIVE | 20260717-diskaudit-v2-heartbeat-monitor | `monitor.py` runs every 5 min; TG PRESI alerts on stale/failed runs |
| **Daily PRESI report** | ✅ LIVE | 20260719-havnvard-presi-report | Metadata aggregates + PRESCAB daily operational read |
| **Weekly PRESCAB review** | ✅ LIVE | 20260718-diskaudit-prescab-weekly-review | `weekly_prescab_review.py`; VP-Operations governance loop |
| **Grafana dashboard** | ✅ LIVE | — | 12 panels; `:9452/d/diskaudit/diskaudit`; deep-link in daily PRESI report |
| **Restic backup engine** | ✅ LIVE (Phase 2) | 20260718-havnvard-restic-migration | 10 app dirs, 20 systemd timers (backup + retention), daily + weekly |
| **Web UI (DEDUP / CLEANUP / BACKUP tabs)** | ✅ LIVE (new 2026-07-25) | 20260725-havnvard-ui | Tailnet-only; `:9457`; filter/sort/export (no delete/move actions) |

**Database schema status:**  
```
havnvard.diskaudit.* (Primary)
  files               8.4M+ rows (spark/nas/agent-1)
  scan_runs           Track start/finish/status of inventory scans
  scan_errors         Capture permission/read failures per scan
  dedup_runs          Dedup job lifecycle (rdfind or nas_trigkey_dedup)
  dedup_worker_status Worker concurrency tracking (rdfind parallel)
  dedup_staging       Temp table for COPY-merge pattern
  duplicate_groups    Final de-duplicated groups (inode-aware)
  integrity_checks    Verdicts from crosshost_verify (match/mismatch/missing_dest/unreadable_source)
  crosshost_verify_runs  Track cross-host hash verification job state (NEW 2026-07-25)
  backup_runs         Restic backup job tracking
  report_snapshots    Daily report snapshots for day-over-day deltas
  load_bearing_paths  443 patterns; provenance tracked (systemd/cron/thoth.census)
  load_bearing_refresh_runs  Refresh lifecycle for load-bearing registry
  critical_patterns   37+ patterns for critical-file scope (backup_coverage #7)
  file_category_patterns  Classification rules (active/stale/etc.)
  backup_scope_rules  27 auditable exclusion rules
  backup_coverage     Complete universe classification (NEW 2026-07-25)
  
Migrations applied (all additive/idempotent):
  20260717_diskaudit_multihost_dedup_v2.sql
  20260717_diskaudit_dedup_staging_v2.sql
  20260718_diskaudit_classification_v1.sql
  20260718_diskaudit_backup_coverage_v2.sql
  20260718_diskaudit_nas_uid_gid_bigint.sql
  20260717_diskaudit_monitor_v2.sql
  20260717_diskaudit_reclaimable_fix_v2.sql
  20260725_diskaudit_crosshost_integrity_v1.sql (content_sha256/hashed_at/hash_source columns)
  20260725_diskaudit_havnvard_ui_mv.sql (materialized views for UI)
```

### B. The Three-Host Topology

| Host | Role | FS | Capacity | Content (rows) | Scan Method | Notes |
|------|------|----|----|---|---|---|
| **server-1** | Primary compute | ext4 NVMe | 3.6T (68% used, 1.1T free) | 10.7M | Local Python `scan.py` + `stat()` | Ubuntu 24.04 ARM64; root access for cross-user dirs |
| **nas-1** | QNAP TS-453A QTS 5.2.9 | ext4 RAID5 | 15.4T (49% used, 7.9T free) | 2.3M | Native BusyBox crawl via SSH, **never mount** | No Python; 64MB `/tmp` (shared tmpfs); ssh + scp only |
| **agent-1** | Ubuntu desktop | ext4 NVMe | 468G (6% used) | 380k | Remote agent + systemd scan | Passwordless sudo; already installed; client architecture |

**Key constraints:**
- **NAS is not Linux:** BusyBox `sh`, no Python, no GNU tools. `find -printf` does not work. `/tmp` is 64MB tmpfs shared with live NAS system processes.
- **Hardlinks:** 2M+ hardlinked files on the server. Naive byte sums overstate by ~2×. All totals must be `DISTINCT (host, inode)`.
- **Cross-filesystem:** the server is **single ext4 device** (`-xdev`). NAS has **10 shares** (not all scanned yet).
- **Throughput:** NAS-side `sha256sum` sustains ~50 MB/s. Local the server NVMe is ~10× that. Schedule design must account for this asymmetry.

### C. Current Hash Coverage

**Sparse and recent — a baseline, not a check:**

```sql
SELECT host, count(*) FILTER (content_sha256 NOT NULL) hashed, 
       count(*) total, min(hashed_at), max(hashed_at)
FROM diskaudit.files WHERE still_exists AND file_type='regular'
GROUP BY host
ORDER BY host;

 host       | hashed   | total     | min(hashed_at)  | max(hashed_at)
 -----------+----------+-----------+-----------------+----------------
 nas-1 |     8,580 | 2,290,057 | 2026-07-25      | 2026-07-25
 server-1 |     8,687 | 10,719,162| 2026-07-25      | 2026-07-25
 agent-1    |   158,285 |    380,102 | 2026-07-25      | 2026-07-25
```

**Interpretation:** Only 0.37% of the server, 0.04% of NAS, 41.6% of agent-1 have hashes. All hashes are from today
(cross-host candidate set ~23k rows; candidate set ~0.3% of the server, ~0.1% of agent-1). `first_hash == last_hash`
for every row. Bit-rot detection is **mathematically impossible** until a re-hash produces a **different result**.

---

## PART II: THE GAP — Why INFRA-126 Exists

### A. The Operator's Questions (What He Actually Cares About)

1. **"Am I actually backed up?"**  
   Per file, with evidence. Distinguish **hash-proven** vs **path-matched guess**. Today: partial answers via
   `diskaudit.backup_coverage` and `crosshost_verify.py`. Both are working but narrow (candidate sets << 100% of files).

2. **"What can I safely delete?"**  
   Hardlinks excluded. Load-bearing paths protected. Safe candidates reported via UI dedup/cleanup tabs.

3. **"Is anything rotting?"**  
   **Currently unanswerable.** That is INFRA-126.

4. **"How stale is my assurance?"**  
   Nothing tracks **the age of a verification**. INFRA-126 introduces `hashed_at` and `first_hash` to answer this.

### B. Why Hash Comparison Matters

**Hash match proves identity, not integrity.**  
If a file was corrupt when copied, both copies match and both are bad. Three-way verification requires:
- the server file hash: H₁
- NAS backup hash: H₂
- Third copy (restic snapshot) hash: H₃

If H₁ ≠ H₂ (mismatch over time), it's either:
- **Legitimate change** (file is mutable: chrome profile, sqlite DB, log file) — expected, not corruption
- **Corruption** (same mtime/size but different bytes) — undetected until re-hashed

Today only `mtime + size` distinguish them. INFRA-126 adds **time-series hashing** to detect bit-rot.

### C. The Defect Pattern Found

Measured on 2026-07-25:  
**3,110 files showed same-size/different-bytes across cross-host verification.**  
All 3,110 were **legitimate live-state drift**, not damage. But:
- Drift can mask corruption (if mutable file is also attacked/damaged, you won't know).
- **No baseline exists** to know which files are mutable by design vs unexpectedly drifting.

---

## PART III: HARD CONSTRAINTS (Non-Negotiable)

### Safety & Integrity

1. **HavnVard/diskaudit NEVER deletes, moves, renames, overwrites any scanned file, ever.**  
   Not via any API, shell, or filesystem call. Labels, reports, classification only. Delete is the operator's decision alone.
   Guard test exists: `test_no_forbidden_delete_move_primitives_anywhere` fails whole suite if violated.

2. **Hash match is identity proof, not integrity proof.**  
   Do not conflate. Baseline + re-check is needed to detect change.

3. **Orphan safety for remote jobs.**  
   If the local Python process dies, the remote `hash_batch.sh` on the NAS keeps running. Supervise and kill by name
   (`systemd-run --unit=`). Do NOT use `pkill -f` — it matches its own command line and self-kills.

4. **Resumable and idempotent.**  
   Re-hashing 2.7 TB at 50 MB/s is ~15-hour job. Must survive interruption and resume from `content_sha256 IS NULL`.

5. **Everything must fail LOUDLY.**  
   Silent failure is the recurring defect. Verification loop must stop running visibly, not quietly skip and report success.

### Performance & Resource Contention

6. **GPU/LLM contention is real and significant.**  
   Embedding + inference share one GPU. A burst of background work produced **two-hour total embedding blackout**
   (68% failure rate over 24h, impact on memory system). Any heavy background job must yield to the memory system.
   **HELM WaitingRoom is the gating mechanism:** memory work = P1 (never suspended); PRESCAB/cabinet = P2 (may suspend);
   non-critical batch = P3-P7 (suspended first).

7. **NAS `/tmp` is 64 MB tmpfs shared with live NAS system processes.**  
   Writing crawl output to `/tmp` causes real ENOSPC and destabilizes the NAS. Never write there. Use `/share/CACHEDEV1_DATA/.diskaudit_scratch` instead.

8. **Short transactions.**  
   A prior version held a SELECT open for 46 minutes, blocked vacuum on 13.4M-row table.
   All DB access must commit/rollback within seconds, before entering multi-hour remote work.

9. **Byte figures must be inode-deduped.**  
   `DISTINCT (host, inode)`, never raw row sums. Hardlinks skew naive totals by ~2×.

### Operational Constraints

10. **No passwordless sudo on the NAS for SMART/mdadm.**  
    NAS SSH is password-only via `sshpass`. Blocks unattended SMART queries. (Tracked: INFRA-116.)
    **Live RAID5 parity scrub exists** (monthly, `15 2 6 * * /sbin/storage_util --data_scrubbing raid_id=-1`).
    Parity scrub can detect and correct mismatches BUT cannot detect files corrupt before writing.

11. **Restic has its own integrity checks.**  
    Do not duplicate protection. Restic manifests already provide `[verification_state]`.

12. **Three-way trust is not available yet.**  
    Only the server + NAS + agent-1 exist. No third independent copy. Cannot yet prove "this copy is definitely bad."
    Until a third copy (or verified snapshot history from restic) exists, "mismatch" is inconclusive.

---

## PART IV: REQUIREMENTS FOR INFRA-126

### 4.1 Core Feature: Scheduled Re-Verification Loop

#### Requirement 1: Selection Policy (What to Hash, How Often)

**Cannot re-hash 2.7 TB nightly at 50 MB/s (~15h job).**  
Must define a **tiered selection strategy:**

- **Tier A (Fresh baseline):** Files hashed 0-7 days ago. These are recent + already cached in memory; cheap re-hash (likely no change).  
  **When:** Weekly (e.g., Wednesday nights when TechWatch is paused; INFRA-110 conflict exists).  
  **Why:** Validates baseline hasn't corrupted; detects immediate drift.

- **Tier B (Monthly assurance):** Files hashed 7-31 days ago. Broader set; verifies one month's worth.  
  **When:** Monthly (e.g., 6th of each month, off-peak hours).  
  **Why:** Regular rhythm; catches seasonal patterns.

- **Tier C (Annual archival):** Files hashed >90 days ago. Rare-access files.  
  **When:** Quarterly or annually (e.g., Jan/Apr/Jul/Oct).  
  **Why:** Cold-data integrity for files that haven't been verified yet.

- **Tier D (Mutable-file baseline):** Files known to change (SQLite, Chrome profile, `/var/log/*`).  
  **When:** After each change is detected, re-hash to update baseline.  
  **Why:** Establish expected-change baseline; detect corruption masquerading as legitimate drift.

- **Tier E (Critical patterns):** Load-bearing paths (systemd/cron/thoth.census).  
  **When:** After every load-bearing refresh (currently daily via `refresh_load_bearing_paths.py`).  
  **Why:** Rapid detection if critical infrastructure is tampered with.

**Acceptance Criterion:**  
Design doc specifies selection thresholds (e.g., "files from 7-31 days old this month") and explains the value trade-off vs resource cost. A simple `hashed_at` range query must be able to produce the next tier's candidate set without full-table scan.

#### Requirement 2: Assurance Age Transparency

**Owner must see how stale his verification is, per file + per host.**

- Add `days_since_first_hash` and `days_since_last_hash` computed columns to the UI + Grafana.
- Dashboard metric: **"% of files verified within last 30 days"** per host. Current: 0% (all hashes are today).
- Per-file export (CSV) must include `hashed_at`, `first_hash`, `last_hash`, `hash_mismatch_count`.
- TG PRESI daily report must include **"Verification SLA status"** (e.g., "the server: 42% verified within 30d, 95% within 90d; NAS: 0.4% within 30d").

**Acceptance Criterion:**  
A new user opening the UI can immediately see: "When was this file last hash-verified?" and "Is it overdue for re-check?"
without SQL.

#### Requirement 3: Divergence Handling (Mismatch Detection & Classification)

**A file's hash changed. Is it corruption or legitimate drift?**

**Distinguish:**
- **Legitimate change:** File is mutable by design (Chrome profile, SQLite DB, log file, Git worktree).
- **Corruption:** Same mtime/size, different bytes (impossible for an immutable file; suspicious for a mutable one).
- **Unclassified:** No previous baseline; cannot tell yet.

**Implementation:**

1. On re-hash mismatch, compute **mutable-file likelihood score:**
   - Path matches `/var/log/*` → 99% likely mutable
   - Path matches `*.sqlite` / `*.db` → 98% likely mutable
   - Owned by user (not system) → 70% likely mutable
   - mtime unchanged, size unchanged → 5% likely legitimate change (corruption signal)
   - mtime changed, size changed → 95% likely legitimate change

2. **Create four new tables:**
   ```
   diskaudit.hash_divergences (
     host, path, old_hash, new_hash, old_hashed_at, new_hashed_at,
     mtime_old, mtime_new, size_old, size_new,
     divergence_type ('legitimate_drift' | 'unconfirmed_corruption' | 'unclassified'),
     mutable_score (0-100),
     operator_verdict (NULL | 'benign' | 'suspicious' | 'confirmed_corruption'),
     escalated_to_tg (boolean),
     first_divergence_at,
     last_seen_divergence_at
   )
   
   diskaudit.mutable_file_registry (
     host, path_pattern, reason ('data_cache' | 'log' | 'sqlite' | 'chrome_profile' | ...),
     regex_or_literal (boolean)
   )
   
   diskaudit.corruption_suspects (
     host, path, first_divergence_at, mutable_score, operator_action (NULL | 'monitored' | 'isolated' | 'investigated'),
     notes
   )
   
   diskaudit.hash_verification_sla (
     host, tier ('A' | 'B' | 'C' | 'D' | 'E'),
     target_recheck_days (7 | 30 | 90 | custom),
     last_completed_at, next_scheduled_at, files_pending,
     critical_overdue_count
   )
   ```

3. **Alert rules:**
   - `mutable_score < 20 AND hash changed` → TG PRESI: **"[HOST] possible corruption: PATH"** + divergence details + 4-week history
   - `mutable_score > 80 AND hash changed` → Log entry only (expected drift), no TG alert
   - `operator_verdict = 'confirmed_corruption'` → Escalate to the operator inbox + Plane ticket HIGHEST

**Acceptance Criterion:**  
Run a test hash divergence (e.g., `echo zzz >> test.txt` on the server, re-hash, detect mismatch, classify as legitimate).
Verify that `legitimate_drift` is logged but NOT alerted, and `unconfirmed_corruption` IS alerted to TG PRESI with full context.

#### Requirement 4: Multi-Copy Decision Logic

**When a file has copies on multiple hosts + one copy's hash differs, which is truth?**

**Three-way comparison (if third copy exists via restic):**
- the server: H₁
- NAS: H₂
- Restic snapshot (from date X): H₃

Majority vote:
- If H₁ == H₂ ≠ H₃ → the server + NAS are in agreement; snapshot is stale. Flag snapshot for re-verification.
- If H₁ ≠ H₂ == H₃ → NAS + snapshot agree; the server is the divergence. Alert operator + add to `corruption_suspects`.
- If H₁ ≠ H₂ ≠ H₃ → Three-way split. Cannot resolve; escalate to the operator.

**Two-copy case (current):**
- the server ≠ NAS → Unresolvable; add to `corruption_suspects` with flag **"no third copy; operator must choose authoritative version"**.
- Mutable-file heuristic only partially helps.

**Acceptance Criterion:**  
Given a synthetic three-copy mismatch (the server/NAS/restic with hash values), the system correctly applies
majority-vote logic and sets the `operator_verdict` to the right state without requiring manual SQL.

#### Requirement 5: Alerting & Escalation

**Silent failure is the recurring defect. Verification loop must crash LOUDLY.**

**Alert on:**
1. **Stale verification** (no re-hash in >target_days for a tier):  
   TG PRESI: **"[HOST] [TIER-name] overdue: 42 of 50k critical files unverified >30 days. Last Tier-A run: 2026-07-12. Re-hash stalled?"**

2. **Hash job failure:**  
   - Crashed mid-run → `crosshost_verify_runs.status='failed'` → TG alert + add to Plane HIGHEST.
   - Orphaned remote process (NAS side) → Detected by heartbeat timeout → Alert + recovery instructions.

3. **Corruption suspects:**  
   - `mutable_score < 20 AND hash divergence` → TG: **"[HOST] possible corruption: [PATH]"** with 4-week trend.
   - Operator confirms corruption → Plane ticket HIGHEST + add to FERJA (separate delete-authorized component, v+1).

4. **Verification SLA miss:**  
   - Tier E (critical paths) overdue >1 day → Page (TG, urgent).
   - Tier A overdue >7 days → TG alert (non-urgent).
   - Tier B overdue >30 days → Grafana dashboard warning.

**Acceptance Criterion:**  
A hash job stops mid-run (simulated via process kill). Verify that: (1) `status='running'` row persists with stale `last_heartbeat_at`,
(2) TG PRESI receives an alert within 5 minutes (via `monitor.py` poll), (3) Operator can read the exact failure point from logs,
(4) Re-running the same command resumes from `content_sha256 IS NULL` (idempotent).

#### Requirement 6: Interaction with Monthly RAID Scrub & Restic

**Do not duplicate protection that already exists.**

**RAID parity scrub:**  
Detects + corrects parity mismatches at the disk level. Runs monthly on NAS (`15 2 6 * * /sbin/storage_util --data_scrubbing raid_id=-1`).
- Correlate: If RAID scrub runs on day 6th, delay Tier B hash verification until day 7 (let any parity repairs settle).
- Surface: RAID scrub results in Grafana + TG PRESI (INFRA-127 separate effort, tracked separately).

**Restic:**  
Restic's own manifest provides `[verification_state]` per backup snapshot. On every restic backup completion, extract
`verification_state` and populate `diskaudit.backup_verification_state` (new table):
```
restic_snapshot_id, host, verification_passed (bool), last_verified_at, corrupt_count
```
Restic verification is independent of this feature; no duplication. But correlate results in the three-way decision logic above.

**Acceptance Criterion:**  
Query shows: "RAID scrub completed 2026-07-06, 0 repairs. Tier B hash run 2026-07-07 checked 5M files; restic verified 42 snapshots; zero divergence across all three."

---

### 4.2 Explicitly Proposed Features (Not Currently Tracked — Mark `[PROPOSED]`)

#### `[PROPOSED]` Verification Trust Score Per File

Instead of binary "verified" / "unverified," compute a **trust score (0-100)** based on:
- Age of most recent verification (recent = higher trust)
- Number of times re-verified without divergence (consistent = higher trust)
- Mutable-file status (mutable files have lower inherent trust)
- Three-way copy agreement (all copies match = 100; two-of-three match = 70; split = 0)

Operator can sort backups + cleanup candidates by trust score (high trust = safe to delete).

**Rationale:** Bridges the "hash match is identity, not integrity" gap. A file verified 100 times with zero divergence
deserves more trust than a file verified once.

#### `[PROPOSED]` Predictive Drive Failure Correlation (Requires INFRA-116)

When NAS SMART data becomes available (INFRA-116 unblocks this), correlate drive sector errors with hash divergences:
- "Which files diverged on disk-1?" → Early warning of drive failure.
- Alert pattern: "drive-2 sector-error count increasing; 47 files on drive-2 have divergences. Consider replacing drive-2."

**Rationale:** Bit-rot often precedes full-disk failure by weeks. Correlation + early detection saves one full-disk loss.

#### `[PROPOSED]` Automated Remediation (v+1, requires FERJA)

Once a third copy exists (restic snapshot or offsite backup), and a mismatch is confirmed:
- **Candidate recommendation:** "File is corrupt on the server; NAS copy is valid (hash-proven); restore from NAS?"
- **Operator approval:** the operator reads recommendation, explicitly types "approve: <snapshot-id> <path>" to authorize.
- **Execution:** FERJA (separate component) reads approval, restores NAS → the server, re-hashes to confirm.

**Rationale:** Three-way majority vote + FERJA isolation = safe automated cleanup without risking accidental data loss.

#### `[PROPOSED]` Continuous Low-Priority Background Verification

Instead of scheduled tiers, run a low-priority background job that continuously re-hashes files at a fixed bandwidth
(e.g., 2 MB/s, ~10% of NAS's sustained capacity), never blocking critical work. Timer-based tiers still serve as "fast
assurance" for urgent categories.

**Rationale:** Spreads cost over time; improves coverage cadence from "monthly" to "continuous."

#### `[PROPOSED]` Multi-Share NAS Scheduling Stagger

NAS has 10 shares. Schedule them to never overlap + not collide with TechWatch (INFRA-110):
- Week 1: Public share
- Week 2: homes share
- Week 3: Download share
- … etc, on a 10-week rotation.

**Rationale:** Avoids contention on the single NAS; keeps crawl + hash work distributed.

---

### 4.3 V+1 Stubs (Depend on v1 existing)

#### V+1A: Automated Remediation from Known-Good Copy (FERJA integration)

**Problem:** Corruption is confirmed but unfixable today (operator reads report, manually restores).  
**Solution:** Once majority-vote determines authoritative copy, FERJA restores + re-hashes to validate.  
**Acceptance:** Operator approves a corruption-confirmed file; FERJA restores + re-hashes; backup_coverage classification updates to `BACKED_UP_VERIFIED`.

#### V+1B: Snapshot Strategy (INFRA-115)

**Problem:** No QNAP snapshots configured; RAID protects disk failure, not deletion/ransomware/corruption.  
**Solution:** Enable QNAP snapshots; verify periodic snapshot verification runs via corruption-detection tools.  
**Acceptance:** Monthly snapshot + hash-verify snapshot against live files; divergences logged.

#### V+1C: Checksumming Filesystem (Defer Until Hardware Upgrade)

**Problem:** ext4 has no checksums; bit-rot is silent at the filesystem level.  
**Solution:** Migrate to btrfs/ZFS (requires full-disk re-initialize; too risky in current operational phase).  
**Acceptance Criterion:** Phase 3 roadmap; hardware+team capacity.

#### V+1D: Offsite Third Copy (INFRA-76 + INFRA-96)

**Problem:** Only local copies (the server + NAS). Ransomware/correlated failure kills all.  
**Solution:** Push encrypted NAS snapshots to cloud backup (S3 / Backblaze / etc.) weekly.  
**Acceptance:** Third copy offline; hash-verify quarterly; majority-vote no longer inconclusive.

#### V+1E: Policy-Driven Retention Tied to Verification State

**Problem:** INFRA-124 failure: old backup tarballs don't auto-delete (silent retention-policy breakage).  
**Solution:** Tie retention rules to verification state: only delete tarballs confirmed 3-way-verified.  
**Acceptance:** Policy engine queries latest `hash_divergences` + `backup_verification_state`; enforce via systemd timer.

---

### 4.4 V+2 Stubs (Further-horizon)

#### V+2A: Continuous Verification as Background Service

Move from timer-based tiers to a daemon that continuously re-hashes at configurable bandwidth, reporting live progress to Grafana.

#### V+2B: Multi-Device Coverage (INFRA-114)

Client agents on Windows/iOS/Android, each uploading file metadata + optional content hashes to central Postgres.

#### V+2C: Abandoned Software Detection (Original Differentiator)

Detect files/dirs that are orphaned specifically because a module was decommissioned (a deprecated app's archive,
a removed user's home, etc.), not just "large and cold."

---

## PART V: ACCEPTANCE CRITERIA (Testable by Engineer on Machine)

### A. Core INFRA-126 Acceptance (v1)

1. **Selection Policy & Tier System:**
   - [ ] Query `SELECT * FROM diskaudit.hash_verification_sla` returns four rows (Tiers A/B/C/E).
   - [ ] Each tier specifies `target_recheck_days` and `last_completed_at`.
   - [ ] Query to find next-tier candidates returns <200k rows (tractable batch size).

2. **Assurance Age Transparency:**
   - [ ] Grafana dashboard shows **"% verified within last 30d"** per host. Current: 0%.
   - [ ] UI (dedup/cleanup/backup tabs) displays `hashed_at` + `days_since_hash` per file.
   - [ ] Daily TG PRESI report includes **"Verification SLA"** line (e.g., "the server 42% within 30d").

3. **Divergence Detection & Classification:**
   - [ ] Run synthetic test: `echo modified >> /tmp/test-file-immutable`, re-hash, verify mismatch logged.
   - [ ] `hash_divergences` row created with `mutable_score < 30` → Alert sent to TG PRESI.
   - [ ] `mutable_score > 80` (e.g., `/var/log` file) → No TG alert, logged only.
   - [ ] Four tables exist: `hash_divergences`, `mutable_file_registry`, `corruption_suspects`, `hash_verification_sla`.

4. **Multi-Copy Decision Logic:**
   - [ ] Three-copy test case: the server H₁, NAS H₂ ≠ H₁, restic H₃ = H₂ → System sets `operator_verdict='investigate_spark'`.
   - [ ] Two-copy case: H₁ ≠ H₂ → Creates `corruption_suspects` row, no auto-resolution.

5. **Alerting & Escalation:**
   - [ ] Tier A verification >7 days overdue → TG PRESI alert within 5 min (via monitor.py).
   - [ ] Hash job crashes mid-run → `status='failed'` in `crosshost_verify_runs` + TG alert.
   - [ ] Orphaned remote process on NAS → Detected by heartbeat timeout, alert + recovery steps.

6. **Idempotency & Resumability:**
   - [ ] Kill hash job mid-run, re-run same command → Resumes from `content_sha256 IS NULL`.
   - [ ] Re-running `match` command twice produces identical `integrity_checks` rows (idempotent).

---

### B. Metrics & Reporting (v1)

1. **Daily TG PRESI Report Must Include:**
   - [ ] Verification SLA status line
   - [ ] Corruption suspects count (if any)
   - [ ] Files overdue for re-verification (by tier + by host)
   - [ ] Example: `"the server Tier-A 40% verified. Tier-B 8% verified (0 files since 2026-07-01; OVERDUE). NAS 0% (crawl in progress)."`

2. **Grafana Dashboard (`:9452/d/diskaudit/diskaudit`):**
   - [ ] Panel: **"Verification age (days)"** stacked bar chart per host, bucketed 0-7d / 7-30d / 30-90d / 90+d.
   - [ ] Panel: **"Corruption suspects this month"** with severity badges.
   - [ ] Panel: **"SLA attainment"** — Tier A/B/C/E % on-time vs overdue.
   - [ ] Panel: **"Hash divergences by mutable score"** — scatter plot to spot unexpected mutable files.

3. **UI Export (dedup/cleanup/backup tabs):**
   - [ ] CSV export includes: `hashed_at`, `hash_age_days`, `mutable_score`, `divergence_count_4w`.
   - [ ] Columns are sortable in UI; no need for SQL.

---

### C. Edge Cases & Failure Modes (v1)

1. **When NAS is Slow/Unresponsive:**
   - [ ] `hash_batch.sh` timeout (20 min) → Local process cancels + logs reason → Resume next run.
   - [ ] Orphaned remote process detected → Alert + `ps w | grep hash_batch` recovery step documented.

2. **When a File Becomes Unreadable:**
   - [ ] `content_sha256 IS NULL`, `hashed_at = <timestamp>`, `hash_source='error'` → Logged, not failed.
   - [ ] Later scan finds file readable → Retry succeeds.

3. **When a File is Deleted Between Scans:**
   - [ ] `diskaudit.files.still_exists=false` → Skipped during re-hash (cannot re-hash nonexistent file).
   - [ ] `divergence` table ignores it.

4. **When GPU Contention Blocks Hash Job:**
   - [ ] Job pauses, logs reason ("GPU >50% busy, yielding") → Retries every 30s until free.
   - [ ] TG alert only if >30 min of blocked time (not every pause).

5. **When RAID Parity Scrub Runs Simultaneously:**
   - [ ] Hash job detects RAID scrub in progress (e.g., via NAS CPU load) → Delays start until scrub completes.
   - [ ] Or: schedule hash runs to never overlap with known RAID scrub window.

---

## PART VI: DEPENDENCIES & IMPLEMENTATION ORDER

### Build Order (v1)

1. **Migrate new tables** (`hash_divergences`, `mutable_file_registry`, `corruption_suspects`, `hash_verification_sla`).
2. **Compute mutable-file likelihood heuristic** (path matching + mtime/size drift analysis).
3. **Build Tier A (Fresh Baseline) selector** — query `hashed_at BETWEEN now()-7d AND now()`.
4. **Implement single-tier re-hash job** (leverage existing `hash_batch.sh` + `crosshost_verify.py` patterns).
5. **Implement divergence detection** — compare new hash against stored `content_sha256`; classify drift.
6. **Implement multi-copy decision logic** — two-copy (the server ↔ NAS) and three-copy (+ restic) cases.
7. **Implement alerting** — TG PRESI for overdue/corruption/failed runs.
8. **Implement Grafana panels** — 4 new panels (age distribution, SLA attainment, corruption suspects, divergence scatter).
9. **Update daily PRESI report** — add SLA status line + corruption count.
10. **Extend UI** — add `hashed_at` + `days_since_hash` to dedup/cleanup/backup tabs.
11. **Document + test** — runbook + pytest suite covering tier selection, divergence classification, alerting.

### Dependencies on Other Tickets

- **INFRA-127:** RAID scrub reporting (timing + result correlation). **Not blocking:** can stagger runs manually initially.
- **INFRA-116:** NAS passwordless sudo (SMART data). **Not blocking:** optional for v+1 predictive drive failure.
- **INFRA-76 / INFRA-96:** Offsite backup. **Not blocking:** two-copy decision logic works today.
- **INFRA-110:** TechWatch schedule (GPU contention). **Blocking timing only:** Tier A must schedule around TechWatch if HELM contention exists.

---

## PART VII: RISK REGISTER

| Risk | Severity | Mitigation | Owner |
|------|----------|-----------|-------|
| **Re-hash job orphans remote process on NAS, accumulates over weeks, fills disk** | HIGH | Heartbeat-based process supervision + documented `ps w` recovery. Operator runs cleanup weekly. | Implementation |
| **Mutable-file heuristic misclassifies a critical immutable file as "drift ok"** | MEDIUM | Whitelist/blacklist + operator review of divergences before auto-closing. | Design + testing |
| **Tier A runs weekly but clashes with TechWatch, starving memory system** | MEDIUM | Stagger schedule (e.g., Tuesday nights) or implement low-priority yielding via HELM WaitingRoom. | Scheduling + HELM integration |
| **All three copies diverge (the server ≠ NAS ≠ restic); operator cannot resolve** | MEDIUM | Escalate to Plane HIGHEST + note timestamps/hashes. No auto-resolution in this case. | Design |
| **Silent test failure: "verification loop ran but found no divergences" (too narrow candidate set)** | MEDIUM | Validation: run against known-modified file; verify divergence detected within one test cycle. | Testing |
| **Transient NAS timeout causes false "corruption suspected" alert; operator wastes time investigating** | LOW | Alert only after 3 consecutive failed re-hash attempts (idempotent); include "verify NAS reachable" in alert body. | Implementation |
| **Database bloat from `hash_divergences` growing unbounded** | LOW | Retention policy: archive divergences >1 year old to separate table monthly. | Implementation |

---

## PART VIII: COST MODEL (Resource Estimate)

### NAS Throughput & Time

| Tier | Files (est.) | Total bytes | @ 50 MB/s | Window | Overlap Risk |
|------|------|---|---|---|---|
| **Tier A (Fresh, 0-7d)** | 10k | 20 GB | 7 min | Weekly | 0% (non-overlapping) |
| **Tier B (Monthly, 7-31d)** | 100k | 250 GB | 85 min | Monthly (once) | 0% if scheduled off-peak |
| **Tier C (Quarterly, >90d)** | 500k | 1.2 TB | 6.8 h | Quarterly | 0% if scheduled off-peak |
| **Tier D (Mutable baseline update)** | 5k | 5 GB | 2 min | After each divergence | On-demand, low cost |
| **Tier E (Critical paths)** | 500 | 100 MB | 2 sec | After load-bearing refresh | Low cost |

### GPU/HELM Impact

- **Tier A (7 min/week):** Negligible (0.2% of weekly budget).
- **Tier B (85 min/month):** Run off-peak; if collides with TechWatch, HELM WaitingRoom queues hash job at P3.
- **Tier C (6.8 h/quarter):** Schedule outside business hours (e.g., Sunday 02:00).

### Postgres Impact

- **DB write rate:** ~100 rows/sec during match phase. Peak: 10k rows/min during divergence insert.
- **Vacuum impact:** Incremental divergence inserts are low-churn; no blocking concern.
- **Long transactions:** Explicitly kept <5 sec; no vacuum blocking risk.

---

## PART IX: RELATED PLANE ITEMS CONSOLIDATED

### Core INFRA-126 Cluster (5 items)

- **INFRA-126** [low] Scheduled periodic re-hashing for bit-rot detection ← **Your target**
- **INFRA-127** [low] NAS-side scheduled integrity scrub report — surface QNAP RAID scrub into HavnVard/Grafana
- **INFRA-125** [medium] Per-share used-vs-total capacity reporting (needs provisioning-size source)
- **INFRA-128** [medium] Precise per-share `du` totals — BusyBox `du` over SSH times out on large shares

### Integrity & Backup Risk (8 items)

- **INFRA-134** [urgent] No backup coverage for ChromaDB vector stores — MUNINN's was **unrecoverable** ← requires verification strategy
- **INFRA-115** [high] No QNAP snapshots configured — zero protection vs deletion/corruption/ransomware
- **INFRA-116** [high] NAS SSH password-only, no passwordless sudo — blocks unattended SMART/mdadm
- **INFRA-117** [high] `bkup_server` partially stale — 6 restic repos untouched since 2026-07-19, legacy rotation stopped April
- **INFRA-96** [urgent] Offsite NAS replication down ~1 day — DB backups local-only
- **INFRA-76** [urgent] Comprehensive off-machine backup coverage (local-only paths/devices)
- **INFRA-124** [high] Weekly CRM backup retention silently broken — 15 tarballs survived a keep-12 policy
- **INFRA-57** [urgent] / **INFRA-92** [medium] Local-only repos with no remote (backup gap)

### Duplication & Backup-Job Root Cause (2 items — same defect, filed twice)

- **INFRA-136** [high] NAS backup job re-copies unchanged files nightly instead of hardlinking — 213 GB, silently regrows
- **INFRA-102** [urgent] `paperclip-instance.tar.gz` duplicated 14× across daily backups (15 GB) — **same root cause, filed 2026-07-18**

### HavnVard Platform (16 items)

- **INFRA-97** [high] whole-disk file inventory (v1 log-only; v2 dedup) — main tracker
- **INFRA-111** [urgent] Templated per-device scan pattern to kick off all devices at once
- **INFRA-112** [medium] Files-not-backed-up-yet report
- **INFRA-113** [medium] Duplicate-files report
- **INFRA-105** [urgent] Grafana dashboard for disk/file storage
- **INFRA-101** [medium] diskaudit Grafana UI/UX overhaul
- **INFRA-98** [medium] Timestamped progress checkpoints for hang detection
- **INFRA-99** [low] Deferred hang-detection/monitoring upgrades (v3 candidates)
- **INFRA-108** [urgent] 2 of 8 recent NAS-crawl runs failed — reliability
- **INFRA-107** [urgent] NAS-crawl cadence mismatch caused `v_backup_coverage` false negatives
- **INFRA-109** [urgent] Phase 2: migrate remaining backup targets to restic
- **INFRA-110** [urgent] TechWatch enrich runs ~9 h daily, collides with `havnvard-nas-crawl.timer`
- **INFRA-114** [low] Multi-platform coverage — Windows/iOS/Android (owner-deferred)

### Adjacent (3 items)

- **INFRA-131** [urgent] MUNINN search returned 0 results for 28 days (repaired)
- **INFRA-119** [high] `muninn.item_embeddings` empty despite 13,718 chunks
- **MONITOR-36** [urgent] Rotate `diskaudit_agent` Postgres password (exposed in transcript)

### Observation

**Pattern in INFRA-102 vs INFRA-136:** Same defect filed twice a week apart. This is why INFRA-126 must include
**correlation logic**: dedup + correlate findings across runs so a single root cause doesn't spawn duplicate tickets.

---

## PART X: SUCCESS CRITERIA (6 Months Post-Launch)

1. **Verification SLA met consistently:** 90%+ of Tier A files re-verified within 7d, 80%+ of Tier B within 30d, 50%+ of Tier C within 90d.
2. **Corruption detected in time:** Any bit-rot on NAS is detected within 30 days (before second backup cycle). Zero cases of "file was corrupt for months undetected."
3. **Mutable-file baseline stable:** <5% of divergences are unexpected drifts (99% are legitimate or already classified).
4. **Operator confidence:** Daily TG PRESI report is trusted as true (no false "everything is verified" claims when 0% is actually verified).
5. **No orphaned processes:** Weekly audit shows <1 orphaned `hash_batch.sh` per month (acceptable churn from kills).
6. **INFRA-124-type failures prevented:** Retention policies tied to verification state, no silent policy drift.

---

## APPENDIX A: Schema Additions (Migration Template)

```sql
-- 20260726_infra_126_bitrot_verification_v1.sql

BEGIN;

-- Tier + SLA tracking
CREATE TABLE diskaudit.hash_verification_sla (
  sla_id SERIAL PRIMARY KEY,
  host TEXT NOT NULL,
  tier CHAR(1) NOT NULL CHECK (tier IN ('A','B','C','D','E')),
  target_recheck_days INT NOT NULL,
  last_completed_at TIMESTAMPTZ,
  next_scheduled_at TIMESTAMPTZ,
  files_pending BIGINT DEFAULT 0,
  critical_overdue_count BIGINT DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host, tier)
);

-- Hash divergence log (append-only)
CREATE TABLE diskaudit.hash_divergences (
  divergence_id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  old_hash CHAR(64),
  new_hash CHAR(64) NOT NULL,
  old_hashed_at TIMESTAMPTZ,
  new_hashed_at TIMESTAMPTZ NOT NULL,
  mtime_old BIGINT,
  mtime_new BIGINT,
  size_old BIGINT,
  size_new BIGINT,
  divergence_type TEXT NOT NULL CHECK (divergence_type IN ('legitimate_drift', 'unconfirmed_corruption', 'unclassified')),
  mutable_score SMALLINT CHECK (mutable_score BETWEEN 0 AND 100),
  operator_verdict TEXT CHECK (operator_verdict IN ('benign', 'suspicious', 'confirmed_corruption', NULL)),
  escalated_to_tg BOOLEAN DEFAULT FALSE,
  first_divergence_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_divergence_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host, path, old_hash, new_hash, new_hashed_at)
);
CREATE INDEX idx_hash_divergences_unresolved 
  ON diskaudit.hash_divergences(host, divergence_type, created_at DESC)
  WHERE operator_verdict IS NULL;

-- Mutable file registry
CREATE TABLE diskaudit.mutable_file_registry (
  registry_id SERIAL PRIMARY KEY,
  host TEXT,  -- NULL = global pattern
  path_pattern TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('data_cache', 'log', 'sqlite', 'chrome_profile', 'git_worktree', 'system_cache', 'temp', 'other')),
  regex_or_literal BOOLEAN NOT NULL DEFAULT FALSE,
  created_by TEXT DEFAULT 'SYSTEM',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host, path_pattern, reason)
);

-- Corruption suspects
CREATE TABLE diskaudit.corruption_suspects (
  suspect_id BIGSERIAL PRIMARY KEY,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  first_divergence_at TIMESTAMPTZ NOT NULL,
  mutable_score SMALLINT,
  operator_action TEXT CHECK (operator_action IN ('monitored', 'isolated', 'investigated', NULL)),
  suspected_since TIMESTAMPTZ NOT NULL DEFAULT now(),
  escalated_to_plane BOOLEAN DEFAULT FALSE,
  plane_ticket_id TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(host, path)
);

-- Add columns to diskaudit.files (additive only)
ALTER TABLE diskaudit.files 
  ADD COLUMN IF NOT EXISTS first_hash CHAR(64),
  ADD COLUMN IF NOT EXISTS hash_divergence_count SMALLINT DEFAULT 0;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_files_content_sha256_null 
  ON diskaudit.files(host, path) WHERE content_sha256 IS NULL;
CREATE INDEX IF NOT EXISTS idx_files_hashed_at_range 
  ON diskaudit.files(host, hashed_at DESC) INCLUDE (path, content_sha256, size_bytes);

COMMIT;
```

---

## APPENDIX B: Runbook Skeleton

**Filename:** `/home/user/runbooks/20260726-infra-126-bitrot-verification/RUNBOOK.md`

### Manual Tier A Hash Run

```bash
cd /opt/havnvard && source .venv/bin/activate
python tier_a_verify.py --host server-1 --test-mode
python tier_a_verify.py --host server-1
python tier_a_verify.py --host nas-1  # ~7 min
```

### Health Check

```bash
psql "$POSTGRES_URL" -c "SELECT host, tier, last_completed_at, files_pending, critical_overdue_count FROM diskaudit.hash_verification_sla ORDER BY host, tier;"
psql "$POSTGRES_URL" -c "SELECT count(*), divergence_type FROM diskaudit.hash_divergences GROUP BY divergence_type;"
psql "$POSTGRES_URL" -c "SELECT host, path, mutable_score, operator_verdict FROM diskaudit.corruption_suspects WHERE operator_verdict IS NULL LIMIT 10;"
```

---

## APPENDIX C: Test Suite Outline

```python
# tests/test_infra_126_bitrot.py

class TestTierSelection:
  def test_tier_a_selects_0_to_7_days(): ...
  def test_tier_b_selects_7_to_31_days(): ...
  def test_tier_c_selects_over_90_days(): ...
  def test_tier_e_critical_paths_after_load_bearing_refresh(): ...

class TestDivergenceDetection:
  def test_hash_mismatch_creates_divergence_row(): ...
  def test_mutable_score_heuristic_classifies_correctly(): ...
  def test_unconfirmed_corruption_alerts_tg(): ...
  def test_legitimate_drift_logs_no_alert(): ...

class TestMultiCopyLogic:
  def test_three_way_majority_vote_spark_nas_restic(): ...
  def test_two_way_unresolvable_flags_corruption_suspects(): ...

class TestAlertingAndEscalation:
  def test_overdue_verification_sla_alerts_tg(): ...
  def test_hash_job_failure_creates_plane_ticket(): ...
  def test_orphaned_remote_process_detected_by_heartbeat(): ...

class TestIdempotency:
  def test_rerun_same_tier_idempotent(): ...
  def test_resume_from_null_content_sha256(): ...
```

---

## SUMMARY

**INFRA-126 transforms HavnVard from a one-shot "inventory + snapshot" system into a standing assurance loop.**

**What changes:**
- Baseline hashes (today) become starting points, not endpoints.
- Periodic re-verification (weekly Tier A → quarterly Tier C) detects divergence over time.
- Divergence classification (drift vs corruption) + multi-copy logic answer "which copy is truth?"
- SLA tracking + alerting ensure verification stays current and corruption surfaces quickly.

**What stays the same:**
- HavnVard never deletes/moves/overwrites files (still labels/reports only).
- Cross-host dedup + backup-coverage classification remain intact.
- Restic + RAID parity scrub integrate without duplication.

**For ChatGPT or implementation engineer:**
This spec is your source of truth. Tables, queries, alerting logic, acceptance criteria, and test cases are all here.
Start with the build order (Part VI); stop when acceptance criteria (Part V) are met.

---

**End of Specification**

---

**Generated by Claude Code on 2026-07-25.  
Repo: `/opt/havnvard` + `/home/user/runbooks/`.  
Related memory: `[[project_havnvard_build]]`, `[[feedback_havnvard_never_autodelete]]`.  
For questions: Refer to the 45 Plane items consolidated in Part IX, or the existing runbooks under `/home/user/runbooks/20260725-*`.
