# RUNBOOK — HavnVard (technical/module name: diskaudit)

**Last updated: 2026-07-25**

## ⚠️ ABSOLUTE CONSTRAINT — READ FIRST

**HavnVard/diskaudit NEVER deletes, moves, or overwrites any scanned file. It only
produces labels, reports, and classifications.** Every delete/move decision stays
with the operator — the tool itself never auto-deletes or auto-moves anything,
on the server, on the NAS, or on any client. Every script in this repo (`scan.py`,
`dedup.py`, `load_nas_inventory.py`, `crosshost_verify.py`, etc.) is read-only
with respect to the files it scans; the only writes are into the `diskaudit`
Postgres schema, this repo's own log/report output, and (for the restic
sub-system) restic's own backup repositories — never into the scanned trees
themselves. If you ever see a feature described in a way that sounds like
"cleanup" or "delete candidates," it means **advisory label only** — confirmed
throughout this doc and in FEATURES.md.

---

## Purpose

Whole-disk file inventory, cross-host (real, cryptographic SHA-256) duplicate
detection, backup-coverage cross-check, and file-status classification
(active / load-bearing / stale / possibly-obsolete / orphaned) across
**server-1, nas-1 (NAS), and any onboarded client host (e.g. `agent-1`)**
— purely advisory, log-only. See `README.md` in this repo for full architecture
and file-by-file description (not duplicated here).

## Scope

- Hosts currently reporting into `diskaudit.files` (live, confirmed 2026-07-25):
  `server-1` (10,719,162 rows), `nas-1` (2,290,057 rows), `agent-1`
  (380,102 rows). Total: 13,389,321 rows.
- Server = the server (`server-1`): owns the Postgres schema, dedup engine, NAS
  SSH-crawl orchestration, monitor, PRESCAB weekly review, TG PRESI daily
  report, Grafana dashboard, and (new, Phase 2) the restic backup engine for
  9 other the server app directories.
- Clients (e.g. `agent-1`) run `scan.py` locally on their own timer and write
  directly to the central Postgres over Tailscale (see `CLIENT_INSTALL.md`).

## Entry points

| Script | Role |
|---|---|
| `scan.py` | Local whole-disk metadata crawl (this host) |
| `nas_native_crawl.sh` + `load_nas_inventory.py` | NAS crawl (runs natively on NAS via SSH; ~1,450x faster than mounting) |
| `run_all_nas_shares.sh` | Loops `load_nas_inventory.py` across all known NAS shares |
| `dedup.py` (+ `bucketing.py`) | rdfind-based duplicate detection, writes `duplicate_group_id` |
| `crosshost_verify.py` | **New, 2026-07-25, in active development on this branch** — cross-host SHA-256 content verification (candidates/hash/match/report subcommands); answers "is my the server/agent-1 data really backed up on the NAS" without needing rdfind's local-filesystem access. Non-destructive; writes only `content_sha256`/`hashed_at`/`hash_source` on `diskaudit.files` plus its own `diskaudit.integrity_checks` / `diskaudit.crosshost_verify_runs` rows. Treat as **PARTIAL** until this branch merges — CLI surface may still change. |
| `hash_batch.sh` | Companion shell helper for `crosshost_verify.py` batch hashing (unmodified) |
| `hash_stat_batch.sh` | Companion shell helper for `nas_trigkey_dedup.py` (1.4.0): digest + stat before/after, stat-only lines, `#DONE` trailer |
| `backup_coverage.py` | **New, 2026-07-25** — TRUE backup-coverage classifier: every in-scope server-1/agent-1 file gets exactly one row in `diskaudit.backup_coverage` (`BACKED_UP_VERIFIED` / `BACKED_UP_UNVERIFIED` / `NOT_BACKED_UP` / `EXCLUDED`), vs. `v_backup_coverage`'s critical_patterns-only scope or `crosshost_verify.py`'s <1%-of-files size-candidate scope. Subcommands `classify` / `verify` (cheap promotion, no new hashing) / `report` (ranked markdown). Scope exclusions are data, not code — see `diskaudit.backup_scope_rules`. Runbook: `/home/user/runbooks/20260725-havnvard-backup-coverage/RUNBOOK.md`. |
| `nas_trigkey_dedup.py` | Within-host duplicate detection for nas-1 and agent-1 (rdfind can't run on either host). **Rewritten in 1.4.0** (see "NAS within-host dedup" below): stat-bound digests, scoped runs, fail-loud transport, one-transaction publish into an immutable per-run snapshot. Tracked via `diskaudit.dedup_runs`, `dedup_tool='sha256-within-host'`. Reuses `crosshost_verify.py`'s remote transport; uses its own `hash_stat_batch.sh` and `nas_dedup_core.py`. |
| `heartbeat.py` | Shared heartbeat helpers used by scan/dedup/NAS-load/crosshost jobs |
| `scan_guard.py` | 1.4.3: per-(host, root) scan advisory lock + per-scan staging cleanup (scan.py, load_nas_inventory.py) |
| `monitor.py` | Every-5-min stale/failed run monitor → TG PRESI alert |
| `refresh_load_bearing_paths.py` | Builds the load-bearing override (protects cold-but-live infra files from misclassification) |
| `refresh_classification_mv.py` | Refreshes `diskaudit.mv_file_status` (the classification view). **No argparse — running it with ANY argument, including `--help`, immediately executes the full `REFRESH MATERIALIZED VIEW CONCURRENTLY` (≈6 min against the current 13M-row table). It is safe (read-only against scanned files, idempotent) but not obviously so from the CLI — do not assume `--help` is free.** |
| `weekly_prescab_review.py` | Weekly PRESCAB (VP-Operations, logic_governance) operational review, logs to `jobs.cabinet_runs` |
| `havnvard_report.py` | Daily metadata report + optional PRESCAB analysis (`--analyze`) to TG PRESI, persists `diskaudit.report_snapshots` for day-over-day deltas |
| `backup_heartbeat_cli.py` | CLI used by the restic wrapper scripts (`/srv/apps/backup/restic-*.sh`) to record start/finish into `diskaudit.backup_runs` |
| `refresh_classification_mv.py`, `refresh_load_bearing_paths.py` | see classification layer above |

## Start / stop / restart

All `diskaudit-*` and `havnvard-*` systemd units are **root-owned system units**
under `/etc/systemd/system/` (`User=root` in `[Service]`, `Type=oneshot`) — this
is **not** a svc user-unit app. Use plain `sudo systemctl`, never the
`sudo -u svc XDG_RUNTIME_DIR=... systemctl --user` pattern used for
other user-unit services.

```bash
# Check what's scheduled (confirm live)
systemctl list-timers --all | grep -E 'diskaudit|havnvard'

# Manual one-off run of any stage (all are oneshot services, safe to run ad hoc)
sudo systemctl start diskaudit-scan.service              # full the server scan
sudo systemctl start diskaudit-nas-crawl.service          # full NAS crawl (all shares)
sudo systemctl start diskaudit-monitor.service            # stale/failed run check now
sudo systemctl start diskaudit-load-bearing-refresh.service
sudo systemctl start diskaudit-classification-refresh.service
sudo systemctl start diskaudit-prescab-review.service
sudo systemctl start havnvard-presi-report.service        # daily TG report now (User=havnvard, not root)

# Restic backup targets (Phase 2, LIVE — see INFRASTRUCTURE section)
sudo systemctl start havnvard-restic-<target>.service
# (3.2.0: the -retention timers are disabled; never start them, they delete without the owner's order)

# Enable/disable a timer (rare — these are meant to stay enabled)
sudo systemctl disable --now diskaudit-scan.timer
sudo systemctl enable --now diskaudit-scan.timer

# Direct script invocation (bypasses systemd, same effect)
cd /opt/havnvard && source .venv/bin/activate
python scan.py --dry-run --root /home/user      # cheap bounded validation run
sudo .venv/bin/python scan.py                      # full real run (needs root for cross-user read)
```

Note: `havnvard-presi-report.service` runs as **`User=havnvard`**, not root
(it only reads Postgres + posts to Telegram, no filesystem crawl) — the one
exception to the "all root" pattern above.

## Health checks

```bash
# Any run currently stuck "running"? (monitor.py alerts on this every 5 min, but check directly)
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select scan_id, host, status, started_at, last_heartbeat_at from diskaudit.scan_runs where status='running';"

# Last completed scan per host (freshness)
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select host, max(finished_at) from diskaudit.scan_runs where status='completed' group by host;"

# Recent backup_runs (restic Phase 2)
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select backup_job, host, status, started_at, finished_at from diskaudit.backup_runs order by started_at desc limit 12;"

# Timers actually active (don't trust static docs — confirm live)
systemctl list-timers --all | grep -E 'diskaudit|havnvard'

# journal for a given unit
journalctl -u diskaudit-scan.service --since "1 day ago"
journalctl -u havnvard-restic-app-e.service -n 100
```

Grafana dashboard: **`https://server-1.example.ts.net:9452/d/diskaudit/diskaudit`**
(Tailnet-only, HTTPS-only — port 9452 is Grafana; **do not confuse with :9446**,
which is the operator's unrelated custom "Prometheus" control-plane app, not this dashboard).

## Log locations

- **Primary**: `journalctl -u <unit>` — every `diskaudit-*` and `havnvard-*`
  systemd service is `StandardOutput=journal` / `StandardError=journal`. This
  is the log SoT for nearly everything.
- File-based: `/opt/havnvard/logs/weekly_prescab_review.log` (only
  file-based log found in this repo; everything else goes to the journal).
- `.gitignore`'d runtime dirs (never committed, don't expect them populated
  outside a live run): `logs/`, `nas_inbox/` (SSH/rsync scratch area for the
  NAS crawl — `_nas_etc` subdir holds the NAS's own copied `/etc/passwd`,`/etc/group`
  for uid/gid resolution), `data/`, `exports/`, `tmp/`.
- Restic wrapper script logs: check the individual `/srv/apps/backup/restic-*.sh`
  scripts' own logging (they're a separate small repo, `/srv/apps/backup/`,
  git-owned by group `uo-ai`) — journal is still the primary source since they
  run as systemd oneshot services too.

## DB checks

Schema `diskaudit` in database `havnvard` (Postgres, `127.0.0.1:5432`).
Credentials SoT: `/etc/havnvard/havnvard.env` → `POSTGRES_URL` (never inline
the password in this file or any log).

18 tables, 7 views (confirmed live 2026-07-25):

```
Tables: backup_runs, classification_config, critical_patterns,
        crosshost_verify_runs*, decommissioned_path_patterns, dedup_runs,
        dedup_staging, dedup_worker_status, files, files_staging,
        git_repo_roots, integrity_checks*, load_bearing_paths,
        load_bearing_refresh_runs, report_snapshots, run_heartbeats,
        scan_errors, scan_runs
        (* = new 2026-07-25, crosshost integrity work, still in flight)

Views:  v_backup_coverage, v_critical_files, v_duplicate_groups,
        v_duplicate_groups_by_host, v_file_status, v_git_tracked_recency,
        v_nas_orphans (original deployment only; not in schema/baseline.sql)
```

```bash
# Row counts by host
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select host, count(*) from diskaudit.files group by host;"

# Classification MV freshness/size
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select count(*) from diskaudit.mv_file_status;"

# Duplicate groups + CORRECTLY inode-deduped reclaimable space
PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
  "select count(*), sum(reclaimable_bytes_total) from diskaudit.v_duplicate_groups;"
```

**Always use exact `count(*)`, never `n_live_tup`,** per standing operating rule.

## INFRASTRUCTURE AND STORAGE

**Never-delete constraint restated: nothing below ever deletes, moves, or
overwrites a scanned file. All writes are confined to the `diskaudit` Postgres
schema, this repo's own logs/reports, and restic's own backup repos.**

### Storage paths
- the server root filesystem: single ext4 partition `/dev/nvme0n1p2` (3.6T, 64%
  used as of 2026-07-25). `scan.py` walks this with `-xdev` semantics (skips
  other mounts, e.g. `/var/lib/docker` overlay internals excluded by design).
- NAS: `nas-1` (QNAP), shares under `/share/CACHEDEV1_DATA/<share>`,
  crawled **natively over SSH** (BusyBox `find`/`stat`/`xargs`, no Python on
  the NAS) — never mounted locally. **`/mnt/nas-diskaudit` (referenced by
  `havnvard_report.py`'s `collect_capacity()` for NAS disk-utilization %) does
  not exist on the server** — confirmed via `mount`/`df` 2026-07-25. This means the
  NAS capacity (used/total %) figure in the daily report/dashboard is **always
  unavailable** (the code degrades gracefully to `None`, so this doesn't error,
  but the NAS row is permanently blank in that specific panel — file/byte
  counts for NAS are still fully populated via the DB, only the raw
  disk-utilization-% panel is affected).
- Client hosts (e.g. `agent-1`): run `scan.py` locally, write straight to the
  central Postgres over Tailscale. See `CLIENT_INSTALL.md` for onboarding.
- This repo on disk: `/opt/havnvard`, **40M** total (code + venv +
  small scratch dirs only — no bulk data lives in the repo itself, it's all in
  Postgres).

### Database
- `havnvard` (Postgres, `127.0.0.1:5432`), schema `diskaudit`. See DB checks
  above for table/view list. Primary key on `files` is `(host, path)`.
- `diskaudit.files` currently holds **13,389,321 rows** (server-1 10,719,162;
  nas-1 2,290,057; agent-1 380,102), confirmed 2026-07-25.
- `diskaudit.mv_file_status` (classification materialized view): 7,744,739
  rows, all 3 indexes valid, confirmed 2026-07-25.
- `diskaudit.backup_runs`: 72 rows so far (restic Phase 2 activity log).

### ⚠️ Hardlink double-counting gotcha (documented 2026-07-25, the operator)

**Raw `sum(size_bytes)` totals in this system double-count hardlinks.**
Confirmed live: **2,291,752** `still_exists` rows on `server-1` have
`nlink > 1`. Concrete example verified against production data 2026-07-25 —
`/srv/apps/heimdall`:

| Method | Result |
|---|---|
| Raw `sum(size_bytes)` over all rows under that path | **720 GB** |
| `sum(size_bytes)` over `DISTINCT ON (inode)` rows | **384 GB** |
| Real `du -sh` on disk | **388 GB** (matches the inode-deduped figure, not the raw one) |

**Any "total size" or "reclaimable space" figure MUST dedupe by
`(host, inode)` — e.g. `SELECT DISTINCT ON (host, inode) ... ` or an
equivalent `GROUP BY inode` before summing — or it will overstate true disk
usage by roughly 2x on heavily-hardlinked trees.**

**Current code status (checked 2026-07-25) — inconsistent, document as-is:**
- **Correctly deduped**: `diskaudit.v_duplicate_groups_by_host` /
  `diskaudit.v_duplicate_groups` (the "reclaimable space" views) — fixed by
  migration `20260717_diskaudit_reclaimable_fix_v2.sql`, which explicitly
  computes `GREATEST(count(DISTINCT inode) - 1, 0) * max(size_bytes)`. This
  is correct, and it's the number the daily report calls "reclaimable."
- **NOT deduped (raw, overstated)**: the headline **host/total byte figures**
  used in `havnvard_report.py` (`collect_metrics()`, the
  `select host, count(*), coalesce(sum(size_bytes),0) ... group by host`
  query) and the equivalent query in `weekly_prescab_review.py`. These are
  the numbers that appear as "the server: X files, Y bytes" / "NAS: ..." in the
  daily TG PRESI report and (same query shape) the Grafana dashboard (2
  panels in `diskaudit.json` use `sum(size_bytes)` directly, none use
  `DISTINCT ON`). **These totals overstate real disk usage** on any tree with
  significant hardlinking (e.g. heimdall, ~2x). Only the specific
  "reclaimable" figure is trustworthy as-is; the plain file/byte totals per
  host are not a reliable measure of true disk usage until this is fixed.
  This is a documentation gotcha, not (yet) a code fix — flagging for anyone
  reading the dashboard or PRESI report numbers.

### Cache / scratch / temp locations
`logs/`, `nas_inbox/` (+ `_nas_etc`), `data/`, `exports/`, `tmp/` — all
`.gitignore`'d, created on demand by a live run, safe to be empty/absent at
rest.

### Retention
- No explicit retention/pruning logic found in this repo for `diskaudit.files`
  itself — rows are never dropped, only marked `still_exists=false` when a
  file disappears between scans (append-only history by design).
- Restic backups (Phase 2, below): the paired
  `havnvard-restic-<target>-retention.service`/`.timer` (`forget`+`prune`)
  is DISABLED since 3.2.0 (INFRA-571): nothing is deleted without the owner's order.

### Services / timers (confirmed live via `systemctl list-timers --all`, 2026-07-25)

Core diskaudit (all root-owned, all `active`/`waiting`):

| Timer | Schedule | Notes |
|---|---|---|
| `diskaudit-scan.timer` | daily 08:00 | full the server scan (changed 2026-07-18 from monthly) |
| `diskaudit-nas-crawl.timer` | every 4h | shifted 30min earlier 2026-07-19 to reduce overlap with TechWatch's 04:00–14:00 window (INFRA-110, not fully resolved) |
| `diskaudit-monitor.timer` | every 5 min | stale/failed run alerting |
| `diskaudit-load-bearing-refresh.timer` | daily 08:20 | changed 2026-07-19 from weekly |
| `diskaudit-classification-refresh.timer` | daily 08:35 | changed 2026-07-19 from monthly; 15 min after load-bearing so it picks up fresh data same cycle |
| `diskaudit-prescab-review.timer` | weekly, Sun 18:00 UTC | |
| `havnvard-presi-report.timer` | daily 15:00 (local) | `User=havnvard`, not root |

Restic backup engine (Phase 2 — **LIVE, not "planned" as older README/module.yaml
text says** — see discrepancy note below), 10 targets, each with a daily
backup timer (the paired weekly retention timers are disabled since 3.2.0: they deleted without the owner's order): app-a,
app-b, app-c, config-files, app-d, app-e,
app-f, app-g, app-h, app-i. Scripts live in the
sibling repo `/srv/apps/backup/` (group `uo-ai`), invoked from
`/etc/systemd/system/havnvard-restic-*.service` (root-owned units in this
app's systemd namespace). `restic 0.19.1` confirmed installed at
`/usr/local/bin/restic` (module.yaml's note that restic is "not yet installed"
is stale — see discrepancies below).

### Dependencies
- `rdfind` (apt) — dedup engine, must not be replaced.
- `sshpass` + `ssh` + `rsync` — NAS transfer channel.
- `restic` 0.19.1 (ARM64 GitHub release binary, not the apt package) —
  backup engine, confirmed live.
- Passwordless `sudo -n crontab -l -u <user>` for each `CRONTAB_USERS` entry
  (load-bearing-path classification signal).
- PostgreSQL `havnvard` schema `diskaudit`.
- NAS side: BusyBox v1.24.1 multi-call binary (`find`/`stat`/`xargs`, no
  GNU-only flags), bash 3.2.57 sh-compat mode. No Python/package manager on
  the NAS.

### Backup behavior
Restic Phase 2 (this is a HavnVard-adjacent but distinct capability — it
backs up **other** app directories, not the disk-inventory data itself):
daily `restic backup` per target (the weekly `forget`/`prune` timers are disabled since 3.2.0). All
runs logged via `backup_heartbeat_cli.py` into `diskaudit.backup_runs`
(`run_type`/`backup_job`, `host`, `status`, heartbeat), monitored by the same
`monitor.py` STALE/ERROR logic used for scan/dedup runs (Plane INFRA-98).

## NAS within-host dedup (`nas_trigkey_dedup.py`, 1.4.0)

Design, requirements (HV-REQ-01..38) and test plan: `/home/user/runbooks/20261109-havnvard-nas-dedup/20261109_ARCHITECTURE.md`
(Plane INFRA-519 work, INFRA-520 source gaps). Feeds the operator quarantine script
`nas_dedup_delete.py` (lives in that runbook dir, NOT in this repo).

**Racy-clean rule (3.3.2, INFRA-520 G1).** A digest counts only if it was taken at least 2 s after the file's mtime.
`hash_stat_batch.sh` reports a file whose mtime is within 2 s of the batch start (on the NAS's own clock) or in the
future as `UNSTABLE` and does not hash it; the driver and the publish SQL refuse any binding with
`bound_at < mtime + 2 s` (older bindings made before the guard are re-hashed once). Reason: mtime has 1 s
resolution, so a same-second rewrite keeps size and mtime and a digest taken in that window could later look fresh.
`--path-prefix` is an alias of `--path`.

**Run it** (always supervised, never a bare background process; `User=havnvard`):
```
cd /opt/havnvard
# scoped run (minutes): one directory tree, boundary-safe (/a/b never matches /a/bc)
systemd-run --unit=havnvard-nas-dedup-scoped-$(date +%H%M) --uid=havnvard --wait --pipe --working-directory=/opt/havnvard \
  /opt/havnvard/.venv/bin/python3 nas_trigkey_dedup.py --host nas-1 --path /share/CACHEDEV1_DATA/Public/<dir>
# whole host, bkup_server left out (what the weekly timer runs; first run re-hashes every legacy digest, plan on ~1 day)
systemd-run --unit=havnvard-nas-dedup-full-$(date +%Y%m%d) --uid=havnvard --working-directory=/opt/havnvard \
  /opt/havnvard/.venv/bin/python3 nas_trigkey_dedup.py --host nas-1 --exclude /share/CACHEDEV1_DATA/bkup_server
# plan only (3.3.2): read-only SQL, prints candidates / files and bytes to hash / fresh digests reused; no run row, no ssh
.venv/bin/python3 nas_trigkey_dedup.py --host nas-1 --path /share/CACHEDEV1_DATA/Public/<dir> --dry-run
# after a killed long run (3.3.2): publish groups from the digests already fresh, no ssh/scp, minutes not hours
systemd-run --unit=havnvard-nas-dedup-publish-$(date +%H%M) --uid=havnvard --wait --pipe --working-directory=/opt/havnvard \
  /opt/havnvard/.venv/bin/python3 nas_trigkey_dedup.py --host nas-1 --publish-only
# hash only, publish nothing (a --limit run can never produce a publishable result)
... nas_trigkey_dedup.py --host nas-1 --limit 1000
# reproducible snapshot export (what the delete script consumes); two exports of unchanged data differ only in run_id/timestamps
.venv/bin/python3 nas_trigkey_dedup.py --export <run_id> --format csv > dryrun_<run_id>.csv
```
Exit codes: 0 completed | 2 run failed | 3 database unreachable (alertlib `db_down`) | 4 refused: a whole-host run is
already active (no run row is created; the timer unit treats 4 as success) | 143/130 SIGTERM/SIGINT (run marked failed).

**What a run does.** Plan (SQL, scoped) -> hash in size-ascending batches of <= 500 files or 4 GiB, ssh timeout
`max(600, 120 + bytes/(20 MB/s))` -> publish in ONE transaction. A digest is reused only while *fresh*: the
`dedup_digest_bindings` row (size/mtime/inode/dev it was computed against) must equal the inventory row; legacy digests have no
binding and are re-hashed once. A batch that fails (any ssh/scp rc != 0, missing `#DONE` trailer, a path unaccounted for or
foreign, a malformed line) is retried ONCE under a new name; a second failure fails the run, which publishes nothing and keeps
the previous completed snapshot as the latest. Remote result files are removed only after their rows are committed.

**Read the results** (`R` = run id printed by the run):
```sql
SELECT status, is_partial, root_dirs, exclude_paths, duplicate_groups_found, grouped_identities, duplicate_files_found,
       files_hashed, files_inherited, files_reused, excluded_zero_byte, errors_by_reason, transport_failures, retries,
       bytes_reclaimable, failure_reason, current_stage FROM diskaudit.dedup_runs WHERE dedup_run_id = R;
SELECT group_id, size_bytes, identity_count, member_count, keeper_path FROM diskaudit.dedup_group_snapshots WHERE dedup_run_id = R;
SELECT path, role, in_recycle_bin, in_backup_tree, links_outside_inventory FROM diskaudit.dedup_group_members
 WHERE dedup_run_id = R ORDER BY group_id, (role <> 'keeper'), path COLLATE "C";
SELECT path, outcome, reason FROM diskaudit.dedup_run_items WHERE dedup_run_id = R AND outcome = 'error';   -- per-file errors
```
Roles: `keeper` (+ `keeper_link` = other paths of the keeper's inode), `victim` (+ `victim_link`). Keeper rule (1.4.1): not in a recycle bin -> not in the
bkup_server backup tree ->
earliest mtime -> shortest path -> bytewise. `bytes_reclaimable` counts a victim inode only when all its links are listed in the
inventory (`links_outside_inventory`). Legacy labels on `files.duplicate_group_id` from before 1.4.0 are ADVISORY and are replaced per
scope by each 1.4.0 publish; the delete script never reads them.

**Failure recovery.** A `failed` run needs no rollback (nothing was published): read `failure_reason`, fix the cause, re-run.
Digests already committed are valid and bound and are reused. A killed process (SIGKILL/OOM) leaves a `running` row: `monitor.py`
alerts on it after 10 min (`--stale-minutes`; the background heartbeat beats every 15 s, so a 40-minute single-file batch does not
trip it), then `UPDATE diskaudit.dedup_runs SET status='failed', failure_reason='killed', finished_at=now() WHERE dedup_run_id=<id>`.
An orphaned remote script after SIGTERM: as the NAS backup user, `ps w | grep hash_stat_batch` and kill only `nasdedup_*`.
Leftover files in `/share/CACHEDEV1_DATA/.diskaudit_scratch/` named `nasdedup_*` are this tool's own and safe to remove.

**Release gate before the delete script may act on a scope** (HV-REQ-34): the fixture acceptance (HV-REQ-32), the injected-failure
negative test (HV-REQ-33; `NASDEDUP_FAULT=scp_get:0` makes every `.hashes` fetch of batch 0 return rc 124, touching nothing on the NAS)
and the one-time reconcile (`migrations/20261109_diskaudit_nas_dedup_v3_reconcile.sql`, both counts 0) pass, then two consecutive
scoped dry runs on that scope are `completed`, with 0 transport failures, 0 per-file errors inside the scope, and byte-identical
exports after dropping run_id and timestamps. Record the gate table in the NAS-dedup runbook.

**Switches.** Include `bkup_server` (the operator decision; ~+2.2 M reps, ~+31 h once): drop `--exclude /share/CACHEDEV1_DATA/bkup_server` from the
unit's `ExecStart`, `daemon-reload`. Raise `--assumed-mbps` once a full run reports its measured MB/s. Optional indexes
(`migrations/20261109_diskaudit_nas_dedup_v3_indexes.sql`, run without `-1`/`--single-transaction`) only if a scoped run exceeds 10 minutes.

**Schema** (migration `20261109_diskaudit_nas_dedup_v3.sql`, additive): `dedup_digest_bindings`, `dedup_run_items`,
`dedup_group_snapshots`, `dedup_group_members`, new `dedup_runs` columns. Apply with `lock_timeout` set; it never blocks a running dedup.

**1.4.1 change notes (bug-hunt, INFRA-520, 20261109):** (BH-3) `in_backup_tree` joins the keeper ORDER BY right after
`in_recycle_bin`, so a `bkup_server` replica is never the keeper while a live copy exists (HV-REQ-28); (BH-1) `classify_path` refuses
every C0 control character, DEL, U+0085, U+2028, U+2029 as `UNSAFE_PATH`; (BH-8) a path holding U+FFFD (undecodable name, stored lossy)
is recorded `NON_UTF8_PATH`, never sent to the NAS and never marked `still_exists=false`; (BH-7) `load_nas_inventory.py` reads the
crawl TSV with `newline="\n"` so a bare CR inside a name cannot tear a row (the name then reaches HavnVard and is refused as
`UNSAFE_PATH`). Snapshots published by 1.4.0 are still accepted by the delete script (>= 1.4.0) but may carry a backup-tree keeper
(the script now refuses those groups itself).

**1.4.2 change notes (scan/crawl fixes, INFRA-518 + INFRA-520, 20261109):** (1) `scan.py` `merge()` is now one
`INSERT ... SELECT DISTINCT ON (path) ... ON CONFLICT (host, path) DO UPDATE` plus one UPDATE marking rows not re-seen
(`last_seen_scan_id <> scan_id`, root-prefix scoped); no join between `files` and `files_staging` remains, so a host with no prior
rows can no longer drive the planner into the quadratic nested-loop anti-join (scans 4370/4371 hung 30 min each). first_seen /
last_seen / still_exists / disappeared_at semantics unchanged. (2) An explicit `--root` is never excluded by a DEFAULT exclude that is
its ancestor (`/run/media/...` is now scannable); the run logs `default exclude X waived`. (3) R-4: `nas_native_crawl.sh` skips any
path containing a LF (`! -path`), lists the topmost such entry hex-encoded in `<share>.unsafe`, and `load_nas_inventory.py` records
each as a `scan_errors` row `UNSAFE_NAME_LF` (the entry and its subtree are not inventoried; the NAS needs `hexdump`, checked at start).
(4) CLIENT_INSTALL.md section 4B: no-root install. Tests: `tests/test_scan_merge_and_unsafe_names.py`. Opus review additions: (5) staged paths that collapse to one stored path are logged as `scan_errors` `DUPLICATE_STAGED_PATH` (counted in `errors_count`) and the kept row is chosen deterministically; (6) `scan.py` exits 2 when `--root` is itself inside a `--exclude` or an excluded component (it would crawl nothing and mark every row under the root disappeared); (7) the disappearance `LIKE` prefix escapes `_`, `%` and backslash (a root `/d/my_dir` no longer matches `/d/myXdir`). Merge at 7 M staged rows: 264 s vs 550 s on 1.4.1. Known, filed: concurrent scans of one host share `files_staging` (INFRA-522).

**1.4.3 change notes (INFRA-522 R142-6, INFRA-518 R142-8, 20261109):** (1) `files_staging` gains a nullable `scan_id`; every staged row is tagged and `merge()` reads only its own scan's rows. Migration `migrations/20261109_diskaudit_files_staging_scan_id_v1.sql` (additive, `lock_timeout` 5 s) must be applied BEFORE 1.4.3 is deployed. (2) `scan_guard.py`: a session-level advisory lock per (host, root); a second scan of the same root exits 3 with `REFUSED` on stderr before touching the DB (also `load_nas_inventory.py`, per host + share root). Start-up cleanup deletes only staged rows no live scan can own (finished scans, legacy NULL scan_id, dead `running` scans of the same host+root). (3) A directory whose listing, or an entry whose stat, fails during an otherwise complete crawl (local EACCES/EIO; NAS `find: <dir>: Permission denied`, `stat: can't stat '<path>'`) is a held path: stored rows at/under it are NOT marked disappeared, and its `scan_errors` row gains `[HELD_BACK: N stored rows ...]`. Nested held paths overlap in N. `nas_native_crawl.sh` is unchanged: BusyBox 1.24.1 `find` prints `find: <abs dir>: Permission denied` (verified on the NAS as `backup`, non-root).

**Version 2.0.0** (`module.yaml`, README, this RUNBOOK, `thoth.census.version` for `havnvard` must agree).

## HavnVard Backup (`python -m backup`, 2.2.0)

Spec: `/home/user/runbooks/20261110-havnvard-restic/20261110_SPEC.md`. Install steps: README "Install HavnVard Backup".
Config `~/.config/havnvard/backup.toml`; secrets `restic.pass`, `rest.pass`, `hub-passwords/*.pass` (all 600, never in git);
state `~/.local/state/havnvard/` (last job, offsite logs/flag/tries/hold files, disk-guard marker).

| Task | Command | Notes |
|---|---|---|
| Hub status | `python -m backup health` | 0 ok, 1 problem, 2 could not check. Alerts via alertlib key `havnvard-backup-health` |
| Hub stopped by disk guard | free space above 125 GB; the guard restarts it only if it stopped it | marker `~/.local/state/havnvard/hub-diskguard.stopped` contains `stopped`; emptying it makes the hub stay down on purpose |
| Hold a repo back from offsite | write its name in `~/.local/state/havnvard/offsite-NAME.hold` | |
| Flagged offsite file | listed in `offsite-NAME.flagged`; compare offsite vs hub copy, then clear the line and its `.tries` line | restic can read the repo only if the file is correct |
| Hub without alertlib | on the server: `python -m backup health-relay --ssh HOST --python PY --repo-dir DIR` | exit 0 healthy, 1 hub problem (alerted), 2 relay failed (alerted); render the hourly timer with `--render-units DIR` |
| Coverage link | `python -m backup coverage-sync DEVICE [--dry-run]` after `backup_coverage.py classify` | needs `POSTGRES_URL`; apply migration `20261111_diskaudit_restic_coverage_v1.sql` first (by hand) |
| Backup names + catalog | hub: `python -m backup catalog run` (timer `havnvard-hub-catalog`, hourly at :40) | names each new data snapshot `YYYYMMDD_DEVICE_NNNNNN` (restic tag; one counter for all devices, never resets), appends ADDED/GONE lines to `~/.local/state/havnvard/catalog/catalog.tsv`, then backs the whole catalog up into every repo as `YYYYMMDD_CATALOG_NNNNNN_catalog.tsv` tagged `havnvard-catalog`. Needs `hub-passwords/<repo>.pass` for each repo (exit 1 lists any missing). First run names only each repo's newest snapshot (`--all-history` for every one). `state.json` is the commit point; a crash leaves nothing half-written |
| Offsite feed (DESKTOP-1) | `~/.local/bin/havnvard-hub-pull` (repo `scripts/havnvard_hub_pull.sh`) runs as `ExecStartPre` of `restic-hub-offsite.service` | copies new settled files from the agent-1 hub into `~/restic-hub` (add only, snapshots last, never locks); log `~/.local/state/havnvard-hub-pull.log`; INFRA-547 |
| Which backup holds a file | `python -m backup where bob.txt [--device the server] [--catalog FILE]` | 0 found, 1 not in any backup. Without the hub: `restic dump <catalog snapshot> <path>` from any repo (hub, NAS, Internxt), then `grep` |
| Not backed up | `python -m backup not-backed-up [--host H] [--by type\|folder] [--limit N]` | |
| Prune (owner only) | `python -m backup prune DEVICE --keep-monthly N --owner-key FILE` | hub only; shows the list, asks for the exact text; archive kept. 3.2.0: no prune timer; on upgrade run `systemctl --user disable --now havnvard-hub-prune.timer` |
| Prove a device | `python -m backup restore-drill DEVICE` | all files must match |
| Lost device password | not recoverable; restore the password from the password manager | |

### Archiving an app

Archiving an app must also stop its backups (GHY-209/210 were the same miss twice: a class, not a bug). In the same change:

1. the server, `spark-backup` repo: disable `havnvard-restic-<app>.timer` AND `havnvard-restic-<app>-retention.timer`
   (`sudo systemctl disable --now ...`), and archive the unit files and scripts in that repo.
2. HavnVard config: remove the app's paths from the device's `paths` in `~/.config/havnvard/backup.toml` and re-run `enroll`
   (or edit `[device] paths`).
3. Run `python -m backup check-timers`: it must print that every timer still has its script and source (exit 0). It lists
   any `havnvard-restic-*` timer whose ExecStart script, WorkingDirectory or `BACKUP_SRC` no longer exists.
4. Leave the app's existing restic repo in place until the operator says to delete it.

Rollback: stop and disable the user units (`systemctl --user disable --now havnvard-backup.timer ...`); repos on the hub are untouched.
Tests: `pytest tests/test_backup_core.py tests/test_backup_restic.py tests/test_backup_round2.py tests/test_backup_catalog.py` (tmp dirs, local restic repos and local-path rclone remotes only).

## Common failures + recovery

| Symptom | Cause | Recovery |
|---|---|---|
| `scan_runs.status='running'` forever | Externally-killed run (timeout/pkill/OOM) — no signal handler in v1 | `UPDATE diskaudit.scan_runs SET status='failed', finished_at=now() WHERE scan_id=<id>;` then re-run manually |
| `refresh_classification_mv.py --help` "hangs" for minutes | **Not a hang** — the script has no argparse; ANY invocation runs the full `REFRESH MATERIALIZED VIEW CONCURRENTLY` (≈6 min at current row count) | Wait it out (safe, idempotent), or check `select * from pg_stat_activity where query ilike '%refresh_file_status%'` to confirm it's progressing, not stuck |
| NAS crawl fails on one share | `run_all_nas_shares.sh` continues past a per-share failure | Check `diskaudit.scan_errors` / journal for the specific share; re-run `load_nas_inventory.py --share <name>` alone |
| Dashboard "total size" looks implausibly high vs `du -sh` | Hardlink double-counting (see gotcha above) — not a bug, a known raw-sum limitation | Use `diskaudit.v_duplicate_groups` (`reclaimable_bytes_total`) for a trustworthy figure, or compute `DISTINCT ON (host, inode)` yourself |
| NAS capacity % blank in report | `/mnt/nas-diskaudit` doesn't exist on the server (NAS is SSH-crawled, never mounted) | Expected/graceful — not a bug. File/byte counts for NAS are still correct; only the raw capacity-% panel is unavailable |
| TG PRESI report not arriving | `havnvard-presi-report.service` failed, or `AGENT_BOT_TOKEN`/`TG_PRESIDENT_CHAT` misconfigured | `journalctl -u havnvard-presi-report.service`; verify env resolves via `/etc/havnvard/havnvard.env` fallback in `get_dsn()`/`tg_token()` |
| Monitor stops alerting | `diskaudit-monitor.timer` disabled/failed | `systemctl status diskaudit-monitor.timer`; re-enable if disabled |

## Safe deploy

1. Confirm current branch/dirty state (`git status`) before touching anything.
2. For a code change: edit on a feature branch, `--dry-run` the affected
   script against a bounded scope first (e.g. `scan.py --dry-run --root
   /home/user`), verify output, then let the systemd timer pick it up (or
   `sudo systemctl start <unit>` manually) rather than editing on `main`.
3. Schema changes go through `migrations/` (numbered, dated SQL files), then regenerate `schema/baseline.sql`
   with `scripts/make_baseline_schema.py` from the migrated database (INFRA-557) —
   never hand-edit `diskaudit.*` objects outside a migration file.
4. Never run a script as an experiment against the FULL 13M-row `files` table
   without `--dry-run` first if the script supports it.

## Rollback

- Code: `git revert` the offending commit on this repo (independent git repo,
  own history — not tied to any other repo's rollback).
- Schema: migrations here are additive/forward-only by convention; a rollback
  requires a new migration that reverses the change (no down-migrations
  scaffolded) — write and review one rather than hand-editing.
- Backups (restic): `restic snapshots` + `restic restore <snapshot-id>
  --target <dir>` per target repo — **restore is the operator's explicit
  action, never automatic.**

## Escalation

- Plane trackers: **INFRA-97** (main HavnVard tracker), **INFRA-98**
  (monitoring), **INFRA-99** (deferred v3), **INFRA-109** (remaining restic
  targets), **INFRA-110** (TechWatch schedule collision, partially resolved).
- TG PRESI group receives automated alerts from `monitor.py` (stale/failed
  runs) and the daily `havnvard_report.py` summary — check there first for
  any live incident signal before diving into logs.
- Owner: the operator (havnvard@server-1). No other on-call.

## GitHub notes

Independent git repo. Changes land on a branch and merge to `main` after review; releases are tagged `vX.Y.Z`.

## Operator notes

- This repo also has an **older pointer-style runbook convention** (see table
  below) that pointed at `/home/user/runbooks/<name>/README.md` files. That convention predates the 2026-07-20
  THOTH-hand-off standard (CLAUDE.md §10) and this file now carries the real
  operational content directly, per the current per-app runbook standard —
  the pointer table below is kept as a historical index into those detailed
  design/decision runbooks, not removed:

| Runbook | Covers |
|---|---|
| `20260717-diskaudit-v1` | Whole-disk inventory scanner (v1, log-only) |
| `20260717-diskaudit-v2-dedup` | Duplicate detection (rdfind wrapper), multi-host `(host,path)` schema |
| `20260717-diskaudit-v2-heartbeat-monitor` | Heartbeat/stage tracking, stale-run detection, TG PRESI alerting |
| `20260718-diskaudit-classification` | File-status classification, load-bearing override |
| `20260718-diskaudit-prescab-weekly-review` | Weekly PRESCAB operational review dispatch |
| `20260718-havnvard-restic-migration` | Phase 2 — restic-based backup engine, per-target build process |

These design runbooks are the authors' private notes and are not part of this repository.

- **As of this audit (2026-07-25), another agent has in-flight, uncommitted
  work on this branch** (`havnvard_report.py`, `heartbeat.py`, `monitor.py`
  modified; `crosshost_verify.py`, `hash_batch.sh`, and migration
  `20260725_diskaudit_crosshost_integrity_v1.sql` untracked/new) building
  cross-host content-hash verification. This doc describes it at a
  point-in-time, high level only (see Entry points table) — re-verify once
  that work merges.

## Discrepancies found during this audit (2026-07-25)

- **`module.yaml` / `README.md` say restic is "planned future addition ... not
  yet installed."** Live check: `restic 0.19.1` IS installed
  (`/usr/local/bin/restic`), and **10 restic backup targets are live** with
  daily+weekly systemd timers and 72 logged runs in `diskaudit.backup_runs`.
  This is a stale doc claim, not a live gap.
- **`module.yaml` describes `scan.py` as monthly** (`OnCalendar=*-*-01
  02:00:00`); the live timer (per the timer's own embedded change-note) runs
  **daily at 08:00**, changed 2026-07-18. `module.yaml` was not updated to
  match.
- **`thoth.census` `runbook` field pointed at `README.md`**, not a runbook —
  corrected in this pass (see below).
- **`thoth.census` `updated_at` was stale (2026-07-17)** despite substantial
  work since (classification layer, restic Phase 2, PRESI report, in-flight
  crosshost work) — refreshed in this pass.
- Old `RUNBOOK.md` was a pointer-only index (20 lines); this pass merges in
  full operational content per the current per-app runbook standard while
  preserving the pointer table for historical traceability.
