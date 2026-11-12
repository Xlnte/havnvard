# HavnVard

**Storage Assurance.** Whole-disk file inventory, deduplication, and
file-status classification system for spark-20cf + attached NAS
(nas-ts453a). v1.4.3.

## Status

Active, `thoth.census` system_key `havnvard`, primary path
`/srv/diskaudit`. Owner: parker.

## What this does

HavnVard crawls every file across multiple hosts into `ultra_crm.diskaudit`
schema, finds real (SHA-256, cryptographic) duplicates across hosts, checks
whether "critical" files are actually backed up somewhere else, and
classifies files as active/load-bearing/stale/possibly-obsolete/orphaned —
without ever auto-deleting anything. See the full design doc
(`/home/parker/.claude/plans/witty-swinging-shore.md`) and runbooks under
`/home/parker/runbooks/20260717-diskaudit-*` and `/20260718-diskaudit-*` for
architecture, decisions, and verification history.

**Cross-host content verification** (`crosshost_verify.py`, added
2026-07-25, runbook `/home/parker/runbooks/20260725-havnvard-crosshost-integrity/`):
`dedup.py` drives `rdfind`, which needs local filesystem access — the NAS is
not mounted on Spark, so NAS files were never deduped or cross-checked
against spark-20cf/trigkey. `crosshost_verify.py` closes that gap without
needing a mount: it prefilters `diskaudit.files` to sizes appearing on >=2
hosts (>=1MB), hashes just that candidate set (SHA-256, over SSH for
nas-ts453a/trigkey, locally for spark-20cf, inode-aware so hardlinked rows
are hashed once, not once per path), then cryptographically proves — or
disproves — that a given spark/trigkey file is genuinely byte-identical to a
copy on the NAS. Answers the two questions PAF actually cares about: "is my
data genuinely intact on the NAS?" and "what could I safely clean up on
Spark?" — the latter as candidates only, never automatically.

**NAS within-host dedup (`nas_trigkey_dedup.py`, 1.4.0, Plane INFRA-519 / INFRA-520):**
finds files with byte-identical content on one host (nas-ts453a, trigkey) for an operator
quarantine script that moves files. A digest is reused only while it is *fresh* (the stat it was
computed against still matches the inventory); every ssh/scp step is checked and every batch must
account for exactly the paths it was sent, otherwise the run fails and publishes nothing; groups are
recomputed from fresh digests inside one transaction and stored as an immutable per-run snapshot
(`dedup_group_snapshots` / `dedup_group_members`). Supports `--path <dir>` (scoped run, minutes
instead of a day), `--exclude <dir>`, `--limit N` (hash only, publishes nothing) and `--export <run_id>`.
Design, requirements and test plan:
`/home/parker/runbooks/20261109-havnvard-nas-dedup/20261109_ARCHITECTURE.md`; operation: RUNBOOK.md
section "NAS within-host dedup".

## Files

| File | Purpose |
|---|---|
| `scan.py` | Whole-disk metadata crawler (path/size/perms/owner/timestamps). Run locally per host; `--host`/`--root` flags let it tag rows for a different host name if crawling a mount. |
| `scan_guard.py` | **1.4.3 (INFRA-522):** per-(host, root) Postgres advisory scan lock (a second scan of the same root is refused, exit 3) and per-scan `files_staging` cleanup, used by scan.py and load_nas_inventory.py. Needs migration `20261109_diskaudit_files_staging_scan_id_v1.sql`. |
| `heartbeat.py` | Shared heartbeat/progress-tracking helpers used by scan.py, dedup.py, load_nas_inventory.py during long-running jobs. |
| `bucketing.py` | LPT (longest-processing-time) bin-packing for parallel dedup worker assignment; also handles `ARG_MAX`-safe chunking of same-size candidate groups. |
| `dedup.py` | rdfind integration + parallel worker orchestration for duplicate detection. |
| `monitor.py` | Polls for stale/failed scan and dedup runs every 5 min, alerts to TG PRESI group. Idempotent. |
| `nas_native_crawl.sh` | BusyBox-only (no Python/package manager needed) crawl script, scp'd to and run directly on the NAS. Writes results to a flat file on the NAS's own real disk (never `/tmp` — small tmpfs shared with live NAS processes). |
| `load_nas_inventory.py` | Orchestrates one NAS share: runs `nas_native_crawl.sh` over SSH, ships results back, loads into the same schema as scan.py, tagged `host=nas-ts453a`. `--share <name>` per invocation. |
| `run_all_nas_shares.sh` | Loops `load_nas_inventory.py` across every known NAS share; continues past a per-share failure instead of aborting the whole run. |
| `refresh_load_bearing_paths.py` | Builds the "load-bearing override" registry (cron/systemd/thoth.census cross-reference) that protects cold-but-live files from being misclassified as abandoned. Bounded scope, full per-run audit trail (`diskaudit.load_bearing_refresh_runs`). |
| `refresh_classification_mv.py` | Refreshes the `diskaudit.mv_file_status` materialized view (the classification layer: active/load-bearing/stale/possibly-obsolete/orphaned). |
| `weekly_prescab_review.py` | Assembles current diskaudit state and dispatches to PRESCAB (vp-operations, logic_governance mode) for a weekly trend review. Logged to `jobs.cabinet_runs`. |
| `crosshost_verify.py` | Cross-host SHA-256 content verification (no NAS mount needed). Subcommands: `candidates` (report the size-based candidate set, no hashing), `hash --host <h>` (hash one host's candidates; resumable, inode-aware, heartbeat-tracked), `match` (join hashes across hosts, populate `duplicate_group_id` + `diskaudit.integrity_checks`), `report` (render markdown reports via `report.py`). |
| `hash_batch.sh` | POSIX/BusyBox-compatible remote hashing script, scp'd to and run on nas-ts453a/trigkey by `crosshost_verify.py hash`; deleted from both sides after results are loaded. Read-only; includes a passwordless-`sudo` READ fallback (sha256sum only) for root-owned files, a no-op where sudo doesn't exist (NAS). |
| `nas_trigkey_dedup.py` | Within-host dedup for nas-ts453a/trigkey (1.4.0 rewrite): plan -> size-aware hash batches -> one-transaction publish. See the paragraph above and RUNBOOK. |
| `nas_dedup_core.py` | Pure functions for `nas_trigkey_dedup.py` (freshness, scope pattern, batch planner, result verifier, keeper rule, progress note); no DB/SSH, unit-tested alone. |
| `hash_stat_batch.sh` | Remote script for `nas_trigkey_dedup.py`: SHA-256 plus stat before/after, stat-only lines for hardlink siblings, `#DONE` trailer. Read-only; `hash_batch.sh` stays untouched for `crosshost_verify.py`. |
| `report.py` | Renders `crosshost_verify.py`'s DB data (dedup groups, NAS integrity verdicts, cleanup candidates) to markdown under `reports/` (gitignored). Recommendations only — never an instruction, never deletes/moves anything. |
| `module.yaml` | Module manifest (version, entrypoints, databases, risks) per this repo's Module Standard. |
| `requirements.txt` | Python deps (installed in `.venv`, not committed). |
| `requirements-dev.txt` | Test-only deps (pytest), additive to requirements.txt. |
| `tests/test_nas_dedup_core.py`, `tests/test_nas_trigkey_dedup.py`, `tests/test_hash_stat_batch.py` | NAS-dedup suite: pure-function tests, DB + fake-SSH tests on a throwaway schema (never a real host), and the real remote script run under `sh`. See `tests/README.md`. |
| `tests/test_crosshost_verify.py` | pytest suite for `crosshost_verify.py`: candidate-SQL shape, hash-loader idempotency, synthetic cross-host match grouping, and a codebase-wide guard that fails if any delete/move/rename primitive is ever introduced against a scanned path. |
| `logs/` | Local log output directory. |

## Entry points / schedule

Systemd timers (all on Spark):
- `diskaudit-scan.timer` — daily 08:00, full local scan
- `diskaudit-nas-crawl.timer` — every 4 h at :20 (00/04/08/12/16/20), full NAS crawl (all shares)
- `diskaudit-nas-dedup.timer` — weekly Sunday 02:00, NAS within-host dedup with `bkup_spark` excluded (installed; enabled only after the release gate passes once)
- `diskaudit-monitor.timer` — every 5 min, health check + TG alerting
- `diskaudit-prescab-review.timer` — weekly, Sunday 18:00 UTC
- `diskaudit-load-bearing-refresh.timer`, `diskaudit-classification-refresh.timer` — periodic classification-layer refresh

Manual invocation:
```
sudo /srv/diskaudit/.venv/bin/python scan.py            # full Spark scan
sudo /srv/diskaudit/run_all_nas_shares.sh                # full NAS crawl
```

## Database

Schema `diskaudit` in `ultra_crm` (Postgres). Core table `diskaudit.files`
(`(host, path)` primary key). Key views: `v_duplicate_groups`,
`v_file_status`, `v_backup_coverage`, `v_nas_orphans`.

## Dashboard

Grafana: `https://spark-20cf.tail5f354b.ts.net:9452/d/diskaudit/diskaudit`

## Requirements

- Python 3.12.12 (in `.venv`)
- System binaries: `rdfind` (apt; the dedup engine, must not be replaced), `sshpass` + `ssh` + `rsync` (NAS transfer channel to nas-ts453a), passwordless `sudo -n crontab -l -u <user>` for each user in `CRONTAB_USERS` (used by `refresh_load_bearing_paths.py` for a crontab-discovery classification signal). `crosshost_verify.py` reuses the same `sshpass`/`ssh` channel, plus `sha256sum` on every target host (present on both BusyBox and GNU coreutils) and passwordless `sudo -n` on trigkey for a small number of root-owned-file reads.
- Test-only: `pytest>=8.0` (`requirements-dev.txt`, `tests/`) — automated suite for `crosshost_verify.py` and the 1.4.0 NAS dedup, including the codebase-wide delete/move guard. Run: `.venv/bin/pytest tests/ -v` (the NAS-dedup DB tests build and drop a throwaway `diskaudit_t_*` schema; no production row is written).
- NAS side (nas-ts453a, not a local dependency but must be documented): BusyBox v1.24.1 multi-call binary providing `find`/`stat`/`xargs` (no GNU-only flags like `-printf` or `xargs -d`/`-a`), invoked via bash 3.2.57 in sh-compat mode (NOT BusyBox ash). No Python or package manager on the NAS.
- Database: PostgreSQL, schema `diskaudit` in database `ultra_crm` at `127.0.0.1:5432`. Credentials source-of-truth: `/srv/forge/.secrets/prod/diskaudit.env` `POSTGRES_URL`.
- Systemd: `diskaudit-*` units (`.service`+`.timer` pairs) for scheduling: scan, nas-crawl, nas-dedup, monitor, classification-refresh, load-bearing-refresh, prescab-review.
- Planned future addition: `restic` (install latest ARM64 GitHub release binary directly, NOT the apt package which is a stale 0.16.4 predating the 0.18.0 chunk-shuffling fix) — for an upcoming backup-migration phase, not yet installed.

## Hard constraint

Never auto-deletes or auto-moves files. Every status/label is advisory —
actual delete/move decisions are made by the operator, informed by this
system's reports.
