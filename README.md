# HavnVard

**Know that every file you care about is backed up, prove the backups restore, and find any file in any backup.**
HavnVard is a self-hosted storage-assurance toolkit for a home or small-office fleet: a few Linux machines, a NAS and
a cloud account. Version 3.1.1.

> **Absolute rule: HavnVard never deletes, moves or overwrites a scanned file.** Every "duplicate", "stale" or
> "not backed up" result is a report for you to read. Deleting anything is always your decision, made by hand.

## Example setup: the home network it was built for

HavnVard was built for, and runs every day on, one family's home network:

- **An NVIDIA DGX Spark** as the always-on server. It runs the database, the web pages and the scheduled scans.
- **A QNAP NAS** as the local backup target. HavnVard also inventories it with the NAS's own BusyBox tools, so no
  extra software has to be installed on the NAS.
- **Several family members' computers** around the house, each enrolled as a backup client.
- **Every machine runs Ubuntu Linux** today.
- **Tailscale** joins them all into one private network, so every device can reach the hub and be checked, wherever
  in the world it is, without opening ports on the home router.

Nothing in the code depends on this exact hardware: the names of your machines, NAS and shares go in your site file.

## What it does (most valuable first)

| # | Function | What you get |
|---|---|---|
| 1 | **"Am I actually backed up?"** | Every file on every machine is classified as backed up or not; `not-backed-up` lists what is missing by folder and file type. Most backup tools only tell you the job ran. |
| 2 | **Encrypted backup of every machine to a hub you own** | restic repositories on an append-only rest-server: ransomware on a laptop cannot erase its backups. One command enrols a device. |
| 3 | **Proof that restores work** | `restore-drill` restores random files and compares SHA-256 fingerprints ("80/80 match"). Finding nothing to compare is a fail, not a pass. |
| 4 | **Find any file in any backup** | `where bob.txt` names the backup holding each version (`20261111_SERVER-1_000042`). The catalog is stored inside every backup, so it survives losing the hub. |
| 5 | **Safe duplicate finder across machines** | Matches by content (SHA-256), never by name; produces a list and never deletes. |
| 6 | **Offsite and second-copy** | Add-only upload of the already-encrypted repositories to any rclone remote, plus a mirror on a NAS. |
| 7 | **Bit-rot detection** | Scheduled re-hashing and multi-copy comparison (`infra126/`), so silent corruption is found while a good copy exists. |
| 8 | **Health and alerts** | Stale backups, failed jobs, free space, offsite lag; JSON output; alerts through any command you choose. |
| 9 | **Whole-disk inventory** | Every file on Linux machines and QNAP-style NAS shares in one PostgreSQL schema. |
| 10 | **Web pages** | Browse duplicates, cleanup candidates and backup coverage; export CSV/JSON. |

## Two parts, two install paths

* **HavnVard Backup (`backup/`)** — Python 3.11+ standard library and restic. No database needed. Start with
  "Install HavnVard Backup" below. Functions 2, 3, 4, 6 and 8.
* **Inventory, dedup and verification (top-level scripts, `infra126/`, `webapp/`)** — needs PostgreSQL (schema
  `diskaudit`, built in one step from `schema/baseline.sql`, see "Database") and a site file. Functions 1, 5, 7, 9 and 10.

## Site file (inventory tools)

Everything that differs between installations lives in one TOML file: `/etc/havnvard/site.toml`,
`~/.config/havnvard/site.toml`, or the path in `$HAVNVARD_SITE`. Copy `config/site.example.toml` and edit it.
It names your hosts (the local machine, the NAS, remote "agent" machines), the database env file, the NAS and the
optional alert/report integrations. **It never holds a password:** it names the files that hold them.

## Known limits in 3.1.1

* `migrations/` is the change history of the original deployment, not an install path; new sites use
  `schema/baseline.sql` (see "Database").
* Database tests run only against a scratch database you name in `HAVNVARD_TEST_DSN` (see `tests/README.md`).
* Windows and phone clients are not built.

## Install HavnVard Backup

HavnVard Backup (2.0.0) turns restic into a HavnVard feature: one always-on **hub** keeps an encrypted, append-only
repository per device; the hub prunes, copies to a NAS and uploads to any cloud storage rclone supports.
Everything is `python -m backup ...` (Python 3.11+, standard library only). **Nothing here runs sudo or installs a
service for you: the tool writes the unit files to `./out/` and prints the commands for you (or your Claude) to run.**
To let Claude drive the install, tell it: "set up HavnVard Backup, follow CLAUDE_SETUP.md".

### Before you start
- One always-on Linux machine as the hub, with a disk at least 2 x the data to back up, formatted **ext4** (not exFAT or NTFS).
- Every device can reach the hub: same home network, or Tailscale.
- Admin (sudo) rights on the hub; ordinary user rights on each device.
- `restic` and `rclone` on the machines that use them; [`rest-server`](https://github.com/restic/rest-server) on the hub.
- A cloud storage account for the offsite copy: your existing Google Drive, OneDrive or Internxt works, plus about 10
  minutes to authorise rclone. **Suggested, not required:** a separate account used only for backups, so a hacked everyday
  account cannot reach the backups and the backups do not eat its quota.
- A password manager or paper for each device's backup password. **Without it a lost device's backups cannot be read.**
  `enroll` creates the password and never prints it: copy `~/.config/havnvard/restic.pass` into your password manager now.

### 1. Install the hub (on the hub machine)
```bash
python -m backup hub install --repo-root /data/restic-hub --listen <hub LAN or Tailscale address> --port 8000
```
Renders the append-only rest-server unit and the disk guard, health and prune timers into `./out/` and prints the
install commands. The disk guard stops the hub below 100 GB free and restarts it at 125 GB, so a backup can never fill
the disk. `--listen` defaults to loopback, which no other device can reach.

### 2. Choose the hub and enrol each device (on every device, including the hub itself)
```bash
python -m backup hub set <hub-host>[:8000]
python -m backup enroll my-laptop --paths ~/Documents ~/Pictures --excludes generic \
    --limit-upload 4096 --quiet-hours 08-18
```
`enroll` creates `~/.config/havnvard/restic.pass` and `rest.pass` (random, mode 600, never overwritten if present), the
excludes file, and the backup timer in `./out/`. It prints one line to append to the hub's `.htpasswd` (a hash, not the
password). Then `python -m backup client-run --init` makes the first backup. `--limit-upload` caps upload in KiB/s (0 = none).
`--quiet-hours 08-18` means no backup starts in those local hours. Excludes profiles: `generic`, `ml-workstation`, `desktop-sync`, or your own file.
Alerts: `[alerts] command = ["your-notifier"]` in `~/.config/havnvard/backup.toml` (any program; key and text arrive in
`HAVNVARD_ALERT_KEY`/`HAVNVARD_ALERT_TEXT`), or `[alerts] alertlib_path = "/path/to/alertlib"` if you run alertlib.

### 3. Hub-side passwords (so the hub can prune and copy)
Append-only devices cannot delete or prune. For the hub to do that, copy each device's `restic.pass` to the hub as
`~/.config/havnvard/hub-passwords/<device>.pass` (mode 600, over SSH or by hand; never by chat).

### 4. Offsite copy to any rclone remote (on the hub)
```bash
rclone config                                   # authorise Google Drive, OneDrive or Internxt once
python -m backup offsite add gdrive --rclone-remote gdrive:havnvard-backup
python -m backup offsite add gdrive-crypt --rclone-remote gdrive-crypt: --crypt   # optional: an rclone crypt remote
python -m backup offsite run                    # resumes where it stopped; run it from a timer
```
The repos are already encrypted by restic; `--crypt` additionally hides file names. Uploads are copy-only, never delete
anything the hub has, and a file that keeps coming back damaged is flagged and reported (and shown by `health`).

### 5. Second on-site copy on the NAS (optional)
```bash
python -m backup nas-target --smb //nas/havnvard-bkup --user havnvard --cred-file ~/.config/havnvard/nas.cred --mountpoint /mnt/havnvard-nas
python -m backup nas-copy
```
Uses a normal SMB user (the NAS only allows SSH for administrators). `nas-target` renders the mount unit; the admin
step is printed. `nas-copy` mirrors the already-encrypted repo files (no passwords needed on the hub). Put the NAS password into the credentials file yourself; never paste it in chat.

### 6. Watch it and prove it
```bash
python -m backup health          # snapshot age (> 26 h), last job, hub and NAS free space, offsite; non-zero on any problem
python -m backup prune           # hub only; default keep 7 daily, 4 weekly (no monthly; the operator 20261111); --dry-run first
python -m backup restore-drill my-laptop   # restores 20 random files, full SHA-256 compare, prints X/Y matched
python -m backup coverage-sync my-laptop    # mark files BACKED_UP_UNVERIFIED (never VERIFIED: a listing is not a hash check) when the latest snapshot holds the same path+size+mtime
python -m backup not-backed-up --host agent-1 --by folder --limit 25   # biggest NOT backed-up folders (or --by type)
python -m backup check-timers   # list havnvard-restic-* timers whose script or backup source no longer exists
```

A hub without `alertlib` (agent-1): on the server run `python -m backup health-relay --ssh agent-1 --python PATH --repo-dir DIR`
(or render an hourly timer with `--render-units ./out`). It runs `health --json --no-alert` on the hub and raises or
resolves the alert locally; a failed ssh or unreadable output is itself an alert.

Alerts go through the shared `alertlib`; if it cannot be reached `health` says `ALERT NOT SENT` and still exits non-zero.
**A device is not backed up until `restore-drill` prints all files matched.**

### Restore one file
```bash
export RESTIC_REPOSITORY=rest:http://<hub>:8000/<device>/ RESTIC_PASSWORD_FILE=~/.config/havnvard/restic.pass
export RESTIC_REST_USERNAME=<device> RESTIC_REST_PASSWORD="$(cat ~/.config/havnvard/rest.pass)"
restic snapshots && restic restore latest --target /tmp/restore --include /home/me/Documents/file.txt
```

### Phones
HavnVard Backup 2.0 installs nothing on phones. Put phone data in a folder that a backed-up computer receives (for
example with Syncthing, Immich or a cable copy) and include that folder in `--paths`.

**Full install guide, Android (Syncthing-Fork) and iPad (idevicebackup2 on plug-in):
[`docs/20261112_PHONES_AND_TABLETS.md`](docs/20261112_PHONES_AND_TABLETS.md).** Read its warnings first.
Your mileage may vary. In short:

- ⚠️ **Android with lots of file movement: consider SEND ONLY from the phone to the HavnVard hub, and set the
  matching folders on the hub the same way (one hub folder per phone folder, Receive Only).** One-way flow means
  nothing done on the hub can change or delete files on the phone. Send Only does not stop a phone-side delete
  reaching the hub: restic snapshots are what bring a deleted file back.
- ⚠️ **Set Num Connections to 6** in the phone's **Web GUI** (Syncthing-Fork ☰ → Web GUI → Actions → Advanced →
  Devices → hub). It is not on the app's device screen. Set the same on the hub. Measured here: 1 connection
  10.8 MiB/s, 4 connections 19.5 MiB/s.
- ⚠️ **If you set run conditions (Wi-Fi only and/or while charging), use FORCE START (ignore run conditions)** for
  the big first sync, then turn it off again. Otherwise syncing silently stops whenever a condition is not met.
- ⚠️ **Playing with the Advanced settings is like handling dynamite: do so cautiously.** One change at a time, note
  the old value, pause a folder before experimenting. No undo.

## Files

| File | Purpose |
|---|---|
| `scan.py` | Whole-disk metadata crawler (path/size/perms/owner/timestamps). Run locally per host; `--host`/`--root` flags let it tag rows for a different host name if crawling a mount. |
| `scan_guard.py` | **1.4.3 (INFRA-522):** per-(host, root) Postgres advisory scan lock (a second scan of the same root is refused, exit 3) and per-scan `files_staging` cleanup, used by scan.py and load_nas_inventory.py. Needs migration `20261109_diskaudit_files_staging_scan_id_v1.sql`. |
| `verify_tree.py` | **1.5.0 (INFRA-538):** full-byte proof before any copy is deleted. SHA-256 of every byte on BOTH sides in the same run (NAS side hashed on the NAS), exact file-list match, and a built-in canary before any result is trusted (1.6.0, the operator 20261110: 5 identical copies of an 8.5 MB book text + 1 copy with one `m`→`M` in the last partial 4 MiB chunk, at a position that changes every run, must read as exactly that one file different; 6 identical copies must all read equal). Exit 0 VERIFIED / 3 not / 4 canary failed. Records `diskaudit.tree_verifications` + `integrity_checks` (`basis='fresh'`); `mark-deleted --run-id` links each deletion. Called by spark-backup-db.sh / spark-backup-daily.sh before deleting a local backup dir. Needs migration `20261110_diskaudit_tree_verify_v1.sql`. |
| `heartbeat.py` | Shared heartbeat/progress-tracking helpers used by scan.py, dedup.py, load_nas_inventory.py during long-running jobs. |
| `bucketing.py` | LPT (longest-processing-time) bin-packing for parallel dedup worker assignment; also handles `ARG_MAX`-safe chunking of same-size candidate groups. |
| `dedup.py` | rdfind integration + parallel worker orchestration for duplicate detection. |
| `monitor.py` | Polls for stale/failed scan and dedup runs every 5 min, alerts to TG PRESI group. Idempotent. |
| `nas_native_crawl.sh` | BusyBox-only (no Python/package manager needed) crawl script, scp'd to and run directly on the NAS. Writes results to a flat file on the NAS's own real disk (never `/tmp` — small tmpfs shared with live NAS processes). |
| `load_nas_inventory.py` | Orchestrates one NAS share: runs `nas_native_crawl.sh` over SSH, ships results back, loads into the same schema as scan.py, tagged `host=nas-1`. `--share <name>` per invocation. |
| `run_all_nas_shares.sh` | Loops `load_nas_inventory.py` across every known NAS share; continues past a per-share failure instead of aborting the whole run. |
| `refresh_load_bearing_paths.py` | Builds the "load-bearing override" registry (cron/systemd/thoth.census cross-reference) that protects cold-but-live files from being misclassified as abandoned. Bounded scope, full per-run audit trail (`diskaudit.load_bearing_refresh_runs`). |
| `refresh_classification_mv.py` | Refreshes the `diskaudit.mv_file_status` materialized view (the classification layer: active/load-bearing/stale/possibly-obsolete/orphaned). |
| `weekly_prescab_review.py` | Assembles current diskaudit state and dispatches to PRESCAB (vp-operations, logic_governance mode) for a weekly trend review. Logged to `jobs.cabinet_runs`. |
| `crosshost_verify.py` | Cross-host SHA-256 content verification (no NAS mount needed). Subcommands: `candidates` (report the size-based candidate set, no hashing), `hash --host <h>` (hash one host's candidates; resumable, inode-aware, heartbeat-tracked), `match` (join hashes across hosts, populate `duplicate_group_id` + `diskaudit.integrity_checks`), `report` (render markdown reports via `report.py`). |
| `hash_batch.sh` | POSIX/BusyBox-compatible remote hashing script, scp'd to and run on nas-1/agent-1 by `crosshost_verify.py hash`; deleted from both sides after results are loaded. Read-only; includes a passwordless-`sudo` READ fallback (sha256sum only) for root-owned files, a no-op where sudo doesn't exist (NAS). |
| `nas_trigkey_dedup.py` | Within-host dedup for nas-1/agent-1 (1.4.0 rewrite): plan -> size-aware hash batches -> one-transaction publish. See the paragraph above and RUNBOOK. |
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

Systemd timers (all on the server):
- `diskaudit-scan.timer` — daily 08:00, full local scan
- `diskaudit-nas-crawl.timer` — every 4 h at :20 (00/04/08/12/16/20), full NAS crawl (all shares)
- `diskaudit-nas-dedup.timer` — weekly Sunday 02:00, NAS within-host dedup with `bkup_server` excluded (installed; enabled only after the release gate passes once)
- `diskaudit-monitor.timer` — every 5 min, health check + TG alerting
- `diskaudit-prescab-review.timer` — weekly, Sunday 18:00 UTC
- `diskaudit-load-bearing-refresh.timer`, `diskaudit-classification-refresh.timer` — periodic classification-layer refresh

Manual invocation:
```
sudo /opt/havnvard/.venv/bin/python scan.py            # full the server scan
sudo /opt/havnvard/run_all_nas_shares.sh                # full NAS crawl
```

## Database

Schema `diskaudit` (PostgreSQL 15+). Core table `diskaudit.files` (`(host, path)` primary key). Key views:
`v_duplicate_groups`, `v_file_status`, `v_backup_coverage`.

**New install:** create an empty database, put its URL in the env file your site file names (`POSTGRES_URL=...`),
then build the whole schema in one step:

```bash
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 --single-transaction -f schema/baseline.sql
```

Then give each of your hosts a bit-rot verification schedule (the monitor's overdue alarm checks these rows; the
example is at the end of `schema/seed.sql`):

```bash
psql "$POSTGRES_URL" -c "INSERT INTO diskaudit.hash_verification_sla (host, tier, target_recheck_days, schedule_mode)
  SELECT h, t, d, m FROM unnest(ARRAY['server-1','nas-1']) AS h,
       (VALUES ('A',7,'weekly'),('B',30,'monthly'),('C',90,'quarterly'),('E',1,'daily')) AS s(t,d,m)
  ON CONFLICT (host, tier) DO NOTHING"
```

`schema/baseline.sql` is the current schema plus generic starting rules (`schema/seed.sql`: OS, cache and temp paths
excluded from backup coverage; QNAP system folders). It names no hosts: every scan writes its own host name. The
load-bearing-path refresh reads an optional external `thoth.census` registry; without one it scans systemd and
crontab only and logs the skip. Add your
own rules with plain `INSERT`s afterwards.

`migrations/` is the change history of the original deployment (see `migrations/README.md`); a new site does not run
it. Maintainers regenerate the baseline after a schema change with `scripts/make_baseline_schema.py` (pass
`--site-names <your private names file>`; see `migrations/README.md`), which refuses to
write a file that still names a private host.

## Dashboard

Grafana: `https://server-1.example.ts.net:9452/d/diskaudit/diskaudit`

## Requirements

- Python 3.12.12 (in `.venv`)
- System binaries: `rdfind` (apt; the dedup engine, must not be replaced), `sshpass` + `ssh` + `rsync` (NAS transfer channel to nas-1), passwordless `sudo -n crontab -l -u <user>` for each user in `CRONTAB_USERS` (used by `refresh_load_bearing_paths.py` for a crontab-discovery classification signal). `crosshost_verify.py` reuses the same `sshpass`/`ssh` channel, plus `sha256sum` on every target host (present on both BusyBox and GNU coreutils) and passwordless `sudo -n` on agent-1 for a small number of root-owned-file reads.
- Test-only: `pytest>=8.0` (`requirements-dev.txt`, `tests/`) — automated suite for `crosshost_verify.py` and the 1.4.0 NAS dedup, including the codebase-wide delete/move guard. Run: `.venv/bin/pytest tests/ -v` (the NAS-dedup DB tests build and drop a throwaway `diskaudit_t_*` schema; no production row is written).
- NAS side (nas-1, not a local dependency but must be documented): BusyBox v1.24.1 multi-call binary providing `find`/`stat`/`xargs` (no GNU-only flags like `-printf` or `xargs -d`/`-a`), invoked via bash 3.2.57 in sh-compat mode (NOT BusyBox ash). No Python or package manager on the NAS.
- Database: PostgreSQL, schema `diskaudit` in database `havnvard` at `127.0.0.1:5432`. Credentials source-of-truth: `/etc/havnvard/havnvard.env` `POSTGRES_URL`.
- Systemd: `diskaudit-*` units (`.service`+`.timer` pairs) for scheduling: scan, nas-crawl, nas-dedup, monitor, classification-refresh, load-bearing-refresh, prescab-review.

## Hard constraint

Never auto-deletes or auto-moves files. Every status/label is advisory —
actual delete/move decisions are made by the operator, informed by this
system's reports.

**Delete-basis rule (the operator 20261109, INFRA-538):** no copy may be deleted unless 100% of its
bytes were proven equal to the kept copy in the same run: `verify_tree.py` (rows with
`basis='fresh'`) or the delete script's own in-run rehash. Size, mtime, a partial hash or a
digest read back from `diskaudit.files` (`basis='stored'`, crosshost `match`) never count.

## Credits

HavnVard is glue and safety rules around excellent open-source tools. It runs them or imports them as ordinary
dependencies, under their own licenses. The one file shipped inside this repository is htmx (`webapp/app/static/htmx.min.js`),
with its license beside it and in `NOTICE`.

| Project | What HavnVard uses it for | License |
|---|---|---|
| [restic](https://github.com/restic/restic) | Every backup: encrypted, deduplicated snapshots, `check`, `restore` | BSD-2-Clause |
| [rest-server](https://github.com/restic/rest-server) | The hub's append-only repository server | BSD-2-Clause |
| [rclone](https://github.com/rclone/rclone) | Offsite copy to Google Drive, OneDrive, Internxt or any other remote | MIT |
| [PostgreSQL](https://www.postgresql.org/) | The inventory database | PostgreSQL License |
| [psycopg](https://github.com/psycopg/psycopg) | Python access to PostgreSQL | LGPL-3.0 |
| [rdfind](https://github.com/pauldreik/rdfind) | Fast duplicate finding on Linux hosts (run as a separate program) | GPL-2.0-or-later |
| [BusyBox](https://busybox.net/) | `find`, `stat` and `sha256sum` on the NAS (the NAS's own copy; nothing installed) | GPL-2.0 |
| [FastAPI](https://github.com/fastapi/fastapi), [Uvicorn](https://github.com/Kludex/uvicorn) | The web pages | MIT, BSD-3-Clause |
| [Jinja2](https://github.com/pallets/jinja), [MarkupSafe](https://github.com/pallets/markupsafe) | Page templates | BSD-3-Clause |
| [htmx](https://github.com/bigskysoftware/htmx) 1.9.10 | Live-updating web pages (copy included) | BSD-2-Clause |
| [Flask](https://github.com/pallets/flask) | Optional: the bit-rot verification pages (`infra126/web/`) | BSD-3-Clause |
| [OpenSSH](https://www.openssh.com/), [rsync](https://rsync.samba.org/), [sshpass](https://sourceforge.net/projects/sshpass/) | Reaching the NAS and remote machines; copying files (run as separate programs) | BSD, GPL-3.0, GPL-2.0 |
| [asyncpg](https://github.com/MagicStack/asyncpg) | Database access for the web pages | Apache-2.0 |
| [pytest](https://github.com/pytest-dev/pytest) | The test suite | MIT |
| [Tailscale](https://tailscale.com/) | Optional: the private network between machines (the setup above) | BSD-3-Clause (client) |
| [Grafana](https://github.com/grafana/grafana) | Optional: dashboards over the same database | AGPL-3.0 |

Thanks to the people who build and maintain them. The web-page header and footer (`webapp/app/static/forge-chrome/`)
come from the authors' own UI kit.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
