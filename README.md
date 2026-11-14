# HavnVard

**Know that every file you care about is backed up, prove the backups restore, and find any file in any backup.**
HavnVard is a self-hosted storage-assurance toolkit for a home or small-office fleet: a few Linux machines, a NAS and
a cloud account. Version 3.3.3.

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

## Known limits in 3.3.0

* `migrations/` is the change history of the original deployment, not an install path; new sites use
  `schema/baseline.sql` (see "Database").
* Database tests run only against a scratch database you name in `HAVNVARD_TEST_DSN` (see `tests/README.md`).
* Windows and phone clients are not built.

## Install HavnVard Backup

HavnVard Backup (2.0.0) turns restic into a HavnVard feature: one always-on **hub** keeps an encrypted, append-only
repository per device; the hub copies to a NAS and uploads to any cloud storage rclone supports.
**Long-term storage (3.2.0):** nothing is ever deleted from a backup unless its owner orders it. There is no
automatic clean-up; `prune` needs a rule, the owner's own password file and a typed confirmation, and never removes
snapshots tagged `archive`.
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
Renders the append-only rest-server unit and the disk guard, health and catalog timers (no prune timer: nothing is deleted on a schedule) into `./out/` and prints the
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

### 3. Hub-side passwords (so the hub can name backups and run drills)
Append-only devices cannot delete. For the hub to read each repo (catalog, restore drills), copy each device's `restic.pass` to the hub as
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
python -m backup health          # every backup stream of every device (> 26 h), last job, hub and NAS free space, offsite; non-zero on any problem
python -m backup prune my-laptop --keep-monthly 12 --owner-key ~/my-laptop.pass   # hub only, owner's order only: no default rule,
                                 # shows what would go, then asks you to type "DELETE FROM my-laptop <N> SNAPSHOTS BY RULE keep_monthly=12";
                                 # archive-tagged snapshots always kept; the hub's stored password is refused
python -m backup restore-drill my-laptop   # restores 20 random files, full SHA-256 compare, prints X/Y matched
python -m backup coverage-sync my-laptop    # mark files BACKED_UP_UNVERIFIED (never VERIFIED: a listing is not a hash check) when the latest snapshot holds the same path+size+mtime
python -m backup not-backed-up --host agent-1 --by folder --limit 25   # biggest NOT backed-up folders (or --by type)
python -m backup check-timers   # list havnvard-restic-* timers whose script or backup source no longer exists
```

**An offsite uploader that runs on another machine (3.3.2).** Some cloud drives are reachable only through a desktop
app's sync folder, so the upload runs on that desktop, not on the hub, and the hub's own `offsite` checks never see it.
Have that uploader write a status file and tell the hub how to fetch it, in `backup.toml` on the hub:
```toml
[offsite_remote.cloud-desk]
status_command = ["ssh", "-o", "BatchMode=yes", "desktop-1", "cat", ".local/state/offsite-cloud.status.json"]
expect_source = "agent-1:/srv/hub/restic-hub"   # default: "<this hostname>:<[hub_local] repo_root>"
```
The status file is one JSON object: `{"source": "<host>:<folder it read>", "at": <epoch>, "rc": <exit>, "flagged": <n>,
"hold": [repos], "repos": {"<repo>": {"ok_at": <epoch of its last full upload>}}}`. `health` reports a problem when the
file cannot be fetched or read, when the uploader read **any folder other than this hub** (for example a retired hub it
was never re-pointed from), when its last run failed or is older than `offsite_stale_hours`, and for every hub repo not
fully uploaded within that limit. Offsite problems raise only their own alert key, `havnvard-offsite-stale`
(`havnvard-offsite-stale-<hub>` through `health-relay`), resolved only when every offsite check passes; they never fire the main health key.

**Every backup stream of every device (3.3.3).** One repository often holds several streams: restic groups snapshots
by host + paths, so a server that backs up its home folder and twenty app folders into one repository has 21 streams.
`health` used to look only at the newest snapshot file of the repository, so one fresh stream hid every stopped one.
Where the hub has the device's hub-side password (`~/.config/havnvard/hub-passwords/<repo>.pass`, the same file the
catalog uses), `health` now reads the snapshot list (`restic snapshots --no-lock --no-cache`: read-only) and reports
`device <repo>` as a problem when **any** stream's newest snapshot is older than the limit, naming each stale stream.
Settings, in `backup.toml` on the hub:
```toml
[health]
stale_hours = 26          # default limit for every device
check_streams = true      # "auto" (default): stream check where a hub-side password exists; true: a missing password is a problem
restic = "~/.local/bin/restic"   # optional; useful when health runs over ssh (health-relay) with a short PATH

[health.devices.laptop-1]
stale_hours = 48          # this device only

[health.devices.server-1]
retired_streams = ["server-1|/srv/old-app"]   # "host|path[|path...]": streams that stopped on purpose; counted, not judged
```
**Copy lag:** a device whose backups reach the hub only through a daily copy (for example app streams that a server
backs up locally and a scheduled `restic copy` brings to the hub) keeps its original snapshot times, so a stream backed
up just after the copy reaches almost 48 h before the next one lands. Give that device `stale_hours` above 24 h plus the
copy interval (for example 52), not the 26 h default.

A stale device raises its own alert key, `havnvard-device-stale-<repo>` (also through `health-relay`), resolved by the
first run that finds every stream fresh; alertlib keeps it to one notice per incident. A repository the hub cannot read
(no password with `check_streams = true`, restic missing or failing) is never "fresh": it is a `stream check <repo>`
problem on the main key, the device key is left as it was, and the newest-file age check still runs. A
`[health.devices.<name>]` that names no hub repository is a problem too (a typo would silently leave the real device on
the default limit).

A hub without `alertlib` (agent-1): on the server run `python -m backup health-relay --ssh agent-1 --python PATH --repo-dir DIR`
(or render an hourly timer with `--render-units ./out`). It runs `health --json --no-alert` on the hub and raises or
resolves the alert locally; a failed ssh or unreadable output is itself an alert.

Alerts go through the shared `alertlib`; if it cannot be reached `health` says `ALERT NOT SENT` and still exits non-zero.
**A device is not backed up until `restore-drill` prints all files matched.**

### Long-term storage: offload, pull back, find, delete on purpose (3.2.0)
Nothing is ever deleted from a backup unless its owner orders it. New backups use 64 MiB pack files, so no file in a
repository comes near 4 GB; an interrupted upload (Wi-Fi drop) is resent on the next run.
```bash
python -m backup offload ~/Photos/2019        # archive + read EVERY file back, SHA-256; prints X/Y VERIFIED + the list.
                                              # HavnVard deletes nothing; you delete the VERIFIED files yourself
python -m backup find tax2021                 # every backed-up version of a file
python -m backup pullback ~/Docs/tax2021.pdf ~/Docs/notes.txt   # space-separated; newest backup holding each
python -m backup pullback --date 2026-11-13                     # everything offloaded that day
python -m backup pullback --date 2026-11-13 --vanished          # everything that disappeared that day
python -m backup pullback --from my-laptop --key-file ~/laptop.pass --login-file ~/laptop-login.pass ~/Photos --target ~/restored
python -m backup forget-before my-laptop 2020-01-01 --owner-key ~/laptop.pass   # hub; shows the list, asks for exact text
python -m backup forget-after  my-laptop 2026-11-01 --owner-key ~/laptop.pass
```
`pullback` never overwrites: an existing identical file is left alone; an existing different file is kept and the backed-up
copy is written next to it as `NAME_PULLBACK-YYYYMMDD-HHMM.EXT` (`PULLBACK` in capitals, the extension stays last; a
second pullback of the same backed-up file finds that copy and writes nothing). `pullback FILE --snapshot ID` restores only
the files named (3.3.0; 3.2.0 restored the whole snapshot, INFRA-578). Archive snapshots survive every keep rule and every
`forget-*` unless `--include-archive` (which the typed text then names). The NAS and offsite copies are copy-only, so
they still hold (and restore) snapshots the hub deleted. Offload records need `migrations/20261113_diskaudit_archive_offload_v1.sql`.

### Accounts, registration and schedules (3.3.0)
The hub can serve pages (`python -m backup hub web --listen <tailnet-ip> --port 8001`). The **company or household owns
the files**: one store per company, opened by a **store key** the administrator holds (shown once at registration; the
hub keeps only its fingerprint).
```bash
python -m backup hub setup-code            # on the hub's console: one-time code (1 hour) for the FIRST registration
# open http://<hub>:8001/register: the first account becomes the administrator; everyone else needs an invite
python -m backup hub adopt my-laptop --store-key-file ~/store.key --confirm "ADD STORE KEY TO my-laptop"   # additive
python -m backup checkin --run             # on a device (timer every 5 min): ask the hub "am I due?", run if so
```
* **Administrator** and **user** are separate accounts; the same email (and password) may hold one of each.
* **Who owns which file** is recorded: folder owners by path, the computer's primary user, or files an admin released
  to them; **a shared folder is owned by that PC's administrator.** **Not yet enforced in 3.3.0:** no hub page or
  command shows or pulls files yet, so nothing uses that filter. A user restores with their computer's own restic key
  (`find` / `pullback` on that computer), which sees everything backed up from that computer, shared folders included.
* **Disable** a user who quits or is fired: every web session stops at once, the check-in token of every computer the
  user is primary user of is revoked, and that computer's line is removed from the hub's rest-server htpasswd (kept
  aside in `hub.htpasswd.removed`), so the laptop can no longer reach its backups through the hub. The computer's own
  restic key is still in its repository (and in NAS/offsite copies) until the admin removes it with the store key:
  `python -m backup hub revoke-device-key DEVICE --store-key-file ~/store.key --confirm "REMOVE DEVICE KEYS FROM DEVICE"`
  (key removal only; no snapshot is touched). The files stay with the company.
* **Force-open:** an admin reaches a user's files only by forcing a password reset. A new random password is shown to
  the admin once; it opens only a read-only view of the notice. The user acknowledges with **their own old password**
  (or a reset code they redeem themselves): "Your administrator X reset your password on DATE and accessed all your
  files. Reason: R." Then they set their own password. The user is emailed.
* **Every admin-issued password reset** ("Reset password") carries the same mandatory notice. An admin can never reset
  another admin's password, nor an account of another company. A reset code works for 24 h, once; it ends as soon as
  anything else changes the account (the user finishes the notice, a new reset, a force-open, a disable), and redeeming
  one always leads to the notice first. It is refused when redeemed from a browser logged in as an administrator.
* **With `[mail]` configured**, the reset code and the force-open generated password go **only to the user's email**
  and are never shown to the admin (page or CLI). Without mail they are shown to the admin, and the user's page says so.
* **The user's page lists every force-open and reset for good**: when, which admin, why, who got the code, and how,
  when and from where it was acknowledged (old password or reset code). Acknowledging never removes a row.
* **Honest limits.** Without mail, an admin who redeems a user's reset code from a browser with no admin session can act
  as that user once (and acknowledge the notice); the user's page then shows "acknowledged with a reset code" with the
  address and browser. As root, `pullback` does not write into a folder another user controls (not root-owned, or
  group/other-writable): run it as that user, or use `--target`. What cannot be hidden: every login, reset and acknowledgement is in the
  hash-chained audit log with the client address and browser, and the user's page permanently shows how many times an
  administrator reset their password, when, by whom and why. Whoever has root on the hub can read every backup the hub
  holds a password for; the log makes tampering visible, not impossible. Logins are limited to 5 failures a minute per
  account and per address.
* **Schedules page** (`/admin/schedules`): per computer `interval`, `constant_loop` (the next run starts when the last
  ends; after a failure the gap doubles, up to 60 min), `manual` or `paused`; last run, length, next run, last check-in.
  A device that cannot reach the hub runs nothing (no 15-minute retry loop) and reports it later as a missed check-in
  (not a failed backup, so the next backup is not pushed back). A run whose end never reaches the hub is marked failed
  ("stale") after twice the longest recorded run (at least 1 h; 24 h before any run length is known), so backups
  keep being scheduled; a run end the device could not send is kept and sent at the next check-in.
* An administrator who forgot their password cannot be reset by another administrator (3.3.0 has no admin recovery
  page yet): keep two administrators and a password manager.
* State: one SQLite file `~/.local/state/havnvard/accounts.db` on the hub (600). Not yet built: file search/pull back in
  the web page (use `find` / `pullback`), SMTP invites, store-key rotation.

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
