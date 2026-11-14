# FEATURES — HavnVard (technical/module name: diskaudit)

**How to use the features.** For an operator who is new to HavnVard.

**Last updated: 2026-11-11 (2.0.0 adds HavnVard Backup)**

## ⚠️ ABSOLUTE CONSTRAINT — READ FIRST

**HavnVard/diskaudit NEVER deletes, moves, or overwrites any scanned file.**
Every feature below — including ones with names like "duplicate detection,"
"orphan," "stale," "backup coverage," or "reclaimable space" — produces
**labels, reports, and classifications only**. Nothing in this system ever
runs `rm`/`unlink`/`mv`/any delete API against a scanned file, on the server, the
NAS, or any client. Wherever a feature's name could be misread as "this cleans
things up automatically," this doc says so explicitly: it doesn't. Every
delete/move decision is yours (the operator's) alone, made by reading these reports.

---

## Quick reference

| Feature | Status | Command |
|---|---|---|
| Whole-disk inventory scan (the server) | **WORKING** | `sudo /opt/havnvard/.venv/bin/python scan.py` |
| Whole-disk inventory scan (NAS) | **WORKING** | `sudo /opt/havnvard/run_all_nas_shares.sh` |
| Client-host onboarding + scan | **WORKING** | see `CLIENT_INSTALL.md`; live example: `agent-1` (380,102 files) |
| Duplicate detection (dedup.py / rdfind) | **WORKING** | `python dedup.py --host server-1` |
| Within-host duplicate detection (nas-1 / agent-1 — no rdfind available) | **WORKING** (new, 2026-07-25) | `python nas_trigkey_dedup.py --host nas-1 \| agent-1` |
| Cross-host content-hash verification | **PARTIAL** (new, in flight on this branch, 2026-07-25) | `python crosshost_verify.py candidates \| hash \| match \| report` |
| HavnVard Backup: hub install, enrol a device, client backup (restic, append-only) | **WORKING** (2.0.0) | `python -m backup hub install \| hub set \| enroll \| client-run` |
| HavnVard Backup: offsite to any rclone remote (optional crypt), NAS second copy | **WORKING** (2.0.0) | `python -m backup offsite add \| offsite run \| nas-target \| nas-copy` |
| HavnVard Backup: `health` watches an offsite uploader on another machine (`[offsite_remote]` status file): wrong/retired source hub, failed or stopped runs and per-repo upload age are problems; own alert key `havnvard-offsite-stale` only (never the main health key) (also via `health-relay`) | **SHIPPED code 3.3.2** | `python -m backup health \| health-relay` |
| HavnVard Backup: `health` checks every backup stream (restic host + paths) of every device with a per-device limit (`[health.devices.<repo>]` `stale_hours`, `retired_streams`); own alert key per device `havnvard-device-stale-<repo>` (also via `health-relay`); an unreadable repository is a loud `stream check` problem, never a fresh device | **SHIPPED code 3.3.3** | `python -m backup health \| health-relay` |
| HavnVard Backup: health (stale snapshot, job result, free space), owner-ordered prune (no automatic deletion, 3.2.0), restore drill | **WORKING** (3.2.0) | `python -m backup health \| prune \| restore-drill DEVICE` |
| HavnVard Backup: accounts (first account = admin with setup code, invites, admin/user, disable cuts web sessions, device check-in tokens and the device's hub login; force-open = new random password, the user's OLD password reaches only a notice (admin, date, reason, 'accessed all your files') that only the user acknowledges, then the user sets their own password; with `[mail]` set the code goes only to the user's email; every force-open and reset stays listed on the user's page; login rate limit; admin-only release; shared folder owned by the PC admin; hash-chained audit) · pullback (identical file skipped, same name different content -> NAME_PULLBACK-YYYYMMDD-HHMM.EXT, missing folders recreated, a folder that refuses files: carries on, lists every item, exits 1, popup until clicked + hub notice until dismissed; as root, never writes into a folder another user controls) · schedules page + device check-in (interval / constant loop with run lengths, stale-run expiry) | **SHIPPED code 3.3.0** (hub web app and device check-in not switched on for existing computers yet) | `python -m backup hub setup-code \| hub web \| hub adopt \| hub force-open \| checkin --run` |
| File-status classification (active/load-bearing/stale/possibly-obsolete/orphaned) | **WORKING** | query `diskaudit.v_file_status` / `diskaudit.mv_file_status` |
| Load-bearing override (protect cold-but-live infra files) | **WORKING** | `python refresh_load_bearing_paths.py` |
| Backup-coverage check (critical_patterns-scoped) | **WORKING** | query `diskaudit.v_backup_coverage` |
| TRUE backup-coverage classifier (complete file universe) | **WORKING** (new, 2026-07-25) | `python backup_coverage.py classify --host server-1 \| agent-1` |
| NAS-orphan detection | **WORKING** | query `diskaudit.v_nas_orphans` (original deployment only: the view names one NAS host, so `schema/baseline.sql` leaves it out) |
| Stale/failed run monitor + TG alert | **WORKING** | `python monitor.py` (runs every 5 min via timer) |
| Daily metadata report to TG PRESI | **WORKING** | `python havnvard_report.py` |
| Weekly PRESCAB operational review | **WORKING** | `python weekly_prescab_review.py` |
| Grafana dashboard | **WORKING** | `https://server-1.example.ts.net:9452/d/diskaudit/diskaudit` |
| Restic backup engine (10 targets) | **WORKING** (Phase 2, live — docs elsewhere call it "planned," that's stale) | `sudo systemctl start havnvard-restic-<target>.service` |
| "Abandoned due to software lifecycle change" detection | **PLANNED** (v2 differentiator vs generic disk-usage tools — flagged in `module.yaml` risks as NOT YET DESIGNED) | — |
| Automated test suite | **STUBBED** (no tests exist; verification is manual/live-data only, see `tests/README.md`) | — |
| **HavnVard UI (web app)** — DEDUP/CLEANUP/BACKUP browsing + export | **WORKING** (added 20260725) | `https://server-1.example.ts.net:9457` (Tailnet-only) |

---

## 1. Whole-disk inventory scan (the server) — WORKING

**What it does:** Crawls the root filesystem (single ext4 device, `-xdev`
style — does not cross into other mounts), recording path, size, permissions,
owner/group, inode, nlink, extension, mtime/atime/btime for every file into
`diskaudit.files`. **Metadata only — it never reads file contents in this
step.** Files that disappear between scans are marked `still_exists=false`,
never dropped from history.

**Why you'd use it:** Baseline inventory — "what's actually on this disk, and
how has it changed since last time." Everything else (dedup, classification,
backup-coverage) is built on top of this table.

**Command:**
```bash
cd /opt/havnvard && source .venv/bin/activate
python scan.py --dry-run --root /home/user      # cheap bounded validation run first
sudo .venv/bin/python scan.py                      # full real run (root needed to read cross-user homes)
```

**Worked example (validated live 2026-07-25):**
```bash
$ PGPASSWORD=... psql -U havnvard -h 127.0.0.1 -d havnvard -c \
    "select host, count(*) from diskaudit.files group by host;"
    host    |  count
------------+----------
 nas-1 |  2290057
 server-1 | 10719162
 agent-1    |   380102
```

**Expected output:** rows in `diskaudit.files` (upserted, keyed `(host,
path)`), a `diskaudit.scan_runs` row transitioning `running → completed`, and
(if any files errored during stat) rows in `diskaudit.scan_errors`. Scheduled
daily 08:00 via `diskaudit-scan.timer` on the server.

**Never deletes/moves anything** — read-only `stat()`/`statx()` against the
filesystem.

## 2. Whole-disk inventory scan (NAS) — WORKING

**What it does:** Same inventory as above, but for `nas-1`. Because
mounting the NAS (NFS/SSHFS) plateaued at ~20 files/sec, this instead SCPs a
BusyBox-compatible shell script (`nas_native_crawl.sh`) to the NAS and runs it
**natively there** over SSH — validated at ~29,300 files/sec (~1,450x faster).
Results ship back to the server as a flat file and load into the same
`diskaudit.files` table, tagged `host=nas-1`.

**Why you'd use it:** Same reason as #1, for the NAS side of the inventory.

**Command:**
```bash
sudo /opt/havnvard/run_all_nas_shares.sh          # all shares, continues past per-share failure
python load_nas_inventory.py --share Public                 # one share
python load_nas_inventory.py --share Public --dry-run       # stage only, no merge
python load_nas_inventory.py --share homes --keep-scratch   # leave crawl output for inspection
```

**Worked example:** `nas-1` currently shows 2,290,057 rows (confirmed
2026-07-25). No `btime` (birth time) is available for NAS rows — this is
expected, not an error (BusyBox has no equivalent, degrades the same way
`scan.py` does when `statx` isn't supported).

**Never deletes/moves anything** — read-only crawl; the NAS-side script never
does more than `find`/`stat`.

## 3. Duplicate detection (dedup.py) — WORKING

**What it does:** Runs `rdfind` (size → first/last-byte → full SHA-256
elimination) against a host's known file scope, then writes a stable,
cross-host-comparable `duplicate_group_id` back onto `diskaudit.files`. One
extra representative-file hash per confirmed group derives a real content
hash (rdfind's own group ids aren't stable across runs).

**Why you'd use it:** Find real (byte-identical, cryptographically verified)
duplicate files — the basis for the "reclaimable space" figures.

**Command:**
```bash
python dedup.py --host server-1                       # scope from diskaudit.files
python dedup.py --host nas-1 --root /mnt/nas-audit  # explicit root
python dedup.py --host server-1 --parallel 4           # size-balanced parallel rdfind workers
```

**Worked example / expected output:** query
`diskaudit.v_duplicate_groups_by_host` for per-host groups, or
`diskaudit.v_duplicate_groups` for the cross-host rollup — both are
**correctly inode-deduped** (see the hardlink gotcha in RUNBOOK.md; this is
the one place in the codebase that already handles it correctly, per the
`20260717_diskaudit_reclaimable_fix_v2.sql` migration):
```sql
select count(*), sum(reclaimable_bytes_total) from diskaudit.v_duplicate_groups;
```

**Never deletes/merges/hardlinks anything** — read-only with respect to the
files being scanned; the only writes are `duplicate_group_id` values on
`diskaudit.files`.

### 3a. Within-host dedup for hosts rdfind can't reach (`nas_trigkey_dedup.py`) — WORKING (new, 2026-07-25)

**Why it exists:** `dedup.py` requires `rdfind` on the scanned host. `rdfind`
is not installed on the QNAP (`nas-1`) and can't be installed there;
mounting the NAS over the network and running rdfind against the mount is
too slow (~20 files/sec observed) to be viable. `agent-1` could technically
run rdfind directly, but this tool covers both hosts with one reusable
implementation and shares NAS-hashing infrastructure already proven in
`crosshost_verify.py`.

**What it does:** size-prefilters `diskaudit.files` candidates within a
single host, groups same-size candidates **by inode first** (same inode =
same bytes by definition — never re-hash two paths sharing an inode), then
hashes only one representative path per inode via the same
scp-script/ssh/scp-results-back `hash_batch.sh` pattern `crosshost_verify.py`
uses for cross-host verification. Digests are then fanned out locally (no
extra remote I/O) to every sibling path sharing that inode. Groups by
`sha256`, requiring **≥2 distinct inodes** (not just ≥2 rows) to count as a
real duplicate group, and writes `duplicate_group_id` via the same
`diskaudit.dedup_staging` COPY-then-merge pattern `dedup.py` already uses.

**Command:**
```bash
python nas_trigkey_dedup.py --host nas-1 --limit 200000 --batch-size 500
python nas_trigkey_dedup.py --host agent-1
```

**Never deletes/moves/overwrites anything** — same read-only contract as
`dedup.py`; writes only `duplicate_group_id` + `content_sha256` on
`diskaudit.files` via `diskaudit.dedup_runs`/`dedup_staging`.

## 4. Cross-host content-hash verification — PARTIAL (in flight, 2026-07-25)

**What it does:** New capability being built on this branch, not yet merged.
Answers two operator questions directly: "is my the server/agent-1 data genuinely,
cryptographically intact on the NAS?" and "what could I safely delete from
the server once I trust that?" Works around the fact NAS files were never run
through `dedup.py`/rdfind (no local filesystem access to the NAS) by
filtering `diskaudit.files` to sizes that appear on ≥2 hosts and are ≥1MB —
collapsing ~8.6M candidate rows to a tractable set before hashing anything.

**Command (subcommands, per its own `--help`):**
```bash
python crosshost_verify.py candidates   # build the size-based candidate set
python crosshost_verify.py hash         # hash candidates (uses hash_batch.sh under the hood)
python crosshost_verify.py match        # confirm true duplicates by hash across hosts
python crosshost_verify.py report       # markdown report of findings
```

**Status caveat:** untracked/modified on this branch as of 2026-07-25 by a
concurrent development effort — treat the CLI surface, table names
(`diskaudit.integrity_checks`, `diskaudit.crosshost_verify_runs` — both
already exist live in Postgres as of this audit) and exact behavior as
**subject to change until merged**. Re-verify against the code before relying
on it operationally.

**Never deletes/moves anything** — explicitly documented in its own docstring
as read-only against every scanned filesystem; it only writes its own DB rows,
its own log output, and its own markdown reports.

## 5. File-status classification — WORKING

**What it does:** Labels every file `active` / `load-bearing` / `stale` /
`possibly-obsolete` / `orphaned` based on age (mtime/atime) **overridden** by
a "load-bearing" registry (see #6) so a cold-but-live cron script or yearly
tool doesn't get mislabeled just because nobody touched it recently. Lives in
`diskaudit.mv_file_status` (materialized view, refreshed by
`refresh_classification_mv.py`).

**Why you'd use it:** The actual "should I look at deleting this" signal —
this is the layer that turns raw inventory into a prioritized review list.
**"Orphaned" and "possibly-obsolete" are labels for you to review, not
delete instructions** — nothing acts on these labels automatically.

**Command:**
```sql
select host, path, file_status from diskaudit.v_file_status
where file_status in ('orphaned','possibly-obsolete') limit 50;
```

**Worked example:** 7,744,739 rows currently in `diskaudit.mv_file_status`
(confirmed 2026-07-25, all 3 indexes valid).

**⚠️ CLI gotcha:** `refresh_classification_mv.py` has **no argument parsing**.
Running it with `--help` (or any other flag) doesn't print help — it
immediately runs the real `REFRESH MATERIALIZED VIEW CONCURRENTLY` (≈6
minutes against the current row count). Safe (idempotent, read-only against
scanned files) but surprising if you expected instant `--help` output.

## 6. Load-bearing override — WORKING

**What it does:** Builds `diskaudit.load_bearing_paths` by cross-referencing
a small, explicit, bounded set of sources — systemd unit `ExecStart` lines,
each `CRONTAB_USERS` entry's crontab, and `thoth.census` — so infrastructure
files that are rarely touched but still genuinely live don't get flagged
stale. Every row records exact provenance (e.g.
`systemd-unit:/etc/systemd/system/diskaudit-scan.service#ExecStart`), and
every run is logged to `diskaudit.load_bearing_refresh_runs` for full
traceability ("we don't want a grep going haywire and not knowing where it's
firing from" — the operator, 2026-07-18).

**Why you'd use it:** Prevents false positives in the classification layer
(#5) for cold-but-critical files.

**Command:**
```bash
python refresh_load_bearing_paths.py                 # real run (also refreshes the classification MV at the end)
python refresh_load_bearing_paths.py --dry-run
python refresh_load_bearing_paths.py --no-mv-refresh  # skip the trailing MV refresh
```

**Never deletes/moves anything** — read-only against systemd unit files,
crontabs, and `thoth.census`; only writes are its own registry table + run log.

## 7. Backup-coverage check — WORKING

**What it does:** Checks whether files flagged "critical"
(`diskaudit.critical_patterns`) actually have a verified copy somewhere else
(another host, or a restic backup) — a "is this safety-netted" view, not a
backup action itself.

**Command:**
```sql
select * from diskaudit.v_backup_coverage limit 50;
```

**Never backs anything up itself** — this is a read-only coverage report;
actual backing-up happens via the restic engine (#12) and NAS/dedup crawls,
independently.

**Known scope gap (fixed by #7b below, 2026-07-25):** this view only covers
files matching `diskaudit.critical_patterns` — ~46% of the table. It was
never the complete-universe answer to "what needs backing up."

## 7b. TRUE backup-coverage classifier (`backup_coverage.py`) — WORKING (new, 2026-07-25)

**What it does:** Complete-universe version of #7 — every in-scope regular
file on server-1/agent-1 gets exactly one row in `diskaudit.backup_coverage`:
`BACKED_UP_VERIFIED` (hash-proven), `BACKED_UP_UNVERIFIED` (path+size+mtime or
restic-manifest match, not hash-confirmed), `NOT_BACKED_UP` (no counterpart —
the actual deliverable list), or `EXCLUDED` (matched an auditable rule in
`diskaudit.backup_scope_rules`, with the reason recorded). Built because
BOTH #7 (critical_patterns-scoped) and `crosshost_verify.py`'s cross-host
size-candidate set (measured 2026-07-25: 0.3% of server-1's files, 0.1% of
agent-1's) structurally exclude the files that most need checking — a file
with no counterpart anywhere never enters either candidate set.

**Commands:**
```bash
python backup_coverage.py classify --host server-1   # fast, no remote hashing
python backup_coverage.py verify   --host server-1    # cheap: promote using EXISTING hash evidence only
python backup_coverage.py report   --host server-1 --out report.md --top 300
```

**Never backs anything up itself, never hash-verifies via a new remote hash
job on its own** (`classify`/`verify` only use cheap path/size/mtime matching
and hash evidence `crosshost_verify.py` already produced) — a dedicated
hash-upgrade pass for `backup_coverage`'s own matched pairs is a known V+1
gap (see runbook `/home/user/runbooks/20260725-havnvard-backup-coverage/RUNBOOK.md`).

**Ground-truth note:** the NAS's `bkup_server` share was checked live and
found NOT to be a literal path-for-path mirror of the server (contains per-app
tar.gz snapshots + restic repos + DB dump trees) — `classify`'s matching
logic was designed around this confirmed reality, not the "mirrors known
the server paths" assumption a prior brief stated.

## 8. NAS-orphan detection — WORKING

**What it does:** Surfaces files that exist on the NAS with no corresponding
copy elsewhere (candidates for "is this actually the only copy of this").

**Command:**
```sql
select * from diskaudit.v_nas_orphans limit 50;
```

Original deployment only: the view names one NAS host, so `schema/baseline.sql` (new installs) leaves it out.

**Advisory only** — "orphan" here means "only known copy," not "safe to
delete." No automatic action follows from this label.

## 9. Stale/failed run monitor — WORKING

**What it does:** Every 5 minutes, polls `scan_runs`, `dedup_runs`,
`dedup_worker_status`, and `backup_runs` for two conditions — STALE
(`status='running'` with an old heartbeat) and ERROR (`status='failed'`) —
and alerts to TG PRESI. Idempotent re-alerting logic (won't spam, won't go
permanently silent after the first alert).

**Command:**
```bash
python monitor.py                              # real run, alerts on findings
python monitor.py --dry-run                     # check without alerting
python monitor.py --stale-minutes 30            # tune staleness threshold
python monitor.py --test-mode                   # [TEST]-prefixed TG alerts
```

**Never touches scanned files** — reads run-tracking tables only, writes
`alerted_at` timestamps.

## 10. Daily metadata report to TG PRESI — WORKING

**What it does:** Collects counts/bytes/freshness/dedup/backup-coverage/error
metrics, persists a `diskaudit.report_snapshots` row for day-over-day deltas,
renders a phone-scannable summary, and posts to TG PRESI. **Metadata only —
no file contents, no actions.**

**Command:**
```bash
python havnvard_report.py --dry-run     # collect + render + print, no snapshot, no send
python havnvard_report.py --no-send     # snapshot + print, don't send to TG
python havnvard_report.py               # full: collect, snapshot, send
python havnvard_report.py --analyze     # also run PRESCAB daily analysis + post it (what the timer runs)
```

**Known limitation (confirmed 2026-07-25):** the host byte totals in this
report's headline numbers are **raw `sum(size_bytes)`, not inode-deduped** —
see the hardlink gotcha in RUNBOOK.md. Only the "reclaimable" figure (fed
from `v_duplicate_groups`) is inode-correct.

**Dashboard/report deep link:**
`https://server-1.example.ts.net:9452/d/diskaudit/diskaudit`

## 11. Weekly PRESCAB operational review — WORKING

**What it does:** Assembles current-state metrics and dispatches to PRESCAB
(VP-Operations, `logic_governance` mode — this is an operational state review,
not creative brainstorming) for a weekly trend read. Logs to
`havnvard.jobs.cabinet_runs`.

**Command:**
```bash
python weekly_prescab_review.py --dry-run              # print task_text only
python weekly_prescab_review.py                        # real dispatch
python weekly_prescab_review.py --test-mode            # [TEST]-prefixed
python weekly_prescab_review.py --base-url http://127.0.0.1:9103
```

**Never touches scanned files** — reads aggregate metrics, dispatches text to
PRESCAB.

## 12. Restic backup engine (Phase 2) — WORKING

> **3.2.0 (INFRA-571): the weekly `forget`/`prune` retention timers are DISABLED** (they broke the never-delete rule). To disable them on a site that still has them: `systemctl list-unit-files --no-legend 'havnvard-restic-*-retention.timer' | awk '{print $1}' | xargs -r sudo systemctl disable --now`. Backups keep running; deletion is only `prune`/`forget-before`/`forget-after` on the owner's order.

**What it does:** Daily `restic backup` (no automatic forget/prune since 3.2.0) for **10
other the server app directories** (app-a, app-b,
app-c, config-files, app-d, app-e, app-f, app-g,
app-h, app-i) — a genuinely separate capability from the
disk-inventory scan itself, living under this app's systemd namespace and
sharing its `backup_runs`/monitor infrastructure. **This is documented
elsewhere in this repo (`module.yaml`, `README.md`) as "planned, not yet
installed" — that's stale.** `restic 0.19.1` is confirmed installed and all
10 backup timers are active; the 10 retention timers are disabled (3.2.0).

**Why you'd use it:** Real backup coverage for other app directories, with
restic's own dedup/compression/encryption, verified independently of the
disk-inventory scan.

**Command:**
```bash
sudo systemctl start havnvard-restic-app-e.service            # one-off backup now
journalctl -u havnvard-restic-app-e.service -n 50              # check result
```

**Worked example:** `diskaudit.backup_runs` has 72 logged runs as of
2026-07-25.

**Restore is a manual, explicit operator action — never automatic:**
```bash
restic -r <repo> snapshots
restic -r <repo> restore <snapshot-id> --target <dir>
```
Restic backups are copies; nothing about this feature ever touches the
original scanned files.

## 13. "Abandoned due to software lifecycle change" detection — PLANNED

**What it would do:** The actual differentiator this project set out to
build vs generic disk-usage tools — detecting files/dirs that are orphaned
specifically because of a software change (deprecated module, superseded
config, orphaned migration leftover), not merely "large and cold." **Flagged
explicitly in `module.yaml`'s own risk list as NOT YET DESIGNED** — this is
an honest gap, not a hidden one. Nothing to run yet.

## 14. Automated test suite — STUBBED

No pytest/CI exists. Verification has been entirely live/manual: real
scan/dedup/backup runs against production data, checked via direct SQL and
`restic check`/restore-diff cycles. `bucketing.py` has one inline self-test
(500-group correctness check), run manually, not wired into CI. See
`tests/README.md` (already states this honestly — not duplicated further
here).

## 15. HavnVard UI (web app) — WORKING (added 20260725)

**What it is:** the first user-facing UI over diskaudit data. Before this,
the only interface was Grafana (`:9452`) — 12 aggregate panels, good for
trends over time, useless for browsing or acting on individual file/group
lists. This closes that gap with a small FastAPI + Jinja2 + HTMX
server-rendered app at `/opt/havnvard/webapp/`, bound
127.0.0.1:9108 and fronted by Caddy Tailnet-only at
`https://server-1.example.ts.net:9457`. No client-side JS framework, no
build step, no CDN assets (htmx.min.js served locally). systemd unit
`havnvard-ui.service` (enabled, `Restart=always`).

**Absolute constraint carried through into the UI:** exactly as stated
above for the rest of HavnVard — **no route, template, or button in this
app ever deletes, moves, renames, or overwrites a scanned file, anywhere,
not even disabled.** The only actions available are filter/sort/paginate
and CSV/JSON export (for the separate, not-yet-built P5/FERJA authorized
cleanup process).

It presents exactly three views, sharing one common layout/filter/pagination
/export interaction model (`app/common.py`) rather than three bespoke pages:

### A) DEDUP — `/havnvard/dedup`
One row per duplicate group per host, across **all three** scanned devices
(server-1, agent-1, nas-1). Source: `diskaudit.mv_dedup_groups_by_host`,
a new indexed materialized view (`migrations/20260725_diskaudit_havnvard_ui_mv.sql`)
added because the live `v_duplicate_groups_by_host` view took ~4s/query —
unusable interactively. **Hardlink-aware:** reclaimable bytes =
`GREATEST(distinct_inode_count - 1, 0) * size_bytes`, verified byte-identical
(0 mismatches) to the corrected `v_duplicate_groups_by_host` fix from
2026-07-17. A group with `distinct_inode_count = 1` is a pure hardlink set —
always shows 0 reclaimable, flagged with a "hardlink set" badge, never a
false-positive space estimate. Every row also shows a hash-proven vs
path-matched-guess evidence badge. Filters: host, path substring, min size,
min files/group, evidence type. Sort: reclaimable, size, file count, distinct
inodes. Export: CSV/JSON, capped at 50,000 rows (ORDER BY + LIMIT, current
filter/sort — never an unbounded dump).

### B) CLEANUP — `/havnvard/cleanup`
Per-file rows on the server + agent-1 that belong to a duplicate group on that
host (candidates to remove — never removed by this app). Joined to the same
`mv_dedup_groups_by_host` for its group's reclaim figure and evidence badge,
so KPI totals are always computed once per **group**, never once per file
row (summing per-file would double/triple-count the same reclaimable bytes
across every group member). Pure hardlink-only groups are hidden by default
(0 bytes reclaimable either way) behind an explicit "include hardlink-only
sets" toggle. Filters: host, path substring, min size, evidence type,
hardlink-only toggle. Export: CSV/JSON, 50,000-row cap.

### C) BACKUP — `/havnvard/backup`
Files on the server + agent-1 not confirmed safely present on the NAS. **Primary
source:** `diskaudit.backup_coverage` (host, path, `classification` IN
`NOT_BACKED_UP`/`BACKED_UP_UNVERIFIED`/`EXCLUDED`/`BACKED_UP_VERIFIED`,
`match_method`) — landed live, mid-build, from a concurrent migration; by the
time this UI shipped both server-1 and agent-1 showed 100% coverage
evaluation. The view's banner always states per-host evaluation completeness
explicitly so a 0%-evaluated host never silently reads as "all safe."
**Fallback source** (used only if `backup_coverage` is ever absent):
`diskaudit.integrity_checks` — a much narrower, hash-proven-only sample
(~23k rows vs 8.5M+ files) from `crosshost_verify.py`; the banner states this
is a partial sample, not a complete inventory, whenever it's active. Every
row carries an explicit evidence badge (hash-proven / path+size+mtime guess /
no evidence) — a "guess" never renders as if it were proof. **"Mismatch" is
labeled explicitly as not-necessarily-corruption** (live mutable state like a
Chrome profile or sqlite file vs a point-in-time snapshot) right in the page
caveat, not buried in a footnote. Filters: host, classification (when
`backup_coverage` is live), path substring, min size. Export: CSV/JSON,
50,000-row cap.

**Verified working (2026-07-25, live data):**
- DEDUP: 689,539 groups matched (unfiltered), ~409.6 GB reclaimable, 3,014,793
  member files, 2,507 hash-proven groups.
- CLEANUP: 264,538 groups involved, ~120.8 GB reclaimable, 1,268,285 candidate
  file rows (default filter, hardlink-only sets hidden).
- BACKUP: 3,752,298 candidate files (default filter: NOT_BACKED_UP +
  BACKED_UP_UNVERIFIED), ~1.2 TB not confirmed safely on NAS; source =
  `diskaudit.backup_coverage` (both server-1 and agent-1 at 100% evaluated).
- Light/dark toggle present on every page (localStorage-persisted, respects
  OS `prefers-color-scheme` on first visit).
- CSV and JSON exports validated (correct headers, correct row counts,
  hardlink/evidence caveat columns included).
- systemd unit `havnvard-ui.service`: enabled, `Restart=always` confirmed
  (killed the process directly, auto-recovered within `RestartSec=5`).
- `https://server-1.example.ts.net:9457` reachable and correct through
  Caddy (reverse-proxied to 127.0.0.1:9108) — **but note:** the Tailnet TLS
  cert at `/etc/caddy/certs/server-1.example.ts.net.crt` expired
  **2026-07-24**, a pre-existing, machine-wide issue affecting every
  Caddy-fronted service on this box (reproduced independently on the
  pre-existing `:9452` Grafana block), not something introduced by this
  build. Needs a `tailscale cert` renewal + `systemctl reload caddy` as a
  separate, cross-cutting fix — see `RUNBOOK.md`'s `20260725-havnvard-ui`
  runbook for the exact recovery command.

**Run/manage:**
```bash
sudo systemctl status havnvard-ui.service
sudo systemctl restart havnvard-ui.service
journalctl -u havnvard-ui.service -f
```

Full runbook: `/home/user/runbooks/20260725-havnvard-ui/RUNBOOK.md`.

---

## Where to look next

- Full architecture/file list: `README.md` (this repo).
- Start/stop/health/DB checks/failure recovery: `RUNBOOK.md` (this repo).
- Client onboarding: `CLIENT_INSTALL.md` (this repo).
- Design doc: `/home/user/.claude/plans/witty-swinging-shore.md`.
- Plane: INFRA-97 (main), INFRA-98 (monitoring), INFRA-99 (deferred v3),
  INFRA-109 (remaining restic targets), INFRA-110 (TechWatch schedule
  collision).


---

## HavnVard Backup (2.0.0)

Full install steps: `README.md` "Install HavnVard Backup"; agent steps: `CLAUDE_SETUP.md`. Not in 2.0: marking files
BACKED_UP_VERIFIED from snapshots, the "not backed up" report, bit-rot re-hash schedule, dashboard, Windows backup, phone apps.

| Command | What it does | Failure behaviour |
|---|---|---|
| `hub install` | Renders the append-only rest-server unit, disk guard, health and catalog timers (no prune timer since 3.2.0); prints install commands | Runs no sudo or systemctl |
| `hub set HOST[:PORT]` | Writes the hub address to `~/.config/havnvard/backup.toml` | Rejects bad addresses |
| `enroll DEVICE --paths ...` | Random password files (600, never printed, never overwritten), excludes, client timer; prints the hub `.htpasswd` hash line | Exit 2 on bad name or missing path |
| `client-run [--init]` | One backup (what the timer runs); exit code is restic's (3 = some files unreadable, snapshot saved) | Hub unreachable or wrong password: exit 2, recorded for `health` |
| `offsite add / run` | Copy-only upload of the encrypted repos to any rclone remote; data before snapshots; flag-after-3-resends | 0 done, 75 time budget used, 2 failure |
| `nas-target`, `nas-copy` | SMB mount unit; mirror of every hub repo's encrypted files to the NAS (no passwords on the hub) | Refuses to write if the share is not mounted |
| `health` | Snapshot age > 26 h, last job, hub and NAS free space (< 500 GB), offsite recency and flagged files, via alertlib | Exit 1 problem, 2 could not check |
| `offload FOLDER [--no-db]` | Device: backup tagged `archive` + `archive-YYYYMMDD` (64 MiB packs), every file read back with `restic dump` and SHA-256 compared with the live file; manifest in `~/.local/state/havnvard/offload/` + `diskaudit.archive_offload` rows; prints X/Y VERIFIED. Deletes nothing: the owner deletes VERIFIED files | Exit 1 if any file not VERIFIED or the DB record failed |
| `pullback FILE... \| --date D [--vanished] [--folder F] \| --snapshot ID` | Restores files; `--target DIR` (default original place); `--from DEVICE --key-file F [--login-file F]` onto any device, read only. Never overwrites: identical existing file left alone, different one kept and the backup copy written as `NAME_PULLBACK-YYYYMMDD-HHMM.EXT`; restored files hash-checked against the offload manifest | Exit 1 on a manifest mismatch, 2 if nothing matches |
| `find PATTERN` | Every backed-up version of a file; on a device without the hub catalog it reads the newest catalog copy from its own repo | Exit 1 not found |
| `forget-before DEVICE DATE` / `forget-after DEVICE DATE` | Hub: owner deletes snapshots taken before / on-or-after a date: `--owner-key`, full list, exact typed text; archive kept unless `--include-archive` | Exit 1 not confirmed |
| `prune DEVICE` | Hub-side forget + prune for one device on the owner's order: no default rule, `--owner-key` (hub's stored copy refused), dry-run list then exact typed text; `--keep-tag archive` always; no timer (3.2.0) | Exit 1 not confirmed or failed, 2 refused |
| `health --json` | Same checks as one JSON object `{ok, exit_code, checks[]}`; exit 2 with `{error}` if it cannot run | 2.1.0 |
| `health-relay --ssh HOST` | On the server: runs the hub's `health --json --no-alert` over ssh, alerts via local alertlib; ssh failure or bad output = alert | 2.1.0; `--render-units DIR` writes the hourly timer |
| `coverage-sync DEVICE` | Latest restic snapshot listing vs `diskaudit.backup_coverage`: same path+size+mtime -> BACKED_UP_UNVERIFIED (a listing is not a hash check; VERIFIED needs SHA-256) | 2.1.0; needs migration `20261111_diskaudit_restic_coverage_v1.sql`; run after `backup_coverage.py classify`; listing match, not a SHA-256 compare |
| `not-backed-up` | NOT_BACKED_UP totals per host and top folders or file types by bytes (hardlink-deduplicated) | 2.1.0 |
| `check-timers` | Lists havnvard-restic-* timers whose ExecStart script, WorkingDirectory or BACKUP_SRC is gone | 2.1.0; read-only |
| `catalog run` | Hub: names new data snapshots `YYYYMMDD_DEVICE_NNNNNN` (restic tag, global counter), appends ADDED/GONE file-version lines to the catalog, backs the full catalog up into every repo (tag `havnvard-catalog`); health, drill and coverage-sync skip catalog snapshots | 2.2.0 (the operator 20261111); append-only so restic stores only the new tail |
| `where PATTERN` | Which backup holds a file: first backup with each version, and the first without it | 2.2.0; exit 1 = not in any backup |
| `restore-drill DEVICE` | Restores a random sample, full SHA-256 compare, prints X/Y; self-test canary first | Nothing comparable is NOT a pass |
