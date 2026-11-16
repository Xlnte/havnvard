# Changelog

Older releases are described in `FEATURES.md` and `docs/*_RELEASE_*.md`.

## 3.3.12 (20261117)

INFRA-637 (one credential-file reader). Built on fix/infra-566-565 (3.3.11) with fix/infra-541-540-539 (3.3.7) merged in, so this branch holds the whole 3.3.7 to 3.3.12 chain.

- **One reader (INFRA-637).** `crosshost_verify._read_nas_token_text` is now a one-line wrapper over `token_file.read_token_text` (same name, tests patch it). `infra126/.../transport.py` (`SshpassSshTransport._load_credentials`, was an unconditional `sudo cat`) and `backup_coverage._nas_env` (was `sudo -n cat`) use the same helper: direct read first, `sudo` only after a PermissionError. The infra126 package finds `token_file.py` in the checkout root (`$HAVNVARD_HOME`, else three levels above `transport.py`).
- **Fail fast (INFRA-637).** The sudo fallback is `sudo -n cat` with stdin closed and a 30 s timeout, so a service with no terminal gets an exit code at once instead of a hung password prompt. Failure raises `token_file.TokenReadError`, which names the file and the exit code and never carries the file's text or sudo's stderr. Every caller already lets it reach a top-level handler that records the message (`load_nas_inventory`, `crosshost_verify` run rows) or the traceback (`backup_coverage`, infra126 CLI).
- **Guard.** `tests/test_token_file.py` fails if any other non-test `.py` file runs `sudo cat` / `sudo -n cat` on a file.
- **Review fix (3.3.12).** infra126 `transport._read_token_text` tried a plain `import token_file` first, so any `token_file.py` on `sys.path`
  (the cwd of `python -m`, a stale `/srv/diskaudit.bak-*`, a worktree) won over `$HAVNVARD_HOME` and the checkout the package is installed from,
  and it put the checkout root in front of `sys.path` for every later import. It now follows `validate_live.py`'s order (`$HAVNVARD_HOME`, then
  the checkout root), loads `token_file.py` by path without touching `sys.path`, and keeps the plain import as the last resort. Two tests.
  The `TokenReadError` text also names `sudo -v` for a run by hand.

## 3.3.11 (20261117)

INFRA-566 and INFRA-565 (public-release privacy findings PF1 and FILE-4). Built on fix/infra-633-635 (3.3.10); 3.3.7 to 3.3.10 are held on their own branches.

- **Generic tool name (INFRA-566).** `nas_trigkey_dedup.py` is now `nas_host_dedup.py` (and `tests/test_nas_host_dedup.py`). The old path stays as a
  deprecated shim that prints one DEPRECATED line to stderr and forwards the arguments and exit code, so a unit, timer or cron line that still
  names it keeps working. The repo's unit file, docs and tests use the new name. Remove the shim once no unit names it; do not publish while it exists.
- **Generic column and value names (INFRA-565, part).** Migration `20261117_diskaudit_generic_names_v1.sql`: `integrity_checks.spark_host/spark_path`
  -> `source_host/source_path`, `report_snapshots.spark_files/spark_bytes` -> `local_files/local_bytes`, verdict value `investigate_spark` ->
  `investigate_server` (rows updated, CHECK re-created), `git_repo_roots.discovered_via` default `'find-scan-20260718'` -> `'manual'`. Two read-only
  views keep the old column names for old readers: `v_integrity_checks_legacy_names`, `v_report_snapshots_legacy_names` (not in the baseline).
  **Apply the migration and deploy 3.3.11 code together** (3.3.10 code names the old columns).
- **Review fix (3.3.11).** The verdict rename failed on any suspect linked to a divergence: `trg_infra126_sync_suspect_review` copied the
  new value into `hash_divergences` while that table's old CHECK still stood. The migration now drops both CHECKs first and switches the trigger
  off for the two UPDATEs (and back to its previous mode), so it renames the value only. Real rollback file
  `20261117_diskaudit_generic_names_v1_rollback.sql` replaces the prose note (whose order would have failed the CHECK); a forward + rollback
  round trip gives a schema identical to the old baseline.
- **Not done (follow-up):** the `infra126_*` tables, `v_infra126_*` views, functions, indexes and `INFRA126_*` environment variables keep their
  names: a Grafana dashboard provisioned outside this repo reads the two views, and the package's operator configuration uses the env names.

## 3.3.10 (20261116)

Follow-ups INFRA-633 and INFRA-635. Built on fix/infra-564-563-562 (3.3.9). 3.3.7 (INFRA-541/540/539) is held by fix/infra-541-540-539; 3.3.8 by fix/infra-569-568-567.

- **No `sudo cat` when already root (INFRA-633).** `load_nas_inventory._nas_creds()` read the NAS admin token with `sudo cat` on every call. New
  `token_file.read_token_text()` reads the file directly and falls back to `sudo cat` only after a PermissionError; a missing file raises and is
  not retried via sudo; `_nas_creds(reader=...)` is injectable for tests; no credential content is logged. Same rule as INFRA-540 in crosshost_verify.py.
- **site_hosts must match the site file exactly (INFRA-635).** `infra126/scripts/validate_live.py` now compares `diskaudit.site_hosts` to the
  site file as (host, role) and names the missing and the extra rows. New `init_site_hosts.py --prune --confirm-prune` deletes the extra
  site_hosts rows (a removed host, or a NAS role that changed; apply() then re-inserts the changed one). `--dry-run --prune` lists what would go.
  `hash_verification_sla` rows of removed hosts are tuned data and are kept unless `--include-sla` is added. `--prune` alone refuses.
- **Review: --prune refuses an untrusted site file.** It (and `--dry-run --prune`) exits 2 without deleting when no site file was read (the
  built-in defaults would have pruned every real host), when `[hosts] nas` or `sources`/`all` is not set explicitly, when the NAS host is not in
  `[hosts] all`, or when the site file shares no (host, role) with `diskaudit.site_hosts`. The dry run's connection is read-only.

## 3.3.9 (20261116)

Follow-ups from the 3.1.0 baseline review (INFRA-564, 563, 562). Built on the open branch fix/infra-569-568-567 (3.3.8); 3.3.7 is held by fix/infra-541-540-539.

- **make_baseline_schema.py hardening (INFRA-564).** A COMMENT whose text ends in a doubled quote (`''a'';`) is now matched whole, so its later
  lines get the same name rewrites. A column comment goes with its dropped view. `SET transaction_timeout` (pg_dump 17) is stripped, so the
  baseline loads on PostgreSQL 15 and 16. The generator drops no object by default any more.
- **SLA rows from the site file (INFRA-563).** New `init_site_hosts.py` inserts one `hash_verification_sla` row per (host, tier A/B/C/E) for
  every host in the site file, only where missing, so tuned values stay. `infra126/scripts/validate_live.py` now expects hosts x 4 (and names
  the missing or unexpected rows) instead of a literal 12.
- **Generic NAS-orphan view (INFRA-562).** New table `diskaudit.site_hosts (host, role)`; `v_nas_orphans` is back in `schema/baseline.sql`
  and takes the NAS from it instead of naming one host. Same name and columns. Migration `20261116_diskaudit_site_hosts_v1.sql`.
- **Review fixes.** Without a `nas` row in `site_hosts`, reading `v_nas_orphans` raises (function `diskaudit.site_nas_hosts_configured()`,
  one-time filter) instead of returning no rows, so "not configured" cannot read as "no orphans". A real rollback file,
  `migrations/20261116_diskaudit_site_hosts_v1_rollback.sql` (`-v nas_host=...`, stops with an error without it), replaces the note that
  pointed at the 20260718 migration (whose published copy names a placeholder host, so its view would match nothing).
- **Deploy:** apply the migration, then run `python3 init_site_hosts.py` (until it runs, reading `v_nas_orphans` raises an error naming the script), then deploy code.

## 3.3.8 (20261116)

Follow-ups from the 3.1.1 review (INFRA-569, 568, 567). 3.3.7 is held by the open branch fix/infra-541-540-539.

- **gen_cleanup_page.py uses psycopg 3 (INFRA-569).** It imported `psycopg2`, which is not in `requirements.txt`, so the page
  could not be generated on a clean install. Same read-only session, dict rows.
- **make_baseline_schema.py needs `--site-names` (INFRA-568).** Pass the private rules file, or set `HAVNVARD_SITE_NAMES`, or say
  `--no-site-names` if the site has no private names. Leaving all three out exits 2 and leaves the old baseline untouched, so a
  regeneration can no longer silently drop private rules.
- **Empty `[nas] backup_tree_prefix` is a visible warning (INFRA-567).** `nas_trigkey_dedup.py` prints it and records it in the new
  column `dedup_runs.warnings` (migration `20261116_diskaudit_dedup_runs_warnings_v1.sql`). Tests added for the empty prefix and for
  LIKE escaping of `%`, `_` and backslash in the prefix.
- **Deploy:** apply the migration before the new code runs a dedup (the run row INSERT names `warnings`).

## 3.3.7 (20261116)

- **verify_tree NAS hash floor is tunable (INFRA-541).** Env `NAS_FLOOR_BPS` (same name and unit, bytes/s, as the backup scripts' `lib-nas.sh`) or `verify --nas-floor-bps`; default stays 10 MB/s. A bad env value is ignored with a warning on stderr; a bad CLI value is a usage error.
- **NAS backup credentials are read directly (INFRA-540).** `sudo cat` only after a PermissionError; readers/creds injectable for tests. Contents never logged.
- **Stale canary sweep (INFRA-539).** Each canary run first removes `.diskaudit_scratch/verify_tree_canary_<pid>_<ts>` dirs older than 1 day (exact ASCII name only; the NAS side refuses a symlink or non-directory; named-file removal + rmdir). `VERIFY_TREE_SWEEP_DRY_RUN=1` only logs. Failures are logged as `CANARY_SWEEP_FAILED` and summarised on stdout as `CANARY_SWEEP=...` (only when something was found or failed).

## 3.3.6 (20261115)

Hub hardening from the 3.3.0 and 3.3.5 reviews (INFRA-626, 612, 613, 614, 609, 610, 605, 606, 596, 595, 585):

- **Web error counters are visible (INFRA-626).** `GET /healthz` (JSON: web errors, mail outbox counts, refused notices) and a status line
  on the Schedules page. Opt-in: set `hub_web = "http://127.0.0.1:8001"` in backup.toml and `health` checks it.
  `TypeError`/`AttributeError` at the web boundary are bugs: logged WITH traceback (server log only), counted, plain 500 with an error id.
  One computer-name rule (`config.DEVICE_NAME_RE`: letter/digit first, 1-63 characters) for `enroll` and `add_device`; the device API
  route still accepts the old pattern so a computer added before 3.3.6 keeps checking in.
- **Login limiter (INFRA-612, S2).** Keyed on (address, account) plus one global cap (100 failures a minute), not on the address alone, so one
  person's typos behind a proxy no longer lock everyone out. `X-Forwarded-For` is believed only when `REMOTE_ADDR` is listed in
  `HAVNVARD_TRUSTED_PROXIES` (comma-separated); otherwise ignored.
- **htpasswd edits (INFRA-613, 614).** `cut_htpasswd` runs under a lock and refuses a symlinked file; the hub's own password file is replaced
  by temp file + fsync + rename (a crash can no longer leave it empty).
- **Check-in queue files (INFRA-609).** Appends and the rewrite after a flush are locked, and the rewrite removes only the lines it sent, so a
  line appended during a flush is kept. **Hub notices (INFRA-610):** at most 50 open per computer; the 51st is refused (audited `notice.refused`,
  device gets a 400 and keeps it).
- **Mail (INFRA-605, 606).** AUTH is only attempted over TLS (`ssl` or a successful STARTTLS), else `failed: ... cleartext`; `ssl`/`starttls`
  are parsed strictly (the string "false" is false). The hub no longer sends mail inside the web request: a bounded queue (50) and one worker;
  the request sees `queued`, the real outcome is audited as `mail.result` and counted.
- **Schedules (INFRA-596, F18):** the change and its `schedule.set` audit row are one transaction; an unknown computer is refused.
- **Permissions (INFRA-595, F17):** state directory 0700, database and `-wal`/`-shm` 0600 whatever the umask.
- **Admin recovery (INFRA-585, F3):** `python -m backup hub admin-reset --confirm "RESET ADMIN PASSWORD" [--email ...]` on the hub console
  (no web or API route): new generated password shown once, sessions ended, `admin.recovery_reset` audit row.

## 3.3.5 (20261115)

Hub web and accounts hardening from the 3.3.0 review (INFRA-592, 591, 593, 600, 623, 589, 574; INFRA-582 was already fixed in 3.3.4):

- **CSRF on /login, /register, /reset (INFRA-592, F14).** A pre-session token cookie (`hv_csrf`) is issued with each of these forms and
  must come back in the form; without it the POST is a 403. Every CSRF compare now uses `hmac.compare_digest`.
- **Server-side session expiry (INFRA-591, F13).** Checked on every request, audited as `session.expired`. Administrators: 12 h
  absolute, 30 min idle. Users: 30 days absolute, no idle limit (they stay remembered). `last_seen_at` is now kept. Override with
  `HAVNVARD_SESSION_ADMIN_ABS_H`, `_USER_ABS_H`, `_ADMIN_IDLE_MIN`, `_USER_IDLE_MIN` (0 = no limit).
- **Bad input is a 400 (INFRA-593, F15):** missing or non-numeric fields, bad Content-Length, non-object JSON. Any other error is a plain
  500 page with an error id; both are logged with the exception and counted (`App.errors`). No traceback reaches the browser.
- **`add_device` uses the API's name rule (INFRA-600, F22):** `A-Za-z0-9._-`, 1-64 characters, one shared pattern.
- **/register audit row and its auto-login now record address and browser (INFRA-623).**
- Lint and script fixes: F541 in `hubweb.register` (INFRA-589); `report.py` run as a script no longer raises NameError (INFRA-574).
- INFRA-582 (`pullback --vanished` for a file made and deleted the same day) was fixed in 3.3.4; 3.3.5 adds a three-snapshot regression test.

## 3.3.4 (20261114)

NAS within-host dedup (`nas_trigkey_dedup.py`, `hash_stat_batch.sh`, `nas_dedup_core.py`), INFRA-520:

- **Racy-clean digests (G1).** `hash_stat_batch.sh` reads the hashing host's clock once per batch and reports a
  file whose mtime is within 2 s of that time, or in the future, as `UNSTABLE` instead of hashing it. A
  same-second rewrite keeps size and mtime, so such a digest could later look fresh while the bytes differ.
  `digest_is_fresh()` and the publish SQL also require `bound_at >= mtime + 2 s` (`RACY_MARGIN_S`), where
  `bound_at` is the driver's clock read BEFORE the batch's remote work starts (a lower bound on when each file
  was hashed). A legacy (pre-guard) binding is re-hashed only if it was bound within 2 s of mtime by that clock;
  a legacy binding taken later in a long batch still passes this term (the delete path's own re-hash of keeper
  and victim is the backstop). A file modified within 2 s of a batch start is grouped one run later.
- **`--path-prefix` (G4)** is accepted as an alias of `--path`.
- **`--publish-only` (G5):** no hashing and no ssh/scp; publishes groups from the digests already fresh (use
  after a killed long run). Not combinable with `--limit`.
- **`--dry-run`:** prints the plan (candidates, files and bytes to hash, fresh digests reused) and exits. No
  run row, no database write (the session is set READ ONLY, so a write raises), no remote I/O; a scope with no
  inventory rows exits 2 like a live run. Opt-in: the default stays a live run, which never touches a file
  (it reads files and writes only database rows).
- Docs: module.yaml timer line no longer claims an `--exclude` the unit does not pass (excludes come from the
  site file).

## 3.3.3 (20261114)

- Review fix (INFRA-549): `check_streams` accepts only `true`, `false` or `"auto"` (`0` and `1` were accepted as `false`/`true`);
  a bad per-device setting is reported as a `health config` problem, not as "cannot read the backups"; README notes the
  copy lag for devices that reach the hub through a daily copy.

- `health` checks **every backup stream of every device** (INFRA-549). A stream is restic's host + paths grouping; one
  repository can hold many (a server backing up its home folder and each app folder separately). Where the hub holds the
  device's hub-side password, `health` reads the snapshot list (`restic snapshots --json --no-lock --no-cache`, read-only)
  and reports `device <repo>` as a problem when any stream's newest snapshot is older than the limit, naming the stale
  streams. Catalog snapshots never count as backups. This replaces the newest-snapshot-file check for that repository.
  **Behaviour change:** a 3.3.2 hub that already holds hub-side passwords switches to the stream check on upgrade
  (`check_streams` defaults to `"auto"`); set `check_streams = false` to keep the 3.3.2 file-age check.
- New `[health]` settings: `check_streams` (`"auto"` default = where a hub-side password exists; `true` = a missing
  password is a problem; `false` = off), `restic` (path to the binary), and per device `[health.devices.<repo>]`
  `stale_hours` and `retired_streams` (`"host|path"` strings: counted, not judged). A `[health.devices.<name>]` that
  names no hub repository, or a malformed setting, is a problem.
- A stale device raises its own alert key `havnvard-device-stale-<repo>` (from `health` and from `health-relay`) and
  resolves it at the first run where every stream is fresh. Device checks never decide the main key.
- Fail-open rule: a repository whose snapshot list cannot be read is a `stream check <repo>` problem on the main key,
  never a fresh device; its device key is left as it was and the newest-file age check still runs. `health-relay`
  resolves a device key only from a readable result, never after a failed relay, and exits 2 when a device alert could
  not be raised.
- `health-relay` waits up to 300 s for the hub (was 120 s) and the rendered unit allows 6 min (was 3 min).
- Why: on a live hub one fresh home-folder stream every few hours kept a server's repository green while 41 app streams
  had stopped 3 to 4 days earlier and 7 more 13 to 78 days earlier.

## 3.3.2 (20261114)

- `health`: new `[offsite_remote.<name>]` target for an offsite uploader that runs on another machine (for example a
  desktop holding a cloud drive's sync folder). The hub fetches the uploader's status file with `status_command` and
  reports a problem when it cannot be fetched or parsed, when the uploader read a folder other than this hub
  (`expect_source`; the retired-hub case), when the last run failed or is older than `offsite_stale_hours`, and for
  every hub repo not fully uploaded within that limit. Held repos are reported, not failed.
- Offsite problems raise their own alert key `havnvard-offsite-stale` (`havnvard-offsite-stale-<hub>` from
  `health-relay`); it is resolved only from a readable result whose offsite checks all pass, never after a failed relay.
- Offsite checks (names starting `offsite `) no longer decide the main key `havnvard-backup-health`
  (`havnvard-backup-health-<hub>` from `health-relay`); they fire and resolve only the offsite key. Before, every
  offsite problem alerted twice and held the main incident open for the whole upload backlog, so a new device-backup
  failure in that window got no OPEN notice of its own. **Behaviour change for the 3.3.1 local `[offsite.<name>]`
  checks too:** they now alert under `havnvard-offsite-stale` only. `health` exit code and JSON `ok`/`exit_code` are
  unchanged (still 1 for any problem, offsite included); `health-relay` resolves the main key and exits 1 when only
  offsite checks fail.
- `health-relay` exits 2 (not 1) when an offsite alert could not be raised, the same rule as the main key: an alert
  that was not sent is a relay failure, never a plain "problem reported".
- Why: after a hub move, the desktop uploader kept uploading the retired hub's folder and later nothing at all, while
  `health` on the new hub stayed green because it only knew offsite targets it runs itself.
