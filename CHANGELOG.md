# Changelog

Older releases are described in `FEATURES.md` and `docs/*_RELEASE_*.md`.

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
