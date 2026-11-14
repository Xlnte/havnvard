# Changelog

Older releases are described in `FEATURES.md` and `docs/*_RELEASE_*.md`.

## 3.3.3 (20261114)

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
