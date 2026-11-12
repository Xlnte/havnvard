# CLAUDE_SETUP.md: set up HavnVard Backup (for the user's Claude)

You are Claude, asked to set up HavnVard Backup. The tool is `python -m backup` in this repo (Python 3.11+, standard
library only). Human version: README.md "Install HavnVard Backup". Follow these steps in order.

## Rules that never bend
1. **Never print, log, paste or send a password or key.** `enroll` creates `restic.pass` and `rest.pass` (mode 600) and
   prints only a hash. Do not `cat` them. If a step needs a password moved, move the file (scp/ssh), do not read it out.
2. **Never overwrite an existing `restic.pass`.** It protects existing backups. `enroll` already refuses to; do not work around it.
3. **Do not run `sudo` or `systemctl` unless the user has said yes to the specific step.** The tool renders units to `./out/`
   and prints install commands; show them to the user. User-level units (`systemctl --user`) need no sudo.
4. **Detect first, ask only what you cannot detect.** One question at a time.
5. **A device is done only after one backup and one restore have both succeeded** (step 7). Never report success before.

## 1. Detect (do not ask)
Run and note: `hostname -s`, `python3 --version` (need 3.11+), `which restic rclone rest-server`, `df -h` for the
hub candidate, `tailscale status` (reachable devices), whether `~/.config/havnvard/backup.toml` already exists
(then this is a re-run: read it with `cat`, it has no secrets, and continue from where it stopped).
Missing `restic`/`rclone`/`rest-server`: tell the user the package or download needed; install only with their yes.

## 2. Ask (only what you could not detect)
- Which machine is the hub (always on, ext4 disk, at least 2 x the data)? Its address on the home network or Tailscale.
- Which folders should this device back up? (Phone data: tell them to place it in one of these folders; HavnVard installs nothing on phones.)
- Where should the offsite copy go (Google Drive, OneDrive, Internxt, or another rclone remote)? Suggest a separate
  account used only for backups; not required.
- Do they have a password manager? Each device's backup password must be saved there (or on paper).

## 3. Hub (on the hub machine, once)
`python -m backup hub install --repo-root <dir on the big ext4 disk> --listen <hub address> --port 8000`.
Show the user the printed commands and run them with their yes. Check: `systemctl --user status restic-hub.service`.

## 4. Enrol this device
```
python -m backup hub set <hub-host>[:port]
python -m backup enroll <device-name> --paths <folders...> [--excludes generic|ml-workstation|desktop-sync] [--limit-upload KIB] [--quiet-hours HH-HH]
```
`enroll` prints a `name:{SHA}...` line: append it to the hub's `.htpasswd` (`~/.config/havnvard/hub.htpasswd` on the hub), then
`systemctl --user kill -s HUP restic-hub.service` there. Then tell the user, in plain words: **"Save
`~/.config/havnvard/restic.pass` in your password manager now; without it these backups cannot be read."** Offer to
open the file path for them; do not display its contents. Copy the file to the hub as
`~/.config/havnvard/hub-passwords/<device-name>.pass` (mode 600) so the hub can prune; use scp, not chat. (The NAS copy needs no password: it mirrors encrypted files.)

## 5. First backup and timer
`python -m backup client-run --init`, expect exit 0 or 3 (3 = some files unreadable, snapshot saved). Then install the
rendered timer: `cp out/havnvard-backup.* ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user enable --now havnvard-backup.timer`.

## 6. Offsite and NAS (hub only, if the user wants them)
`rclone config` is interactive and needs the user's browser: guide them, do not enter credentials for them. Then
`python -m backup offsite add <name> --rclone-remote <remote>:<path> [--crypt]` and `python -m backup offsite run`.
NAS: `python -m backup nas-target ...` (the user fills the password into the credentials file themselves), then
`python -m backup nas-copy`.

## 7. Prove it (required)
1. `python -m backup health` on the hub and on the device: exit 0. If the hub has no `alertlib` (agent-1), also set up, on the server,
   `python -m backup health-relay --ssh <hub> --python <path> --repo-dir <dir> --render-units ./out`, install the rendered
   hourly timer, and run `health-relay` once by hand: exit 0.
2. `python -m backup restore-drill <device-name>`: it must print `N/N matched`. If it prints `0/0` or any mismatch, the
   setup is NOT done: report exactly what it printed.
3. Restore one named file by hand once (README "Restore one file") and open it with the user.

## 8. Report to the user (short)
What was installed where, the hub address, the backup schedule, the offsite target, the `health` and `restore-drill`
results (as X/Y), and the single thing they must do: **keep each device's backup password in a password manager.**

## Failure handling
`python -m backup` exit codes: 0 ok, 1 a check found a problem, 2 it could not do what you asked (read the stderr
line; do not retry blindly), 75 from `offsite run` means the time budget ran out and the timer continues it.
