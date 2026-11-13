# HavnVard: backing up phones and tablets (Android + iPad)

> **YOUR MILEAGE MAY VARY.** Everything below was set up and measured on ONE home network, with ONE Android
> phone (Samsung S24 Ultra, Syncthing-Fork v2.1.3), ONE iPad (iPadOS 26.5.2) and ONE hub (trigkey, Ubuntu,
> Syncthing v1.27.2), on 2026-11-12. Your phone, your Wi-Fi, your router, your Android version and your battery
> settings are different. Treat every number here as "what happened once", not as a promise.

HavnVard installs **nothing on phones**. A phone's files reach the HavnVard hub through a separate app, land in a
folder on the hub, and the hub's normal hourly restic backup picks that folder up from there:

```
Android ── Syncthing-Fork (Send Only) ──▶ hub folder (Receive Only) ─┐
                                                                     ├─▶ restic (hourly, encrypted, deduped) ─▶ hub repo + offsite
iPad ──── USB cable ── idevicebackup2 (on plug-in) ──▶ hub folder ──┘
```

**Syncthing is sync, not backup.** If a file is deleted on the phone, Syncthing deletes it on the hub too. The only
thing that brings it back is a restic snapshot taken *before* the deletion. So the restic step is not optional:
**make sure the hub folder is inside the hub's restic `--paths`**, and run `havnvard backup restore-drill` once.

---

## ⚠️ Before you touch any advanced setting

**Playing with Syncthing's advanced settings is like handling dynamite: you should do so cautiously.**

- The **Actions → Advanced** page edits Syncthing's raw configuration. There is no "are you sure?", no undo button,
  and a wrong value can stop syncing silently, delete files on the other side, or drain your phone's battery.
- **Change one thing at a time.** Write down the old value first. Check that syncing still works (folders say
  "Up to Date" on both sides) before changing the next thing.
- **Never change a folder's ID**, and never point two different folders at the same path.
- **Never turn on "Ignore Delete" or switch folder types back and forth** unless you understand exactly what it does
  to the files already on both sides.
- If something goes wrong: **pause the folder first, then think.** A paused folder cannot delete anything.

You have been warned. Your mileage may vary.

---

## Part 1: Android with Syncthing-Fork

### 1.1 Install
- On the phone: install **Syncthing-Fork** (F-Droid, or the GitHub releases of `researchxxl/syncthing-android`).
  **Do not use the old "Syncthing" app**: the official Android app was archived in December 2024.
- Grant **All files access**, **Notifications**, and set **Battery → Unrestricted** (Android Settings → Apps →
  Syncthing-Fork → Battery). Without Unrestricted, Android will kill the app in the background and syncing stops
  without telling you.
- On the hub: install Syncthing and run it as a user service that survives logout:
  ```bash
  sudo apt install -y syncthing
  systemctl --user enable --now syncthing
  sudo loginctl enable-linger $USER
  echo 'fs.inotify.max_user_watches=524288' | sudo tee /etc/sysctl.d/90-syncthing.conf && sudo sysctl --system
  ```
- **Set a GUI password on the hub** (Actions → Settings → GUI) before you open the GUI to the network.
- **Hub GUI over Tailscale, no SSH tunnel needed:** if you use Tailscale, bind the hub's GUI to the hub's Tailscale
  address so you can open it from any tailnet device:
  ```bash
  syncthing cli config gui raw-address set <hub-tailscale-ip>:8384
  ```
  Undo with `syncthing cli config gui raw-address set 127.0.0.1:8384`. After a reboot, check the GUI still loads;
  if Tailscale came up after Syncthing, run `systemctl --user restart syncthing`. **Closing the GUI or the tunnel
  never stops syncing**: Syncthing runs as a service whether or not anyone is looking at it.

### 1.2 Pair the phone with the hub
1. Hub GUI: **Actions → Show ID** (QR code).
2. Phone: **Devices → +** → scan the QR → name it after the hub → save.
3. Hub GUI: accept the pairing banner.

### 1.3 ⚠️ RECOMMENDED for phones with lots of file movement: SEND ONLY from the phone

**If your Android phone moves, renames, creates and deletes a lot of files** (camera bursts, WhatsApp media,
screen recordings, downloads that come and go, apps that reorganise their own folders), **seriously consider
making every phone folder SEND ONLY, and setting the matching folder on the hub to RECEIVE ONLY.**

Why:
- With the default **Send & Receive** on both sides, any change on the hub flows back to the phone. A hub-side
  cleanup, a restore, a permission change or a tool that touches the folder can rewrite or delete files **on your
  phone**.
- Heavy churn on two-way folders produces **conflict copies** (`*.sync-conflict-*` files), rename storms and
  rescans that cost battery.
- **Send Only on the phone + Receive Only on the hub** makes the data flow one way: phone → hub. The hub is a copy;
  the phone is the source. Nothing done on the hub can damage the phone.

How, for **each** folder:
1. **Phone** (Syncthing-Fork): Folders → **+** → pick the folder (for example `/storage/emulated/0/DCIM`) →
   **Folder type: Send Only** → share it with the hub → save.
2. **Hub** GUI: accept the "new folder" banner → set the path yourself (for example
   `~/syncthing/<phone-name>/DCIM`, one subfolder per phone folder) → **Advanced → Folder Type: Receive Only** →
   save.
3. **Set the folders up the same on both sides:** same folder (same folder ID, which the banner fills in for you),
   same label, one hub folder per phone folder, and Send Only ↔ Receive Only as a matching pair. Do this for every
   folder, not just the first one.
4. Turn **Ignore Permissions** on for the hub folder (Android permissions do not map to Linux).
5. Check both sides say **Up to Date** before adding the next folder.

What Send Only does **not** do:
- It does **not** protect against deletion. A file deleted on the phone is deleted on the hub. Only restic snapshots
  (or Syncthing **File Versioning** on the hub folder, for example Staggered, 30 days) can bring it back.
- If the hub folder ever shows **"Local Additions"** or "Revert Local Changes", something changed on the hub side.
  Read what it is before clicking anything. **Revert Local Changes deletes the hub's local changes.**

Your mileage may vary: some people prefer two-way sync for a folder they edit on both sides. For a backup, one way
is safer.

### 1.4 ⚠️ More speed: set Num Connections to 6 (in the WEB GUI, not the app)

Syncthing can open several connections to the same device at once. The default is one. More connections helped a
lot on our network:

| Connections | Measured receive speed on the hub |
|---|---|
| 1 (default) | 10.8 MiB/s |
| 4 | 19.5 MiB/s |
| 6 | recommended setting (PAF, 2026-11-12) |
| 8 | not comparable: the big transfer finished during the test |

**The setting is NOT on the phone app's device screen.** The app's device page (Dynamic, Folders, Compression,
Introducer, Auto Accept, Pause, Untrusted, Custom sync settings) does not show it. It is in the **Web GUI**:

On the **phone**:
1. Syncthing-Fork → **☰ menu → Web GUI**.
   If the Web GUI will not load (for example right after the app restarted), wait a minute and try again, or open
   `http://127.0.0.1:8384` (some versions use `https://`) in the phone's browser.
2. **Actions → Advanced** (not Settings). **This is the dynamite page. Be careful.**
3. **Devices → <your hub>** → **Num Connections** → `6` (it shows `0`, meaning default, until you change it).
4. **Save.** Then exit and reopen Syncthing-Fork.

On the **hub**, set the same number for the phone (the higher limit lets either side open the extra connections):
```bash
syncthing cli config devices <PHONE-DEVICE-ID> raw-num-connections set 6
```
or Hub GUI → Actions → Advanced → Devices → <phone> → Num Connections → `6` → Save.

Check: the hub's log shows `Additional connection (+N) for device ...`, and the hub GUI's download rate goes up.

Notes and warnings:
- More connections mean more battery. Once the first big sync is done, daily changes are small; **consider going
  back to a lower number** if your battery suffers.
- The gain shrinks with each extra connection. Above 4 to 6, the phone's Wi-Fi is usually the limit, not
  Syncthing.
- Older Syncthing versions (before multiple-connection support) ignore this setting.
- Your mileage may vary. Measure before and after on your own network.

### 1.5 ⚠️ Run conditions: use FORCE START (ignore run conditions) for the big first sync

Syncthing-Fork has **run conditions** (Settings → Run conditions): run only on Wi-Fi, only on certain Wi-Fi networks,
only while charging, not in power-saving mode. They save battery, **but they also stop syncing completely** whenever a
condition is not met, and the app does not shout about it.

**If you have set it to require Wi-Fi and/or charging, use FORCE START to ignore the run conditions** when you
need it to sync now, especially for the **first big sync** (tens of GB):
- In Syncthing-Fork, use the **Force start** option (shown in the app's menu / status screen, and available as a
  quick-settings tile on some versions) so it runs regardless of the run conditions.
- Keep the phone on Wi-Fi anyway: Force start on mobile data can burn through a data plan.
- When the first sync is done, **turn Force start off again** so the run conditions protect your battery and data.

Signs that run conditions are blocking you: the hub shows the phone as **Disconnected**, the app says something like
"Syncthing is disabled" or "run conditions not met", or nothing has synced since you unplugged the charger.

### 1.6 Check it is working
- Both sides: every folder **Up to Date**; the hub lists the phone as **Connected**.
- Hub: `restic ls latest <hub-folder> | head` lists your phone files after the next hourly backup.
- There is no Telegram alert for a stalled phone yet. Look at the hub GUI now and then.

---

## Part 2: iPad (and iPhone) with idevicebackup2

Apple does not allow an app to read the whole device, and sideloading does not change that (a sideloaded app is
still sandboxed; TrollStore does not work on current iPadOS). The reliable route is a **full encrypted device backup
over USB** from the hub, the same kind iTunes/Finder makes.

### 2.1 One-time setup on the hub
```bash
sudo apt install -y libimobiledevice-utils usbmuxd
mkdir -p ~/ipad-backup
idevicepair pair                        # iPad unlocked; tap Trust, enter passcode; repeat until SUCCESS
idevicebackup2 -i encryption on         # asks for the password; STORE IT IN YOUR PASSWORD MANAGER
idevicebackup2 backup --full ~/ipad-backup
```
**Without the encryption password the backup can never be restored.** Encryption is also the only way saved
passwords, Wi-Fi and Health data are included.

⚠️ **Keep the iPad unlocked with Auto-Lock set to Never during the first full backup, and plug it straight into a
port on the hub (not through a USB hub on a drive).** Our first attempt aborted with
`Could not receive from mobilebackup2 (-4)` because the iPad dropped off USB; a different cable and a direct port
fixed it. Watch for drops with `journalctl -f -u usbmuxd`.

### 2.2 Make it automatic on plug-in
A udev rule starts a systemd user service whenever the iPad is plugged in. The script waits up to 10 minutes for
the iPad to be trusted, runs an incremental backup and writes `last-run.json` (`rc` 0 = success) and
`last-run.log`. Find your iPad's USB ID with `lsusb` (Apple is vendor `05ac`). Full files and procedure: the hub
runbook `runbooks/20261112-ipad-backup-trigkey/20261112_RUNBOOK.md` (Plane INFRA-114).

Check after a run: `cat ~/ipad-backup/last-run.json` → `"rc":0`.
**Never run `idevicebackup2` by hand while the plug-in service is running**: two runs in one folder break each other.

### 2.3 Restore
iPad connected, unlocked, **Find My iPad off**:
```bash
idevicebackup2 restore --system --settings ~/ipad-backup
```

---

## Part 3: what the hub does with it
1. **restic, hourly**: backs up the hub folders (encrypted, deduplicated, one snapshot per run). The first run after a
   big phone sync takes a while. A one-off `incomplete metadata` error while a backup was still being written is
   harmless; the next run picks the files up.
2. **Catalog**: records the backup names and the files inside them.
3. **Inventory** (daily): hashes files into the HavnVard database so it can mark them backed up and verified.

## Not built yet
- Telegram message per iPad backup (Plane INFRA-570). No alert if a phone stops syncing.
- Windows device backup.

**Your mileage may vary.** Test a restore of one real file before you trust any of this.
