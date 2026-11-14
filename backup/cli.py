"""`python -m backup ...` command line. Exit codes: 0 ok, 1 a check found a problem, 2 the tool could not do it
(75 from `offsite run` = time budget used, the timer resumes)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, config
from .config import BackupError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m backup", description="HavnVard Backup (restic) " + __version__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    hub = sub.add_parser("hub", help="hub side").add_subparsers(dest="hub_cmd", required=True)
    hi = hub.add_parser("install", help="render the hub units and print the install commands (runs nothing)")
    hi.add_argument("--repo-root", required=True)
    hi.add_argument("--port", type=int, default=8000)
    hi.add_argument("--listen", default="127.0.0.1", help="address to listen on (default loopback only)")
    hi.add_argument("--out", default="./out")
    hi.add_argument("--rest-server", help="path to the rest-server binary")
    hs = hub.add_parser("set", help="on a device: choose the hub")
    hs.add_argument("address", metavar="HOST[:PORT]")
    hub.add_parser("setup-code", help="on the hub's console: print the one-time code the FIRST registration needs")
    hw = hub.add_parser("web", help="serve the hub pages (register, log in, users, computers, schedules, audit)")
    hw.add_argument("--listen", default="127.0.0.1")
    hw.add_argument("--port", type=int, default=8001)
    ha = hub.add_parser("adopt", help="add the company's store key to a device's existing repository (additive)")
    ha.add_argument("device")
    ha.add_argument("--store-key-file", required=True, help="file holding the store key from the recovery kit")
    ha.add_argument("--confirm", metavar="TEXT", help='exactly "ADD STORE KEY TO DEVICE"')
    hf = hub.add_parser("force-open", help="admin: open a user's files by resetting their password (new random "
                        "password shown once; the user must read a notice at next login; emailed; audited)")
    hf.add_argument("user_email")
    hf.add_argument("--admin", required=True, metavar="EMAIL", help="your administrator account")
    hf.add_argument("--admin-password-file", help="file holding your admin password (default: asked)")
    hf.add_argument("--reason", required=True, help="the user will see this, word for word")
    hf.add_argument("--confirm", metavar="EMAIL", help="type the user's email again")
    hr2 = hub.add_parser("revoke-device-key", help="after disabling a user: remove the computer's own restic key from its "
                         "repository on the hub (KEY REMOVAL ONLY; snapshots untouched; needs the store key)")
    hr2.add_argument("device")
    hr2.add_argument("--store-key-file", required=True, help="file holding the store key from the recovery kit")
    hr2.add_argument("--confirm", metavar="TEXT", help='exactly "REMOVE DEVICE KEYS FROM DEVICE"')
    hg = hub.add_parser("diskguard", help="stop/start the hub on low disk (run by its timer)")
    hg.add_argument("--stop-gb", type=int)
    hg.add_argument("--start-gb", type=int)

    en = sub.add_parser("enroll", help="enrol this device")
    en.add_argument("device")
    en.add_argument("--paths", nargs="+", required=True)
    en.add_argument("--excludes", default="generic", help="generic, ml-workstation, desktop-sync or a file path")
    en.add_argument("--limit-upload", type=int, metavar="KIB", help="upload cap KiB/s (default 4096, 0 = none)")
    en.add_argument("--quiet-hours", metavar="HH-HH", help="no backups in these local hours, e.g. 08-18")
    en.add_argument("--schedule", default="hourly", help="systemd OnCalendar value")
    en.add_argument("--out", default="./out")

    cr = sub.add_parser("client-run", help="back this device up now (what the timer runs)")
    cr.add_argument("--init", action="store_true", help="create the repository on the hub if it does not exist")

    of = sub.add_parser("offsite", help="offsite copies to rclone remotes").add_subparsers(dest="off_cmd", required=True)
    oa = of.add_parser("add")
    oa.add_argument("name")
    oa.add_argument("--rclone-remote", required=True, metavar="REMOTE:PATH")
    oa.add_argument("--crypt", action="store_true", help="the remote is an rclone crypt remote")
    orun = of.add_parser("run")
    orun.add_argument("--name")
    orun.add_argument("--max-seconds", type=int, default=21000)
    orun.add_argument("--bwlimit", default="3M")

    nt = sub.add_parser("nas-target", help="render the SMB mount unit for the NAS target")
    nt.add_argument("--smb", required=True, metavar="//HOST/SHARE")
    nt.add_argument("--user", required=True)
    nt.add_argument("--cred-file", required=True)
    nt.add_argument("--mountpoint", required=True)
    nt.add_argument("--uid", type=int)
    nt.add_argument("--gid", type=int)
    nt.add_argument("--vers", default="3.0")
    nt.add_argument("--out", default="./out")
    sub.add_parser("nas-copy", help="copy hub repos onto the NAS mount")

    h = sub.add_parser("health", help="snapshot age, last job, free space, offsite; non-zero on any problem")
    h.add_argument("--no-alert", action="store_true")
    h.add_argument("--json", action="store_true", help="print one JSON object (ok, exit_code, checks) instead of text")

    hr = sub.add_parser("health-relay", help="on a machine that can alert: run `health --json` on a hub over ssh and alert locally")
    hr.add_argument("--ssh", required=True, metavar="HOST")
    hr.add_argument("--python", default="python3", help="python on the hub")
    hr.add_argument("--repo-dir", default="havnvard", help="HavnVard checkout on the hub (relative to its home or absolute)")
    hr.add_argument("--render-units", metavar="DIR", help="write the hourly service+timer here instead of running")

    cs = sub.add_parser("coverage-sync", help="mark files BACKED_UP_UNVERIFIED (in a snapshot, not hash-checked) from the latest restic snapshot")
    cs.add_argument("device")
    cs.add_argument("--dry-run", action="store_true", help="count matches, write nothing")

    nb = sub.add_parser("not-backed-up", help="report: what is NOT backed up, biggest first")
    nb.add_argument("--host")
    nb.add_argument("--by", choices=["type", "folder"], default="folder")
    nb.add_argument("--limit", type=int, default=25)

    sub.add_parser("check-timers", help="list havnvard-restic-* timers whose script or backup source is gone")

    pr = sub.add_parser("prune", help="hub: delete old snapshots of ONE device by a keep rule, on the owner's order only "
                        "(no default rule; archive snapshots always kept; typed confirmation)")
    pr.add_argument("device")
    pr.add_argument("--owner-key", metavar="FILE", help="the owner's own copy of this repository's password (required)")
    pr.add_argument("--confirm", metavar="TEXT", help="the exact confirmation text, for scripts")
    pr.add_argument("--keep-daily", type=int)
    pr.add_argument("--keep-weekly", type=int)
    pr.add_argument("--keep-monthly", type=int)
    pr.add_argument("--keep-yearly", type=int)
    pr.add_argument("--stale-lock-hours", type=float, default=6.0)
    pr.add_argument("--dry-run", action="store_true")

    ca = sub.add_parser("catalog", help="hub: name new backups YYYYMMDD_DEVICE_NNNNNN and back the file catalog up into every repo")
    ca.add_argument("catalog_cmd", choices=["run"])
    ca.add_argument("--all-history", action="store_true", help="first run: name every existing snapshot, not only the newest")
    ca.add_argument("--recover", action="store_true", help="state.json lost: keep the catalog, resume numbering above every used number")
    wh = sub.add_parser("where", help="which backup holds a file: search the catalog by (part of) its path")
    wh.add_argument("pattern")
    wh.add_argument("--device")
    wh.add_argument("--catalog", help="catalog file (default: this hub's own)")
    of2 = sub.add_parser("offload", help="device: archive a folder, prove every file restores (SHA-256), print the "
                         "verified list; HavnVard never deletes, you do")
    of2.add_argument("folder")
    of2.add_argument("--no-db", action="store_true", help="do not record in diskaudit.archive_offload")
    pb = sub.add_parser("pullback", help="put backed-up files back; never overwrites: a different existing file is kept "
                        "and the backed-up copy is written as NAME_PULLBACK-YYYYMMDD-HHMM.EXT")
    pb.add_argument("files", nargs="*", metavar="FILE", help="files or folders, space-separated (newest backup that holds each)")
    pb.add_argument("--date", metavar="YYYY-MM-DD", help="everything offloaded that day (with --vanished: everything that disappeared that day)")
    pb.add_argument("--vanished", action="store_true")
    pb.add_argument("--version", metavar="BACKUP_NAME", help="with FILES: this backup, e.g. 20260302_LAPTOP_000123")
    pb.add_argument("--snapshot", metavar="ID")
    pb.add_argument("--folder", help="only under this folder")
    pb.add_argument("--target", default="/", help="restore under this directory (default: the original place)")
    pb.add_argument("--from", dest="from_device", metavar="DEVICE", help="another device's backups (read only)")
    pb.add_argument("--key-file", help="with --from: the owner's copy of that repository's password")
    pb.add_argument("--login-file", help="with --from away from the hub: that device's hub login password file")
    fd = sub.add_parser("find", help="search every backed-up version of a file (alias of `where`, also works on a device)")
    fd.add_argument("pattern")
    fd.add_argument("--device")
    fd.add_argument("--catalog")
    fd.add_argument("--from", dest="from_device", metavar="DEVICE")
    fd.add_argument("--key-file")
    fd.add_argument("--login-file")
    for nm, word in (("forget-before", "taken before"), ("forget-after", "taken on or after")):
        fb = sub.add_parser(nm, help=f"hub: the owner deletes a device's snapshots {word} a date "
                            "(list, owner key, exact typed text; archive kept unless --include-archive)")
        fb.add_argument("device")
        fb.add_argument("date", metavar="YYYY-MM-DD")
        fb.add_argument("--owner-key", metavar="FILE")
        fb.add_argument("--include-archive", action="store_true")
        fb.add_argument("--confirm", metavar="TEXT")
    ck = sub.add_parser("checkin", help="device: ask the hub whether a backup is due (schedules page); --run runs it")
    ck.add_argument("--run", action="store_true")
    rd = sub.add_parser("restore-drill", help="restore a random sample and compare SHA-256")
    rd.add_argument("device")
    rd.add_argument("--sample", type=int, default=20)
    rd.add_argument("--seed", type=int)
    rd.add_argument("--scratch")
    return p


def _dispatch(a: argparse.Namespace) -> int:
    from . import archive, catalog, coverage, drill, enroll, health, hub, nas, nobackup, offsite, prune, relay, timers
    if a.cmd == "hub":
        if a.hub_cmd == "install":
            print("\n".join(hub.hub_install(a.repo_root, a.port, a.listen, Path(a.out), a.rest_server)))
        elif a.hub_cmd == "set":
            print(f"hub set to {hub.hub_set(a.address)} in {config.config_path()}")
        elif a.hub_cmd == "setup-code":
            from .accounts import Accounts
            print("One-time setup code for the first registration (valid 1 hour):")
            print("  " + Accounts().new_setup_code())
        elif a.hub_cmd == "web":
            from .hubweb import serve
            serve(a.listen, a.port)
        elif a.hub_cmd == "adopt":
            from .accounts import Accounts, adopt_repo
            from .util import read_secret, restic_bin
            want = f"ADD STORE KEY TO {a.device}"
            if a.confirm != want:
                print(f'adds a key to {a.device}\'s repository (nothing else changes); pass --confirm "{want}"')
                return config.PROBLEM_EXIT
            print(f"{a.device}: store key {adopt_repo(restic_bin(), drill._env_for(a.device), read_secret(Path(a.store_key_file).expanduser()), Accounts())}")
        elif a.hub_cmd == "force-open":
            return _force_open_cli(a)
        elif a.hub_cmd == "revoke-device-key":
            from .accounts import Accounts, revoke_device_keys
            from .util import hub_password_dir, read_secret, restic_bin
            want = f"REMOVE DEVICE KEYS FROM {a.device}"
            if a.confirm != want:
                print(f"removes every restic key of {a.device}'s repository except the store key (the computer's own "
                      f'password stops working; no snapshot is touched); pass --confirm "{want}"')
                return config.PROBLEM_EXIT
            hub_local = config.load().get("hub_local")
            if not hub_local:
                raise BackupError("run this on the hub (`hub install` first)")
            repo = Path(hub_local["repo_root"]) / prune.check_device(a.device)
            r = revoke_device_keys(restic_bin(), str(repo), read_secret(Path(a.store_key_file).expanduser()), Accounts(),
                                   a.device, hub_password_dir() / f"{a.device}.pass")
            print(f"{a.device}: removed {len(r['removed'])} key(s): {', '.join(r['removed']) or 'none'}; "
                  f"kept: {', '.join(r['kept'])}; {r['hub_key']}")
            print("NAS and offsite copies keep the old key files until they are refreshed from the hub (copy-only).")
        else:
            return hub.diskguard(a.stop_gb, a.start_gb)
        return 0
    if a.cmd == "enroll":
        print("\n".join(enroll.enroll(a.device, a.paths, a.excludes, a.limit_upload, a.quiet_hours,
                                      Path(a.out), a.schedule)))
        return 0
    if a.cmd == "client-run":
        return enroll.client_run(a.init)
    if a.cmd == "checkin":
        from .checkin import checkin
        return checkin(run=a.run)
    if a.cmd == "offsite":
        if a.off_cmd == "add":
            offsite.offsite_add(a.name, a.rclone_remote, a.crypt)
            print(f"offsite target {a.name} saved")
            return 0
        return offsite.offsite_run(a.name, a.max_seconds, a.bwlimit)
    if a.cmd == "nas-target":
        print("\n".join(nas.nas_target(a.smb, a.user, a.cred_file, a.mountpoint, Path(a.out), a.uid, a.gid, a.vers)))
        return 0
    if a.cmd == "nas-copy":
        return nas.nas_copy()
    if a.cmd == "health":
        return health.run_health(not a.no_alert, a.json)
    if a.cmd == "health-relay":
        if a.render_units:
            print("\n".join(str(p) for p in relay.render_units(Path(a.render_units), a.ssh, a.python, a.repo_dir)))
            return 0
        return relay.relay(a.ssh, a.python, a.repo_dir)
    if a.cmd == "coverage-sync":
        return coverage.coverage_sync(a.device, a.dry_run)
    if a.cmd == "not-backed-up":
        return nobackup.not_backed_up(a.host, a.by, a.limit)
    if a.cmd == "catalog":
        return catalog.catalog_run(first_run_latest_only=not a.all_history, recover=a.recover)
    if a.cmd == "where":
        return catalog.run_where(a.pattern, a.device, a.catalog)
    if a.cmd == "check-timers":
        return timers.run_check()
    if a.cmd == "prune":
        return prune.prune(a.device, {"keep_daily": a.keep_daily, "keep_weekly": a.keep_weekly,
                                      "keep_monthly": a.keep_monthly, "keep_yearly": a.keep_yearly},
                           a.owner_key, a.confirm, a.stale_lock_hours, a.dry_run)
    if a.cmd == "offload":
        return archive.offload(a.folder, a.no_db)
    if a.cmd == "pullback":
        return archive.pullback(a.date, a.files, a.version, a.folder, a.vanished, a.target,
                                a.from_device, a.key_file, a.login_file, a.snapshot)
    if a.cmd == "find":
        return archive.find(a.pattern, a.device, a.catalog, a.from_device, a.key_file, a.login_file)
    if a.cmd in ("forget-before", "forget-after"):
        return archive.forget_dated(a.device, a.date, a.owner_key, a.cmd == "forget-after", a.include_archive,
                                    a.confirm)
    return drill.drill(a.device, a.sample, a.seed, a.scratch)


def _force_open_cli(a: argparse.Namespace) -> int:
    import getpass
    from .accounts import Accounts
    from .util import read_secret
    if (a.confirm or "").strip().lower() != a.user_email.strip().lower():
        print(f"force-open resets {a.user_email}'s password and opens all their files; pass --confirm {a.user_email}")
        return config.PROBLEM_EXIT
    accts = Accounts()
    pw = read_secret(Path(a.admin_password_file).expanduser()) if a.admin_password_file else \
        getpass.getpass(f"password for administrator {a.admin}: ")
    adm = accts.login(a.admin, pw, kind="admin")
    accts.logout(adm["token"])
    if adm["scope"] != "full" or adm["must_ack"]:
        raise BackupError("this administrator account has a pending notice; log in on the hub page first")
    users = [u for u in accts.list_accounts(kind="user") if u["email"] == a.user_email.strip().lower()]
    if not users:
        raise BackupError(f"no user account {a.user_email}")
    r = accts.force_open(adm["account_id"], users[0]["id"], a.reason, a.confirm)
    print(f"force-open of {r['user_email']} started and logged.")
    print(f"New password (shown once, not kept): {r['new_password']}" if r["new_password"] else
          f"New password: {r['code_delivery']}")
    print(f"Email to the user: {r['email_status']}" + ("" if r["email_status"] == "sent" else " - tell them yourself"))
    print("This password only shows the notice: it cannot acknowledge it or set a password. The user acknowledges "
          "with their OWN old password (or a reset code they redeem themselves), after reading that you reset their "
          "password and accessed all their files, and why; then they set their own.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except BackupError as e:
        print(f"havnvard-backup: ERROR: {e}", file=sys.stderr)
        return config.ERROR_EXIT
