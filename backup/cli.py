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
                        "and the backed-up copy is written as NAME_pullback-YYYYMMDD-HHMM.EXT")
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
        else:
            return hub.diskguard(a.stop_gb, a.start_gb)
        return 0
    if a.cmd == "enroll":
        print("\n".join(enroll.enroll(a.device, a.paths, a.excludes, a.limit_upload, a.quiet_hours,
                                      Path(a.out), a.schedule)))
        return 0
    if a.cmd == "client-run":
        return enroll.client_run(a.init)
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except BackupError as e:
        print(f"havnvard-backup: ERROR: {e}", file=sys.stderr)
        return config.ERROR_EXIT
