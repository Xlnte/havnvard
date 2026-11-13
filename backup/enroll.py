"""Device enrolment and the client backup run (ported from restic-hub-backup)."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

from . import config
from .config import BackupError
from .render import PKG, render_task
from .util import new_secret_file, read_secret, restic_bin, run

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
QUIET_RE = re.compile(r"^(\d{1,2})-(\d{1,2})$")


def parse_quiet(s: str) -> tuple[int, int]:
    m = QUIET_RE.match(s or "")
    if not m or not all(0 <= int(g) <= 23 for g in m.groups()) or m.group(1) == m.group(2):
        raise BackupError(f"bad --quiet-hours {s!r}; use HH-HH with different hours 0-23, e.g. 08-18")
    return int(m.group(1)), int(m.group(2))


def in_quiet(quiet: str, hour: int) -> bool:
    a, b = parse_quiet(quiet)
    return (a <= hour < b) if a < b else (hour >= a or hour < b)


PROFILES = ("generic", "ml-workstation", "desktop-sync")   # files in backup/excludes/


def excludes_text(profile: str) -> str:
    p = Path(profile)
    if profile in PROFILES:
        src = PKG / "excludes" / f"{profile}.txt"
    elif p.is_file():
        src = p
    else:
        raise BackupError(f"unknown excludes profile {profile!r}: use {', '.join(PROFILES)} or a file path")
    home = str(Path.home())
    text = src.read_text().replace("{HOME}", home)
    return text.rstrip() + f"\n{config.config_dir()}\n"   # never back the secrets up into the repo they guard


def htpasswd_sha1_line(device: str, password: str) -> str:
    return f"{device}:{{SHA}}" + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()  # noqa: S324


def enroll(device: str, paths: list[str], excludes: str, limit_upload: int | None, quiet: str | None,
           out_dir: Path, schedule: str = "hourly") -> list[str]:
    if not NAME_RE.match(device):
        raise BackupError(f"bad device name {device!r}: letters, digits, . _ - only")
    if not paths:
        raise BackupError("--paths needs at least one folder")
    abs_paths = []
    for p in paths:
        ap = str(Path(p).expanduser().resolve())
        if not Path(ap).exists():
            raise BackupError(f"backup path does not exist: {ap}")
        abs_paths.append(ap)
    if limit_upload is not None and limit_upload < 0:
        raise BackupError("--limit-upload must be >= 0 (KiB/s; 0 = unlimited)")
    if quiet:
        parse_quiet(quiet)
    cdir = config.config_dir()
    new_restic = new_secret_file(cdir / "restic.pass")
    new_rest = new_secret_file(cdir / "rest.pass")
    ex_text = excludes_text(excludes)
    (cdir / "excludes.txt").write_text(ex_text)
    dev = {"name": device, "paths": abs_paths, "excludes": excludes,
           "limit_upload_kib": 4096 if limit_upload is None else limit_upload}
    if quiet:
        dev["quiet_hours"] = quiet
    cfg = config.load()
    cfg["device"] = dev
    config.save(cfg)
    render_task(out_dir, "havnvard-backup", f"HavnVard backup of {device} to the hub", "client-run --init",
                f"OnCalendar={schedule}\nRandomizedDelaySec=10m", success_exit="3")
    line = htpasswd_sha1_line(device, read_secret(cdir / "rest.pass"))
    ud = "~/.config/systemd/user"
    return [
        f"restic.pass: {'created' if new_restic else 'already existed, left untouched'} ({cdir / 'restic.pass'}, mode 600, not shown)",
        f"rest.pass:   {'created' if new_rest else 'already existed, left untouched'} ({cdir / 'rest.pass'}, mode 600, not shown)",
        "SAVE restic.pass in your password manager or on paper NOW: without it this device's backups cannot be read.",
        "",
        "ON THE HUB, append this line (a hash, not the password) to the hub's .htpasswd, then reload it: systemctl --user kill -s HUP restic-hub.service",
        f"  {line}",
        "",
        "ON THIS DEVICE (needs `hub set HOST[:PORT]` done first):",
        f"  cp {out_dir}/havnvard-backup.service {out_dir}/havnvard-backup.timer {ud}/ && systemctl --user daemon-reload",
        "  python -m backup client-run --init     # first backup, creates the repo on the hub",
        "  systemctl --user enable --now havnvard-backup.timer",
        "  python -m backup restore-drill " + device + "   # proof: restore a sample and compare SHA-256",
    ]


def client_env(cfg: dict) -> tuple[dict, dict]:
    dev, hub = cfg.get("device"), cfg.get("hub")
    if not dev:
        raise BackupError("this device is not enrolled; run `enroll` first")
    if not hub or not hub.get("address"):
        raise BackupError("no hub set; run `hub set HOST[:PORT]` first")
    cdir = config.config_dir()
    env = {
        "RESTIC_REPOSITORY": f"rest:http://{hub['address']}/{dev['name']}/",
        "RESTIC_PASSWORD_FILE": str(cdir / "restic.pass"),
        "RESTIC_REST_USERNAME": dev["name"],
        "RESTIC_REST_PASSWORD": read_secret(cdir / "rest.pass"),
    }
    if not (cdir / "restic.pass").is_file():
        raise BackupError(f"missing {cdir / 'restic.pass'}")
    return env, dev


PACK_MIB = 64   # 3.2.0 (owner decision): every pack file ~64 MiB, so no repo file comes near 4 GB


def pack_size(dev: dict) -> int:
    v = int(dev.get("pack_size_mib", PACK_MIB))
    if not 4 <= v <= 128:
        raise BackupError(f"pack_size_mib {v} must be 4..128 (restic's limit is 128 MiB)")
    return v


def backup_cmd(restic: str, dev: dict, paths: list[str], tags: tuple[str, ...] = ("auto",),
               json_out: bool = False) -> list[str]:
    """The one restic backup command line (timer runs and offload share it)."""
    cmd = [restic, "backup", "--one-file-system", "--exclude-caches",
           "--exclude-file", str(config.config_dir() / "excludes.txt"),
           "--pack-size", str(pack_size(dev)), "--host", dev["name"]]
    for t in tags:
        cmd += ["--tag", t]
    if dev.get("limit_upload_kib"):
        cmd += ["--limit-upload", str(dev["limit_upload_kib"])]
    if json_out:
        cmd.append("--json")
    return cmd + list(paths)


def write_last(rc: int, device: str, note: str = "") -> None:
    d = config.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "backup-last.json").write_text(json.dumps(
        {"device": device, "rc": rc, "ok": rc in (0, 3), "at": dt.datetime.now(dt.timezone.utc).isoformat(),
         "note": note}))


def client_run(init: bool = False, hour: int | None = None) -> int:
    """Back this device up. Exit code is restic's (3 = some files unreadable, snapshot still saved).
    Inside quiet hours nothing runs and the exit is 0 with a printed notice (health still watches snapshot age)."""
    cfg = config.load()
    env, dev = client_env(cfg)
    hr = dt.datetime.now().hour if hour is None else hour
    if dev.get("quiet_hours") and in_quiet(dev["quiet_hours"], hr):
        print(f"havnvard-backup: skipped, inside quiet hours {dev['quiet_hours']}")
        return 0
    restic = restic_bin()
    if init:
        probe = run([restic, "cat", "config"], env=env, timeout=120)
        if probe.returncode == 10:   # restic: repository does not exist
            made = run([restic, "init"], env=env, timeout=300)
            if made.returncode != 0:
                write_last(made.returncode, dev["name"], "init failed")
                raise BackupError(f"restic init failed: {made.stderr.strip()[-300:]}")
            print("havnvard-backup: repository created on the hub")
        elif probe.returncode != 0:
            write_last(probe.returncode, dev["name"], "hub unreachable or wrong password")
            raise BackupError(f"cannot open repository (rc {probe.returncode}): {probe.stderr.strip()[-300:]}")
    r = run(backup_cmd(restic, dev, dev["paths"]), env=env)
    print(r.stdout[-2000:], end="")
    if r.returncode not in (0, 3):
        print(r.stderr[-1000:])
    write_last(r.returncode, dev["name"])
    print(f"havnvard-backup: exit {r.returncode}")
    return r.returncode
