"""Second on-site target: a restic repo copy on the NAS, written as a non-admin SMB user.

QNAP allows SSH only for administrators, so the route is an SMB (CIFS) mount of a share the
`havnvard` user can write. This module renders the mount unit and copies hub repos onto it.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from . import config
from .config import BackupError
from .render import render
from .util import hub_password_dir, restic_bin, run

SMB_RE = re.compile(r"^//[A-Za-z0-9._-]+/[^\s]+$")


def systemd_escape_path(path: str) -> str:
    """Equivalent of `systemd-escape --path` for absolute paths (mount unit names)."""
    p = "/" + "/".join(x for x in path.split("/") if x)
    if p == "/":
        return "-"
    out = []
    for ch in p.strip("/"):
        if ch == "/":
            out.append("-")
        elif ch.isalnum() and ch.isascii() or ch in ":_.":
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode())
    s = "".join(out)
    return "\\x2e" + s[1:] if s.startswith(".") else s


def nas_target(smb: str, user: str, cred_file: str, mountpoint: str, out_dir: Path,
               uid: int | None = None, gid: int | None = None, vers: str = "3.0",
               repo_subdir: str = "restic") -> list[str]:
    if not SMB_RE.match(smb):
        raise BackupError(f"bad --smb {smb!r}; use //HOST/SHARE")
    mp = Path(mountpoint)
    if not mp.is_absolute():
        raise BackupError("--mountpoint must be an absolute path")
    cf = Path(cred_file).expanduser()
    note = ""
    if cf.exists():
        if cf.stat().st_mode & 0o077:
            raise BackupError(f"{cf} must be mode 600 (it holds the NAS password)")
        if f"username={user}" not in cf.read_text().splitlines():
            raise BackupError(f"{cf} has no line 'username={user}'")
    else:
        cf.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(cf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"username={user}\npassword=\n")
        note = f"CREATED {cf} (mode 600) with an EMPTY password line: put the NAS password after `password=` yourself; never paste it in chat."
    unit = systemd_escape_path(str(mp)) + ".mount"
    path = render("havnvard-nas.mount.tmpl", out_dir, unit, smb=smb, mountpoint=str(mp), cred_file=str(cf),
                  uid=os.getuid() if uid is None else uid, gid=os.getgid() if gid is None else gid, vers=vers)
    config.update("nas", {"smb": smb, "user": user, "cred_file": str(cf), "mountpoint": str(mp),
                          "repo_subdir": repo_subdir})
    lines = [f"# wrote {path}"]
    if note:
        lines.append(note)
    lines += [f"sudo mkdir -p {mp}   # admin step: mount units live in /etc/systemd/system",
              f"sudo cp {path} /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now {unit}",
              "# if the mount fails with a protocol error, edit vers= in the unit (2.1 or 3.1.1) and retry"]
    return lines


def nas_copy() -> int:
    """Copy every hub repo that has a hub-side password file onto the NAS mount (restic copy, same password).
    Returns 0 when every device copied, 1 otherwise; a missing mount is an error, not a pass."""
    cfg = config.load()
    nas, hub = cfg.get("nas"), cfg.get("hub_local")
    if not nas or not hub:
        raise BackupError("need `nas-target` and `hub install` done on this machine first")
    mp = Path(nas["mountpoint"])
    if not os.path.ismount(mp):
        raise BackupError(f"{mp} is not mounted; refusing to write to the local disk instead")
    restic = restic_bin()
    pdir, ok, bad = hub_password_dir(), [], []
    devices = sorted(p.stem for p in pdir.glob("*.pass")) if pdir.is_dir() else []
    if not devices:
        raise BackupError(f"no device password files in {pdir}; nothing can be copied")
    for dev in devices:
        src, dst = Path(hub["repo_root"]) / dev, mp / nas.get("repo_subdir", "restic") / dev
        pw = str(pdir / f"{dev}.pass")
        if not (src / "config").is_file():
            bad.append((dev, "no repo on the hub yet"))
            continue
        common = ["--password-file", pw, "--from-repo", str(src), "--from-password-file", pw]
        if not (dst / "config").is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            r = run([restic, "-r", str(dst), "init", *common, "--copy-chunker-params"])
            if r.returncode != 0:
                bad.append((dev, f"init rc {r.returncode}: {r.stderr.strip()[-150:]}"))
                continue
        r = run([restic, "-r", str(dst), "copy", "--retry-lock", "30m", *common])
        (ok if r.returncode == 0 else bad).append(dev if r.returncode == 0 else (dev, f"copy rc {r.returncode}: {r.stderr.strip()[-150:]}"))
    print(f"nas-copy: {len(ok)}/{len(devices)} devices copied")
    for dev, why in bad:
        print(f"  FAILED {dev}: {why}")
    return 0 if not bad else config.PROBLEM_EXIT
