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


def nas_copy(max_seconds: int = 21000, bwlimit: str = "0") -> int:
    """Mirror every hub repo onto the NAS mount as-is: the files are already encrypted, so this needs NO
    device passwords (review 20261111 F1: the earlier `restic copy` version made the hub hold every device's
    password just to copy). Reuses the offsite uploader with the mount as a local rclone path, so it keeps the
    same copy-only, snapshots-last, cut-off-repair rules. A missing mount is an error, not a pass."""
    from .offsite import _run_target
    cfg = config.load()
    nas, hub = cfg.get("nas"), cfg.get("hub_local")
    if not nas or not hub:
        raise BackupError("need `nas-target` and `hub install` done on this machine first")
    mp = Path(nas["mountpoint"])
    if not os.path.ismount(mp):
        raise BackupError(f"{mp} is not mounted; refusing to write to the local disk instead")
    root = Path(hub["repo_root"])
    if not root.is_dir():
        raise BackupError(f"hub repo_root {root} is not a directory")
    dst = mp / nas.get("repo_subdir", "restic")
    dst.mkdir(parents=True, exist_ok=True)
    rc = _run_target("nas", str(dst), root, max_seconds, bwlimit)
    print(f"nas-copy: rc={rc} (0 = every repo mirrored, 75 = time budget used, 2 = failure)")
    return rc
