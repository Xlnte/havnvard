"""Hub-side retention. Append-only clients cannot forget or prune; the hub does, with its own copy of each
device's repo password (hub-passwords/DEVICE.pass, 600), straight on the local repo directory."""
from __future__ import annotations

import os
import time
from pathlib import Path

from . import config
from .config import BackupError
from .util import hub_password_dir, restic_bin, run

DEFAULTS = {"keep_daily": 7, "keep_weekly": 4, "keep_monthly": 0}   # about 5 weeks of history


def retention(over: dict) -> dict:
    out = dict(DEFAULTS)
    out.update({k: int(v) for k, v in config.load().get("retention", {}).items() if k in DEFAULTS})
    out.update({k: int(v) for k, v in over.items() if v is not None})
    if any(v < 0 for v in out.values()) or not any(out.values()):
        raise BackupError(f"bad retention {out}: values must be >= 0 and not all zero")
    return out


def oldest_lock_age_h(repo: Path, now: float) -> float | None:
    d = repo / "locks"
    if not d.is_dir():
        return None
    mt = [e.stat().st_mtime for e in os.scandir(d) if e.is_file()]
    return (now - min(mt)) / 3600 if mt else None


def prune(over: dict, stale_lock_hours: float = 6.0, dry_run: bool = False) -> int:
    hub = config.load().get("hub_local")
    if not hub:
        raise BackupError("prune runs on the hub; run `hub install` here first")
    root, pdir, keep = Path(hub["repo_root"]), hub_password_dir(), retention(over)
    devices = sorted(p.stem for p in pdir.glob("*.pass")) if pdir.is_dir() else []
    if not devices:
        raise BackupError(f"no device password files in {pdir}; the hub cannot prune without them")
    restic, done, bad = restic_bin(), [], []
    for dev in devices:
        repo, pw = root / dev, str(pdir / f"{dev}.pass")
        if not (repo / "config").is_file():
            bad.append((dev, "no repository on the hub"))
            continue
        env = {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": pw}
        age = oldest_lock_age_h(repo, time.time())
        if age is not None and age > stale_lock_hours:
            # `restic unlock` removes only stale locks (crashed or long-dead holders), never a live one.
            run([restic, "unlock"], env=env, timeout=300)
            print(f"{dev}: oldest lock {age:.1f} h old, ran restic unlock (stale locks only)")
        cmd = [restic, "forget", "--prune", "--retry-lock", "30m",
               *[f"--{k.replace('_', '-')}={v}" for k, v in keep.items() if v], "--group-by", "host,paths"]
        if dry_run:
            cmd.append("--dry-run")
        r = run(cmd, env=env)
        (done if r.returncode == 0 else bad).append(dev if r.returncode == 0 else (dev, f"rc {r.returncode}: {r.stderr.strip()[-200:]}"))
    print(f"prune: {len(done)}/{len(devices)} repos {'checked (dry run)' if dry_run else 'pruned'}, keep {keep}")
    for dev, why in bad:
        print(f"  FAILED {dev}: {why}")
    return 0 if not bad else config.PROBLEM_EXIT
