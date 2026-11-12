"""Restore drill: restore a random sample of files from the latest snapshot into a scratch dir and compare the
full SHA-256 with the live files. Restore is the only proof a backup works; this prints X/Y matched."""
from __future__ import annotations

import datetime as dt
import json
import os
import random
import re
import subprocess
import tempfile
from pathlib import Path

from . import config
from .config import BackupError
from .enroll import client_env
from .util import hub_password_dir, restic_bin, run, sha256_file


def _canary() -> None:
    """The comparison must tell one changed byte from none, or its verdicts mean nothing."""
    with tempfile.TemporaryDirectory(prefix="havnvard-canary-") as d:
        a, b, c = (Path(d) / n for n in "abc")
        body = b"x" * 5_000_000 + b"m" + b"y" * 1000
        a.write_bytes(body)
        b.write_bytes(body)
        c.write_bytes(body.replace(b"m", b"M"))
        if sha256_file(a) != sha256_file(b) or sha256_file(a) == sha256_file(c):
            raise BackupError("drill canary failed: SHA-256 comparison cannot be trusted")


def _env_for(device: str) -> dict:
    cfg = config.load()
    hub, pw = cfg.get("hub_local"), hub_password_dir() / f"{device}.pass"
    if hub and pw.is_file() and (Path(hub["repo_root"]) / device / "config").is_file():
        return {"RESTIC_REPOSITORY": str(Path(hub["repo_root"]) / device), "RESTIC_PASSWORD_FILE": str(pw)}
    if cfg.get("device", {}).get("name") == device:
        return client_env(cfg)[0]
    raise BackupError(f"cannot open {device}'s repository: no hub-side password file and this is not that device")


def _parse_time(s: str) -> float:
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    return dt.datetime.fromisoformat(s).timestamp()


def _esc(p: str) -> str:
    return re.sub(r"([\\*?\[])", r"\\\1", p)


def sample_files(restic: str, env: dict, snap_id: str, snap_time: float, k: int, rng: random.Random):
    """Reservoir-sample k restorable files from `restic ls --json` without holding the listing in memory.
    A file is eligible only if the live copy exists with the same size and is not newer than the snapshot."""
    proc = subprocess.Popen([restic, "ls", "--json", snap_id], env={**os.environ, **env},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pool, seen, skipped = [], 0, 0
    for line in proc.stdout:
        try:
            n = json.loads(line)
        except ValueError:
            continue
        if n.get("type") != "file" or not n.get("size"):
            continue
        try:
            st = Path(n["path"]).stat()
        except OSError:
            skipped += 1
            continue
        if st.st_size != n["size"] or st.st_mtime > snap_time:
            skipped += 1
            continue
        seen += 1
        if len(pool) < k:
            pool.append(n["path"])
        elif (j := rng.randrange(seen)) < k:
            pool[j] = n["path"]
    err = proc.stderr.read()
    if proc.wait() != 0:
        raise BackupError(f"restic ls failed rc={proc.returncode}: {err.strip()[-300:]}")
    return pool, seen, skipped


def drill(device: str, sample: int = 20, seed: int | None = None, scratch: str | None = None) -> int:
    if sample < 1:
        raise BackupError("--sample must be >= 1")
    _canary()
    env, restic = _env_for(device), restic_bin()
    from .catalog import latest_data_snapshot   # 2.2.0: catalog snapshots are not backups of the device
    snap = latest_data_snapshot(restic, env)
    if not snap:
        raise BackupError(f"{device}: repository has no data snapshots, nothing to restore")
    files, eligible, skipped = sample_files(restic, env, snap["id"], _parse_time(snap["time"]), sample,
                                            random.Random(seed))
    if not files:
        print(f"restore-drill {device}: 0/0 compared ({skipped} files skipped as changed or missing live); "
              "NOT PROVEN, run it where the live files are")
        return config.PROBLEM_EXIT
    with tempfile.TemporaryDirectory(prefix="havnvard-drill-", dir=scratch) as tmp:
        cmd = [restic, "restore", snap["id"], "--target", tmp]
        for p in files:
            cmd += ["--include", _esc(p)]
        rr = run(cmd, env=env)
        if rr.returncode != 0:
            raise BackupError(f"restic restore failed rc={rr.returncode}: {rr.stderr.strip()[-300:]}")
        matched, bad = 0, []
        for p in files:
            got = Path(tmp) / p.lstrip("/")
            try:
                same = sha256_file(got) == sha256_file(p)
            except OSError as e:
                bad.append((p, f"unreadable: {e}"))
                continue
            if same:
                matched += 1
            else:
                bad.append((p, "SHA-256 differs"))
    print(f"restore-drill {device}: {matched}/{len(files)} matched (snapshot {snap['short_id'] if 'short_id' in snap else snap['id'][:8]}, "
          f"{eligible} eligible files, {skipped} skipped as changed or missing live)")
    for p, why in bad:
        print(f"  MISMATCH {p}: {why}")
    return 0 if matched == len(files) else config.PROBLEM_EXIT
