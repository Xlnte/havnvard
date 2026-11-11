"""Helpers for the HavnVard Backup tests. Everything runs in tmp dirs with local restic repos and local-path
rclone 'remotes': no Postgres, no live hub, no NAS, no real rclone remote, no network."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

HAVE_RESTIC = shutil.which("restic") is not None
HAVE_RCLONE = shutil.which("rclone") is not None
needs_restic = pytest.mark.skipif(not HAVE_RESTIC, reason="restic not installed")
needs_rclone = pytest.mark.skipif(not (HAVE_RESTIC and HAVE_RCLONE), reason="restic/rclone not installed")


def restic(repo, pw, *args, env=None):
    e = {**os.environ, "RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": str(pw), **(env or {})}
    r = subprocess.run(["restic", *args], env=e, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    return r.stdout


def make_repo(repo, pw, data, snapshots=1):
    pw.write_text("test-password\n")
    restic(repo, pw, "init")
    for i in range(snapshots):
        (data / f"extra{i}.txt").write_text(f"change {i}\n" * 50)
        restic(repo, pw, "backup", str(data))
