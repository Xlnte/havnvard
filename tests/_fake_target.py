"""Fake remote-hash transports for nas_trigkey_dedup tests -- no real SSH, no NAS.

FakeTarget runs the REAL hash_stat_batch.sh locally (`sh`) against files the test
created under tmp_path (GNU `stat -c` takes the same %s %Y %i %d %h %F codes as
BusyBox), so the production script text is exercised end to end. Fault knobs:

  scp_get_failures  {batch_idx: n}   next n scp_get(.hashes) of that batch return rc 124 (n=99: always)
  ssh_failures      {batch_idx: n}   next n `sh hash_stat_batch.sh` calls of that batch return rc 124
  mutate_hashes     callable(text)->text   rewrite the fetched .hashes (truncate, drop trailer, corrupt)
  responder         callable(name, items)->(hashes_text, errs_text)   canned output instead of running the script
  on_ssh / on_rm    callables fired before the hash script runs / before each rm -f
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess

import crosshost_verify as cv

_BATCH_RE = re.compile(r"nasdedup_\d+_(\d+)")


def _idx(name: str):
    m = _BATCH_RE.search(name)
    return int(m.group(1)) if m else None


def _cp(rc=0, err=""):
    return subprocess.CompletedProcess([], rc, stdout="", stderr=err)


class FakeTarget(cv._RemoteHashTarget):
    def __init__(self, tmp_path):
        self.scratch_dir = str(tmp_path / "scratch")
        self.scp_get_failures = {}
        self.ssh_failures = {}
        self.mutate_hashes = None
        self.responder = None
        self.on_ssh = None
        self.on_rm = None
        self.log = []                      # (op, detail)
        self.ssh_timeouts = []
        self.rm_calls = []
        self.sent_lists = []               # contents of every .paths file uploaded

    # -- ssh -----------------------------------------------------------------
    def ssh(self, remote_cmd, timeout_sec=None):
        self.log.append(("ssh", remote_cmd))
        if remote_cmd.startswith("mkdir -p"):
            os.makedirs(self.scratch_dir, exist_ok=True)
            return _cp()
        if remote_cmd.startswith("rm -f "):
            paths = remote_cmd[len("rm -f "):].split()
            self.rm_calls.append(paths)
            if self.on_rm:
                self.on_rm(paths)
            for p in paths:
                if os.path.exists(p):
                    os.remove(p)
            return _cp()
        if remote_cmd.startswith("sh "):
            _sh, script, scratch, name = shlex.split(remote_cmd)
            self.ssh_timeouts.append(timeout_sec)
            idx = _idx(name)
            if self.on_ssh:
                self.on_ssh(name)
            if self.ssh_failures.get(idx, 0) > 0:
                self.ssh_failures[idx] -= 1
                return _cp(124, "timed out (fake)")
            if self.responder:
                with open(os.path.join(scratch, f"{name}.paths"), encoding="utf-8") as f:
                    items = [tuple(l.rstrip("\n").split("|", 1)) for l in f if l.strip()]
                h, e = self.responder(name, items)
                with open(os.path.join(scratch, f"{name}.hashes"), "w", encoding="utf-8") as f:
                    f.write(h)
                with open(os.path.join(scratch, f"{name}.hasherrs"), "w", encoding="utf-8") as f:
                    f.write(e)
                return _cp()
            r = subprocess.run(["sh", script, scratch, name], capture_output=True, text=True, timeout=120)
            return _cp(r.returncode, r.stderr)
        return _cp()

    def scp_put(self, local_path, remote_path, timeout_sec=None):
        self.log.append(("put", remote_path))
        os.makedirs(os.path.dirname(remote_path), exist_ok=True)
        shutil.copyfile(local_path, remote_path)
        if remote_path.endswith(".paths"):
            with open(local_path, encoding="utf-8") as f:
                self.sent_lists.append(f.read())
        return _cp()

    def scp_get(self, remote_path, local_path, timeout_sec=None):
        self.log.append(("get", remote_path))
        idx = _idx(remote_path)
        if remote_path.endswith(".hashes") and self.scp_get_failures.get(idx, 0) > 0:
            self.scp_get_failures[idx] -= 1
            return _cp(124, "timed out after 600s (fake, see INFRA-240)")
        if not os.path.exists(remote_path):
            return _cp(1, "no such file (fake)")
        shutil.copyfile(remote_path, local_path)
        if self.mutate_hashes and remote_path.endswith(".hashes"):
            with open(local_path, encoding="utf-8", newline="") as f:
                text = f.read()
            with open(local_path, "w", encoding="utf-8", newline="") as f:
                f.write(self.mutate_hashes(text))
        return _cp()
