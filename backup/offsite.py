"""Offsite copy of the hub's encrypted repos to any rclone remote (ported from restic-hub-offsite).

Kept from the live, reviewed script (hub-scripts review F1-F8, FN-1..FN-7): copy-only (never rclone
sync/purge); the hub holds no passwords here, only ciphertext moves; locks/ never uploaded;
snapshot files are listed BEFORE the data pass and uploaded AFTER it, so a snapshot never lands
before its packs; --immutable --size-only; --cutoff-mode soft; an offsite file is removed only when
it is SMALLER than the hub copy (cut-off upload); a file that comes back LARGER than a hub copy
whose SHA-256 equals its restic name is re-sent at most MAX_TRIES times, then FLAGGED and left out of
every later pass and reported; a resend counts only if the bad copy was really removed; temp files
live in the state dir; HOLD file = repos not uploaded; flock prevents overlap.
Dropped: the Internxt FUSE-mount pacing (buffer dir, --inplace, mount checks): a real rclone
remote does not need it. New: bounded no-progress loop so a failing remote cannot spin for hours.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from . import config
from .config import BackupError
from .util import rclone_bin, run, sha256_file

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$")
MAX_TRIES = 3
FATAL_RC = (2, 7)
HASHED_DIRS = ("data/", "index/", "snapshots/", "keys/")


def offsite_add(name: str, remote: str, crypt: bool) -> None:
    if not NAME_RE.match(name):
        raise BackupError(f"bad offsite name {name!r}")
    if not remote:
        raise BackupError("--rclone-remote is required")
    if crypt:
        rname = remote.split(":", 1)[0]
        r = run([rclone_bin(), "listremotes", "--long"], timeout=60)
        if r.returncode != 0:
            raise BackupError(f"rclone listremotes failed: {r.stderr.strip()[-200:]}")
        types = {ln.split(":")[0]: ln.split(":", 1)[1].strip() for ln in r.stdout.splitlines() if ":" in ln}
        if ":" not in remote or types.get(rname) != "crypt":
            raise BackupError(f"--crypt: rclone remote {rname!r} is not of type crypt "
                              f"(found {types.get(rname)!r}); create it with `rclone config` first")
    config.update("offsite", {name: {"rclone_remote": remote, "crypt": crypt}})


class _Run:
    def __init__(self, name: str, remote: str, hub: Path, max_seconds: int, bwlimit: str):
        self.name, self.dst_root, self.hub = name, remote.rstrip("/"), hub
        self.rclone = rclone_bin()
        self.st = config.state_dir()
        self.st.mkdir(parents=True, exist_ok=True)
        self.log_path = self.st / f"offsite-{name}.log"
        self.flag_path = self.st / f"offsite-{name}.flagged"
        self.tries_path = self.st / f"offsite-{name}.tries"
        self.hold_path = self.st / f"offsite-{name}.hold"
        self.orphans_path = self.st / f"offsite-{name}.orphans-ok"
        self.bwlimit = bwlimit
        self.orphan_left = int(config.load().get("offsite_settings", {}).get("orphan_check_bytes", 2 * 1024**3))
        self.orphans_deferred = 0
        self.orphans_ok: set[str] | None = None
        for p in (self.flag_path, self.tries_path, self.orphans_path):
            p.touch()
        self.start = time.monotonic()
        self.max_seconds = max_seconds
        self.min_left = min(120, max_seconds // 4)
        self.flags = ["--immutable", "--size-only", "--cutoff-mode", "soft", "--transfers", "2",
                      "--checkers", "4", "--bwlimit", bwlimit, "--retries", "1", "--low-level-retries", "5",
                      "--log-file", str(self.log_path), "--log-level", "ERROR"]

    def log(self, msg: str) -> None:
        line = f"[{dt.datetime.now():%F %T}] {msg}"
        print(line)
        with open(self.log_path, "a") as f:
            f.write(line + "\n")

    def left(self) -> int:
        return int(self.max_seconds - (time.monotonic() - self.start))

    def flagged(self, repo: str) -> list[str]:
        pre = f"{repo}/"
        return [ln[len(pre):] for ln in self.flag_path.read_text().splitlines() if ln.startswith(pre)]

    def filter_file(self, repo: str) -> Path:
        p = self.st / f"offsite-{self.name}-flt-{repo}.txt"
        p.write_text("".join(f"- /{f}\n" for f in self.flagged(repo)))
        return p

    def offsite_sizes(self, repo: str) -> dict[str, int]:
        r = run([self.rclone, "lsjson", "-R", "--files-only", "--no-mimetype", "--no-modtime",
                 f"{self.dst_root}/{repo}"], timeout=1800)
        if r.returncode == 3:   # rclone: directory not found == nothing uploaded yet
            return {}
        if r.returncode != 0:
            raise BackupError(f"rclone lsjson failed rc={r.returncode}: {r.stderr.strip()[-200:]}")
        return {e["Path"]: int(e["Size"]) for e in json.loads(r.stdout or "[]")}

    def delete_offsite(self, repo: str, rel: str) -> bool:
        r = run([self.rclone, "deletefile", f"{self.dst_root}/{repo}/{rel}"], timeout=300)
        return r.returncode == 0

    def cleanup(self, repo: str) -> int:
        """Fix half-written or bad offsite files. Returns number of files removed (resends). Raises on lsjson failure."""
        sizes, n, flagged = self.offsite_sizes(repo), 0, set(self.flagged(repo))
        for rel, ds in sorted(sizes.items()):
            if rel in flagged or rel.startswith("locks/"):
                continue
            try:
                hs = (self.hub / repo / rel).stat().st_size
            except OSError:
                self._orphan(repo, rel, ds)   # review R1: never deleted; 3.2.0: checked once, damage flagged
                continue
            if ds < hs:
                if self.delete_offsite(repo, rel):
                    n += 1
            elif ds > hs:
                n += self._larger(repo, rel, ds, hs)
        if n:
            self.log(f"{repo}: removed {n} half-written file(s)")
        return n

    def _orphan(self, repo: str, rel: str, size: int) -> None:
        """A mirror file the hub no longer has (the owner deleted snapshots on the hub). The mirror copy is now the
        only one, so it is checked ONCE against its own name (restic names data/index/snapshots/keys files by their
        SHA-256) and recorded. A damaged copy (e.g. an upload cut off just before the hub prune) cannot be resent:
        it is FLAGGED, which health alerts on, and kept (never deleted); `restic repair packs` on the mirror salvages it.
        Bounded (review FULL FIX-NOW 5): at most `orphan_check_bytes` per run (default 2 GiB; `orphan_check_bytes` under [offsite_settings] in backup.toml),
        only while the run's time budget lasts, at the run's --bwlimit; the rest is checked on later runs."""
        k = f"{repo}/{rel}"
        if self.orphans_ok is None:
            self.orphans_ok = set(self.orphans_path.read_text().splitlines())
        if not rel.startswith(HASHED_DIRS) or k in self.orphans_ok:
            return
        if size > self.orphan_left or self.left() <= self.min_left:
            self.orphans_deferred += 1
            return
        self.orphan_left -= size
        with tempfile.TemporaryFile() as errf:
            proc = subprocess.Popen([self.rclone, "cat", "--bwlimit", self.bwlimit, f"{self.dst_root}/{repo}/{rel}"],
                                    stdout=subprocess.PIPE, stderr=errf)
            h = hashlib.sha256()
            for chunk in iter(lambda: proc.stdout.read(1 << 20), b""):
                h.update(chunk)
            rc = proc.wait()
            errf.seek(0)
            err = errf.read().decode(errors="replace")
        if rc != 0:
            fails = sum(1 for ln in self.tries_path.read_text().splitlines() if ln.startswith(f"orphan:{k} "))
            with open(self.tries_path, "a") as f:
                f.write(f"orphan:{k} {fails + 1}\n")
            if fails + 1 >= MAX_TRIES and rel not in self.flagged(repo):
                with open(self.flag_path, "a") as f:
                    f.write(k + "\n")
                self.log(f"FLAGGED {k}: mirror-only copy unreadable {MAX_TRIES} times ({err.strip()[-120:]}); kept")
            else:
                self.log(f"{k}: hub copy gone and the mirror copy could not be read ({err.strip()[-120:]}); will retry")
            return
        if h.hexdigest() == Path(rel).name:
            with open(self.orphans_path, "a") as f:
                f.write(k + "\n")
            self.orphans_ok.add(k)
            return
        if rel not in self.flagged(repo):
            with open(self.flag_path, "a") as f:
                f.write(k + "\n")
        self.log(f"FLAGGED {k}: DAMAGED on the mirror and the hub copy is gone (hub deleted it); kept, not deleted. "
                 "Run `restic repair packs` on the mirror repository")

    def _larger(self, repo: str, rel: str, ds: int, hs: int) -> int:
        k = f"{repo}/{rel}"
        verified = rel.startswith(HASHED_DIRS) and sha256_file(self.hub / repo / rel) == Path(rel).name
        if not verified:
            self.log(f"ALERT {k}: offsite ({ds}) larger than hub ({hs}), hub hash unverified; kept")
            return 0
        counts = {}
        for ln in self.tries_path.read_text().splitlines():
            key, _, c = ln.rpartition(" ")
            if c.isdigit():
                counts[key] = int(c)
        c = counts.get(k, 0) + 1
        if c > MAX_TRIES:
            if rel not in self.flagged(repo):
                with open(self.flag_path, "a") as f:
                    f.write(k + "\n")
                self.log(f"FLAGGED {k}: offsite ({ds}) larger than verified hub ({hs}) after {MAX_TRIES} resends; "
                         "no more resends, operator to review")
            return 0
        if self.delete_offsite(repo, rel):    # count a resend only when the bad copy is really gone (FN-6)
            with open(self.tries_path, "a") as f:
                f.write(f"{k} {c}\n")
            self.log(f"{k}: offsite ({ds}) larger than verified hub ({hs}); removed (resend {c} of {MAX_TRIES})")
            return 1
        self.log(f"{k}: offsite larger than verified hub but delete failed; not counted")
        return 0

    def push(self, repo: str, extra: list[str]) -> int:
        """Copy one part of a repo in slices until rclone succeeds or the budget ends. 0 done, 1 incomplete, 2 fatal."""
        stalled = 0
        while self.left() > self.min_left:
            slice_s = max(1, min(self.left(), 900))
            filt = [] if "--files-from" in extra else ["--filter-from", str(self.filter_file(repo))]
            r = run([self.rclone, "copy", str(self.hub / repo), f"{self.dst_root}/{repo}", *self.flags,
                     "--max-duration", f"{slice_s}s", *filt, *extra])
            if r.returncode == 0:
                return 0
            if r.returncode in FATAL_RC:
                self.log(f"ERROR: rclone fatal rc={r.returncode} on {repo}: {r.stderr.strip()[-200:]}")
                return 2
            before = len(self.flagged(repo))
            fixed = self.cleanup(repo) + (len(self.flagged(repo)) - before)
            stalled = 0 if fixed else stalled + 1
            if stalled >= 3:
                self.log(f"ERROR: {repo}: rclone rc={r.returncode} three times with nothing to repair: "
                         f"{r.stderr.strip()[-200:]}")
                return 2
        return 1


def offsite_run(name: str | None = None, max_seconds: int = 21000, bwlimit: str = "3M") -> int:
    """0 = all repos uploaded, 75 = time budget used (the timer resumes), 2 = failure (also raised as BackupError
    for setup problems). Flagged files are reported in the final line and written to the status file."""
    cfg = config.load()
    targets = cfg.get("offsite", {})
    if not targets:
        raise BackupError("no offsite target configured; run `offsite add NAME --rclone-remote REMOTE:PATH`")
    names = [name] if name else sorted(targets)
    if name and name not in targets:
        raise BackupError(f"unknown offsite target {name!r}")
    root = cfg.get("hub_local", {}).get("repo_root")
    if not root or not Path(root).is_dir():
        raise BackupError("hub repo_root missing or not a directory; offsite runs on the hub")
    worst = 0
    for nm in names:
        worst = max(worst, _run_target(nm, targets[nm]["rclone_remote"], Path(root), max_seconds, bwlimit))
    return worst


def _run_target(nm: str, remote: str, hub: Path, max_seconds: int, bwlimit: str) -> int:
    st = config.state_dir()
    st.mkdir(parents=True, exist_ok=True)
    lock = open(st / f"offsite-{nm}.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"offsite {nm}: already running")
        return 0
    o = _Run(nm, remote, hub, max_seconds, bwlimit)
    repos = sorted(p.name for p in hub.iterdir() if p.is_dir() and not p.name.startswith("."))
    o.log(f"=== offsite {nm}: {len(repos)} repos ===")
    rc, total_flagged = 0, 0
    for r in repos:
        if o.hold_path.exists() and r in o.hold_path.read_text().split():
            o.log(f"HOLD {r} (listed in {o.hold_path}; not uploaded)")
            continue
        o.cleanup(r)
        snaps = sorted(str(p.relative_to(hub / r)) for p in (hub / r / "snapshots").glob("*") if p.is_file()) \
            if (hub / r / "snapshots").is_dir() else []
        snaps = [s for s in snaps if s not in set(o.flagged(r))]
        lst = st / f"offsite-{nm}-snaps-{r}.txt"
        lst.write_text("".join(s + "\n" for s in snaps))
        p = o.push(r, ["--filter", "- locks/**", "--filter", "- snapshots/**"])
        if p == 0:
            p = o.push(r, ["--files-from", str(lst)])
        if p == 2:
            rc = 2
            break
        if p == 1:
            o.log(f"INCOMPLETE {r} (time budget used; next run continues)")
            rc = 75
            break
        nf = len(o.flagged(r))
        total_flagged += nf
        o.log(f"OK-FLAGGED {r} ({nf} flagged file(s) not offsite; operator to review)" if nf else f"OK  {r}")
    if o.orphans_deferred:
        o.log(f"{o.orphans_deferred} mirror-only file(s) not checked yet (byte or time budget); later runs continue")
    o.log(f"=== offsite {nm} end rc={rc} flagged={total_flagged} ran {int(time.monotonic() - o.start)}s ===")
    sp = st / f"offsite-{nm}.status.json"
    try:
        prev_ok = json.loads(sp.read_text()).get("ok_at")
    except (OSError, ValueError):
        prev_ok = None
    sp.write_text(json.dumps({"rc": rc, "flagged": total_flagged, "at": time.time(),
                              "ok_at": time.time() if rc == 0 else prev_ok}))
    return rc
