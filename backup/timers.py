"""`check-timers`: list havnvard-restic-* systemd timers whose script or backup source no longer exists
(GHY-209/210: archiving an app left its timers failing). Read-only: only `systemctl list-timers` and
`systemctl cat` are run; the command runner and file probes are injectable."""
from __future__ import annotations

import os
import re

from .config import BackupError
from .util import run

TIMER_RE = re.compile(r"\bhavnvard-restic-[A-Za-z0-9_.@-]*?\.timer\b")
SRC_RE = re.compile(r"""^\s*(?:export\s+)?BACKUP_SRC=["']?(/[^"'\s$]+)""", re.M)


def default_runner(cmd: list[str]) -> tuple[int, str]:
    r = run(cmd, timeout=30)
    return r.returncode, r.stdout


def _exec_paths(unit_text: str) -> list[str]:
    paths = []
    for m in re.finditer(r"^ExecStart=(.*)$", unit_text, re.M):
        for tok in m.group(1).lstrip("-@:+!").split():
            if tok.startswith("/") and re.search(r"\.(sh|py|pl)$", tok):
                paths.append(tok)
        first = m.group(1).lstrip("-@:+!").split()
        if first and first[0].startswith("/"):
            paths.append(first[0])
    return list(dict.fromkeys(paths))


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read(200_000)


def check_timers(runner=default_runner, exists=os.path.exists, read=_read,
                 scopes: tuple[tuple[str, ...], ...] = ((), ("--user",))) -> list[tuple[str, str, str]]:
    """[(timer, what is missing, path)]; empty list = every timer's targets exist."""
    findings, seen = [], set()
    for scope in scopes:
        rc, out = runner(["systemctl", *scope, "list-timers", "--all", "--no-legend", "--no-pager"])
        if rc != 0:
            raise BackupError(f"systemctl {' '.join(scope)} list-timers failed (rc {rc})")
        for timer in sorted(set(TIMER_RE.findall(out))):
            if (scope, timer) in seen:
                continue
            seen.add((scope, timer))
            svc = timer[:-len(".timer")] + ".service"
            rc, txt = runner(["systemctl", *scope, "cat", svc])
            if rc != 0:
                findings.append((timer, "service unit cannot be read (systemctl cat failed)", svc))
                continue
            wd = re.search(r"^WorkingDirectory=-?(\S+)", txt, re.M)
            if wd and wd.group(1).startswith("/") and not exists(wd.group(1)):
                findings.append((timer, "WorkingDirectory is gone", wd.group(1)))
            for p in _exec_paths(txt):
                if not exists(p):
                    findings.append((timer, "ExecStart script is gone", p))
                    continue
                if not re.search(r"\.(sh|py|pl)$", p):
                    continue          # a binary such as /bin/bash: exists, nothing to parse
                try:
                    body = read(p)
                except OSError:
                    continue
                for src in SRC_RE.findall(body):
                    if not exists(src):
                        findings.append((timer, f"backup source (BACKUP_SRC in {p}) is gone", src))
    return findings


def run_check(runner=default_runner) -> int:
    f = check_timers(runner)
    if not f:
        print("check-timers: every havnvard-restic-* timer still has its script and backup source")
        return 0
    for timer, what, path in f:
        print(f"STALE {timer}: {what}: {path}")
    print("check-timers: archived app? disable BOTH havnvard-restic-<app>.timer and havnvard-restic-<app>-retention.timer "
          "(RUNBOOK 'Archiving an app').")
    return 1
