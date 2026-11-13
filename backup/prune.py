"""Hub-side deletion, on the owner's explicit order only (3.2.0, INFRA-571).

HavnVard is long-term storage: nothing is ever removed from a repository unless the owner says so. There is
no default retention rule, no prune timer, and archive-tagged snapshots are never forgotten by a rule.
Every deletion (`prune`, `forget-before`, `forget-after`) goes through `delete_snapshots`: ONE device, the owner's
own copy of that repository's password (`--owner-key`; the hub's stored copy in hub-passwords/, used for catalog,
drills and NAS copy, is refused), the full list printed, the exact typed text, then exactly the listed snapshot
IDs are forgotten (a backup that lands in between is never caught by a moved keep window; review L1).
Honest limit: --owner-key checks which FILE is given, not which key; it is a HavnVard rule, not encryption.
Whoever controls the hub's disk can destroy files on it, which is why the NAS and offsite copies are copy-only."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from . import config
from .config import BackupError
from .util import hub_password_dir, restic_bin, run

KEYS = ("keep_daily", "keep_weekly", "keep_monthly", "keep_yearly")   # fixed order: confirmation text is stable
ARCHIVE_TAG = "archive"


def retention(over: dict) -> dict:
    """Keep rule from the command line only (no stored default; review L2). An empty rule is refused."""
    out = {k: over[k] for k in KEYS if over.get(k) is not None}
    if any(not isinstance(v, int) or v < 0 for v in out.values()):
        raise BackupError(f"bad keep rule {out}: values must be whole numbers >= 0")
    out = {k: v for k, v in out.items() if v}
    if not out:
        raise BackupError("no keep rule given: HavnVard keeps every snapshot unless you choose a rule "
                          "(e.g. --keep-monthly 12); nothing was changed")
    return out


def check_device(device: str) -> str:
    from .enroll import NAME_RE
    if not NAME_RE.match(device or ""):
        raise BackupError(f"bad device name {device!r}: letters, digits, . _ - only")
    return device


def hub_repo_env(device: str, key_file: str | None) -> tuple[Path, dict]:
    hub = config.load().get("hub_local")
    if not hub:
        raise BackupError("deletion runs on the hub; run `hub install` here first")
    repo = Path(hub["repo_root"]) / check_device(device)
    if not (repo / "config").is_file():
        raise BackupError(f"no repository for {device} on the hub")
    return repo, {"RESTIC_REPOSITORY": str(repo), "RESTIC_PASSWORD_FILE": owner_key(device, key_file)}


def owner_key(device: str, key_file: str | None) -> str:
    """The owner's own password file for DEVICE's repository. The hub's stored copy is refused for deletion."""
    if not key_file:
        raise BackupError(f"deleting from {device}'s backups needs --owner-key FILE (the owner's copy of that "
                          "repository's password); nothing was changed")
    p = Path(key_file).expanduser().resolve()
    if not p.is_file():
        raise BackupError(f"--owner-key {p} is not a file")
    if p.is_relative_to(hub_password_dir().resolve()):
        raise BackupError("--owner-key must be the owner's own copy, not the hub's stored password; nothing was changed")
    return str(p)


def confirm_text(device: str, what: str) -> str:
    return f"DELETE FROM {device} {what}"


def confirmed(expected: str, given: str | None, ask=input) -> bool:
    """True only if the exact text was given with --confirm or typed at the prompt. No terminal = no."""
    if given is not None:
        if given != expected:
            print(f'--confirm text does not match; it must be exactly: "{expected}"')
        return given == expected
    if not sys.stdin.isatty():
        print(f'no terminal to ask on; pass --confirm "{expected}" to delete')
        return False
    try:
        return ask(f'Type exactly "{expected}" to delete, anything else to stop: ').strip() == expected
    except EOFError:
        return False


def oldest_lock_age_h(repo: Path, now: float) -> float | None:
    d = repo / "locks"
    if not d.is_dir():
        return None
    mt = [e.stat().st_mtime for e in os.scandir(d) if e.is_file()]
    return (now - min(mt)) / 3600 if mt else None


def clear_stale_locks(restic: str, env: dict, repo: Path, device: str, hours: float) -> None:
    age = oldest_lock_age_h(repo, time.time())
    if age is not None and age > hours:
        run([restic, "unlock"], env=env, timeout=300)   # removes stale locks only, never a live one
        print(f"{device}: oldest lock {age:.1f} h old, ran restic unlock (stale locks only)")


def delete_snapshots(restic: str, env: dict, device: str, snaps: list[dict], what: str,
                     confirm: str | None, ask=input) -> int:
    """The ONE deletion path. Lists every snapshot, asks for the exact text, forgets exactly these IDs, prunes."""
    if not snaps:
        print(f"{device}: nothing to delete ({what})")
        return 0
    for s in snaps:
        print(f"  remove {s['id'][:8]}  {s['time'][:19]}  {','.join(s.get('tags') or [])}  {' '.join(s.get('paths', []))}")
    archived = sum(1 for s in snaps if ARCHIVE_TAG in (s.get("tags") or []))
    print(f"{device}: {len(snaps)} snapshot(s) would be deleted ({archived} archive-tagged)")
    expected = confirm_text(device, f"{len(snaps)} SNAPSHOTS {what}")
    if not confirmed(expected, confirm, ask):
        print(f"{device}: not confirmed; nothing was deleted")
        return config.PROBLEM_EXIT
    r = run([restic, "forget", "--retry-lock", "30m", *[s["id"] for s in snaps]], env=env)
    if r.returncode != 0:
        raise BackupError(f"restic forget failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    p = run([restic, "prune", "--retry-lock", "30m"], env=env)
    if p.returncode != 0:
        print(f"{device}: {len(snaps)} forgotten, but prune FAILED rc={p.returncode}: {p.stderr.strip()[-300:]} "
              "(space not freed yet; re-run `restic prune`)")
        return config.PROBLEM_EXIT
    print(f"{device}: {len(snaps)}/{len(snaps)} snapshots deleted ({what}) and space freed")
    return 0


def prune(device: str, over: dict, key_file: str | None, confirm: str | None = None,
          stale_lock_hours: float = 6.0, dry_run: bool = False, ask=input) -> int:
    keep = retention(over)
    repo, env = hub_repo_env(device, key_file)
    restic = restic_bin()
    clear_stale_locks(restic, env, repo, device, stale_lock_hours)          # before the preview (review L4)
    cmd = [restic, "forget", "--dry-run", "--json", *[f"--{k.replace('_', '-')}={v}" for k, v in keep.items()],
           "--keep-tag", ARCHIVE_TAG, "--group-by", "host,paths"]
    r = run(cmd, env=env)
    if r.returncode != 0:
        raise BackupError(f"restic forget --dry-run failed rc={r.returncode}: {r.stderr.strip()[-300:]}")
    try:
        groups = json.loads(r.stdout or "[]")
    except ValueError as e:
        raise BackupError(f"restic forget --json output unreadable: {e}") from e
    remove = [s for g in groups for s in (g.get("remove") or [])]
    remove = [s for s in remove if ARCHIVE_TAG not in (s.get("tags") or [])]   # belt and braces
    kept = sum(len(g.get("keep") or []) for g in groups)
    print(f"prune {device}: keep {keep} + every '{ARCHIVE_TAG}' snapshot -> {kept} kept, {len(remove)} to delete")
    if dry_run:
        for s in remove:
            print(f"  would remove {s['id'][:8]}  {s['time'][:19]}")
        return 0
    rule = " ".join(f"{k}={v}" for k, v in keep.items())
    return delete_snapshots(restic, env, device, remove, f"BY RULE {rule}", confirm, ask)
