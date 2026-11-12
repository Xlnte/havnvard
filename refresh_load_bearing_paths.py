#!/usr/bin/env python3
"""diskaudit — load-bearing path refresh (classification layer v1).

Builds diskaudit.load_bearing_paths: the "load-bearing override" that protects cold-but-live
files (a monthly cron script, a yearly-run tool, a rarely-touched config) from being mislabeled
stale/possibly-obsolete purely by mtime/atime age. This is the PRESCAB-cabinet-converged core
insight for the whole classification layer — see:
  - design doc: /home/user/.claude/plans/witty-swinging-shore.md
  - runbook:    /home/user/runbooks/20260718-diskaudit-classification/README.md
  - migration:  /srv/apps/migrations/20260718_diskaudit_classification_v1.sql

TRACEABILITY IS A HARD REQUIREMENT, not polish (the operator, 2026-07-18: "we don't want a GREP going
haywire and not knowing where it is being fired from"). Concretely, this script:
  1. Only ever reads from a small, explicit, BOUNDED set of sources — no recursive find over the
     filesystem, no iteration over "every user" or "every file". See SYSTEMD_GLOB, CRONTAB_USERS,
     and the thoth.census query below; that is the entire scope, on purpose.
  2. Logs a full run record (start/finish, per-source counts, per-source errors) into
     diskaudit.load_bearing_refresh_runs before doing anything else, and updates it at the end —
     so "why does load_bearing_paths have this row" always has a queryable answer.
  3. Is a clean standalone CLI (main() guarded by __name__ == "__main__"). It has no
     module-level side effects, so importing it from anywhere else is inert — the ONLY ways
     this ever runs are the systemd timer (diskaudit-load-bearing-refresh.timer) or a human
     invoking it directly at a terminal. Both are self-evidently traceable (journal / shell
     history), unlike a hidden import-time side effect would be.
  4. Writes precise, per-row provenance into load_bearing_paths.source — e.g.
     'systemd-unit:/etc/systemd/system/diskaudit-scan.service#ExecStart', not a generic
     'systemd' category. Every row answers "which exact file/line produced this."

Safety rule for pattern shape (this is the actual "GREP going haywire" guard):
  - EXACT-file patterns (no '%' wildcard) are always safe and always allowed, from any source —
    by construction they can only ever match the one literal path they were built from.
  - DIRECTORY-WILDCARD patterns (trailing '/%', protecting an entire subtree) are only ever
    emitted for WorkingDirectory=/`cd`-target/census paths, and only when that directory is NOT
    under one of DENY_WILDCARD_PREFIXES (/usr, /bin, /sbin, /lib, /lib64, /etc, /var, /proc,
    /sys, /dev, /run, /tmp). Without this gate, a unit whose ExecStart interpreter happens to be
    /usr/bin/python3 could otherwise blanket-protect the entire /usr/bin tree — exactly the kind
    of unintended blast radius this guard exists to prevent.

Idempotent / safe to re-run: upserts on (pattern, source), never deletes. If a systemd unit or
crontab line disappears, its previously-found load_bearing_paths row is simply not refreshed
again (last_verified_at stops advancing) — it is NOT auto-removed, matching this project's
standing no-auto-delete rule. Pruning a stale entry is a manual, the operator-reviewed decision.

Usage:
  refresh_load_bearing_paths.py                 # real run: scan sources, upsert, refresh MV
  refresh_load_bearing_paths.py --dry-run        # scan + print candidates, no DB writes at all
  refresh_load_bearing_paths.py --no-mv-refresh  # upsert load_bearing_paths but skip the
                                                  # (slow, ~60-90s) diskaudit.refresh_file_status()
                                                  # call at the end
"""
from __future__ import annotations

import argparse
import glob
import os
import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone

import psycopg

# ---- DSN resolution — same SoT + fallback order as scan.py / monitor.py / dedup.py. Duplicated
# here (not imported from scan.py) so this script has zero import-chain coupling to the rest of
# diskaudit — requirement #3 above: a clean, standalone CLI entrypoint.
from havnvard_site import get_dsn  # noqa: E402,F401  (3.0.0: one shared lookup; see havnvard_site.py)


# ---- bounded, explicit scope (see module docstring point 1) ----
SYSTEMD_GLOB = "/etc/systemd/system/*.service"  # non-recursive, explicit — no find(1), no walk
# Explicit, hand-maintained list — the only two users that own scheduled work on this box per
# CLAUDE.md (Part II, USER ARCHITECTURE). Deliberately NOT an iteration over every system/passwd
# user: deprecated and test-only accounts are left out on purpose, and iterating
# blindly over all accounts is exactly the unbounded-scan pattern this script must avoid.
import havnvard_site as _site  # noqa: E402  (3.0.0)

# Users whose crontabs are read ([load_bearing] crontab_users in the site file; default: the running user).
CRONTAB_USERS = list(_site.section("load_bearing").get("crontab_users") or [os.environ.get("USER") or "root"])

DENY_WILDCARD_PREFIXES = (
    "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/etc", "/var", "/proc", "/sys", "/dev", "/run", "/tmp",
)

SYSTEMD_DIRECTIVES = ("ExecStart=", "ExecStartPre=", "ExecStartPost=", "WorkingDirectory=", "EnvironmentFile=")


def is_safe_wildcard_root(dirpath: str) -> bool:
    """True if dirpath is safe to protect as a whole subtree (trailing '/%' pattern). False for
    generic system directories where blanket-protecting everything under them would be the
    'GREP going haywire' failure mode (e.g. /usr/bin from an ExecStart interpreter path)."""
    dirpath = dirpath.rstrip("/")
    return not any(dirpath == p or dirpath.startswith(p.rstrip("/") + "/") for p in DENY_WILDCARD_PREFIXES)


def extract_paths_from_tokens(tokens: list[str]) -> list[str]:
    """Absolute-path-looking tokens from a shell-split command line. Strips systemd's leading
    '-' (optional-directive marker, e.g. '-/path/to/EnvironmentFile') and '@'/'+'/'!' prefixes
    (systemd ExecStart modifiers) before checking for a leading '/'."""
    out = []
    for tok in tokens:
        t = tok.lstrip("-@+!")
        if t.startswith("/"):
            out.append(t)
    return out


def scan_systemd_units() -> tuple[list[dict], list[dict]]:
    """Returns (candidates, errors). candidates: [{'pattern','source'}]. errors: [{'source','error'}]."""
    candidates: list[dict] = []
    errors: list[dict] = []
    for unit_path in sorted(glob.glob(SYSTEMD_GLOB)):
        try:
            with open(unit_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            errors.append({"source": f"systemd-unit:{unit_path}", "error": str(e)})
            continue

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            for directive in SYSTEMD_DIRECTIVES:
                if not stripped.startswith(directive):
                    continue
                value = stripped[len(directive):].strip()
                directive_name = directive.rstrip("=")
                source = f"systemd-unit:{unit_path}#{directive_name}:L{lineno}"

                if directive_name == "WorkingDirectory":
                    d = value.lstrip("-")
                    if d.startswith("/") and is_safe_wildcard_root(d):
                        candidates.append({"pattern": d.rstrip("/") + "/%", "source": source})
                elif directive_name == "EnvironmentFile":
                    f_path = value.lstrip("-")
                    if f_path.startswith("/"):
                        candidates.append({"pattern": f_path, "source": source})
                else:  # ExecStart / ExecStartPre / ExecStartPost
                    try:
                        tokens = shlex.split(value)
                    except ValueError:
                        tokens = value.split()
                    for p in extract_paths_from_tokens(tokens):
                        candidates.append({"pattern": p, "source": source})
    return candidates, errors


def scan_crontabs() -> tuple[dict[str, list[dict]], list[dict]]:
    """Returns ({user: candidates}, errors)."""
    per_user: dict[str, list[dict]] = {}
    errors: list[dict] = []
    for user in CRONTAB_USERS:
        cands: list[dict] = []
        try:
            proc = subprocess.run(
                ["sudo", "-n", "crontab", "-l", "-u", user],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode != 0:
                # crontab -l exits nonzero (and prints "no crontab for X") when the user simply
                # has no crontab — not a real error, don't log it as one unless stderr suggests
                # a permission problem.
                if "no crontab" not in (proc.stdout + proc.stderr).lower():
                    errors.append({"source": f"crontab:{user}", "error": (proc.stderr or proc.stdout).strip()[:500]})
                per_user[user] = []
                continue
            lines = proc.stdout.splitlines()
        except (OSError, subprocess.SubprocessError) as e:
            errors.append({"source": f"crontab:{user}", "error": str(e)})
            per_user[user] = []
            continue

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            source = f"crontab:{user}:L{lineno}"
            # A leading `cd /some/path &&` is this project's own convention (see crontab -l
            # output) for setting a working directory before the real command — treat it the
            # same as systemd's WorkingDirectory= when present.
            if stripped.startswith("cd "):
                cd_target = stripped[3:].split("&&", 1)[0].strip()
                if cd_target.startswith("/") and is_safe_wildcard_root(cd_target):
                    cands.append({"pattern": cd_target.rstrip("/") + "/%", "source": source})
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                tokens = stripped.split()
            for p in extract_paths_from_tokens(tokens):
                cands.append({"pattern": p, "source": source})
        per_user[user] = cands
    return per_user, errors


CENSUS_SKIPPED: list[dict] = []   # identity-checked: `is CENSUS_SKIPPED` means the source is absent


def scan_census(conn) -> list[dict]:
    """thoth.census active-system paths — bounded query, same status='active' filter convention
    as diskaudit.critical_patterns' seed (20260717_diskaudit_multihost_dedup_v2.sql)."""
    candidates: list[dict] = []
    with conn.cursor() as cur:
        # 3.1.0 (INFRA-557): thoth.census is an optional external registry. A site without it scans
        # systemd + crontab only; the skip is logged and recorded as census_skipped in sources_scanned.
        cur.execute("SELECT to_regclass('thoth.census') IS NOT NULL")
        if not cur.fetchone()[0]:
            print("[refresh_load_bearing_paths] census source skipped: no thoth.census table", file=sys.stderr)
            return CENSUS_SKIPPED
        cur.execute(
            "SELECT system_key, primary_path, paths FROM thoth.census "
            "WHERE status = 'active' AND primary_path IS NOT NULL"
        )
        rows = cur.fetchall()
    def _looks_like_file(p: str) -> bool:
        # A path with a dotted final segment (e.g. .py/.sql/.md/.service) is treated as a
        # specific file -> exact pattern. Anything else is treated as a directory -> gated
        # wildcard pattern. Applied uniformly to primary_path and paths[] -- thoth.census
        # primary_path is NOT always a directory (e.g. heimdall-crawl's primary_path is a
        # single .py file), so this check can't be skipped for primary_path.
        return "." in p.rstrip("/").rsplit("/", 1)[-1]

    for system_key, primary_path, paths in rows:
        if primary_path and primary_path.startswith("/"):
            if _looks_like_file(primary_path):
                candidates.append({"pattern": primary_path, "source": f"census:{system_key}#primary_path"})
            elif is_safe_wildcard_root(primary_path):
                candidates.append({
                    "pattern": primary_path.rstrip("/") + "/%",
                    "source": f"census:{system_key}#primary_path",
                })
        for i, p in enumerate(paths or []):
            if not p or not p.startswith("/"):
                continue
            if _looks_like_file(p):
                candidates.append({"pattern": p, "source": f"census:{system_key}#paths[{i}]"})
            elif is_safe_wildcard_root(p):
                candidates.append({"pattern": p.rstrip("/") + "/%", "source": f"census:{system_key}#paths[{i}]"})
    return candidates


def upsert_candidates(conn, run_id: int, candidates: list[dict]) -> int:
    """Upserts (pattern, source) rows, stamping last_refresh_run_id. Returns rows touched."""
    if not candidates:
        return 0
    with conn.cursor() as cur:
        for c in candidates:
            cur.execute(
                """
                INSERT INTO diskaudit.load_bearing_paths (pattern, source, last_verified_at, last_refresh_run_id)
                VALUES (%s, %s, now(), %s)
                ON CONFLICT (pattern, source) DO UPDATE SET
                    last_verified_at = now(), last_refresh_run_id = EXCLUDED.last_refresh_run_id
                """,
                (c["pattern"], c["source"], run_id),
            )
    conn.commit()
    return len(candidates)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="Scan + print candidates only, no DB writes at all")
    ap.add_argument("--no-mv-refresh", action="store_true", help="Skip diskaudit.refresh_file_status() at the end")
    args = ap.parse_args()

    systemd_candidates, systemd_errors = scan_systemd_units()
    crontab_per_user, crontab_errors = scan_crontabs()
    crontab_candidates = [c for cands in crontab_per_user.values() for c in cands]

    sources_scanned = {
        "systemd_units": len(glob.glob(SYSTEMD_GLOB)),
        **{f"crontab_{u}": len(crontab_per_user.get(u, [])) for u in CRONTAB_USERS},
    }
    all_errors = systemd_errors + crontab_errors

    if args.dry_run:
        print(f"[refresh_load_bearing_paths] DRY RUN — sources_scanned={sources_scanned}", file=sys.stderr)
        for c in systemd_candidates + crontab_candidates:
            print(f"  {c['pattern']!r:60} <- {c['source']}")
        if all_errors:
            print(f"[refresh_load_bearing_paths] errors: {all_errors}", file=sys.stderr)
        # census requires a DB connection even in dry-run, to show real candidates
        conn = psycopg.connect(get_dsn(), autocommit=False)
        try:
            census_candidates = scan_census(conn)
            for c in census_candidates:
                print(f"  {c['pattern']!r:60} <- {c['source']}")
            print(
                f"[refresh_load_bearing_paths] DRY RUN total candidates: "
                f"{len(systemd_candidates) + len(crontab_candidates) + len(census_candidates)}",
                file=sys.stderr,
            )
        finally:
            conn.close()
        return

    conn = psycopg.connect(get_dsn(), autocommit=False)
    run_id = None
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO diskaudit.load_bearing_refresh_runs (host, status) VALUES (%s, 'running') RETURNING id",
                (_site.local_host(),),
            )
            run_id = cur.fetchone()[0]
        conn.commit()
        print(f"[refresh_load_bearing_paths] run_id={run_id} started_at={datetime.now(timezone.utc).isoformat()}", file=sys.stderr)

        census_candidates = scan_census(conn)
        if census_candidates is CENSUS_SKIPPED:
            sources_scanned["census_skipped"] = 1
        else:
            sources_scanned["census_active"] = len(census_candidates)

        all_candidates = systemd_candidates + crontab_candidates + census_candidates
        # De-dupe within this run (same (pattern, source) can legitimately appear once per
        # match, e.g. a systemd unit referencing the same path in two directives already gets
        # two distinct sources with :L<n> line numbers, so true duplicates here are rare, but
        # ON CONFLICT DO UPDATE handles them safely either way).
        paths_upserted = upsert_candidates(conn, run_id, all_candidates)

        mv_refreshed = False
        if not args.no_mv_refresh:
            print("[refresh_load_bearing_paths] refreshing diskaudit.mv_file_status (this can take ~60-90s on ~11M rows)...", file=sys.stderr)
            with conn.cursor() as cur:
                cur.execute("SELECT diskaudit.refresh_file_status()")
            conn.commit()
            mv_refreshed = True

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.load_bearing_refresh_runs SET
                    finished_at = now(), status = 'completed',
                    sources_scanned = %s, paths_found = %s, paths_upserted = %s,
                    errors = %s,
                    note = %s
                WHERE id = %s
                """,
                (
                    json.dumps(sources_scanned),
                    len(all_candidates),
                    paths_upserted,
                    json.dumps(all_errors) if all_errors else None,
                    f"mv_refreshed={mv_refreshed}",
                    run_id,
                ),
            )
        conn.commit()
        print(
            f"[refresh_load_bearing_paths] run_id={run_id} status=completed "
            f"candidates={len(all_candidates)} upserted={paths_upserted} errors={len(all_errors)} "
            f"mv_refreshed={mv_refreshed}",
            file=sys.stderr,
        )
    except Exception as e:
        conn.rollback()
        if run_id is not None:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE diskaudit.load_bearing_refresh_runs SET finished_at=now(), status='failed', "
                    "errors = %s WHERE id = %s",
                    (json.dumps(all_errors + [{"source": "main", "error": str(e)[:1000]}]), run_id),
                )
            conn.commit()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
