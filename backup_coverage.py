#!/usr/bin/env python3
"""diskaudit — TRUE backup-coverage classifier (HavnVard).

Answers the owner's actual question -- "what on the server/agent-1 is NOT safely
on the NAS" -- across the COMPLETE file universe, not the <1% candidate set
that crosshost_verify.py's cross-host-size-match or v_backup_coverage's
critical_patterns filter cover (both measured 2026-07-25; see
diskaudit/RUNBOOK.md and migrations/20260725_diskaudit_backup_coverage_v3.sql
for the full design-flaw writeup).

Pipeline, run in this order (classify lands FIRST -- fast, no remote I/O):

    backup_coverage.py classify --host server-1
    backup_coverage.py classify --host agent-1
    backup_coverage.py verify   --host server-1   # cheap: promotes rows to
                                                     # VERIFIED using hash
                                                     # evidence ALREADY on disk
                                                     # in diskaudit.files /
                                                     # integrity_checks -- does
                                                     # NOT launch new hashing.
    backup_coverage.py report   --host server-1 --out /path/to/report.md

classify does three things per in-scope file:
  1. Scope check against diskaudit.backup_scope_rules (bulk SQL, first match
     by priority wins) -> EXCLUDED, recorded with the rule reason.
  2. Restic-covered-root check: for the 10 known restic backup targets
     (see RESTIC_TARGETS below), fetch the latest snapshot's file listing
     (`restic ls <snap> --long --json`) and match by (relative path, size)
     -> BACKED_UP_UNVERIFIED / match_method='restic_snapshot_listing'.
     This is a genuine path-based match (restic's own manifest), but restic
     uses BLAKE2b internally, not sha256, so it can never become a hash proof
     against diskaudit.files.content_sha256 -- it is never promoted past
     UNVERIFIED by this fact alone.
  3. Everything else: heuristic match against nas-1's already-crawled
     diskaudit.files inventory by (basename, size) [+-2min mtime tolerance
     when both mtimes are present] -> BACKED_UP_UNVERIFIED /
     match_method='path_size_mtime'. NOTE: an earlier design assumption that
     `/share/CACHEDEV1_DATA/bkup_server` is a literal path-for-path mirror of
     the server was checked live (ssh) and found FALSE -- it holds per-app
     tar.gz snapshots, restic repos, and DB dump trees, not a browsable
     mirror. This basename+size heuristic is the honest, ground-truth-driven
     replacement; it is intentionally weaker evidence and is always labeled
     path_size_mtime, never conflated with a hash proof.
  4. No match at all -> NOT_BACKED_UP. This is the actual deliverable list.

Never deletes/moves/modifies any scanned file -- read-only against
diskaudit.files and read-only (ls/restic ls) against the NAS/restic repos.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import timedelta

import psycopg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crosshost_verify import get_dsn  # noqa: E402
from heartbeat import write_heartbeat  # noqa: E402

import havnvard_site as _site  # noqa: E402  (3.0.0)

KNOWN_HOSTS = _site.source_hosts()   # machines that NEED backup coverage; the NAS is the destination, not a subject
NAS_HOST = _site.nas_host()

# Legacy NAS-side restic repos (before HavnVard Backup 2.0). All site-specific, so all in the site file:
#   [legacy_restic]
#   nas_env = "/etc/havnvard/nas_backup.env"          # NAS_USER / NAS_HOST / NAS_PATH (read with sudo -n cat)
#   password_file = "/etc/havnvard/restic_backup.pass"
#   dir_targets = { app1 = "/srv/app1", docs = "/home/me/docs" }   # repo name -> backed-up directory
#   file_list_target = "config-files"                  # optional: a repo holding an explicit list of files
#   file_list_root = "/etc/myapp"
#   file_list_names = ["a.conf", "b.yaml"]
_LR = _site.section("legacy_restic")
NAS_ENV = _LR.get("nas_env") or "/etc/havnvard/nas_backup.env"
RESTIC_PASSWORD_FILE = _LR.get("password_file") or "/etc/havnvard/restic_backup.pass"
RESTIC_DIR_TARGETS = dict(_LR.get("dir_targets") or {})
RESTIC_FILE_LIST_TARGET = _LR.get("file_list_target") or ""
RESTIC_HELM_FILES_ROOT = _LR.get("file_list_root") or ""
RESTIC_HELM_FILE_NAMES = tuple(_LR.get("file_list_names") or ())

MTIME_TOLERANCE = timedelta(minutes=2)


def _nas_env() -> dict:
    """Read NAS creds via sudo cat (never printed, never logged)."""
    out = subprocess.run(
        ["sudo", "-n", "cat", NAS_ENV], capture_output=True, text=True, check=True
    ).stdout
    env = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _restic_ls_latest(target: str) -> list[dict]:
    """Return the file-node listing (relpath, size, mtime) of the latest
    snapshot for a restic target, via a single sudo-wrapped shell command that
    sources NAS + restic creds ONLY inside the privileged subshell. Read-only
    (restic ls never modifies a repo). Returns [] if the repo/snapshot is
    unreachable -- caller treats that target as "no restic evidence available"
    rather than failing the whole classify run."""
    env = _nas_env()
    repo = f"sftp:{env['NAS_USER']}@{env['NAS_HOST']}:{env['NAS_PATH']}/restic/{target}"
    script = f"""
        set -e
        export RESTIC_PASSWORD_FILE={RESTIC_PASSWORD_FILE}
        export SFTP_CMD="sshpass -f {NAS_ENV.replace('.env', '.pass')} ssh -o StrictHostKeyChecking=accept-new -s sftp"
        restic -o sftp.command="$SFTP_CMD" -r {repo} ls latest --long --json 2>/dev/null
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "bash", "-c", script], capture_output=True, text=True, timeout=120
        )
    except subprocess.TimeoutExpired:
        return []
    if proc.returncode != 0:
        return []
    nodes = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("struct_type") == "node" and obj.get("type") == "file":
            nodes.append(obj)
    return nodes


def _restic_relpath_index(target: str, restic_root: str) -> dict[str, int]:
    """relpath (posix, no leading slash) -> size, for one restic target."""
    idx = {}
    for node in _restic_ls_latest(target):
        path = node.get("path", "")
        if not path.startswith("/"):
            path = "/" + path
        # restic ls paths are rooted at the backup source arg itself, i.e.
        # already relative to restic_root conceptually (restic stores the
        # absolute path given to `backup`), so path IS the absolute path.
        idx[path] = node.get("size", 0)
    return idx


def cmd_classify(conn, host: str, limit: int | None) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO diskaudit.backup_coverage_runs (phase, host, status, current_stage)
        VALUES ('classify', %s, 'running', 'loading scope rules')
        RETURNING run_id
        """,
        (host,),
    )
    coverage_run_id = cur.fetchone()[0]
    conn.commit()

    def hb(stage, **kw):
        write_heartbeat(conn, "backup_coverage", coverage_run_id, host, stage, note=json.dumps(kw) if kw else None)
        conn.commit()

    # 1. Load active scope rules (small table, load once).
    cur.execute(
        "SELECT rule_id, host_pattern, path_pattern, priority FROM diskaudit.backup_scope_rules "
        "WHERE active ORDER BY priority ASC"
    )
    rules = cur.fetchall()  # [(rule_id, host_pattern, path_pattern, priority)]
    conn.commit()

    hb("building restic indexes")
    restic_idx: dict[str, dict[str, int]] = {}
    for target, root in RESTIC_DIR_TARGETS.items():
        restic_idx[target] = _restic_relpath_index(target, root)
    helm_files_idx = {os.path.join(RESTIC_HELM_FILES_ROOT, n) for n in RESTIC_HELM_FILE_NAMES}
    helm_files_sizes = (_restic_relpath_index(RESTIC_FILE_LIST_TARGET, RESTIC_HELM_FILES_ROOT)
                        if RESTIC_FILE_LIST_TARGET else {})

    hb("loading nas inventory for heuristic match")
    cur.execute(
        "SELECT path, size_bytes, mtime FROM diskaudit.files "
        "WHERE host = %s AND still_exists AND file_type = 'regular' AND size_bytes IS NOT NULL",
        (NAS_HOST,),
    )
    nas_by_basize: dict[tuple[str, int], list] = {}
    for path, size_bytes, mtime in cur.fetchall():
        base = os.path.basename(path)
        nas_by_basize.setdefault((base, size_bytes), []).append((path, mtime))
    conn.commit()

    hb("loading candidate files", host=host)
    q = (
        "SELECT path, size_bytes, inode, nlink, mtime, content_sha256 FROM diskaudit.files "
        "WHERE host = %s AND still_exists AND file_type = 'regular'"
    )
    params = [host]
    if limit:
        q += " LIMIT %s"
        params.append(limit)
    cur.execute(q, params)
    rows = cur.fetchall()
    conn.commit()  # release the SELECT immediately -- do not hold it open during classification

    considered = len(rows)
    excluded = matched = not_backed_up = 0

    # Bulk-write via COPY-into-staging + one set-based INSERT ... ON CONFLICT,
    # same pattern dedup.py's write_groups() uses (and for the same reason:
    # one UPDATE/INSERT per file is unacceptably slow at server-1's
    # ~5.7M-file scale -- see 20260717_diskaudit_dedup_staging_v2.sql).
    with conn.cursor() as cur2:
        cur2.execute("DELETE FROM diskaudit.backup_coverage_staging WHERE host = %s", (host,))
    conn.commit()

    _COPY_SQL = (
        "COPY diskaudit.backup_coverage_staging "
        "(host, path, size_bytes, inode, nlink, classification, match_method, "
        " excluded_rule_id, matched_nas_host, matched_nas_path, matched_restic_target, "
        " run_id, notes) FROM STDIN"
    )

    with conn.cursor() as cur2, cur2.copy(_COPY_SQL) as cp:
        for path, size_bytes, inode, nlink, mtime, content_sha256 in rows:
            # 1. scope rules
            matched_rule = None
            for rule_id, host_pat, path_pat, _prio in rules:
                if _like(host, host_pat) and _like(path, path_pat):
                    matched_rule = rule_id
                    break
            if matched_rule is not None:
                excluded += 1
                cp.write_row((host, path, size_bytes, inode, nlink, "EXCLUDED", None, matched_rule, None, None, None, coverage_run_id, None))
                continue

            # 2a. config-files special case
            if path in helm_files_idx and helm_files_sizes.get(path) == size_bytes:
                matched += 1
                cp.write_row((host, path, size_bytes, inode, nlink, "BACKED_UP_UNVERIFIED", "restic_snapshot_listing", None, NAS_HOST, path, RESTIC_FILE_LIST_TARGET, coverage_run_id, None))
                continue

            # 2b. restic directory targets
            found_restic = None
            for target, root in RESTIC_DIR_TARGETS.items():
                if path == root or path.startswith(root.rstrip("/") + "/"):
                    if restic_idx[target].get(path) == size_bytes:
                        found_restic = target
                    break
            if found_restic:
                matched += 1
                cp.write_row((host, path, size_bytes, inode, nlink, "BACKED_UP_UNVERIFIED", "restic_snapshot_listing", None, NAS_HOST, path, found_restic, coverage_run_id, None))
                continue

            # 3. heuristic basename+size (+mtime tolerance) match against NAS inventory
            base = os.path.basename(path)
            candidates = nas_by_basize.get((base, size_bytes))
            if candidates:
                best = candidates[0]
                if mtime is not None:
                    for cand_path, cand_mtime in candidates:
                        if cand_mtime is not None and abs(cand_mtime - mtime) <= MTIME_TOLERANCE:
                            best = (cand_path, cand_mtime)
                            break
                matched += 1
                cp.write_row((host, path, size_bytes, inode, nlink, "BACKED_UP_UNVERIFIED", "path_size_mtime", None, NAS_HOST, best[0], None, coverage_run_id, "basename+size heuristic; bkup_server is NOT a literal path mirror (verified 2026-07-25)"))
                continue

            # 4. no match anywhere
            not_backed_up += 1
            cp.write_row((host, path, size_bytes, inode, nlink, "NOT_BACKED_UP", "none", None, None, None, None, coverage_run_id, None))
    conn.commit()

    hb("merging staging into backup_coverage")
    with conn.cursor() as cur2:
        cur2.execute(
            """
            INSERT INTO diskaudit.backup_coverage
                (host, path, size_bytes, inode, nlink, classification, match_method,
                 excluded_rule_id, matched_nas_host, matched_nas_path, matched_restic_target,
                 run_id, notes)
            SELECT host, path, size_bytes, inode, nlink, classification, match_method,
                   excluded_rule_id, matched_nas_host, matched_nas_path, matched_restic_target,
                   run_id, notes
            FROM diskaudit.backup_coverage_staging
            WHERE host = %s
            ON CONFLICT (host, path) DO UPDATE SET
                size_bytes = EXCLUDED.size_bytes,
                inode = EXCLUDED.inode,
                nlink = EXCLUDED.nlink,
                classification = EXCLUDED.classification,
                match_method = EXCLUDED.match_method,
                excluded_rule_id = EXCLUDED.excluded_rule_id,
                matched_nas_host = EXCLUDED.matched_nas_host,
                matched_nas_path = EXCLUDED.matched_nas_path,
                matched_restic_target = EXCLUDED.matched_restic_target,
                checked_at = now(),
                run_id = EXCLUDED.run_id,
                notes = EXCLUDED.notes
            """,
            (host,),
        )
        cur2.execute("DELETE FROM diskaudit.backup_coverage_staging WHERE host = %s", (host,))
    conn.commit()

    cur.execute(
        """
        UPDATE diskaudit.backup_coverage_runs
        SET status = 'completed', finished_at = now(),
            files_considered = %s, files_excluded = %s, files_matched = %s,
            files_not_backed_up = %s, current_stage = 'done'
        WHERE run_id = %s
        """,
        (considered, excluded, matched, not_backed_up, coverage_run_id),
    )
    conn.commit()
    print(f"[classify] host={host} run_id={coverage_run_id} considered={considered} "
          f"excluded={excluded} matched(unverified)={matched} not_backed_up={not_backed_up}")


def _like(value: str, pattern: str) -> bool:
    """Minimal SQL-LIKE emulation for in-Python rule matching (only % is used
    in the seeded rules; no _ wildcard or escaping needed for these paths)."""
    import re
    if pattern == "%":
        return True
    regex = "^" + re.escape(pattern).replace("%", ".*") + "$"
    return re.match(regex, value) is not None


def cmd_verify(conn, host: str, limit: int | None) -> None:
    """Promote BACKED_UP_UNVERIFIED -> BACKED_UP_VERIFIED using hash evidence
    ALREADY present in diskaudit.files/integrity_checks (from crosshost_verify.py
    runs). Does NOT launch any new hashing -- that is a separate, longer job.
    Safe to run any time; purely additive/idempotent."""
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO diskaudit.backup_coverage_runs (phase, host, status, current_stage)
        VALUES ('verify', %s, 'running', 'promoting from existing hash evidence')
        RETURNING run_id
        """,
        (host,),
    )
    run_id = cur.fetchone()[0]
    conn.commit()

    # integrity_checks columns are named spark_host/spark_path/nas_path (the
    # "spark_*" naming predates agent-1 support in crosshost_verify.py but is
    # used generically for whichever host is the verification SOURCE --
    # confirmed via \d diskaudit.integrity_checks, 2026-07-25).
    q = """
        UPDATE diskaudit.backup_coverage bc
        SET classification = 'BACKED_UP_VERIFIED',
            match_method = 'hash_proven',
            checked_at = now(),
            matched_nas_host = %s,
            matched_nas_path = ic.nas_path,
            run_id = %s,
            notes = COALESCE(bc.notes || '; ', '') || 'promoted via existing integrity_checks match verdict'
        FROM diskaudit.integrity_checks ic
        WHERE bc.host = %s
          AND bc.classification = 'BACKED_UP_UNVERIFIED'
          AND ic.verdict = 'match'
          AND ic.spark_host = bc.host
          AND ic.spark_path = bc.path
    """
    cur.execute(q, (NAS_HOST, run_id, host))
    promoted = cur.rowcount
    conn.commit()

    cur.execute(
        "UPDATE diskaudit.backup_coverage_runs SET status='completed', finished_at=now(), "
        "files_verified=%s, current_stage='done' WHERE run_id=%s",
        (promoted, run_id),
    )
    conn.commit()
    print(f"[verify] host={host} run_id={run_id} promoted_to_verified={promoted}")


def cmd_report(conn, host: str, out_path: str, top_n: int) -> None:
    cur = conn.cursor()
    cur.execute(
        "SELECT classification, count(*), coalesce(sum(size_bytes),0)::bigint FROM diskaudit.backup_coverage "
        "WHERE host = %s GROUP BY classification ORDER BY classification",
        (host,),
    )
    summary = cur.fetchall()

    cur.execute(
        """
        SELECT r.category, r.reason, count(*), coalesce(sum(bc.size_bytes), 0)::bigint
        FROM diskaudit.backup_coverage bc
        JOIN diskaudit.backup_scope_rules r ON r.rule_id = bc.excluded_rule_id
        WHERE bc.host = %s AND bc.classification = 'EXCLUDED'
        GROUP BY r.category, r.reason
        ORDER BY sum(bc.size_bytes) DESC
        """,
        (host,),
    )
    excl_by_rule = cur.fetchall()

    # NOT_BACKED_UP ranked by size, hardlink-aware: one row per DISTINCT
    # (host, inode) so a hardlinked file isn't counted/listed N times.
    cur.execute(
        """
        SELECT DISTINCT ON (inode) path, size_bytes, inode, nlink
        FROM diskaudit.backup_coverage
        WHERE host = %s AND classification = 'NOT_BACKED_UP'
        ORDER BY inode, path
        """,
        (host,),
    )
    distinct_not_backed = cur.fetchall()
    distinct_not_backed.sort(key=lambda r: (r[1] or 0), reverse=True)
    total_not_backed_bytes = sum(r[1] or 0 for r in distinct_not_backed)
    top_rows = distinct_not_backed[:top_n]

    lines = [
        f"# HavnVard Backup Coverage Report — {host}",
        "",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        "",
        "## Summary (by classification)",
        "",
        "| Classification | Files | Bytes | GB |",
        "|---|---|---|---|",
    ]
    for cls, cnt, byt in summary:
        lines.append(f"| {cls} | {cnt:,} | {byt:,} | {byt/1e9:.2f} |")

    lines += [
        "",
        "## Excluded — by rule (bytes, not files, ranked)",
        "",
        "| Category | Reason | Files | GB |",
        "|---|---|---|---|",
    ]
    for cat, reason, cnt, byt in excl_by_rule:
        lines.append(f"| {cat} | {reason} | {cnt:,} | {byt/1e9:.2f} |")

    lines += [
        "",
        f"## NOT_BACKED_UP — ranked by size (hardlink-deduped: {len(distinct_not_backed):,} distinct inodes, "
        f"{total_not_backed_bytes/1e9:.2f} GB total; top {top_n} shown)",
        "",
        "NOTE: bytes below are per DISTINCT INODE. A file with nlink > 1 has other",
        "hardlinked paths on this host not separately listed here (same bytes, already counted once).",
        "",
        "| Size (GB) | nlink | Path |",
        "|---|---|---|",
    ]
    for path, size_bytes, inode, nlink in top_rows:
        lines.append(f"| {(size_bytes or 0)/1e9:.4f} | {nlink} | `{path}` |")

    content = "\n".join(lines) + "\n"
    if out_path:
        with open(out_path, "w") as f:
            f.write(content)
        print(f"[report] wrote {out_path}")
    else:
        print(content)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("classify")
    p1.add_argument("--host", required=True, choices=KNOWN_HOSTS)
    p1.add_argument("--limit", type=int, default=None)

    p2 = sub.add_parser("verify")
    p2.add_argument("--host", required=True, choices=KNOWN_HOSTS)
    p2.add_argument("--limit", type=int, default=None)

    p3 = sub.add_parser("report")
    p3.add_argument("--host", required=True, choices=KNOWN_HOSTS)
    p3.add_argument("--out", default=None)
    p3.add_argument("--top", type=int, default=200)

    args = ap.parse_args()
    conn = psycopg.connect(get_dsn())
    try:
        if args.cmd == "classify":
            cmd_classify(conn, args.host, limit=args.limit)
        elif args.cmd == "verify":
            cmd_verify(conn, args.host, limit=args.limit)
        elif args.cmd == "report":
            cmd_report(conn, args.host, args.out, args.top)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
