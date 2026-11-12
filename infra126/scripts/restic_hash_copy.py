#!/usr/bin/env python3
"""Hash one restic snapshot file and register one independent-source vote."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime,timezone

from havnvard_bitrot.repository import file_key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository",required=True)
    parser.add_argument("--snapshot",required=True)
    parser.add_argument("--snapshot-path",required=True)
    parser.add_argument("--logical-host",required=True)
    parser.add_argument("--logical-path",required=True)
    parser.add_argument("--logical-inode",type=int)
    parser.add_argument("--backup-host",help="Host key used by backup_verification_state; defaults to logical host")
    parser.add_argument("--allow-unverified-repository",action="store_true",help="Emergency override; records evidence as unverified and it cannot vote")
    parser.add_argument("--source-id",required=True,help="Independent source, e.g. restic:spark-bkup-repo")
    args = parser.parse_args()

    command = ["restic","-r",args.repository,"dump",args.snapshot,args.snapshot_path]
    process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    assert process.stdout is not None
    digest = hashlib.sha256()
    for chunk in iter(lambda:process.stdout.read(8*1024*1024),b""):
        digest.update(chunk)
    _,stderr = process.communicate()
    if process.returncode:
        print(stderr.decode("utf-8",errors="replace"),file=sys.stderr)
        return process.returncode
    sha256 = digest.hexdigest()
    captured = datetime.now(timezone.utc)

    import psycopg
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn, conn.cursor() as cur:
        backup_host=args.backup_host or args.logical_host
        cur.execute(
            """
            SELECT verification_passed,last_verified_at,corrupt_count
            FROM diskaudit.backup_verification_state
            WHERE restic_snapshot_id=%s AND host=%s
            """,
            (args.snapshot,backup_host),
        )
        check_row=cur.fetchone()
        repository_verified=bool(check_row and check_row[0] and int(check_row[2] or 0)==0)
        if not repository_verified and not args.allow_unverified_repository:
            parser.error(
                "restic snapshot has no passing backup_verification_state row; run restic check and record_restic_check.py first"
            )
        evidence_state="verified" if repository_verified else "unverified"
        inode=args.logical_inode
        if inode is None:
            cur.execute(
                """
                SELECT inode FROM diskaudit.files
                WHERE host=%s AND path=%s AND still_exists
                ORDER BY hashed_at DESC NULLS LAST LIMIT 1
                """,
                (args.logical_host,args.logical_path),
            )
            row=cur.fetchone()
            if not row:
                parser.error("logical file not found; provide --logical-inode after verifying identity")
            inode=row[0]
        key = file_key(args.logical_host,args.logical_path,inode)
        cur.execute(
            """
            INSERT INTO diskaudit.hash_copy_evidence
                (logical_file_key,logical_host,logical_path,source_kind,independent_source_id,
                 source_path,snapshot_id,sha256,captured_at,verification_state,details)
            VALUES (%s,%s,%s,'restic_snapshot',%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT DO NOTHING
            """,
            (key,args.logical_host,args.logical_path,args.source_id,args.snapshot_path,args.snapshot,sha256,captured,evidence_state,json.dumps({"repository":args.repository,"backup_host":backup_host,"repository_check":check_row[1].isoformat() if check_row and check_row[1] else None})),
        )
        conn.commit()
    print(json.dumps({"sha256":sha256,"logical_file_key":key,"source_id":args.source_id,"snapshot":args.snapshot}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
