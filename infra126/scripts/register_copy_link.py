#!/usr/bin/env python3
"""Register an explicit logical-file-to-copy mapping for multi-copy decisions."""
from __future__ import annotations

import argparse
import os

from havnvard_bitrot.repository import file_key


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--logical-host",required=True)
    parser.add_argument("--logical-path",required=True)
    parser.add_argument("--logical-inode",type=int)
    parser.add_argument("--source-kind",required=True,choices=["live_host","restic_snapshot","qnap_snapshot","offsite"])
    parser.add_argument("--source-id",required=True,help="Independent source identity")
    parser.add_argument("--source-host")
    parser.add_argument("--source-path",required=True)
    args=parser.parse_args()

    import psycopg
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn, conn.cursor() as cur:
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
                parser.error("logical file is not present in diskaudit.files; provide --logical-inode after verifying identity")
            inode=row[0]
        key=file_key(args.logical_host,args.logical_path,inode)
        cur.execute(
            """
            INSERT INTO diskaudit.hash_copy_links
                (logical_file_key,logical_host,logical_path,source_kind,independent_source_id,source_host,source_path)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(logical_file_key,source_kind,independent_source_id,source_path) DO UPDATE
            SET source_host=EXCLUDED.source_host
            """,
            (key,args.logical_host,args.logical_path,args.source_kind,args.source_id,args.source_host,args.source_path),
        )
        conn.commit()
    print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
