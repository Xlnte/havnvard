#!/usr/bin/env python3
"""Ingest exact critical-file rows emitted by the existing load-bearing refresh.

Input is JSON Lines. Each object must contain host, path, and inode. Optional
source defaults to load_bearing_refresh. This script deliberately does not scan
`diskaudit.files` or regex-match 13M rows in one transaction.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from havnvard_bitrot.repository import file_key


def _rows(path: Path):
    with path.open("r",encoding="utf-8") as handle:
        for line_number,line in enumerate(handle,1):
            if not line.strip():
                continue
            row=json.loads(line)
            missing=[name for name in ("host","path","inode") if row.get(name) is None]
            if missing:
                raise ValueError(f"line {line_number}: missing {missing}")
            yield (
                str(row["host"]),str(row["path"]),int(row["inode"]),
                str(row.get("source") or "load_bearing_refresh"),
            )


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--input",required=True,help="Exact critical files as JSONL: host,path,inode,source")
    parser.add_argument("--batch-size",type=int,default=500)
    parser.add_argument("--allow-empty",action="store_true",help="Explicitly allow replacing the registry with zero rows")
    args=parser.parse_args()
    if args.batch_size<1 or args.batch_size>5000:
        parser.error("--batch-size must be 1..5000")

    generation=str(uuid.uuid4())
    import psycopg
    inserted=0
    batch=[]
    with psycopg.connect(os.environ["POSTGRES_URL"]) as conn:
        for host,path,inode,source in _rows(Path(args.input)):
            batch.append((host,path,file_key(host,path,inode),source,generation))
            if len(batch)>=args.batch_size:
                with conn.cursor() as cur:
                    cur.executemany(
                        """
                        INSERT INTO diskaudit.infra126_critical_files
                            (host,path,file_key,source,refresh_generation,refreshed_at)
                        VALUES (%s,%s,%s,%s,%s,now())
                        ON CONFLICT(file_key) DO UPDATE
                        SET host=EXCLUDED.host,path=EXCLUDED.path,source=EXCLUDED.source,
                            refresh_generation=EXCLUDED.refresh_generation,refreshed_at=now()
                        """,batch,
                    )
                conn.commit()
                inserted+=len(batch)
                batch=[]
        if batch:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO diskaudit.infra126_critical_files
                        (host,path,file_key,source,refresh_generation,refreshed_at)
                    VALUES (%s,%s,%s,%s,%s,now())
                    ON CONFLICT(file_key) DO UPDATE
                    SET host=EXCLUDED.host,path=EXCLUDED.path,source=EXCLUDED.source,
                        refresh_generation=EXCLUDED.refresh_generation,refreshed_at=now()
                    """,batch,
                )
            conn.commit()
            inserted+=len(batch)

        if inserted==0 and not args.allow_empty:
            raise RuntimeError("refusing to replace the critical-file registry with an empty generation")

        # The exact-file registry is small. This removes stale metadata only after
        # the new generation was fully committed. It never touches scanned files.
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM diskaudit.infra126_critical_files WHERE refresh_generation<>%s",
                (generation,),
            )
            removed=cur.rowcount
        conn.commit()

    print(json.dumps({"generation":generation,"ingested":inserted,"stale_metadata_removed":removed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
