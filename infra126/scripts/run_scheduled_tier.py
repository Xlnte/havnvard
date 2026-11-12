#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier",required=True,choices=["A","B","C","D","E"])
    parser.add_argument("--hosts",nargs="+",default=None,help="default: every host in INFRA126_HOSTS_JSON (or this machine)")
    parser.add_argument("--max-items",type=int,default=0)
    args = parser.parse_args()
    failures: list[tuple[str,int]] = []
    if args.hosts is None:
        from havnvard_bitrot.config import load_settings
        args.hosts = list(load_settings().hosts)
    for host in args.hosts:
        command = [sys.executable,"-m","havnvard_bitrot.cli","run","--tier",args.tier,"--host",host,"--max-items",str(args.max_items)]
        result = subprocess.run(command,check=False)
        if result.returncode:
            failures.append((host,result.returncode))
    if failures:
        print(f"Tier {args.tier} failures: {failures}",file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
