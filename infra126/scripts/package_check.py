#!/usr/bin/env python3
from __future__ import annotations

import json
import py_compile
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root=Path(__file__).resolve().parents[1]
    for path in [*(root/"src").rglob("*.py"),*(root/"scripts").rglob("*.py"),*(root/"web").rglob("*.py")]:
        py_compile.compile(str(path),doraise=True)
    subprocess.run(["sh","-n",str(root/"bin/remote_hash_batch.sh")],check=True)
    json.loads((root/"grafana/infra126_dashboard.json").read_text())
    result=subprocess.run([sys.executable,"-m","pytest","-q"],cwd=root,check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
