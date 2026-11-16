#!/usr/bin/env python3
"""DEPRECATED compatibility shim (HavnVard 3.3.11, INFRA-566): this file was renamed to nas_host_dedup.py.

It exists only so a systemd unit, timer or cron line that still runs `nas_trigkey_dedup.py` keeps working until
its ExecStart is changed to `nas_host_dedup.py`. It forwards the command line to nas_host_dedup.main() and
exits with its exit code. Remove this file (and tests/test_dedup_shim.py) once no unit, timer or cron line
names it; do not publish a release that still contains it (the old name carries a host name).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nas_host_dedup import *            # noqa: E402,F401,F403  (old `import nas_trigkey_dedup` callers)
from nas_host_dedup import main         # noqa: E402

DEPRECATION = "nas_trigkey_dedup.py is deprecated; run nas_host_dedup.py (same arguments)"

if __name__ == "__main__":
    print(f"[nas_trigkey_dedup] DEPRECATED: {DEPRECATION}", file=sys.stderr, flush=True)
    sys.argv[0] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nas_host_dedup.py")   # usage text names the real tool
    sys.exit(main())
