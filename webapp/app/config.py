"""HavnVard UI (diskaudit webapp) — config.

Non-destructive, strictly read-only against every scanned filesystem. This app
NEVER exposes a delete/move/rename control anywhere -- see FEATURES.md and
RUNBOOK.md "Absolute constraint". It may only EXPORT manifests (CSV/JSON) for
the separate, not-yet-built P5/FERJA authorized cleanup process.
"""
from __future__ import annotations

import os
import sys

# The repo root holds havnvard_site.py (site settings shared with the scan/dedup tools). Appended, never inserted
# first, so it cannot shadow an installed package.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.append(_ROOT)
import havnvard_site as _site  # noqa: E402

# App bind. Internal loopback only; Caddy fronts the Tailnet-only public bind.
APP_HOST = "127.0.0.1"
APP_PORT = 9108
PUBLIC_URL = _site.ui("public_url", f"http://{APP_HOST}:{APP_PORT}")

# Pagination.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# Export caps (ORDER BY + LIMIT, never OFFSET -- exports are "top N under current
# filter/sort", not a full unbounded dump of an 8.5M-row table).
EXPORT_ROW_CAP = 50_000

# Hosts each view operates over (site file [hosts]). DEDUP covers every scanned device; CLEANUP and BACKUP
# cover the source machines only (the NAS is the backup target, not itself a cleanup/backup candidate).
ALL_HOSTS = _site.all_hosts()
SOURCE_HOSTS = _site.source_hosts()
