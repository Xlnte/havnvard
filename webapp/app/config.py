"""HavnVard UI (diskaudit webapp) — config.

Non-destructive, strictly read-only against every scanned filesystem. This app
NEVER exposes a delete/move/rename control anywhere -- see FEATURES.md and
RUNBOOK.md "Absolute constraint". It may only EXPORT manifests (CSV/JSON) for
the separate, not-yet-built P5/FERJA authorized cleanup process.
"""
from __future__ import annotations

# App bind. Internal loopback only; Caddy fronts the Tailnet-only public bind.
APP_HOST = "127.0.0.1"
APP_PORT = 9108
PUBLIC_URL = "https://spark-20cf.tail5f354b.ts.net:9457"

# Pagination.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# Export caps (ORDER BY + LIMIT, never OFFSET -- exports are "top N under current
# filter/sort", not a full unbounded dump of an 8.5M-row table).
EXPORT_ROW_CAP = 50_000

# Hosts each view operates over. DEDUP covers all three scanned devices; CLEANUP
# and BACKUP are scoped to Spark + trigkey only (the NAS is the backup target,
# not itself a cleanup/backup candidate) -- per the owner's exact wording.
ALL_HOSTS = ("spark-20cf", "trigkey", "nas-ts453a")
SOURCE_HOSTS = ("spark-20cf", "trigkey")
