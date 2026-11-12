#!/bin/bash
# diskaudit — run load_nas_inventory.py across every known NAS share.
# Continues past a per-share failure (one bad share shouldn't skip the rest
# of the month's inventory) but exits non-zero overall if any share failed,
# so systemd/monitoring still flags the run as failed.
set -u
cd /srv/diskaudit || exit 1

SHARES=(
  "Public"
  "homes"
  "Download"
  "Multimedia"
  "PAFOther"
  "Recordings"
  "Web"
  "bittorrents"
  "bkup_spark"
  "20049999_PJKYLEpics shared"
  "PAF_Play"
)

failed=()
for share in "${SHARES[@]}"; do
  echo "[run_all_nas_shares] Processing share: $share" >&2
  if ! .venv/bin/python load_nas_inventory.py --share "$share"; then
    echo "[run_all_nas_shares] FAILED: $share" >&2
    failed+=("$share")
  fi
done

if (( ${#failed[@]} > 0 )); then
  echo "[run_all_nas_shares] ${#failed[@]} share(s) failed: ${failed[*]}" >&2
  exit 1
fi

echo "[run_all_nas_shares] all shares completed successfully" >&2
