#!/bin/bash
# diskaudit — run load_nas_inventory.py across every known NAS share.
# Continues past a per-share failure (one bad share shouldn't skip the rest
# of the month's inventory) but exits non-zero overall if any share failed,
# so systemd/monitoring still flags the run as failed.
set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1

# One share name per line (names may contain spaces; # starts a comment). Site-specific, so it lives outside
# the repo: $HAVNVARD_NAS_SHARES, default /etc/havnvard/nas_shares.txt.
SHARES_FILE="${HAVNVARD_NAS_SHARES:-/etc/havnvard/nas_shares.txt}"
if [ ! -r "$SHARES_FILE" ]; then
  echo "[run_all_nas_shares] ERROR: share list $SHARES_FILE not readable" >&2
  exit 2
fi
SHARES=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
  [ -n "$line" ] && SHARES+=("$line")
done < "$SHARES_FILE"
if (( ${#SHARES[@]} == 0 )); then
  echo "[run_all_nas_shares] ERROR: no shares listed in $SHARES_FILE" >&2
  exit 2
fi

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
