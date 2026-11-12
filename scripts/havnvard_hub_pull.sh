#!/usr/bin/env bash
# havnvard-hub-pull (HavnVard 2.2.4, INFRA-547): copy the agent-1 hub's restic repos into DESKTOP-1's ~/restic-hub,
# the folder restic-hub-offsite uploads to Internxt. Runs as ExecStartPre of restic-hub-offsite.service (drop-in
# 10-hub-pull.conf), so a pull and an upload never overlap.
#
# Safe by construction (Opus review 20261111, findings 1-5):
# - Add only: never deletes or overwrites (--ignore-existing). restic names every file under data/ index/ snapshots/
#   keys/ by the sha256 of its content, so an existing name already holds the same bytes.
# - ONE listing, taken once, split locally into data and snapshots: a snapshot is copied only if its data was listed
#   in the same listing (and copied first). A backup finishing mid-run is picked up whole next time.
# - Only restic repo files are listed (config, 64-hex names under keys/ index/ snapshots/ data/xx/), and only files
#   untouched for SETTLE_MIN minutes, so nothing half-written and no stray file is copied. locks/ never.
# - rsync temp files go to $ST/rsync-tmp, never into the uploaded folder.
# - A file the hub removes while it is listed or copied (hourly catalog re-tags, rest-server renames) is not an error.
# - Bounded: the whole pull is cut at MAX_MIN minutes so the upload keeps its time budget.
# Exit 0 = copied (or nothing new); 1 = could not list or copy (desktop alert + log; $ST/havnvard-hub-pull.ok not updated).
set -uo pipefail
SRC_HOST="${SRC_HOST:-hub}"
SRC_DIR="${SRC_DIR:-/mnt/havnvard-hub/restic-hub}"
DST="${DST:-$HOME/restic-hub}"
SETTLE_MIN="${SETTLE_MIN:-10}"
MAX_MIN="${MAX_MIN:-45}"
ST="${ST:-$HOME/.local/state}"; LOG="$ST/havnvard-hub-pull.log"
mkdir -p "$ST/rsync-tmp"
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }
fail() {
  log "FAIL $*"
  command -v notify-send >/dev/null && notify-send -u critical "HavnVard hub pull FAILED" "$* (see $LOG)" 2>/dev/null
  exit 1
}

ALL="$ST/havnvard-hub-pull.all.list"; DATA="$ST/havnvard-hub-pull.data.list"; SNAP="$ST/havnvard-hub-pull.snapshots.list"
HEX='[0-9a-f]{64}'
timeout -k 30 300 ssh -o BatchMode=yes -o ConnectTimeout=20 "$SRC_HOST" \
  "cd '$SRC_DIR' && find . -ignore_readdir_race -type f -mmin +$SETTLE_MIN -not -path '*/locks/*' -printf '%P\n'" > "$ALL" \
  || fail "cannot list $SRC_HOST:$SRC_DIR"
grep -E "^[^/]+/(config|(keys|index|snapshots)/$HEX|data/[0-9a-f]{2}/$HEX)\$" "$ALL" | grep -v '/snapshots/' > "$DATA"
grep -E "^[^/]+/snapshots/$HEX\$" "$ALL" > "$SNAP"
skipped=$(( $(wc -l < "$ALL") - $(wc -l < "$DATA") - $(wc -l < "$SNAP") ))
[ "$skipped" -gt 0 ] && log "note: $skipped non-repo file(s) on the hub not copied"

deadline=$(( $(date +%s) + MAX_MIN * 60 ))
for pass in data snapshots; do
  list="$DATA"; [ "$pass" = snapshots ] && list="$SNAP"
  left=$(( deadline - $(date +%s) )); [ "$left" -gt 0 ] || fail "$pass: time budget of $MAX_MIN min used up"
  out=$(timeout -k 60 "$left" rsync -a --ignore-existing --ignore-missing-args --temp-dir="$ST/rsync-tmp" --stats \
        --files-from="$list" "$SRC_HOST:$SRC_DIR/" "$DST/" 2>>"$LOG"); rc=$?
  [ $rc -eq 0 ] || fail "$pass: rsync exit $rc$( { [ $rc -eq 124 ] || [ $rc -eq 137 ]; } && echo ' (time budget)')"
  n=$(printf '%s\n' "$out" | sed -n 's/^Number of regular files transferred: //p' | tr -d ,)
  b=$(printf '%s\n' "$out" | sed -n 's/^Total transferred file size: \([0-9,]*\).*/\1/p' | tr -d ,)
  log "ok $pass: $(wc -l < "$list") files listed, ${n:-?} copied, $(( ${b:-0} / 1048576 )) MiB"
done
date '+%Y-%m-%d %H:%M:%S' > "$ST/havnvard-hub-pull.ok"
exit 0
