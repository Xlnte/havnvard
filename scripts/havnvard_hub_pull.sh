#!/usr/bin/env bash
# havnvard-hub-pull (HavnVard 2.2.2, INFRA-547): copy the trigkey hub's restic repos into PAFPAD's ~/restic-hub,
# the folder restic-hub-offsite uploads to Internxt. Runs as ExecStartPre of restic-hub-offsite.service, so a pull
# and an upload never overlap.
#
# Safe by construction:
# - Add only. It never deletes or overwrites (--ignore-existing). restic names every file under data/ index/
#   snapshots/ keys/ by the hash of its content, so an existing name already holds the same bytes.
# - Only files untouched for SETTLE_MIN minutes are copied, so a pack the hub is still writing is never copied half-done
#   (with --ignore-existing it would never be fixed later).
# - Snapshots are copied last, so a copied snapshot never points at data that has not arrived yet.
# - locks/ is never copied.
# Exit: 0 copied (or nothing new), 1 the hub could not be reached or a copy failed. Every run logs to $LOG.
set -uo pipefail
SRC_HOST="${SRC_HOST:-trigkey}"
SRC_DIR="${SRC_DIR:-/mnt/havnvard-hub/restic-hub}"
DST="${DST:-$HOME/restic-hub}"
SETTLE_MIN="${SETTLE_MIN:-10}"
ST="${ST:-$HOME/.local/state}"; LOG="$ST/havnvard-hub-pull.log"
mkdir -p "$ST"
log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }

list() {  # $1 = find predicate for snapshots: "-not" (everything else) or "" (snapshots only)
  ssh -o BatchMode=yes -o ConnectTimeout=20 "$SRC_HOST" \
    "cd '$SRC_DIR' && find . -type f -mmin +$SETTLE_MIN -not -path '*/locks/*' $1 -path '*/snapshots/*' -printf '%P\n'"
}

rc=0
for pass in data snapshots; do
  pred="-not"; [ "$pass" = snapshots ] && pred=""
  files="$ST/havnvard-hub-pull.$pass.list"     # overwritten every run (no temp files to clean up)
  if ! list "$pred" > "$files"; then
    log "FAIL $pass: cannot list $SRC_HOST:$SRC_DIR"; rc=1; break
  fi
  if out=$(rsync -a --ignore-existing --stats --files-from="$files" "$SRC_HOST:$SRC_DIR/" "$DST/" 2>>"$LOG"); then
    n=$(printf '%s\n' "$out" | sed -n 's/^Number of regular files transferred: //p' | tr -d ,)
    b=$(printf '%s\n' "$out" | sed -n 's/^Total transferred file size: \([0-9,]*\).*/\1/p' | tr -d ,)
    log "ok $pass: $(wc -l < "$files") files listed, ${n:-?} copied, $(( ${b:-0} / 1048576 )) MiB"
  else
    log "FAIL $pass: rsync exit $?"; rc=1
  fi
  [ $rc -eq 0 ] || break
done
exit $rc
