#!/bin/sh
set -u
MANIFEST=$1
RESULTS=$2
HEARTBEAT=$3
TOKEN_FILE=$4
WORK_DIR=$(dirname "$RESULTS")
DONE="$WORK_DIR/done"
HASH_OUT="$WORK_DIR/current_hash.out"

if [ ! -s "$TOKEN_FILE" ]; then
  echo "missing run token" >&2
  exit 2
fi
umask 077
: > "$RESULTS"
date +%s > "$HEARTBEAT"

while IFS="	" read -r ITEM_ID PATH_B64; do
  START=$(date +%s)
  PATH_VALUE=$(printf '%s' "$PATH_B64" | base64 -d 2>/dev/null)
  if [ -z "$PATH_VALUE" ]; then
    printf '{"item_id":%s,"path":"","status":"failed","duration_ms":0,"error":"path decode failed"}\n' "$ITEM_ID" >> "$RESULTS"
    date +%s > "$HEARTBEAT"
    continue
  fi
  if [ ! -e "$PATH_VALUE" ]; then
    printf '{"item_id":%s,"path":"","status":"missing","duration_ms":0,"error":"file disappeared"}\n' "$ITEM_ID" >> "$RESULTS"
    date +%s > "$HEARTBEAT"
    continue
  fi
  BEFORE=$(stat -c '%i|%s|%Y' "$PATH_VALUE" 2>/dev/null || true)
  if [ -z "$BEFORE" ]; then
    printf '{"item_id":%s,"path":"","status":"unreadable","duration_ms":0,"error":"stat failed"}\n' "$ITEM_ID" >> "$RESULTS"
    date +%s > "$HEARTBEAT"
    continue
  fi
  : > "$HASH_OUT"
  sha256sum "$PATH_VALUE" > "$HASH_OUT" 2>/dev/null &
  HASH_PID=$!
  while kill -0 "$HASH_PID" 2>/dev/null; do
    date +%s > "$HEARTBEAT"
    sleep 15
  done
  wait "$HASH_PID"
  RC=$?
  HASH=$(awk '{print $1}' "$HASH_OUT" 2>/dev/null)
  AFTER=$(stat -c '%i|%s|%Y' "$PATH_VALUE" 2>/dev/null || true)
  END=$(date +%s)
  DURATION=$(( (END - START) * 1000 ))
  if [ "$RC" -ne 0 ] || [ -z "$HASH" ]; then
    printf '{"item_id":%s,"path":"","status":"unreadable","duration_ms":%s,"error":"sha256sum failed"}\n' "$ITEM_ID" "$DURATION" >> "$RESULTS"
  elif [ -z "$AFTER" ]; then
    printf '{"item_id":%s,"path":"","status":"missing","duration_ms":%s,"error":"file disappeared after hash"}\n' "$ITEM_ID" "$DURATION" >> "$RESULTS"
  elif [ "$BEFORE" != "$AFTER" ]; then
    printf '{"item_id":%s,"path":"","status":"changed_during_hash","duration_ms":%s,"error":"metadata changed during hash"}\n' "$ITEM_ID" "$DURATION" >> "$RESULTS"
  else
    INODE=$(printf '%s' "$AFTER" | cut -d'|' -f1)
    SIZE=$(printf '%s' "$AFTER" | cut -d'|' -f2)
    MTIME=$(printf '%s' "$AFTER" | cut -d'|' -f3)
    MTIME_NS=$((MTIME * 1000000000))
    printf '{"item_id":%s,"path":"","status":"hashed","sha256":"%s","inode":%s,"size":%s,"mtime_ns":%s,"duration_ms":%s}\n' "$ITEM_ID" "$HASH" "$INODE" "$SIZE" "$MTIME_NS" "$DURATION" >> "$RESULTS"
  fi
  date +%s > "$HEARTBEAT"
done < "$MANIFEST"

date +%s > "$DONE"
date +%s > "$HEARTBEAT"
