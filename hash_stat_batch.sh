#!/bin/sh
# diskaudit — remote stat-bound content-hash batch script for nas_trigkey_dedup.py
# (HavnVard NAS within-host dedup, 1.4.0; Plane INFRA-519 / INFRA-520).
#
# Successor of hash_batch.sh FOR THIS TOOL ONLY. hash_batch.sh stays untouched
# because crosshost_verify.py parses its `sha256|path` output. This script adds
# what the dedup needs to prove a digest is still true (HV-REQ-05, 06, 17):
#   - the stat of the file BEFORE and AFTER the bytes were read (size, mtime,
#     inode, device, nlink) -- from the SAME host at the SAME moment;
#   - stat-only lines for hardlink siblings (no re-read of the bytes);
#   - a completion trailer carrying the script's own counts, so the driver can
#     tell a finished batch from a truncated one.
#
# POSIX/BusyBox-compatible (no bashisms) -- one script for nas-1
# (BusyBox v1.24.1: stat supports %s %Y %i %d %h %F, no ns, no --version) and
# agent-1 (GNU coreutils).
#
# Usage: hash_stat_batch.sh <scratch-dir> <batch-name>
#   Reads   <scratch-dir>/<batch-name>.paths
#             one line per path:  H|<abs path>   hash it
#                                 S|<abs path>   stat only (hardlink sibling)
#   Writes  <scratch-dir>/<batch-name>.hashes
#             H|<sha64>|<size>|<mtime_s>|<ino>|<dev>|<nlink>|<path>
#             S|<size>|<mtime_s>|<ino>|<dev>|<nlink>|<path>
#             #DONE|hashed=<n>|statonly=<n>|errors=<n>     <- LAST line; absent = failed batch
#           <scratch-dir>/<batch-name>.hasherrs
#             MISSING|p  UNREADABLE|p  UNSTABLE|p  NOT_REGULAR|p
#             (plus raw sha256sum/stat stderr, which never starts with those tokens)
# The PATH is always the LAST field (a path may contain '|'); the Python parser
# splits from the left with a fixed field count.
#
# Read-only against every path it is given. This script NEVER deletes, moves,
# renames or modifies any file it reads; it only writes its own .hashes and
# .hasherrs output under the scratch dir the caller named. Cleanup of those two
# files is the Python driver's job, after the rows are committed to Postgres.
#
# Sudo READ fallback: same rule as hash_batch.sh (sudo -n, read-only, a no-op
# on the NAS where sudo does not exist).
HAVE_SUDO=0
if command -v sudo >/dev/null 2>&1; then
    HAVE_SUDO=1
fi

SCRATCH_DIR="$1"
BATCH_NAME="$2"
if [ -z "$SCRATCH_DIR" ] || [ -z "$BATCH_NAME" ]; then
    echo "usage: $0 <scratch-dir> <batch-name>" >&2
    exit 2
fi

IN_LIST="$SCRATCH_DIR/$BATCH_NAME.paths"
OUT_HASHES="$SCRATCH_DIR/$BATCH_NAME.hashes"
OUT_ERRS="$SCRATCH_DIR/$BATCH_NAME.hasherrs"

if [ ! -f "$IN_LIST" ]; then
    echo "error: path list not found: $IN_LIST" >&2
    exit 2
fi

: > "$OUT_HASHES"
: > "$OUT_ERRS"

echo "[hash_stat_batch] batch=$BATCH_NAME host=$(hostname 2>/dev/null || echo unknown) starting" >&2

N_HASHED=0
N_STAT=0
N_ERR=0

# stat_of <fmt> <path>: print stat or fail. Falls back to sudo -n (read-only)
# where sudo exists, for files under directories this account cannot traverse.
stat_of() {
    stat -c "$1" "$2" 2>/dev/null && return 0
    if [ "$HAVE_SUDO" = "1" ]; then
        sudo -n stat -c "$1" "$2" 2>/dev/null && return 0
    fi
    return 1
}

fail() {  # fail <REASON> <path>
    printf '%s|%s\n' "$1" "$2" >> "$OUT_ERRS"
    N_ERR=$((N_ERR + 1))
}

# pre_stat <path>: sets PRE5 (size|mtime|ino|dev|nlink); returns 1 after
# recording the error when the path cannot be stat'ed or is not a plain file.
pre_stat() {
    PRE5=""
    if [ -L "$1" ]; then
        fail NOT_REGULAR "$1"
        return 1
    fi
    PRE=$(stat_of '%s|%Y|%i|%d|%h|%F' "$1") || {
        fail MISSING "$1"
        return 1
    }
    case "$PRE" in
        *"|regular file"|*"|regular empty file") ;;
        *)
            fail NOT_REGULAR "$1"
            return 1
            ;;
    esac
    PRE5="${PRE%|*}"
    return 0
}

while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    KIND="${line%%|*}"
    p="${line#*|}"
    [ -z "$p" ] && continue
    case "$KIND" in
        H|S) ;;
        *) fail MISSING "$p"; continue ;;
    esac

    pre_stat "$p" || continue

    if [ "$KIND" = "S" ]; then
        printf 'S|%s|%s\n' "$PRE5" "$p" >> "$OUT_HASHES"
        N_STAT=$((N_STAT + 1))
        continue
    fi

    HASHLINE=$(sha256sum "$p" 2>>"$OUT_ERRS") || {
        HASHLINE=""
        if [ "$HAVE_SUDO" = "1" ]; then
            HASHLINE=$(sudo -n sha256sum "$p" 2>>"$OUT_ERRS") || HASHLINE=""
        fi
        if [ -z "$HASHLINE" ]; then
            fail UNREADABLE "$p"
            continue
        fi
    }
    # See hash_batch.sh: never `echo` the line (backslash escapes), and GNU
    # sha256sum prefixes a backslash when the file NAME needs escaping.
    case "$HASHLINE" in
        \\*) HASH=$(printf '%s\n' "$HASHLINE" | cut -c2-65) ;;
        *)   HASH=$(printf '%s\n' "$HASHLINE" | cut -c1-64) ;;
    esac

    POST5=$(stat_of '%s|%Y|%i|%d|%h' "$p") || {
        fail UNSTABLE "$p"
        continue
    }
    if [ "$PRE5" != "$POST5" ]; then
        fail UNSTABLE "$p"
        continue
    fi

    printf 'H|%s|%s|%s\n' "$HASH" "$PRE5" "$p" >> "$OUT_HASHES"
    N_HASHED=$((N_HASHED + 1))
    if [ $((N_HASHED % 200)) -eq 0 ]; then
        echo "[hash_stat_batch] progress: $N_HASHED files hashed" >&2
    fi
done < "$IN_LIST"

printf '#DONE|hashed=%s|statonly=%s|errors=%s\n' "$N_HASHED" "$N_STAT" "$N_ERR" >> "$OUT_HASHES"
echo "[hash_stat_batch] DONE batch=$BATCH_NAME hashed=$N_HASHED statonly=$N_STAT errors=$N_ERR" >&2
exit 0
