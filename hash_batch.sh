#!/bin/sh
# diskaudit — remote content-hash batch script (crosshost_verify.py `hash` subcommand).
#
# Deployed transiently via scp to a scratch dir on the target host, executed
# over ssh, results scp'd back, then deleted from BOTH sides by the Python
# driver (crosshost_verify.py) after a successful load into Postgres. Does
# NOT persist on the remote host between runs -- same lifecycle convention as
# nas_native_crawl.sh.
#
# POSIX/BusyBox-compatible (no bashisms: no arrays, no [[, no `local`) so ONE
# script works unmodified on both:
#   - nas-1  (BusyBox v1.24.1 coreutils, /bin/sh = bash 3.2.57 sh-compat)
#   - agent-1     (full bash / GNU coreutils -- a strict superset, so the
#                  BusyBox-safe subset used here still works)
# Same "write once, works on the constrained shell too" principle already
# established by nas_native_crawl.sh.
#
# Usage: hash_batch.sh <scratch-dir> <batch-name>
#   Reads   <scratch-dir>/<batch-name>.paths    -- newline-delimited absolute
#                                                   paths, one per line
#   Writes  <scratch-dir>/<batch-name>.hashes   -- pipe-delimited: sha256|path
#           <scratch-dir>/<batch-name>.hasherrs -- pipe-delimited: REASON|path
#                                                   REASON in MISSING|UNREADABLE
#
# Deliberately hashes ONE FILE AT A TIME via a read loop, not a single
# `sha256sum <manyfiles>` invocation: a multi-arg sha256sum call silently
# omits the stdout line for any file that fails (permission denied, vanished
# mid-batch, etc.), which breaks positional alignment between the input list
# and the output when the caller tries to zip them back together by order.
# One-at-a-time keeps success/failure attribution unambiguous per path, at
# the cost of one extra process spawn per file (acceptable at this scale --
# a few hundred to a few thousand files per batch, not millions).
#
# Read-only against every path it is given -- this script NEVER deletes,
# moves, renames, or otherwise modifies any file it hashes. It only ever
# writes its own <batch-name>.hashes / <batch-name>.hasherrs output files
# under the scratch dir the caller told it to use.
#
# Sudo READ fallback: some candidate paths (e.g. agent-1's root-owned
# /var/lib/snapd/snaps/*.snap, mode 0600) are unreadable by the ssh user
# directly. If a plain `sha256sum` fails AND `sudo` exists on this host,
# retry once via `sudo -n sha256sum` (passwordless, non-interactive -- never
# hangs prompting for a password; -n makes sudo fail fast instead of
# blocking if it ever isn't actually passwordless). This is a READ-ONLY
# escalation (sha256sum only reads bytes, never writes/deletes/renames) --
# it does not relax the "never modify a scanned file" constraint. NAS
# (BusyBox, nas_backup account) has no sudo at all; the `command -v sudo`
# guard below makes this a no-op there, falling straight through to the
# existing UNREADABLE path.
HAVE_SUDO=0
if command -v sudo >/dev/null 2>&1; then
    HAVE_SUDO=1
fi

set -e

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

echo "[hash_batch] batch=$BATCH_NAME host=$(hostname 2>/dev/null || echo unknown) starting" >&2

COUNT=0
while IFS= read -r p || [ -n "$p" ]; do
    [ -z "$p" ] && continue
    if [ ! -f "$p" ]; then
        # [ -f ] is false BOTH for a genuinely absent file AND for one whose
        # parent directory this account cannot traverse (EACCES) -- e.g.
        # agent-1's /root/.profile. Where sudo exists, re-check as root so a
        # merely-unreadable-by-us file falls through to the hashing attempt
        # below (whose sudo fallback CAN read it) instead of being
        # misreported as MISSING. Found 2026-08-30: ~500 real, root-readable
        # agent-1 files were being logged MISSING on every dedup run.
        if [ "$HAVE_SUDO" = "1" ] && sudo -n test -f "$p" 2>/dev/null; then
            :  # exists; fall through to hashing
        else
            printf 'MISSING|%s\n' "$p" >> "$OUT_ERRS"
            continue
        fi
    fi
    HASHLINE=$(sha256sum "$p" 2>>"$OUT_ERRS") || {
        if [ "$HAVE_SUDO" = "1" ]; then
            HASHLINE=$(sudo -n sha256sum "$p" 2>>"$OUT_ERRS") || {
                printf 'UNREADABLE|%s\n' "$p" >> "$OUT_ERRS"
                continue
            }
        else
            printf 'UNREADABLE|%s\n' "$p" >> "$OUT_ERRS"
            continue
        fi
    }
    # sha256sum output is "<64-hex-char-hash>  <path>" (GNU) or similar
    # (BusyBox). Take only the hash and pair it with OUR OWN known-good $p
    # rather than re-parsing the (possibly escaped) path out of the output.
    # Two traps here, both hit for real on 2026-08-30 (agent-1 run 28):
    #   1. NEVER pass the line through `echo` -- POSIX/dash echo interprets
    #      backslash escapes, so a line starting '\211a4fa...' became a raw
    #      0x89 byte + 61 hex chars, corrupting the digest (surfaced in the
    #      Python driver as UnicodeEncodeError '\udc89' in position 0).
    #      printf '%s\n' is escape-safe on dash, bash, and BusyBox ash.
    #   2. GNU sha256sum ESCAPES filenames containing backslash/newline and
    #      marks such lines with a LEADING '\' (e.g. systemd unit names like
    #      snap-snap\x2dstore-1390.mount), so the hash starts at column 2.
    case "$HASHLINE" in
        \\*) HASH=$(printf '%s\n' "$HASHLINE" | cut -c2-65) ;;
        *)   HASH=$(printf '%s\n' "$HASHLINE" | cut -c1-64) ;;
    esac
    printf '%s|%s\n' "$HASH" "$p" >> "$OUT_HASHES"
    COUNT=$((COUNT + 1))
    if [ $((COUNT % 200)) -eq 0 ]; then
        echo "[hash_batch] progress: $COUNT files hashed" >&2
    fi
done < "$IN_LIST"

TOTAL_ERRS=$(wc -l < "$OUT_ERRS")
echo "[hash_batch] DONE batch=$BATCH_NAME hashed=$COUNT errors=$TOTAL_ERRS" >&2
