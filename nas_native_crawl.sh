#!/bin/sh
# diskaudit — NAS-native crawl script.
#
# Lives on the server as the source of truth; gets scp'd to the NAS and executed
# there via ssh. Does NOT persist on the NAS between runs (the orchestrator,
# load_nas_inventory.py, copies it into the scratch dir, runs it, then
# deletes it as part of cleanup).
#
# Crawls ONE top-level share directory (e.g. "Public", "homes", or
# "Family photos") using only BusyBox-provided find/stat/xargs/
# readlink -- confirmed present on nas-1, no Entware, no python3.
#
# Why per-share, not one giant find over the whole NAS: a failure partway
# through only loses one share's progress, and each share's output can be
# validated/loaded independently before moving to the next.
#
# Verified NAS shell facts (2026-07-18): /bin/sh on this NAS is actually
# bash 3.2.57 invoked in "sh" compat mode (NOT BusyBox ash as originally
# assumed going in -- confirmed via `echo $BASH_VERSION`). find/stat/xargs
# themselves ARE BusyBox v1.24.1 multi-call binary (confirmed via --help
# banners), so all the BusyBox constraints below (no -printf, no xargs -d/-a)
# still apply to those tools. bash's `read -d ''` for NUL-delimited reads
# is confirmed working here as a result -- this script still avoids other
# bashisms (arrays, [[, etc.) to stay portable in case that ever changes.
#
# CRITICAL SAFETY CONSTRAINT: /tmp on this NAS is a 64MB tmpfs SHARED WITH
# LIVE NAS SYSTEM PROCESSES (confirmed via `df -h /tmp`; a prior test run
# writing ~40MB there caused real ENOSPC failures). This script NEVER writes
# to /tmp. All scratch/output goes under /share/CACHEDEV1_DATA/.diskaudit_scratch/
# (real disk, 8.2TB free as of 2026-07-18), created here with chmod 700.
#
# Usage: nas_native_crawl.sh <share-name>
#   nas_native_crawl.sh Public
#   nas_native_crawl.sh "Family photos"
#
# Output, all under /share/CACHEDEV1_DATA/.diskaudit_scratch/ (filenames use
# a sanitized share name -- spaces/slashes replaced with underscore -- but
# the TSV's own path column always contains the real, unsanitized path):
#   <safe_name>.tsv       -- pipe-delimited, one row per entry (files+dirs):
#                            path|mode_hex|size|uid|gid|inode|nlink|mtime|atime|ctime
#                            (mode_hex is stat -c '%f', the FULL st_mode incl.
#                            type bits, as hex -- decode with int(x,16) same
#                            as scan.py. ctime is captured but NOT used as
#                            btime -- this NAS has no birth-time concept at
#                            all; btime stays NULL for every NAS row.)
#   <safe_name>.errs      -- find/stat stderr (permission-denied etc). Never
#                            fatal to the crawl -- e.g. lost+found and other
#                            restricted subtrees are expected here.
#   <safe_name>.unsafe    -- (1.4.2, INFRA-520 R-4) one line per entry whose full path
#                            contains a LINE FEED, as lowercase HEX of the raw path
#                            bytes. Such a name cannot be carried in the newline-framed
#                            .tsv/.symlinks without tearing a row, so the main and
#                            symlink passes skip it (find ! -path "*<LF>*") and it is
#                            listed here instead -- topmost entry only (-prune): its
#                            descendants are not crawled either. load_nas_inventory.py
#                            records every line as a scan_errors row (UNSAFE_NAME_LF);
#                            nothing is silently dropped. Hex because this BusyBox has
#                            no od; hexdump is present and is required (checked below).
#   <safe_name>.symlinks  -- pipe-delimited: path|target (symlinks only;
#                            stat -c has no field for link target, and
#                            stat -c '%N' uses an incompatible quoted format,
#                            so this is a separate pass via readlink).

set -e

SHARE_NAME="$1"
if [ -z "$SHARE_NAME" ]; then
    echo "usage: $0 <share-name>" >&2
    exit 2
fi

SHARE_BASE="/share/CACHEDEV1_DATA"
SHARE_ROOT="$SHARE_BASE/$SHARE_NAME"

if [ ! -d "$SHARE_ROOT" ]; then
    echo "error: share root does not exist or is not a directory: $SHARE_ROOT" >&2
    exit 2
fi

SCRATCH_DIR="$SHARE_BASE/.diskaudit_scratch"
mkdir -p "$SCRATCH_DIR"
chmod 700 "$SCRATCH_DIR"

# Sanitize only the OUTPUT FILENAME (spaces/slashes -> underscore); the real
# share name / real paths inside the TSV are never altered.
SAFE_NAME=$(echo "$SHARE_NAME" | tr ' /' '__')

OUT_TSV="$SCRATCH_DIR/$SAFE_NAME.tsv"
OUT_ERRS="$SCRATCH_DIR/$SAFE_NAME.errs"
OUT_SYML="$SCRATCH_DIR/$SAFE_NAME.symlinks"
OUT_UNSAFE="$SCRATCH_DIR/$SAFE_NAME.unsafe"

# A literal LINE FEED, for find -path patterns (POSIX sh has no $'\n').
NL='
'

# hexdump encodes the unsafe names (see header). Fail loudly now rather than
# silently dropping LF names later.
if ! command -v hexdump >/dev/null 2>&1; then
    echo "error: hexdump not found on this host; cannot encode unsafe (LF) file names" >&2
    exit 3
fi

: > "$OUT_TSV"
: > "$OUT_ERRS"
: > "$OUT_SYML"
: > "$OUT_UNSAFE"

echo "[nas_native_crawl] host=$(hostname 2>/dev/null || echo nas) share=$SHARE_NAME root=$SHARE_ROOT" >&2
echo "[nas_native_crawl] main pass starting -> $OUT_TSV" >&2

# Main pass: every entry (files + dirs; symlinks land here too, recorded via
# lstat-equivalent semantics -- confirmed stat -c without -L reports the
# link itself, not its target, matching Python's entry.stat(follow_symlinks=
# False) in scan.py). -xdev stays on this one filesystem/share.
#
# Deliberately NOT using `set -o pipefail` here: permission-denied subtrees
# (lost+found, other users' restricted homes dirs, etc.) make `find` exit
# non-zero, and with pipefail that would trip `set -e` and abort the whole
# crawl over an expected, non-fatal condition. Confirmed during validation
# against Public (2 permission-denied dirs hit, crawl still completed,
# rc=0 for the pipeline since xargs/stat -- the last stage -- succeeded).
# 1.4.2 (R-4): entries whose path contains a LF are excluded here (! -path) and
# listed in $OUT_UNSAFE below, so no stat record can be torn by a name.
find "$SHARE_ROOT" -xdev ! -path "*$NL*" -print0 2>>"$OUT_ERRS" \
    | xargs -0 stat -c '%n|%f|%s|%u|%g|%i|%h|%Y|%X|%Z' >>"$OUT_TSV" 2>>"$OUT_ERRS"

FILES_COUNT=$(wc -l < "$OUT_TSV")
ERR_COUNT=$(wc -l < "$OUT_ERRS")
echo "[nas_native_crawl] main pass done: $FILES_COUNT entries, $ERR_COUNT error lines" >&2

echo "[nas_native_crawl] symlink pass starting -> $OUT_SYML" >&2

# Symlink pass: readlink confirmed present at /usr/bin/readlink on this NAS.
# NUL-delimited throughout (xargs/find here have no -d/-a GNU extensions;
# read -d '' is a bash builtin, confirmed working since /bin/sh is bash here).
find "$SHARE_ROOT" -xdev ! -path "*$NL*" -type l -print0 2>>"$OUT_ERRS" | \
while IFS= read -r -d '' f; do
    tgt=$(readlink "$f" 2>>"$OUT_ERRS") || continue
    printf '%s|%s\n' "$f" "$tgt" >> "$OUT_SYML"
done

SYML_COUNT=$(wc -l < "$OUT_SYML")
echo "[nas_native_crawl] symlink pass done: $SYML_COUNT symlinks" >&2

# Unsafe-name pass (1.4.2, R-4): topmost entries whose path contains a LF, hex-encoded.
find "$SHARE_ROOT" -xdev -path "*$NL*" -prune -print0 2>>"$OUT_ERRS" | \
while IFS= read -r -d '' f; do
    printf '%s' "$f" | hexdump -v -e '/1 "%02x"' >> "$OUT_UNSAFE"
    echo >> "$OUT_UNSAFE"
done
UNSAFE_COUNT=$(wc -l < "$OUT_UNSAFE")
echo "[nas_native_crawl] unsafe-name pass done: $UNSAFE_COUNT entries with a LF in the path (listed, not crawled)" >&2

# Recompute error count -- the symlink pass re-traverses the same tree and can
# add more error lines (e.g. the same permission-denied dir hit again), so the
# count from right after the main pass would under-report the final total.
ERR_COUNT=$(wc -l < "$OUT_ERRS")
echo "[nas_native_crawl] DONE share=$SHARE_NAME files=$FILES_COUNT errs=$ERR_COUNT symlinks=$SYML_COUNT" >&2
