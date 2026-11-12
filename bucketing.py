"""
bucketing.py -- size-based parallel-worker partitioning for duplicate-file detection.

Two files can only ever be duplicates of each other if they share an EXACT byte
size. So when parallelizing a dedup scan (e.g. rdfind) across N worker
processes, we must partition "candidate" files -- files that share their size
with at least one other file -- into N buckets, one per worker, subject to a
hard correctness constraint:

    ALL files sharing a given size MUST land in the same bucket. Never split
    a same-size group across two workers -- doing so would let duplicates
    spanning that split go undetected. This is a correctness bug, not a
    performance nicety.

Within that constraint, buckets are balanced as evenly as possible by TOTAL
BYTES (not file count), since byte volume drives I/O/hashing cost far more
than file count does.

Algorithm: greedy bin-packing. Sort size-groups by total bytes contributed
(size_bytes * len(file_paths)) descending, then assign each group -- as a
whole, indivisible unit -- to whichever bucket currently has the smallest
running total-bytes-assigned so far. This is the standard "longest processing
time first" (LPT) heuristic for multiprocessor scheduling; it's not optimal
but is provably within 4/3 of optimal makespan and is simple/fast, which is
plenty for N in the 4-16 range.
"""

from __future__ import annotations

import os


def bucket_groups_by_size(
    groups: list[tuple[int, list[str]]], n_buckets: int
) -> list[list[tuple[int, list[str]]]]:
    """Partition same-size file groups into n_buckets, balanced by total bytes --
    same LPT (longest processing time first) bin-packing bucket_by_size() has always
    used, but returns each bucket's assigned size-groups INTACT (a list of
    (size_bytes, paths) tuples), rather than flattening them into a plain path list.

    bucket_by_size() is a thin wrapper around this that flattens the result, kept
    for existing callers that only need plain path lists. This group-preserving
    version exists for callers (dedup.run_parallel()'s per-worker argv-chunking step)
    that must keep tracking which paths belong to which same-size group EVEN AFTER
    bucketing -- because that same "never split a group" invariant has to be
    re-applied one level down, when a single worker's bucket itself gets split into
    multiple rdfind invocations to stay under the OS argv-byte limit (see
    _safe_arg_chunks_by_group()). Splitting a group across two chunks would make
    rdfind (which only ever compares files WITHIN one invocation) silently miss any
    duplicate pair that happened to land on opposite sides of the cut.

    Args:
        groups: list of (size_bytes, [file_paths_sharing_that_size]) tuples.
            Each group is assumed to already be a genuine candidate group
            (len(file_paths) >= 2) -- unique-size singletons should already
            be filtered out by the caller.
        n_buckets: number of worker buckets to produce.

    Returns:
        A list of n_buckets lists of (size_bytes, paths) tuples. Every input group
        appears in exactly one output bucket, as a whole, intact unit.

    Raises:
        ValueError: if n_buckets < 1.
    """
    if n_buckets < 1:
        raise ValueError(f"n_buckets must be >= 1, got {n_buckets}")

    buckets: list[list[tuple[int, list[str]]]] = [[] for _ in range(n_buckets)]
    bucket_totals: list[int] = [0] * n_buckets

    # Sort groups by total bytes contributed (size * count), descending.
    # This is LPT (longest processing time first) bin-packing: placing the
    # heaviest, most constraining units first minimizes the chance that a
    # late-arriving heavy group has to pile onto an already-loaded bucket.
    ordered_groups = sorted(groups, key=lambda g: g[0] * len(g[1]), reverse=True)

    for size_bytes, paths in ordered_groups:
        group_total = size_bytes * len(paths)
        # Linear scan for the smallest running total. N is small (4-16),
        # so this is simpler and just as fast as a min-heap at this scale.
        target = min(range(n_buckets), key=lambda i: bucket_totals[i])
        buckets[target].append((size_bytes, paths))
        bucket_totals[target] += group_total

    return buckets


def bucket_by_size(groups: list[tuple[int, list[str]]], n_buckets: int) -> list[list[str]]:
    """Partition same-size file groups into n_buckets, balanced by total bytes.

    Args:
        groups: list of (size_bytes, [file_paths_sharing_that_size]) tuples.
            Each group is assumed to already be a genuine candidate group
            (len(file_paths) >= 2) -- unique-size singletons should already
            be filtered out by the caller.
        n_buckets: number of worker buckets to produce.

    Returns:
        A list of n_buckets lists of file paths. Every path from a given
        input group appears in exactly one output bucket (the whole group
        goes to one bucket -- never split).

    Raises:
        ValueError: if n_buckets < 1.
    """
    grouped_buckets = bucket_groups_by_size(groups, n_buckets)
    return [[p for _size, paths in bucket for p in paths] for bucket in grouped_buckets]


# Hard ceiling on the effective argv budget, independent of what os.sysconf('SC_ARG_MAX')
# reports. Found necessary the hard way: on this box SC_ARG_MAX=2,097,152 and a real
# full-disk run's chunks (computed as arg_max - env_bytes - a 200,000-byte margin, ~1.89MB)
# still hit 'Argument list too long' in production. An earlier agent had EMPIRICALLY
# measured (direct execve(), no shell word-splitting confound) that failures start
# somewhere between 25,000-30,000 args / ~1.75-2.0MB -- meaning a computed budget of
# ~1.89MB sits INSIDE that uncertain failure zone rather than safely below the
# confirmed-safe 1.75MB boundary. A bigger margin alone is fragile (still anchored to a
# raw sysconf value that may not reflect what actually fails); a hard cap well below the
# confirmed-safe line is not.
_CONFIRMED_SAFE_ARG_MAX = 1_200_000


def _arg_byte_budget(safety_margin_bytes: int) -> int:
    try:
        arg_max = os.sysconf("SC_ARG_MAX")
    except (ValueError, AttributeError, OSError):
        arg_max = None
    if not arg_max or arg_max <= 0:
        arg_max = _CONFIRMED_SAFE_ARG_MAX
    arg_max = min(arg_max, _CONFIRMED_SAFE_ARG_MAX)

    env_bytes = sum(len(k) + len(v) + 2 for k, v in os.environ.items())
    # Never let a misconfigured/huge environment or margin collapse the budget to
    # zero/negative -- fall back to a small but still-useful conservative chunk size
    # rather than producing zero-size or infinite-loop-inducing chunks.
    return max(arg_max - env_bytes - safety_margin_bytes, 50_000)


def _safe_arg_chunks(paths: list[str], safety_margin_bytes: int = 200_000) -> list[list[str]]:
    """Split `paths` into chunks that can each be safely passed as literal argv
    entries to a subprocess (e.g. `rdfind -checksum sha256 <paths...>`) without
    tripping the OS's ARG_MAX limit -- 'OSError: [Errno 7] Argument list too long'.

    The real constraint execve() enforces is TOTAL BYTES of argv + envp (not a flat
    path *count*), so a fixed "N files per chunk" cutoff would be wrong in general --
    too conservative for short average path lengths and unsafe for long ones.
    Confirmed by direct measurement on this host (via execve(), not through a shell --
    no shell word-splitting confound): `getconf ARG_MAX` = 2,097,152 bytes;
    20,000 args at ~1.4MB total succeeded, 25,000 args at ~1.75MB succeeded, and it
    fails somewhere between 25,000-30,000 args (~1.75-2.0MB). rdfind itself has no
    "read paths from a file" / @file response-file option (checked `rdfind -help`
    directly -- only positional FILE args accepted), so chunking has to happen on
    our side, not rdfind's.

    Budget = os.sysconf('SC_ARG_MAX') [or a conservative 1,500,000-byte fallback if
    that's unavailable on this platform] minus the current process's environment size
    (inherited unchanged by the child -- environ counts against the same execve()
    limit as argv) minus `safety_margin_bytes`. The margin absorbs everything this
    function doesn't bother computing precisely: the fixed rdfind command tokens
    (`rdfind -outputname <path> -checksum sha256`, well under 1KB), the argv pointer
    array itself (~8 bytes/entry on a 64-bit kernel), and general slop -- 200,000
    bytes is generous relative to all of that combined.

    Packing is greedy/single-pass (not bin-packing/optimal): walk `paths` in order,
    accumulate into the current chunk, and cut a new chunk as soon as adding the next
    path would exceed budget. Order doesn't matter for correctness (rdfind doesn't
    care what order it receives file arguments in) and preserving input order makes
    behavior easy to reason about and test.

    A single path longer than the entire budget on its own is a degenerate case this
    function can't fix by chunking further -- it still gets emitted alone in its own
    chunk (better than silently dropping it), but a subprocess call with just that one
    path could still fail. Not expected in practice: Linux itself caps a single path
    at PATH_MAX (4096 bytes), far under any plausible budget.
    """
    budget = _arg_byte_budget(safety_margin_bytes)

    chunks: list[list[str]] = []
    current: list[str] = []
    current_bytes = 0
    for p in paths:
        # +1 for the argv NUL terminator each string needs at the syscall boundary.
        p_bytes = len(p.encode("utf-8", errors="surrogateescape")) + 1
        if current and current_bytes + p_bytes > budget:
            chunks.append(current)
            current = []
            current_bytes = 0
        current.append(p)
        current_bytes += p_bytes
    if current:
        chunks.append(current)
    return chunks


def _safe_arg_chunks_by_group(
    groups: list[tuple[int, list[str]]], safety_margin_bytes: int = 200_000
) -> list[list[str]]:
    """Group-aware version of _safe_arg_chunks(): packs same-size GROUPS (not
    individual paths) into argv-byte-safe chunks, never splitting one group's paths
    across two chunks.

    This exists because chunking a worker's bucket by raw path alone -- as
    _safe_arg_chunks() does -- can silently split a group of same-size candidate
    files across two separate rdfind invocations. Since rdfind only ever compares
    files WITHIN one invocation, any such split makes a real duplicate pair
    permanently undetectable, purely because of where an arbitrary byte-budget cut
    happened to land -- the exact same class of correctness bug bucket_by_size()
    already prevents at the worker level ("ALL files sharing a given size MUST land
    in the same bucket"), recurring one level down at the chunk level. (Caught
    empirically, not theoretically: an earlier group-naive version of this chunking,
    validated against a forced single-bucket 4-chunk run on real test data, measured
    23,192 groups / 54,029 rows -- 2 groups and 5 rows silently lost to group splits
    at chunk boundaries -- vs. the correct 23,194 groups / 54,034 rows from an
    unchunked run on the identical data.)

    Takes the GROUP-PRESERVING bucket shape from bucket_groups_by_size() (list of
    (size_bytes, paths) tuples), not a flat path list. Packing is greedy: walk groups
    in input order, accumulate whole groups into the current chunk, cut a new chunk
    as soon as adding the next whole group would exceed budget. Returns plain
    list[list[str]] chunks (flattened paths) since that's what the rdfind subprocess
    call needs -- only the packing decision itself needs to stay group-aware.

    A single group so large that even by itself it exceeds the byte budget cannot be
    split further without breaking correctness (rdfind must see the WHOLE group in
    one invocation to compare its members) -- it is emitted alone, over budget, as an
    unavoidable degenerate case (same posture as _safe_arg_chunks()'s single
    over-budget path). Not expected in practice at the scale of a single "same exact
    byte size" group.
    """
    budget = _arg_byte_budget(safety_margin_bytes)

    def _group_arg_bytes(paths: list[str]) -> int:
        return sum(len(p.encode("utf-8", errors="surrogateescape")) + 1 for p in paths)

    chunks: list[list[str]] = []
    current: list[str] = []
    current_bytes = 0
    for _size, paths in groups:
        g_bytes = _group_arg_bytes(paths)
        if current and current_bytes + g_bytes > budget:
            chunks.append(current)
            current = []
            current_bytes = 0
        current.extend(paths)
        current_bytes += g_bytes
    if current:
        chunks.append(current)
    return chunks


if __name__ == "__main__":
    import random

    random.seed(42)

    N_BUCKETS = 8
    N_GROUPS = 500

    # Build synthetic candidate groups with varied sizes and counts.
    synthetic_groups: list[tuple[int, list[str]]] = []
    next_id = 0
    for g in range(N_GROUPS):
        # Sizes spanning small (a few KB) to large (multi-GB), log-ish spread.
        size_bytes = random.choice(
            [
                random.randint(1_000, 100_000),  # small files
                random.randint(100_000, 10_000_000),  # medium files
                random.randint(10_000_000, 5_000_000_000),  # large files
            ]
        )
        count = random.randint(2, 12)  # each group has >= 2 files, per the contract
        paths = []
        for _ in range(count):
            paths.append(f"/fake/path/group{g:04d}/file{next_id:06d}.bin")
            next_id += 1
        synthetic_groups.append((size_bytes, paths))

    total_input_files = sum(len(paths) for _, paths in synthetic_groups)
    total_input_bytes = sum(size * len(paths) for size, paths in synthetic_groups)

    result = bucket_by_size(synthetic_groups, N_BUCKETS)

    # --- Correctness check 1: every path appears in exactly one bucket, exactly once ---
    all_input_paths: set[str] = set()
    for _, paths in synthetic_groups:
        all_input_paths.update(paths)

    all_output_paths: list[str] = [p for bucket in result for p in bucket]
    all_output_paths_set = set(all_output_paths)

    assert len(all_output_paths) == len(all_output_paths_set), (
        f"Duplicate paths found across buckets! "
        f"{len(all_output_paths)} total entries but only "
        f"{len(all_output_paths_set)} unique paths."
    )
    assert all_output_paths_set == all_input_paths, (
        "Output path set does not match input path set: "
        f"missing={all_input_paths - all_output_paths_set}, "
        f"extra={all_output_paths_set - all_input_paths}"
    )
    assert len(all_output_paths) == total_input_files, (
        f"Expected {total_input_files} total files in output, got {len(all_output_paths)}"
    )
    print(
        f"[PASS] Check 1: all {total_input_files} input paths appear in exactly "
        f"one output bucket, exactly once (no missing, no duplicates)."
    )

    # --- Correctness check 2: no size-group is ever split across two buckets ---
    # For each input group, find which bucket(s) its paths ended up in --
    # must be exactly one bucket.
    path_to_bucket_idx: dict[str, int] = {}
    for bucket_idx, bucket in enumerate(result):
        for p in bucket:
            path_to_bucket_idx[p] = bucket_idx

    split_groups = []
    for size_bytes, paths in synthetic_groups:
        bucket_indices = {path_to_bucket_idx[p] for p in paths}
        if len(bucket_indices) != 1:
            split_groups.append((size_bytes, paths, bucket_indices))

    assert not split_groups, (
        f"{len(split_groups)} size-group(s) were split across multiple buckets! "
        f"This is the correctness bug we must never allow. Examples: {split_groups[:3]}"
    )
    print(
        f"[PASS] Check 2: none of the {len(synthetic_groups)} size-groups were "
        f"split across buckets -- every same-size group landed in a single worker."
    )

    # --- Load-balance report: total bytes per bucket ---
    bucket_byte_totals = []
    for bucket_idx, bucket in enumerate(result):
        bucket_path_set = set(bucket)
        # Recompute bytes per bucket independently of the packing internals,
        # as a cross-check that the reported totals match reality.
        bucket_bytes = 0
        for size_bytes, paths in synthetic_groups:
            if paths and paths[0] in bucket_path_set:
                bucket_bytes += size_bytes * len(paths)
        bucket_byte_totals.append(bucket_bytes)

    print()
    print(f"Per-bucket totals ({N_BUCKETS} buckets, {N_GROUPS} groups, "
          f"{total_input_files} files, {total_input_bytes:,} total bytes):")
    for i, (bucket, byte_total) in enumerate(zip(result, bucket_byte_totals)):
        gb = byte_total / 1_000_000_000
        print(f"  bucket {i}: {len(bucket):5d} files, {byte_total:>18,} bytes ({gb:8.3f} GB)")

    mean_bytes = total_input_bytes / N_BUCKETS
    max_bytes = max(bucket_byte_totals)
    min_bytes = min(bucket_byte_totals)
    skew_pct = (max_bytes - min_bytes) / mean_bytes * 100 if mean_bytes else 0.0
    print()
    print(f"  mean bucket bytes: {mean_bytes:,.0f}  "
          f"min: {min_bytes:,}  max: {max_bytes:,}  spread: {skew_pct:.1f}% of mean")

    print()
    print("ALL CHECKS PASSED")

    # ------------------------------------------------------------------
    # _safe_arg_chunks() self-tests
    # ------------------------------------------------------------------
    print()
    print("--- _safe_arg_chunks() tests ---")

    # Check 1: empty input -> no chunks.
    assert _safe_arg_chunks([]) == [], "empty input should produce zero chunks"
    print("[PASS] Check 1: empty path list -> [] (no chunks)")

    # Check 2: small input -> single chunk, order preserved exactly.
    small = [f"/some/dir/file{i:04d}.txt" for i in range(500)]
    small_chunks = _safe_arg_chunks(small)
    assert len(small_chunks) == 1, f"500 short paths should fit in one chunk, got {len(small_chunks)}"
    assert small_chunks[0] == small, "single-chunk output must preserve input order exactly"
    print(f"[PASS] Check 2: {len(small)} short paths -> 1 chunk, order preserved")

    # Check 3: real-world-scale synthetic run -- 800,000 fake paths at a realistic
    # average length (~60-80 chars), using the REAL runtime budget (default
    # safety_margin_bytes). This is the scale that broke run_parallel() in
    # production (worker buckets of 500k-800k+ files).
    import random as _random
    _random.seed(1234)
    big = []
    for i in range(800_000):
        depth_dirs = "/".join(f"d{_random.randint(0, 999)}" for _ in range(_random.randint(2, 5)))
        fname = f"file_{i:07d}_{'x' * _random.randint(0, 20)}.bin"
        big.append(f"/srv/fake/{depth_dirs}/{fname}")
    avg_len = sum(len(p) for p in big) / len(big)
    big_chunks = _safe_arg_chunks(big)
    assert len(big_chunks) > 1, (
        f"800,000 paths (avg len {avg_len:.1f}) should require multiple chunks, got {len(big_chunks)}"
    )

    # Recompute the exact same budget the function itself used, so we can verify
    # every chunk truly stays under it (not just "looks smaller").
    try:
        _arg_max = os.sysconf("SC_ARG_MAX")
    except (ValueError, AttributeError, OSError):
        _arg_max = None
    if not _arg_max or _arg_max <= 0:
        _arg_max = 1_500_000
    _env_bytes = sum(len(k) + len(v) + 2 for k, v in os.environ.items())
    _budget = max(_arg_max - _env_bytes - 200_000, 50_000)

    for idx, chunk in enumerate(big_chunks):
        chunk_bytes = sum(len(p.encode("utf-8", errors="surrogateescape")) + 1 for p in chunk)
        assert chunk_bytes <= _budget, (
            f"chunk {idx} is {chunk_bytes:,} bytes, over the {_budget:,}-byte budget -- "
            f"this defeats the whole point of chunking"
        )

    # Every input path appears in the output, exactly once, in original order.
    flattened = [p for chunk in big_chunks for p in chunk]
    assert flattened == big, "chunking must preserve all paths, in order, with none dropped or duplicated"

    print(
        f"[PASS] Check 3: 800,000 synthetic paths (avg len {avg_len:.1f} chars) -> "
        f"{len(big_chunks)} chunks, each <= {_budget:,}-byte budget "
        f"(host ARG_MAX={_arg_max:,}), all paths preserved in order"
    )
    for idx, chunk in enumerate(big_chunks):
        chunk_bytes = sum(len(p.encode('utf-8', errors='surrogateescape')) + 1 for p in chunk)
        print(f"  chunk {idx}: {len(chunk):7d} files, {chunk_bytes:>10,} bytes")

    # Check 4: deterministic multi-chunk behavior via a forced tiny budget (huge
    # safety_margin_bytes collapses budget to the 50,000-byte floor regardless of
    # this machine's real ARG_MAX/environment size) -- makes the chunk COUNT and
    # boundaries deterministic and independently verifiable by hand.
    forced = [f"/x/{'p' * 99}" for _ in range(10_000)]  # 103 bytes/path incl. NUL
    forced_chunks = _safe_arg_chunks(forced, safety_margin_bytes=10**12)
    expected_per_chunk = 50_000 // 103  # floor budget // bytes-per-path
    assert all(len(c) <= expected_per_chunk + 1 for c in forced_chunks), (
        "forced-tiny-budget chunks exceeded the expected floor-budget chunk size"
    )
    assert sum(len(c) for c in forced_chunks) == len(forced), "forced-budget test dropped paths"
    assert len(forced_chunks) > 1, "forced-tiny-budget test should produce multiple chunks"
    print(
        f"[PASS] Check 4: forced 50,000-byte floor budget -> {len(forced_chunks)} chunks "
        f"of ~{expected_per_chunk} paths each (deterministic regardless of host ARG_MAX)"
    )

    # Check 5: a single pathological path far larger than any budget still comes
    # back as its own one-path chunk rather than crashing or looping forever.
    huge_path = "/" + ("a" * 500_000)
    degenerate_chunks = _safe_arg_chunks([huge_path], safety_margin_bytes=10**12)
    assert degenerate_chunks == [[huge_path]], "an over-budget single path must still be emitted, alone"
    print("[PASS] Check 5: single over-budget path -> emitted alone in its own chunk (no crash/hang)")

    print()
    print("ALL _safe_arg_chunks() CHECKS PASSED")

    # ------------------------------------------------------------------
    # bucket_groups_by_size() / _safe_arg_chunks_by_group() self-tests
    # ------------------------------------------------------------------
    print()
    print("--- bucket_groups_by_size() / _safe_arg_chunks_by_group() tests ---")

    # Check 1: bucket_by_size() (the flattening wrapper) still produces IDENTICAL
    # output to before the refactor -- same LPT algorithm, same input, same buckets.
    result2 = bucket_by_size(synthetic_groups, N_BUCKETS)
    assert result2 == result, "bucket_by_size() must be byte-for-byte unchanged after the bucket_groups_by_size() refactor"
    print("[PASS] Check 1: bucket_by_size() output unchanged by the group-preserving refactor")

    # Check 2: bucket_groups_by_size() flattens to the exact same thing.
    grouped = bucket_groups_by_size(synthetic_groups, N_BUCKETS)
    flattened_from_grouped = [[p for _s, paths in b for p in paths] for b in grouped]
    assert flattened_from_grouped == result, "flattening bucket_groups_by_size()'s output must equal bucket_by_size()'s output"
    print("[PASS] Check 2: bucket_groups_by_size() flattens to match bucket_by_size() exactly")

    # Check 3: no group is ever split across _safe_arg_chunks_by_group() chunks --
    # the actual correctness property this function exists to guarantee. Use a
    # forced tiny budget so multi-chunking is guaranteed to engage.
    test_groups = [
        (1000, [f"/g{g}/file{i}.bin" for i in range(6)]) for g in range(1000)
    ]
    forced_group_chunks = _safe_arg_chunks_by_group(test_groups, safety_margin_bytes=10**12)
    assert len(forced_group_chunks) > 1, "forced-tiny-budget group test should produce multiple chunks"

    path_to_chunk: dict[str, int] = {}
    for chunk_idx, chunk in enumerate(forced_group_chunks):
        for p in chunk:
            path_to_chunk[p] = chunk_idx
    split_found = []
    for _size, paths in test_groups:
        chunk_ids = {path_to_chunk[p] for p in paths}
        if len(chunk_ids) != 1:
            split_found.append((paths, chunk_ids))
    assert not split_found, f"group(s) split across chunks -- the exact correctness bug this function exists to prevent: {split_found[:3]}"
    total_paths_in = sum(len(p) for _s, p in test_groups)
    total_paths_out = sum(len(c) for c in forced_group_chunks)
    assert total_paths_in == total_paths_out, "no paths should be dropped or duplicated by group-aware chunking"
    print(
        f"[PASS] Check 3: {len(test_groups)} groups (6 files each) -> "
        f"{len(forced_group_chunks)} chunks, NO group ever split across a chunk boundary"
    )

    print()
    print("ALL bucket_groups_by_size() / _safe_arg_chunks_by_group() CHECKS PASSED")
