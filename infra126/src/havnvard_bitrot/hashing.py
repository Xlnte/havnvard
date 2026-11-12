from __future__ import annotations

import hashlib
import os
import stat
import time
from typing import Callable

from .types import HashOutcome, HashResult


def hash_file(
    candidate_item_id: int,
    path: str,
    timeout_seconds: int = 1200,
    chunk_size: int = 8 * 1024 * 1024,
    progress_callback: Callable[[], None] | None = None,
    progress_interval_seconds: int = 30,
) -> HashResult:
    started = time.monotonic()
    last_progress = started
    try:
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            return HashResult(candidate_item_id, path, HashOutcome.SKIPPED, None, before.st_size, before.st_mtime_ns, before.st_ino, 0, "not a regular file")
        digest = hashlib.sha256()
        with open(path, "rb", buffering=0) as handle:
            while True:
                block = handle.read(chunk_size)
                if not block:
                    break
                digest.update(block)
                now = time.monotonic()
                if progress_callback and now - last_progress >= progress_interval_seconds:
                    progress_callback()
                    last_progress = now
                if now - started > timeout_seconds:
                    return HashResult(candidate_item_id, path, HashOutcome.FAILED, None, before.st_size, before.st_mtime_ns, before.st_ino, int((time.monotonic()-started)*1000), "per-file hash timeout")
        after = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return HashResult(candidate_item_id, path, HashOutcome.MISSING, None, None, None, None, int((time.monotonic()-started)*1000), "file disappeared")
    except PermissionError as exc:
        return HashResult(candidate_item_id, path, HashOutcome.UNREADABLE, None, None, None, None, int((time.monotonic()-started)*1000), str(exc))
    except OSError as exc:
        return HashResult(candidate_item_id, path, HashOutcome.FAILED, None, None, None, None, int((time.monotonic()-started)*1000), str(exc))

    duration = int((time.monotonic() - started) * 1000)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return HashResult(candidate_item_id, path, HashOutcome.CHANGED_DURING_HASH, None, after.st_size, after.st_mtime_ns, after.st_ino, duration, "metadata changed during hash")
    return HashResult(candidate_item_id, path, HashOutcome.HASHED, digest.hexdigest(), after.st_size, after.st_mtime_ns, after.st_ino, duration)
