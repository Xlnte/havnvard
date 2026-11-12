"""BH-7 (1.4.1): the crawl TSV is read with ONLY '\\n' as the record terminator, so a file NAME containing a bare
CR (or any other character Python's universal-newline mode treats as a line break) cannot tear a row."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import load_nas_inventory as L  # noqa: E402
import nas_dedup_core as core  # noqa: E402


def _row(path):
    return f"{path}|81a4|100|0|0|5|1|1700000000|1700000000|1700000000\n"


def test_cr_in_name_does_not_tear_the_row(tmp_path):
    tsv = tmp_path / "crawl.tsv"
    names = ["/share/x/cr_du\rp.bin", "/share/x/plain.bin", "/share/x/ff_du\x0cp.bin", "/share/x/crlf\r\nname.bin"]
    # a name with an embedded LF cannot be represented in this newline-framed file at all: the crawl (find -print0 |
    # xargs -0 stat -c '%n|...') writes it raw, so it still tears into a malformed head (logged) and a tail that may
    # parse as a row (Opus review R-4, FILE: safe because the dedup re-stats/re-hashes the real path and freshness
    # needs inode+mtime+size to match). The 3 representable ones must each parse as exactly one row.
    with open(tsv, "w", encoding="utf-8", newline="") as f:
        for n in names[:3]:
            f.write(_row(n))
    with L.open_tsv(str(tsv)) as f:
        lines = list(f)
    assert len(lines) == 3
    parsed = [L.parse_tsv_line(ln) for ln in lines]
    assert all(p is not None for p in parsed)
    assert [p[0] for p in parsed] == names[:3]
    # the default open() would have torn the CR name into two malformed records
    with open(tsv, encoding="utf-8", errors="surrogateescape") as f:
        torn = list(f)
    assert len(torn) > 3
    # HavnVard then refuses the name explicitly instead of never seeing it
    assert core.classify_path(parsed[0][0]) == "UNSAFE_PATH" and core.classify_path(parsed[2][0]) == "UNSAFE_PATH"
    assert core.classify_path(parsed[1][0]) is None
