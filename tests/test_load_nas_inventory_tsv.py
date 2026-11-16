"""BH-7 (1.4.1): the crawl TSV is read with ONLY '\\n' as the record terminator, so a file NAME containing a bare
CR (or any other character Python's universal-newline mode treats as a line break) cannot tear a row."""
from __future__ import annotations

import os
import pytest
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


# ---- 3.3.10 (INFRA-633): the NAS admin token is read directly, sudo only after PermissionError ----

def test_nas_creds_use_injected_reader_without_sudo(monkeypatch):
    import subprocess as sp
    monkeypatch.setattr(sp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sudo must not run")))
    assert L._nas_creds(reader=lambda p: "NAS_ADMIN_USER=u\nNAS_ADMIN_PASS='p'\n") == ("u", "p")
    with pytest.raises(RuntimeError) as e:
        L._nas_creds(reader=lambda p: "NAS_ADMIN_USER=u\n")
    assert "p" not in str(e.value).replace(L.NAS_TOKEN_FILE, "").replace("NAS_ADMIN_USER/NAS_ADMIN_PASS", "").replace("could not parse  from ", "")


def test_token_file_direct_then_sudo_only_on_permission_error(monkeypatch, tmp_path):
    import builtins
    import subprocess as sp
    import token_file as tf
    f = tmp_path / "tok"
    f.write_text("NAS_ADMIN_USER=u\n")
    monkeypatch.setattr(sp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no sudo")))
    assert tf.read_token_text(str(f)) == "NAS_ADMIN_USER=u\n"
    with pytest.raises(FileNotFoundError):                       # a missing file is not retried via sudo
        tf.read_token_text(str(tmp_path / "missing"))
    calls = []
    monkeypatch.setattr(sp, "run", lambda argv, **k: calls.append(argv) or sp.CompletedProcess(argv, 0, stdout="X", stderr=""))
    real = builtins.open
    def deny(p, *a, **k):
        if str(p) == "/denied":
            raise PermissionError
        return real(p, *a, **k)
    monkeypatch.setattr(builtins, "open", deny)
    assert tf.read_token_text("/denied") == "X" and calls == [["sudo", "-n", "cat", "/denied"]]
