"""3.3.12 (INFRA-637): one credential-file reader (token_file.read_token_text). No sudo is ever run here; subprocess is mocked."""
import builtins
import re
import subprocess
from pathlib import Path

import pytest

import token_file

ROOT = Path(__file__).resolve().parents[1]


def _deny(monkeypatch, path):
    real = builtins.open

    def deny(p, *a, **k):
        if str(p) == path:
            raise PermissionError(13, "denied")
        return real(p, *a, **k)

    monkeypatch.setattr(builtins, "open", deny)


def test_sudo_fallback_is_non_interactive_with_closed_stdin_and_a_timeout(monkeypatch):
    _deny(monkeypatch, "/denied")
    seen = {}

    def fake(argv, **k):
        seen.update(argv=list(argv), **k)
        return subprocess.CompletedProcess(argv, 0, stdout="X", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    assert token_file.read_token_text("/denied") == "X"
    assert seen["argv"] == ["sudo", "-n", "cat", "/denied"]
    assert seen["stdin"] is subprocess.DEVNULL and seen["timeout"] == token_file.SUDO_TIMEOUT_SEC


@pytest.mark.parametrize("exc", [
    subprocess.CalledProcessError(1, ["sudo"], output="NAS_PASS=topsecret", stderr="sudo: a password is required"),
    subprocess.TimeoutExpired(["sudo"], 30, output=b"NAS_PASS=topsecret"),
    FileNotFoundError(2, "sudo"),
])
def test_sudo_failures_raise_token_read_error_naming_the_file_only(monkeypatch, exc):
    _deny(monkeypatch, "/denied")
    def fail(argv, **k): raise exc
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(token_file.TokenReadError) as e:
        token_file.read_token_text("/denied")
    assert "/denied" in str(e.value)
    assert "topsecret" not in str(e.value) and "password is required" not in str(e.value)
    assert e.value.__cause__ is None


def test_missing_file_is_not_retried_with_sudo(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no sudo")))
    with pytest.raises(FileNotFoundError):
        token_file.read_token_text(str(tmp_path / "missing"))


def test_no_other_code_runs_sudo_cat_on_a_file():
    """Sweep guard: `sudo cat` / `sudo -n cat` of a file lives in token_file.py only (tests and docs excluded)."""
    pat = re.compile(r'\[\s*"sudo"\s*,\s*(?:"-n"\s*,\s*)?"cat"')
    hits = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
            if ".venv" not in p.parts and "tests" not in p.parts and p.name != "token_file.py" and pat.search(p.read_text(encoding="utf-8"))]
    assert hits == []
