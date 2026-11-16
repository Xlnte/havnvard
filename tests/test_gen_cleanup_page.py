"""gen_cleanup_page.py uses psycopg 3, the repo's one DB driver (INFRA-569, 3.3.8). psycopg2 is not in requirements.txt."""
from __future__ import annotations

import importlib
import sys

import conftest


def _load_without_psycopg2(monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg2", None)            # `import psycopg2` now raises ImportError
    monkeypatch.setitem(sys.modules, "psycopg2.extras", None)
    sys.modules.pop("gen_cleanup_page", None)
    return importlib.import_module("gen_cleanup_page")


def test_imports_without_psycopg2(monkeypatch):
    gcp = _load_without_psycopg2(monkeypatch)
    assert not hasattr(gcp, "psycopg2")


def test_does_not_import_psycopg2_anywhere():
    src = open(conftest.os.path.join(conftest.REPO_ROOT, "gen_cleanup_page.py"), encoding="utf-8").read()
    assert "psycopg2" not in src


def test_writes_page_on_scratch_database(monkeypatch, tmp_path, capsys):
    """End to end on the scratch database: the page is written, read-only session, host rows rendered as text."""
    conftest.connect_retry().close()                              # skips unless HAVNVARD_TEST_DSN is set
    gcp = _load_without_psycopg2(monkeypatch)
    out = tmp_path / "cleanup.html"
    monkeypatch.setattr(gcp, "OUT", str(out))
    gcp.main()
    html_text = out.read_text(encoding="utf-8")
    assert "List B: duplicate cleanup candidates" in html_text and "Coverage" in html_text
    assert "wrote " in capsys.readouterr().out


def test_session_is_read_only(monkeypatch, tmp_path):
    """The page's connection refuses writes (psycopg2's set_session(readonly=True) equivalent, INFRA-569 review)."""
    conftest.connect_retry().close()                              # skips unless HAVNVARD_TEST_DSN is set
    gcp = _load_without_psycopg2(monkeypatch)
    monkeypatch.setattr(gcp, "OUT", str(tmp_path / "cleanup.html"))
    seen = {}
    real_connect = gcp.psycopg.connect

    def spy_connect(*a, **kw):
        conn = real_connect(*a, **kw)
        real_close = conn.close

        def close():
            seen["ro"] = conn.execute("SHOW transaction_read_only").fetchone()[0]
            try:
                conn.execute("CREATE TEMP TABLE _gcp_ro_probe (x int)")
                seen["write"] = "allowed"
            except gcp.psycopg.errors.ReadOnlySqlTransaction:
                seen["write"] = "refused"
            real_close()
        conn.close = close
        return conn

    monkeypatch.setattr(gcp.psycopg, "connect", spy_connect)
    gcp.main()
    assert seen == {"ro": "on", "write": "refused"}
