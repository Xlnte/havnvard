"""havnvard_site: the one site file every inventory tool reads (3.0.0, review F1/F2/F11). No database."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import havnvard_site as hs  # noqa: E402


@pytest.fixture
def site_file(tmp_path, monkeypatch):
    def write(text: str):
        p = tmp_path / "site.toml"
        p.write_text(text)
        monkeypatch.setenv("HAVNVARD_SITE", str(p))
        hs.site.cache_clear()
        return p
    yield write
    hs.site.cache_clear()


def test_hosts_and_agents_resolve(site_file):
    site_file('[hosts]\nlocal="s1"\nnas="n1"\nsources=["s1","a1"]\n[agents.a1]\nssh_host="a1.example"\n')
    assert hs.local_host() == "s1" and hs.nas_host() == "n1"
    assert hs.source_hosts() == ("s1", "a1") and hs.all_hosts() == ("s1", "a1", "n1")
    assert hs.agent_hosts() == ("a1",) and hs.agent("a1")["ssh_host"] == "a1.example"
    with pytest.raises(hs.SiteConfigError):
        hs.agent("missing")


@pytest.mark.parametrize("text,key", [
    ('[hosts]\nsources="s1"\n', "sources"),          # a string, not a list: would become ('s','1')
    ('[hosts]\nlocal=5\n', "local"),
    ('[hosts]\nall=[]\n', "all"),
    ('hosts="x"\n', "[hosts]"),
    ('[agents]\na1="x"\n', "agents.a1"),
])
def test_mistyped_site_file_is_refused(site_file, text, key):
    site_file(text)
    with pytest.raises(hs.SiteConfigError, match=key.replace("[", r"\[").replace("]", r"\]")):
        hs.site()


def test_missing_or_corrupt_site_file_is_loud(site_file, monkeypatch, tmp_path):
    monkeypatch.setenv("HAVNVARD_SITE", str(tmp_path / "nope.toml"))
    hs.site.cache_clear()
    with pytest.raises(hs.SiteConfigError, match="missing file"):
        hs.site()
    site_file("[hosts\n")
    with pytest.raises(hs.SiteConfigError, match="cannot read"):
        hs.site()


def test_env_file_unreadable_is_loud_and_secret_free(site_file, tmp_path, monkeypatch):
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    env = tmp_path / "hv.env"
    env.write_text("POSTGRES_URL=postgresql://u:SECRETPW@h/db\n")
    site_file(f'[database]\nenv_file="{env}"\n')
    assert hs.get_dsn().endswith("@h/db")
    env.chmod(0)
    if os.geteuid() == 0:
        pytest.skip("root reads mode-000 files")
    with pytest.raises(hs.SiteConfigError) as e:
        hs.get_dsn()
    assert "SECRETPW" not in str(e.value) and str(env) in str(e.value)


def test_require_dsn_refuses_builtin_fallback(site_file, monkeypatch):
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    site_file('[hosts]\nlocal="s1"\n')
    assert hs.get_dsn() == hs.DEFAULT_FALLBACK_URL
    with pytest.raises(hs.SiteConfigError, match="no database configured"):
        hs.require_dsn()


@pytest.mark.parametrize("text,key", [
    ('[load_bearing]\ncrontab_users="alice"\n', "crontab_users"),
    ('[scan]\nextra_excludes="/mnt/x"\n', "extra_excludes"),
    ('[report]\napp_prefixes=[["/a"]]\n', "app_prefixes"),
])
def test_mistyped_lists_outside_hosts_are_refused(site_file, text, key):
    site_file(text)
    with pytest.raises(hs.SiteConfigError, match=key):
        hs.site()
