"""HavnVard UI — shared Jinja2Templates instance + forge_core chrome install.

INFRA-51 (FORGE shared header/footer chrome rollout). Prior to this file
each route module (`routes/dedup.py`, `routes/cleanup.py`, `routes/backup.py`,
`routes/group_detail.py`) instantiated its own `Jinja2Templates(...)` pointed
at the same `templates/` directory -- harmless for rendering (all four read
the same files), but `forge_core.jinja.install_chrome()` registers Jinja2
globals on one `Environment` object, so four separate instances would each
need their own install_chrome() call. Centralizing to one shared `templates`
object here means the chrome is installed exactly once, and `base.html`
(extended by every page template) picks up `forge_header()`/`forge_footer()`
regardless of which route rendered the page.

See the forge_core library (vendored chrome; INFRA-165) for
the chrome component itself; /srv/apps/crm-search/main.py for the
closest working FastAPI+Jinja2 reference consumer.
"""
from __future__ import annotations

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from . import config

templates = Jinja2Templates(directory=str(__file__.rsplit("/app", 1)[0] + "/app/templates"))

# Site host names for page text (3.0.0, review F7): pages say what the inventory rows actually carry.
templates.env.globals.update(
    site_local=config._site.local_host(),
    site_nas=config._site.nas_host(),
    site_sources=", ".join(config.SOURCE_HOSTS),
    site_all=", ".join(config.ALL_HOSTS),
    dashboard_url=config._site.ui("dashboard_url"),
)

try:   # optional shared header/footer (forge_core); plain fallback when it is not installed
    from forge_core.jinja import install_chrome
except ImportError:
    def _plain_header(app_nav=(), **_kw):
        links = " · ".join(f'<a href="{escape(i["href"])}"{" class=active" if i.get("active") else ""}>{escape(i["label"])}</a>'
                           for i in app_nav)
        return Markup(f'<header class="hv-header"><b>HavnVard</b> — {links}</header>')

    templates.env.globals.update(forge_header=_plain_header, forge_footer=lambda **_kw: Markup(""))
else:
    install_chrome(
        templates.env,
        module_key="havnvard",
        module_name="HavnVard",
        home_url="/havnvard/dedup",
        settings_url="/havnvard/health",
        legacy_theme_key="havnvard-theme",
    )
