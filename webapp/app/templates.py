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

See /srv/forge_core (github.com/ParkerFairfield/forge_core, INFRA-165) for
the chrome component itself; /srv/ultraops/crm-search/main.py for the
closest working FastAPI+Jinja2 reference consumer.
"""
from __future__ import annotations

from fastapi.templating import Jinja2Templates

from forge_core.jinja import install_chrome

templates = Jinja2Templates(directory=str(__file__.rsplit("/app", 1)[0] + "/app/templates"))

install_chrome(
    templates.env,
    module_key="havnvard",
    module_name="HavnVard",
    home_url="/havnvard/dedup",
    settings_url="/havnvard/health",
    legacy_theme_key="havnvard-theme",
)
