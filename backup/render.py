from __future__ import annotations

from pathlib import Path
from string import Template

from .config import BackupError

PKG = Path(__file__).resolve().parent
REPO_DIR = PKG.parent


def render(template: str, out_dir: Path, out_name: str, **kw) -> Path:
    src = PKG / "templates" / template
    try:
        text = Template(src.read_text()).substitute(**kw)
    except KeyError as e:
        raise BackupError(f"template {template} needs value {e}") from e
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / out_name
    dst.write_text(text)
    return dst


def render_task(out_dir: Path, name: str, description: str, command: str, schedule: str,
                success_exit: str = "0", timeout: str = "6h") -> list[Path]:
    import sys
    kw = dict(description=description, command=command, python=sys.executable,
              repo_dir=str(REPO_DIR), success_exit=success_exit, timeout=timeout, schedule=schedule)
    return [render("havnvard-task.service.tmpl", out_dir, f"{name}.service", **kw),
            render("havnvard-task.timer.tmpl", out_dir, f"{name}.timer", **kw)]
