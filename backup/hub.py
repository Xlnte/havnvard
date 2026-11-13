"""Hub side: rest-server unit, disk guard, and the `hub set` client setting."""
from __future__ import annotations

import shutil
from pathlib import Path

from . import alerts, config
from .config import BackupError
from .render import render, render_task
from .util import run, systemd_arg


def hub_set(address: str) -> str:
    host, _, port = address.partition(":")
    if not host or any(c.isspace() or c in "/@" for c in address):
        raise BackupError(f"bad hub address {address!r}; use HOST or HOST:PORT")
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        raise BackupError(f"bad hub port in {address!r}")
    addr = f"{host}:{port or '8000'}"
    config.update("hub", {"address": addr})
    return addr


def hub_install(repo_root: str, port: int, listen: str, out_dir: Path, rest_server: str | None) -> list[str]:
    """Render units into out_dir and return the lines the operator must run. Runs nothing."""
    if not (0 < port < 65536):
        raise BackupError(f"bad port {port}")
    root = Path(repo_root).expanduser().resolve()
    rs = rest_server or shutil.which("rest-server") or "%h/.local/bin/rest-server"
    htpasswd = config.config_dir() / "hub.htpasswd"
    listen_addr = f"{listen}:{port}"
    written = [render("restic-hub.service.tmpl", out_dir, "restic-hub.service",
                      rest_server=systemd_arg(rs), repo_root=systemd_arg(str(root)),
                      listen=listen_addr, htpasswd=systemd_arg(str(htpasswd)))]
    written += render_task(out_dir, "havnvard-hub-diskguard", "HavnVard hub disk guard",
                           "hub diskguard", "OnBootSec=30s\nOnUnitActiveSec=1min\nAccuracySec=5s", timeout="2min")
    written += render_task(out_dir, "havnvard-hub-health", "HavnVard backup health", "health",
                           "OnCalendar=hourly\nRandomizedDelaySec=5m", success_exit="0", timeout="30min")
    written += render_task(out_dir, "havnvard-hub-catalog", "HavnVard backup names + file catalog", "catalog run",
                           "OnCalendar=*-*-* *:40:00\nRandomizedDelaySec=5m", success_exit="0", timeout="6h")
    # 3.2.0 (INFRA-571): no prune timer. HavnVard is long-term storage; deletion is an owner command, never a schedule.
    config.update("hub_local", {"repo_root": str(root), "port": port, "listen": listen})
    ud = "~/.config/systemd/user"
    lines = [
        f"mkdir -p {root} {ud} && touch {htpasswd} && chmod 600 {htpasswd}",
        f"cp {out_dir}/*.service {out_dir}/*.timer {ud}/",
        "systemctl --user daemon-reload",
        "systemctl --user enable --now restic-hub.service havnvard-hub-diskguard.timer "
        "havnvard-hub-health.timer havnvard-hub-catalog.timer",
        "# upgrading from <3.2.0: systemctl --user disable --now havnvard-hub-prune.timer   (nothing is deleted on a schedule any more)",
        "loginctl enable-linger $USER   # keep the user units running after logout (needs sudo on some systems)",
    ]
    if listen in ("127.0.0.1", "localhost"):
        lines.append(f"# NOTE: --listen {listen} is reachable from this machine only; re-run with --listen "
                     "<this host's LAN or Tailscale address> so devices can connect")
    lines.append(f"# Add each device with the htpasswd line `enroll` prints for it, appended to {htpasswd}")
    return [f"# wrote {p}" for p in written] + lines


def _free_gb(path: Path) -> int:
    out = run(["df", "--output=avail", "-B1", str(path)])
    vals = out.stdout.strip().splitlines()[-1].strip() if out.returncode == 0 and out.stdout.strip() else ""
    if not vals.isdigit():
        raise BackupError(f"df failed on {path}: {out.stderr.strip() or out.stdout.strip()!r}")
    return int(vals) // 1024**3


def diskguard(stop_gb: int | None = None, start_gb: int | None = None) -> int:
    """Ported from restic-hub-diskguard. Below stop_gb free: stop rest-server so every device's backup
    fails cleanly and retries. At/above start_gb: start it again, but only if this guard stopped it.
    An unreadable disk changes nothing and exits 1 with an alert (never a silent 0).
    The marker file holds "stopped" while the guard has the hub down and is emptied on restart
    (HavnVard never deletes files, so the marker is rewritten, not removed)."""
    cfg = config.load().get("hub_local", {})
    stop_gb = stop_gb if stop_gb is not None else int(cfg.get("stop_gb", 100))
    start_gb = start_gb if start_gb is not None else int(cfg.get("start_gb", 125))
    root = cfg.get("repo_root")
    if not root:
        raise BackupError("no hub repo_root configured; run `hub install` first")
    mark = config.state_dir() / "hub-diskguard.stopped"
    mark.parent.mkdir(parents=True, exist_ok=True)
    guard_stopped = mark.exists() and mark.read_text().strip() == "stopped"

    def alert(msg: str) -> None:
        print(f"ALERT: {msg}")
        alerts.fire("havnvard-backup-diskguard", f"Backup hub: {msg}", 1800)

    try:
        free = _free_gb(Path(root))
    except BackupError as e:
        alert(f"disk guard cannot check free space: {e}")
        return config.PROBLEM_EXIT
    if free < stop_gb:
        if run(["systemctl", "--user", "is-active", "-q", "restic-hub.service"]).returncode == 0:
            if run(["systemctl", "--user", "stop", "restic-hub.service"]).returncode == 0:
                mark.write_text("stopped")
                alert(f"{free} GB free < {stop_gb} GB; hub STOPPED, no device can write")
            else:
                alert(f"{free} GB free < {stop_gb} GB; hub stop FAILED")
        return config.PROBLEM_EXIT   # low disk is a problem whether or not we had to act this minute
    if guard_stopped and free >= start_gb:
        if run(["systemctl", "--user", "start", "restic-hub.service"]).returncode == 0:
            mark.write_text("")
            print(f"{free} GB free; hub restarted")
            alerts.resolve("havnvard-backup-diskguard")
            return 0
        alert(f"{free} GB free; hub restart FAILED")
        return config.PROBLEM_EXIT
    return 0
