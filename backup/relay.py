"""`health-relay`: for a hub that cannot alert by itself. Runs on a machine that can, runs `health --json --no-alert` on the
hub over ssh, and raises/resolves the alert locally through backup/alerts.py. A failed ssh, a remote error or output
that is not the expected JSON is itself an alert: the relay never passes silently (review F4)."""
from __future__ import annotations

import json
import shlex
from pathlib import Path

from . import alerts, config
from .config import BackupError
from .health import DEVICE_PREFIX, OFFSITE_KEY, OFFSITE_PREFIX, device_key
from .render import render_task
from .util import run, systemd_arg

KEY = "havnvard-backup-health"
RELAY_TIMEOUT_S = 300   # 3.3.3: the hub now reads every repository's snapshot list (STREAM_TIMEOUT_S each at most)


def remote_command(python: str, repo_dir: str) -> str:
    return f"cd {shlex.quote(repo_dir)} && {shlex.quote(python)} -m backup health --json --no-alert"


def _doc(stdout: str):
    for ln in reversed(stdout.splitlines()):
        if ln.lstrip().startswith("{"):
            try:
                return json.loads(ln)
            except ValueError:
                return None
    return None


def _checks_with(stdout: str, prefix: str) -> list[dict] | None:
    doc = _doc(stdout)
    if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
        return None
    return [c for c in doc["checks"] if isinstance(c, dict) and str(c.get("name", "")).startswith(prefix)]


def offsite_checks(stdout: str) -> list[dict] | None:
    """The offsite checks of a well-formed health result, or None when there is no readable result (3.3.2)."""
    return _checks_with(stdout, OFFSITE_PREFIX)


def device_checks(stdout: str) -> list[dict] | None:
    """The per-device stream verdicts of a well-formed health result, or None when there is none (3.3.3)."""
    return _checks_with(stdout, DEVICE_PREFIX)


def _own_key(name) -> bool:
    n = str(name)
    return n.startswith(OFFSITE_PREFIX) or n.startswith(DEVICE_PREFIX)


def interpret(rc: int, stdout: str, stderr: str = "") -> tuple[bool, str]:
    """(healthy, problem_text). Anything that is not a well-formed health result is a problem."""
    doc = _doc(stdout)
    if not isinstance(doc, dict) or "ok" not in doc or "checks" not in doc and "error" not in doc:
        return False, f"relay: unparsable remote output (rc {rc}): {(stdout or stderr).strip()[-200:]!r}"
    if "error" in doc:
        return False, f"relay: remote health could not run: {doc['error']}"
    if rc not in (0, 1) or bool(doc["ok"]) != (rc == 0):
        return False, f"relay: remote exit code {rc} disagrees with its JSON (ok={doc['ok']})"
    # 3.3.2 review fix 3 / 3.3.3: offsite and device checks are judged under their own keys, never by the main key.
    bad = [c for c in doc["checks"] if not c.get("ok") and not _own_key(c.get("name", ""))]
    if bad:
        return False, "; ".join(f"{c.get('name')}: {c.get('detail')}" for c in bad)
    return True, ""


def relay(host: str, python: str, repo_dir: str, runner=run) -> int:
    """Exit 0 healthy, 1 hub reported a problem (alert raised), 2 relay itself failed (alert raised)."""
    key = f"{KEY}-{host}"
    try:
        r = runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", host, remote_command(python, repo_dir)],
                   timeout=RELAY_TIMEOUT_S)
        healthy, text = interpret(r.returncode, r.stdout, r.stderr)
        failed_relay = r.returncode not in (0, 1) or text.startswith("relay:")
        if r.returncode == 255:
            healthy, text, failed_relay = False, f"relay: ssh to {host} failed: {r.stderr.strip()[-200:]}", True
    except BackupError as e:
        healthy, text, failed_relay = False, f"relay: {e}", True
    stdout = None if failed_relay else r.stdout
    own_rc = max(_relay_offsite(host, stdout), _relay_devices(host, stdout))   # checks with their own alert keys
    if healthy:
        alerts.resolve(key)
        print(f"health-relay {host}: healthy" + (" (offsite or device problem: see its own alert)" if own_rc else ""))
        return own_rc
    sent, detail = alerts.fire(key, f"HavnVard Backup ({host}): {text}")
    print(f"health-relay {host}: PROBLEM {text}")
    print(f"alert: {detail}" if sent else f"ALERT NOT SENT: {detail}")
    return max(config.ERROR_EXIT if (failed_relay or not sent) else config.PROBLEM_EXIT, own_rc)


def _relay_offsite(host: str, stdout: str | None) -> int:
    """3.3.2: offsite problems go out under their own key only; it is resolved only from a readable result whose
    offsite checks all pass (a failed relay leaves it as it was; the relay's own alert covers that case).
    Returns 0 when no offsite check failed, PROBLEM_EXIT when one failed and its alert was raised, and ERROR_EXIT
    when one failed and its alert could NOT be raised (same rule as the main key: an unsent alert is never a 1)."""
    checks = offsite_checks(stdout) if stdout is not None else None
    if not checks:
        return 0
    okey = f"{OFFSITE_KEY}-{host}"
    bad = [c for c in checks if not c.get("ok")]
    if bad:
        sent, detail = alerts.fire(okey, f"HavnVard offsite ({host}): " +
                                   "; ".join(f"{c.get('name')}: {c.get('detail')}" for c in bad))
        if not sent:
            print(f"ALERT NOT SENT ({okey}): {detail}")
            return config.ERROR_EXIT
        return config.PROBLEM_EXIT
    alerts.resolve(okey)
    return 0


def _relay_devices(host: str, stdout: str | None) -> int:
    """3.3.3 (INFRA-549): one key per device, `havnvard-device-stale-<device>`, fired or resolved only from a readable
    result's `device <repo>` verdicts. A failed relay, or a device whose repository the hub could not read (no verdict),
    leaves the device key as it was: those failures alert on the main key. Same exit rule as _relay_offsite."""
    checks = device_checks(stdout) if stdout is not None else None
    rc = 0
    for c in checks or []:
        dev = str(c.get("name", ""))[len(DEVICE_PREFIX):]
        key = device_key(dev)
        if c.get("ok"):
            alerts.resolve(key)
            continue
        sent, detail = alerts.fire(key, f"HavnVard backup ({host}): {dev} is stale: {c.get('detail')}")
        if not sent:
            print(f"ALERT NOT SENT ({key}): {detail}")
            rc = config.ERROR_EXIT
        else:
            rc = max(rc, config.PROBLEM_EXIT)
    return rc


def render_units(out_dir: Path, host: str, python: str, repo_dir: str, schedule: str = "hourly") -> list[Path]:
    cmd = f"health-relay --ssh {systemd_arg(host)} --python {systemd_arg(python)} --repo-dir {systemd_arg(repo_dir)}"
    return render_task(out_dir, "havnvard-health-relay", f"HavnVard backup health relay for {host}", cmd,
                       f"OnCalendar={schedule}\nRandomizedDelaySec=5m", success_exit="1", timeout="6m")
