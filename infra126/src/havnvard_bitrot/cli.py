from __future__ import annotations

import os

import argparse
import json
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from .alerts import CommandAlertSink, NullAlertSink
from .config import load_settings
from .monitor import monitor_once
from .reporting import verification_report
from .repository import Repository
from .types import Tier
from .verifier import VerificationService
from .waitingroom import WaitingRoomGate


def _sink(command: str | None, name: str, allow_null: bool):
    if command:
        return CommandAlertSink(command)
    if allow_null:
        return NullAlertSink()
    raise RuntimeError(f"{name} integration is not configured; refusing silent operation")


def _validate_run_integrations(settings) -> None:
    if settings.allow_null_integrations:
        return
    missing=[]
    for name,value in [
        ("INFRA126_TG_COMMAND",settings.tg_command),
        ("INFRA126_PLANE_COMMAND",settings.plane_command),
        ("INFRA126_WAITINGROOM_ACQUIRE_COMMAND",settings.waitingroom_acquire_command),
        ("INFRA126_WAITINGROOM_RELEASE_COMMAND",settings.waitingroom_release_command),
    ]:
        if not value:
            missing.append(name)
    if missing:
        raise RuntimeError("required integrations are missing: "+", ".join(missing))


def _configure_logging(level: str, log_dir: str, command: str, host: str | None = None, tier: str | None = None) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging,level.upper()))
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root.addHandler(stream)
    try:
        directory = Path(log_dir)
        directory.mkdir(parents=True,exist_ok=True)
        suffix = "_".join(part for part in [command,tier,host] if part)
        handler = TimedRotatingFileHandler(directory/f"infra126_{suffix}.log",when="midnight",backupCount=30,encoding="utf-8")
        handler.setFormatter(formatter)
        root.addHandler(handler)
    except OSError as exc:
        root.warning("file logging unavailable: %s",exc)


def main() -> int:
    parser = argparse.ArgumentParser(prog="havnvard-bitrot")
    parser.add_argument("--log-level",default="INFO")
    sub = parser.add_subparsers(dest="command",required=True)
    run = sub.add_parser("run")
    run.add_argument("--host",required=True)
    run.add_argument("--tier",required=True,choices=["A","B","C","D","E"])
    run.add_argument("--max-items",type=int,default=0,help="0 means no run-level cap")
    run.add_argument("--run-id")
    run.add_argument("--no-resume",action="store_true")
    sub.add_parser("monitor")
    sub.add_parser("report")
    args = parser.parse_args()

    settings = load_settings()
    _configure_logging(args.log_level,settings.log_dir,args.command,getattr(args,"host",None),getattr(args,"tier",None))
    repository = Repository(settings.postgres_url, exclusions=settings.exclude_path_prefixes)
    if args.command == "report":
        print(verification_report(repository))
        return 0

    _validate_run_integrations(settings)
    tg_sink = _sink(settings.tg_command,"TG PRESI",settings.allow_null_integrations)
    plane_sink = _sink(settings.plane_command,"Plane",settings.allow_null_integrations)
    if args.command == "monitor":
        print(json.dumps(monitor_once(repository,tg_sink,plane_sink),default=str,indent=2))
        return 0

    helper = Path(os.getenv("INFRA126_REMOTE_HELPER") or Path(__file__).resolve().parents[2]/"bin"/"remote_hash_batch.sh")
    service = VerificationService(
        repository,settings,tg_sink,plane_sink,
        WaitingRoomGate(settings.waitingroom_acquire_command,settings.waitingroom_release_command),
        helper,
    )
    summary = service.run(
        args.host,Tier(args.tier),run_id=args.run_id,max_items=args.max_items,resume=not args.no_resume,
    )
    print(json.dumps(summary.__dict__,default=str,indent=2))
    return 0 if summary.details.get("status") == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
