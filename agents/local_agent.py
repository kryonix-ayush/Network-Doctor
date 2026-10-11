"""Run the local Network Doctor monitoring agent."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

from agents.outbox import AgentOutbox
from agents.scheduler import MonitorScheduler
from config.logging_config import get_logger
from diagnosis.incident_manager import IncidentManager
from notifications.dispatcher import NotificationDispatcher
from config.settings import Settings
from storage.repository import ResultRepository


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number greater than zero") from exc
    if number <= 0 or number == float("inf") or number != number:
        raise argparse.ArgumentTypeError("value must be finite and greater than zero")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return number


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Continuously monitor authorized HTTPS targets from this computer."
    )
    parser.add_argument("urls", nargs="+", help="HTTPS URLs to monitor")
    settings = Settings.from_env()
    parser.add_argument("--interval", type=_positive_float, default=None, metavar="SECONDS")
    parser.add_argument("--max-concurrent-checks", type=_positive_int, default=None)
    parser.add_argument(
        "--cycles",
        type=_positive_int,
        help="stop after this many cycles (useful for a one-shot smoke test)",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="SQLite history database path (overrides DATABASE_URL)",
    )
    args = parser.parse_args(argv)

    logger = get_logger()
    repository = ResultRepository(
        args.database or settings.database_path,
        database_url=None if args.database else settings.database_url,
    )
    agent_token = os.getenv("AGENT_TOKEN", settings.api_token)
    outbox = AgentOutbox(
        repository,
        settings.api_base_url,
        agent_token,
        settings.agent_id,
        settings.agent_name,
        "local",
        settings.agent_version,
        logger,
    )
    notifier = NotificationDispatcher(repository)
    runtime_policy = {
        "dns_timeout_seconds": settings.dns_timeout,
        "tcp_timeout_seconds": settings.tcp_timeout,
        "http_timeout_seconds": settings.http_timeout,
    }
    remote_settings: dict[str, float | int] | None = None
    settings_refresh_task: asyncio.Task | None = None
    next_settings_refresh = 0.0
    incident_manager = IncidentManager(
        repository,
        settings.failures_to_open_incident,
        settings.successes_to_resolve_incident,
    )
    scheduler: MonitorScheduler | None = None

    async def configured_runner(url: str, check_semaphore: asyncio.Semaphore):
        from checks.runner import run_diagnostics

        return await run_diagnostics(
            url,
            dns_timeout=runtime_policy["dns_timeout_seconds"],
            tcp_timeout=runtime_policy["tcp_timeout_seconds"],
            https_timeout=runtime_policy["http_timeout_seconds"],
            check_semaphore=check_semaphore,
        )

    async def report_callback(report) -> None:
        if agent_token:
            await outbox.heartbeat_if_due(settings.heartbeat_interval_seconds)
            await outbox.enqueue_report(report)

    async def refresh_runtime_settings() -> None:
        nonlocal remote_settings, settings_refresh_task, next_settings_refresh
        if not agent_token or scheduler is None:
            return
        if settings_refresh_task is not None and settings_refresh_task.done():
            remote = settings_refresh_task.result()
            settings_refresh_task = None
            if remote is not None:
                remote_settings = remote
        if remote_settings is not None:
            scheduler.interval_seconds = float(remote_settings["interval_seconds"])
            scheduler.max_concurrent_checks = int(remote_settings["max_concurrent_checks"])
            incident_manager.failures_to_open = int(remote_settings["failures_to_open_incident"])
            incident_manager.successes_to_resolve = int(remote_settings["successes_to_resolve_incident"])
            runtime_policy.update(
                {
                    "dns_timeout_seconds": float(remote_settings["dns_timeout_seconds"]),
                    "tcp_timeout_seconds": float(remote_settings["tcp_timeout_seconds"]),
                    "http_timeout_seconds": float(remote_settings["http_timeout_seconds"]),
                }
            )
        now = asyncio.get_running_loop().time()
        if settings_refresh_task is None and now >= next_settings_refresh:
            settings_refresh_task = asyncio.create_task(outbox.fetch_settings())
            next_settings_refresh = now + 30

    scheduler = MonitorScheduler(
        args.urls,
        repository,
        interval_seconds=args.interval or settings.interval_seconds,
        max_concurrent_checks=args.max_concurrent_checks or settings.max_concurrent_checks,
        logger=logger,
        incident_manager=incident_manager,
        check_runner=configured_runner,
        report_callback=report_callback if agent_token else None,
        transition_callback=notifier.dispatch,
        cycle_callback=refresh_runtime_settings if agent_token else None,
    )
    logger.info(
        "local_agent_started",
        extra={
            "target_count": len(scheduler.targets),
            "interval_seconds": scheduler.interval_seconds,
        },
    )
    try:
        asyncio.run(scheduler.run_forever(max_cycles=args.cycles))
    except KeyboardInterrupt:
        logger.info("local_agent_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
