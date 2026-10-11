"""Independent cloud monitoring worker with DNS-pinned SSRF protections."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from collections.abc import Sequence
from dataclasses import replace

import httpx

from agents.outbox import AgentOutbox
from checks.cloud_probe import run_cloud_diagnostics
from config.logging_config import get_logger
from config.settings import Settings, validate_api_base_url
from storage.repository import ResultRepository


class CloudAgent:
    """Monitor configured targets from the cloud host independently of the laptop."""

    def __init__(
        self,
        settings: Settings,
        repository: ResultRepository,
        logger: logging.Logger | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if settings.agent_location != "cloud":
            raise ValueError("Cloud worker requires AGENT_LOCATION=cloud.")
        self.settings = settings
        self.repository = repository
        self.logger = logger or get_logger()
        self.transport = transport
        self.api_url = validate_api_base_url(settings.api_base_url, "cloud")
        token = os.getenv("AGENT_TOKEN", settings.api_token)
        if len(token) < 32:
            raise ValueError("Set AGENT_TOKEN to a random secret of at least 32 characters.")
        self.outbox = AgentOutbox(
            repository,
            self.api_url,
            token,
            settings.agent_id,
            settings.agent_name,
            "cloud",
            settings.agent_version,
            self.logger,
            transport,
        )
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_checks)
        self._last_target_refresh = 0.0
        self._cached_targets: list[dict[str, object]] = []

    async def refresh_targets(self) -> list[dict[str, object]]:
        """Refresh the authorized target cache, falling back to local cache on API outage."""
        now = asyncio.get_running_loop().time()
        if self._cached_targets and now - self._last_target_refresh < 30:
            return self._cached_targets
        headers = {"Authorization": f"Bearer {self.outbox.agent_token}"}
        try:
            async with httpx.AsyncClient(
                timeout=1.0,
                transport=self.transport,
                verify=True,
            ) as client:
                response = await client.get(f"{self.api_url}/api/v1/targets", headers=headers)
                response.raise_for_status()
                remote_targets = response.json()
                if not isinstance(remote_targets, list):
                    raise ValueError("API returned an invalid target list.")
                settings_response = await client.get(
                    f"{self.api_url}/api/v1/settings",
                    headers=headers,
                )
                settings_response.raise_for_status()
                runtime_settings = settings_response.json()
                self.settings = replace(
                    self.settings,
                    interval_seconds=float(runtime_settings["interval_seconds"]),
                    dns_timeout=float(runtime_settings["dns_timeout_seconds"]),
                    tcp_timeout=float(runtime_settings["tcp_timeout_seconds"]),
                    http_timeout=float(runtime_settings["http_timeout_seconds"]),
                    max_concurrent_checks=int(runtime_settings["max_concurrent_checks"]),
                    failures_to_open_incident=int(runtime_settings["failures_to_open_incident"]),
                    successes_to_resolve_incident=int(runtime_settings["successes_to_resolve_incident"]),
                    retention_days=int(runtime_settings["retention_days"]),
                )
                self._semaphore = asyncio.Semaphore(self.settings.max_concurrent_checks)
                for target in remote_targets:
                    if target.get("enabled"):
                        self.repository.upsert_target(
                            target["name"],
                            target["url"],
                            target.get("expected_status_codes"),
                            True,
                        )
                    else:
                        stored = self.repository.get_target_by_url(target["url"])
                        if stored:
                            self.repository.set_target_enabled(stored["id"], False)
                self._cached_targets = self.repository.list_targets(enabled_only=True)
                self._last_target_refresh = now
        except httpx.HTTPError as exc:
            self._last_target_refresh = now
            self.logger.warning(
                "cloud_target_refresh_failed_using_cache",
                extra={"error_type": type(exc).__name__},
            )
        if not self._cached_targets:
            self._cached_targets = self.repository.list_targets(enabled_only=True)
        return self._cached_targets

    async def run_once(self) -> None:
        """Run one non-overlapping bounded check cycle and queue results locally."""
        targets = await self.refresh_targets()
        await self.outbox.heartbeat_if_due(self.settings.heartbeat_interval_seconds)

        queue: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        for target in targets:
            queue.put_nowait(target)

        async def worker() -> None:
            while True:
                try:
                    target = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    report = await run_cloud_diagnostics(
                        str(target["url"]),
                        dns_timeout=self.settings.dns_timeout,
                        tcp_timeout=self.settings.tcp_timeout,
                        https_timeout=self.settings.http_timeout,
                        allow_private=self.settings.allow_private_cloud_targets,
                        check_semaphore=self._semaphore,
                        expected_status_codes=tuple(target["expected_status_codes"]),
                    )
                    await asyncio.to_thread(
                        self.repository.save_report,
                        report.target.url,
                        report.results,
                    )
                    await self.outbox.enqueue_report(report)
                    self.logger.info(
                        "cloud_target_check_completed",
                        extra={
                            "target_host": report.target.hostname,
                            "success": report.success,
                            "checks_saved": len(report.results),
                        },
                    )
                finally:
                    queue.task_done()

        await asyncio.gather(
            *(worker() for _ in range(min(len(targets), self.settings.max_concurrent_checks)))
        )

    async def run_forever(self, max_cycles: int | None = None) -> int:
        """Repeat monitoring without concurrent cycles or unbounded background tasks."""
        completed = 0
        loop = asyncio.get_running_loop()
        while max_cycles is None or completed < max_cycles:
            started = loop.time()
            await self.run_once()
            completed += 1
            delay = self.settings.interval_seconds - (loop.time() - started)
            if delay > 0 and (max_cycles is None or completed < max_cycles):
                await asyncio.sleep(delay)
            elif delay <= 0:
                self.logger.warning(
                    "cloud_monitor_cycle_delayed",
                    extra={"interval_seconds": self.settings.interval_seconds},
                )
        return completed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the independent Network Doctor cloud worker.")
    parser.add_argument("--cycles", type=int, help="stop after a finite number of cycles")
    parser.add_argument("--database", help="local cloud-worker SQLite state path")
    args = parser.parse_args(argv)
    settings = Settings.from_env(require_api_token=True)
    if args.cycles is not None and args.cycles < 1:
        parser.error("--cycles must be positive.")
    database_path = args.database or str(settings.database_path)
    repository = ResultRepository(
        database_path,
        database_url=None if args.database else settings.database_url,
    )
    agent = CloudAgent(settings, repository)
    try:
        asyncio.run(agent.run_forever(args.cycles))
    except KeyboardInterrupt:
        get_logger().info("cloud_agent_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
