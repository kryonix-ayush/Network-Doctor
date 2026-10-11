"""Bounded, non-overlapping local monitoring scheduler."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Protocol

from checks.models import CheckResult, validate_timeout
from checks.runner import DiagnosticReport, run_diagnostics
from checks.url_validation import validate_url
from config.logging_config import get_logger
from diagnosis.incident_manager import IncidentManager

CheckRunner = Callable[..., Awaitable[DiagnosticReport]]
ReportCallback = Callable[[DiagnosticReport], Awaitable[None]]
TransitionCallback = Callable[[object], Awaitable[None]]
CycleCallback = Callable[[], Awaitable[None]]


class ReportStore(Protocol):
    """Persistence interface used by the scheduler."""

    def save_report(self, target_url: str, results: Iterable[CheckResult]) -> int:
        """Persist the results from one target cycle."""


class MonitorScheduler:
    """Run local checks at a fixed interval and persist every completed cycle."""

    def __init__(
        self,
        targets: Sequence[str],
        repository: ReportStore,
        interval_seconds: float = 10.0,
        max_concurrent_checks: int = 20,
        check_runner: CheckRunner = run_diagnostics,
        logger: logging.Logger | None = None,
        incident_manager: IncidentManager | None = None,
        report_callback: ReportCallback | None = None,
        transition_callback: TransitionCallback | None = None,
        cycle_callback: CycleCallback | None = None,
    ) -> None:
        if isinstance(targets, str) or not targets:
            raise ValueError("Provide at least one HTTPS target URL.")
        validate_timeout(interval_seconds)
        if type(max_concurrent_checks) is not int or max_concurrent_checks < 1:
            raise ValueError("max_concurrent_checks must be a positive integer.")

        self.targets = tuple(dict.fromkeys(validate_url(url).url for url in targets))
        self.repository = repository
        self.interval_seconds = interval_seconds
        self.max_concurrent_checks = max_concurrent_checks
        self.check_runner = check_runner
        self.logger = logger or get_logger()
        self.incident_manager = incident_manager
        self.report_callback = report_callback
        self.transition_callback = transition_callback
        self.cycle_callback = cycle_callback
        self._cycle_lock = asyncio.Lock()

    async def run_once(self) -> None:
        """Run one complete cycle without exceeding the configured check limit."""
        async with self._cycle_lock:
            cycle_started = time.perf_counter()
            semaphore = asyncio.Semaphore(self.max_concurrent_checks)
            queue: asyncio.Queue[str] = asyncio.Queue()
            for target in self.targets:
                queue.put_nowait(target)

            async def worker() -> None:
                while True:
                    try:
                        target = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    try:
                        await self._check_and_store(target, semaphore)
                    finally:
                        queue.task_done()

            worker_count = min(len(self.targets), self.max_concurrent_checks)
            async with asyncio.TaskGroup() as task_group:
                for _ in range(worker_count):
                    task_group.create_task(worker())
            self.logger.info(
                "monitor_cycle_completed",
                extra={
                    "target_count": len(self.targets),
                    "cycle_duration_ms": round((time.perf_counter() - cycle_started) * 1000, 2),
                },
            )

    async def _check_and_store(
        self,
        target_url: str,
        semaphore: asyncio.Semaphore,
    ) -> None:
        report = await self.check_runner(target_url, check_semaphore=semaphore)
        await asyncio.to_thread(
            self.repository.save_report,
            report.target.url,
            report.results,
        )
        if self.report_callback is not None:
            await self.report_callback(report)
        transition = (
            await asyncio.to_thread(
                self.incident_manager.observe,
                report.target.url,
                report.results,
            )
            if self.incident_manager is not None
            else None
        )
        if transition is not None:
            self.logger.warning(
                transition.event_type,
                extra={
                    "target_host": report.target.hostname,
                    "incident_id": transition.incident_id,
                    "diagnosis_code": transition.diagnosis.code if transition.diagnosis else None,
                },
            )
            if self.transition_callback is not None:
                await self.transition_callback(transition)
        self.logger.info(
            "target_check_completed",
            extra={
                "target_host": report.target.hostname,
                "success": report.success,
                "checks_saved": len(report.results),
            },
        )

    async def run_forever(
        self,
        stop_event: asyncio.Event | None = None,
        max_cycles: int | None = None,
    ) -> int:
        """Run cycles serially; delayed cycles are logged rather than overlapped."""
        if max_cycles is not None and (type(max_cycles) is not int or max_cycles < 1):
            raise ValueError("max_cycles must be a positive integer when provided.")

        loop = asyncio.get_running_loop()
        completed_cycles = 0
        while max_cycles is None or completed_cycles < max_cycles:
            if stop_event is not None and stop_event.is_set():
                break

            if self.cycle_callback is not None:
                await self.cycle_callback()
            cycle_started = loop.time()
            await self.run_once()
            completed_cycles += 1
            if stop_event is not None and stop_event.is_set():
                break

            delay = self.interval_seconds - (loop.time() - cycle_started)
            if delay <= 0:
                self.logger.warning(
                    "monitor_cycle_delayed",
                    extra={"interval_seconds": self.interval_seconds},
                )
                await asyncio.sleep(0)
                continue

            if stop_event is None:
                await asyncio.sleep(delay)
                continue
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        return completed_cycles
