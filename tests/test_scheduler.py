import asyncio
import logging
from collections.abc import Iterable
from pathlib import Path
from datetime import UTC, datetime, timedelta

import pytest

from agents.scheduler import MonitorScheduler
from checks.models import CheckResult
from checks.runner import DiagnosticReport
from checks.url_validation import validate_url
from storage.repository import ResultRepository


class InMemoryRepository:
    def __init__(self) -> None:
        self.saved: list[tuple[str, tuple[CheckResult, ...]]] = []

    def save_report(self, target_url: str, results: Iterable[CheckResult]) -> int:
        stored_results = tuple(results)
        self.saved.append((target_url, stored_results))
        return len(stored_results)


def _report(url: str) -> DiagnosticReport:
    return DiagnosticReport(
        validate_url(url),
        (CheckResult("dns", True, 1.0, addresses=("192.0.2.1",)),),
    )


@pytest.mark.asyncio
async def test_scheduler_repeats_cycles_without_overlapping(
    caplog: pytest.LogCaptureFixture,
) -> None:
    active = 0
    maximum_active = 0
    calls = 0

    async def slow_runner(url: str, check_semaphore: asyncio.Semaphore) -> DiagnosticReport:
        nonlocal active, maximum_active, calls
        calls += 1
        async with check_semaphore:
            active += 1
            maximum_active = max(maximum_active, active)
            try:
                await asyncio.sleep(0.02)
            finally:
                active -= 1
        return _report(url)

    repository = InMemoryRepository()
    logger = logging.getLogger("network_doctor.scheduler_test")
    caplog.set_level(logging.WARNING, logger=logger.name)
    scheduler = MonitorScheduler(
        ["https://example.test/"],
        repository,
        interval_seconds=0.005,
        check_runner=slow_runner,
        logger=logger,
    )
    cycles = await scheduler.run_forever(max_cycles=3)

    assert cycles == calls == 3
    assert maximum_active == 1
    assert len(repository.saved) == 3
    assert "monitor_cycle_delayed" in caplog.text


@pytest.mark.asyncio
async def test_scheduler_limits_concurrent_check_work() -> None:
    active = 0
    maximum_active = 0

    async def bounded_runner(url: str, check_semaphore: asyncio.Semaphore) -> DiagnosticReport:
        nonlocal active, maximum_active
        async with check_semaphore:
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
        return _report(url)

    targets = [f"https://host-{number}.test/" for number in range(6)]
    scheduler = MonitorScheduler(
        targets,
        InMemoryRepository(),
        max_concurrent_checks=2,
        check_runner=bounded_runner,
    )
    await scheduler.run_once()
    assert maximum_active == 2


@pytest.mark.asyncio
async def test_concurrent_run_once_calls_are_serialized() -> None:
    active = 0
    maximum_active = 0

    async def runner(url: str, check_semaphore: asyncio.Semaphore) -> DiagnosticReport:
        nonlocal active, maximum_active
        async with check_semaphore:
            active += 1
            maximum_active = max(maximum_active, active)
            try:
                await asyncio.sleep(0.01)
            finally:
                active -= 1
        return _report(url)

    scheduler = MonitorScheduler(
        ["https://example.test/"],
        InMemoryRepository(),
        check_runner=runner,
    )
    await asyncio.gather(scheduler.run_once(), scheduler.run_once())
    assert maximum_active == 1


def test_sqlite_history_survives_repository_restart(tmp_path: Path) -> None:
    database = tmp_path / "network-doctor.sqlite3"
    first_repository = ResultRepository(database)
    first_repository.save_report(
        "https://example.com/",
        (
            CheckResult(
                "https",
                False,
                25.5,
                "http_error",
                "The server returned HTTP 503.",
                status_code=503,
            ),
        ),
    )

    reopened_repository = ResultRepository(database)
    rows = reopened_repository.get_recent(limit=10)
    assert len(rows) == 1
    assert rows[0]["target_url"] == "https://example.com/"
    assert rows[0]["check_type"] == "https"
    assert rows[0]["success"] is False
    assert rows[0]["status_code"] == 503
    assert rows[0]["error_code"] == "http_error"
    assert rows[0]["timestamp_utc"]


def test_history_rejects_non_positive_limits(tmp_path: Path) -> None:
    repository = ResultRepository(tmp_path / "history.sqlite3")
    with pytest.raises(ValueError):
        repository.get_recent(limit=0)


def test_json_logging_includes_only_safe_selected_fields() -> None:
    import json

    from config.logging_config import JSONFormatter

    record = logging.LogRecord(
        "network_doctor",
        logging.INFO,
        __file__,
        1,
        "target_check_completed",
        (),
        None,
    )
    record.target_host = "example.com"
    record.url = "https://example.com/?token=do-not-log"
    payload = json.loads(JSONFormatter().format(record))

    assert payload["event"] == "target_check_completed"
    assert payload["target_host"] == "example.com"
    assert "url" not in payload
    assert "do-not-log" not in JSONFormatter().format(record)


def test_stale_agent_opens_incident_and_heartbeat_resolves_it(tmp_path: Path) -> None:
    database = tmp_path / "agent-heartbeat.sqlite3"
    repository = ResultRepository(database)
    repository.record_heartbeat("cloud-1", "Cloud", "cloud", "1.0.0")
    stale_time = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    with repository._connection() as connection:
        connection.execute(
            "UPDATE agents SET last_heartbeat_at = ? WHERE id = ?",
            (stale_time, "cloud-1"),
        )

    assert repository.mark_stale_agents(stale_after_seconds=90) == ["cloud-1"]
    active = repository.get_active_incident("agent://cloud-1")
    assert active is not None
    assert active["diagnosis_code"] == "local_agent_stale"

    resolved_id = repository.record_heartbeat("cloud-1", "Cloud", "cloud", "1.0.0")
    assert resolved_id == active["id"]
    incident = repository.get_active_incident("agent://cloud-1")
    assert incident is None
    assert repository.list_incidents()[0]["status"] == "resolved"
