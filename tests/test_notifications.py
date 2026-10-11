import asyncio

import pytest

from diagnosis.incident_manager import IncidentManager
from notifications.dispatcher import Channel, NotificationDispatcher
from checks.models import CheckResult
from storage.repository import ResultRepository


@pytest.mark.asyncio
async def test_dispatch_retries_then_records_once_and_deduplicates(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "notify.sqlite3")
    manager = IncidentManager(repository, failures_to_open=1)
    transition = manager.observe(
        "https://example.com/",
        (CheckResult("https", False, 20, "https_timeout"),),
    )
    assert transition is not None
    attempts = 0

    async def flaky_sender(message: str) -> None:
        nonlocal attempts
        attempts += 1
        assert "incident opened" in message
        if attempts < 3:
            raise RuntimeError("temporary channel failure")

    dispatcher = NotificationDispatcher(
        repository,
        channels=(Channel("test", flaky_sender),),
        attempts=3,
        base_delay_seconds=0,
    )
    await dispatcher.dispatch(transition)
    await dispatcher.dispatch(transition)

    assert attempts == 3
    status = repository.notification_status(transition.incident_id)
    assert len(status) == 1
    assert status[0]["delivery_status"] == "delivered"
    assert status[0]["error_summary"] is None


@pytest.mark.asyncio
async def test_dispatch_records_bounded_failure_without_raising(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "notify-failed.sqlite3")
    manager = IncidentManager(repository, failures_to_open=1)
    transition = manager.observe(
        "https://example.com/",
        (CheckResult("https", False, 20, "https_timeout"),),
    )
    assert transition is not None
    attempts = 0

    async def failing_sender(_message: str) -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("temporary channel failure")

    dispatcher = NotificationDispatcher(
        repository,
        channels=(Channel("test", failing_sender),),
        attempts=2,
        base_delay_seconds=0,
    )
    await dispatcher.dispatch(transition)

    assert attempts == 2
    status = repository.notification_status(transition.incident_id)
    assert status[0]["delivery_status"] == "failed"
    assert status[0]["error_summary"] == "RuntimeError"


def test_invalid_notification_attempt_limit_is_rejected(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "notify-invalid.sqlite3")
    with pytest.raises(ValueError):
        NotificationDispatcher(repository, attempts=0)
