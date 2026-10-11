import time
import json

import httpx
import pytest

from agents.outbox import AgentOutbox
from checks.models import CheckResult
from checks.runner import DiagnosticReport
from checks.url_validation import validate_url
from storage.repository import ResultRepository


def _report() -> DiagnosticReport:
    return DiagnosticReport(
        validate_url("https://example.com/"),
        (CheckResult("https", True, 12, status_code=200),),
    )


@pytest.mark.asyncio
async def test_outbox_delivers_then_removes_with_stable_result_id(tmp_path) -> None:
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"accepted": 1, "inserted": 1})

    repository = ResultRepository(tmp_path / "outbox.sqlite3")
    outbox = AgentOutbox(
        repository,
        "http://127.0.0.1:8000",
        "agent-token",
        "local-test",
        "Local test",
        "local",
        "1.0.0",
        transport=httpx.MockTransport(handler),
    )
    await outbox.enqueue_report(_report())
    await outbox.flush()

    assert repository.outbox_size() == 0
    assert requests[0].headers["Authorization"] == "Bearer agent-token"
    posted = requests[0].read()
    payload = json.loads(posted)
    assert payload["agent_id"] == "local-test"
    assert payload["results"][0]["result_id"]
    assert payload["results"][0]["check_type"] == "https"
    assert "status" not in payload["results"][0]


@pytest.mark.asyncio
async def test_outbox_defers_transient_failure_and_retries_same_id(tmp_path) -> None:
    result_ids = []
    fail = True

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal fail
        payload = json.loads(request.content)
        result_ids.append(payload["results"][0]["result_id"])
        if fail:
            return httpx.Response(503)
        return httpx.Response(200, json={"accepted": 1, "inserted": 1})

    repository = ResultRepository(tmp_path / "retry.sqlite3")
    outbox = AgentOutbox(
        repository,
        "http://127.0.0.1:8000",
        "agent-token",
        "local-test",
        "Local test",
        "local",
        "1.0.0",
        transport=httpx.MockTransport(handler),
        retry_base_seconds=0,
    )
    await outbox.enqueue_report(_report())
    if outbox._flush_task is not None:
        await outbox._flush_task
    assert repository.outbox_size() == 1
    due = repository.outbox_due(time.time() + 100, 10)
    assert due[0]["attempt_count"] == 1
    fail = False
    await outbox.flush()
    assert result_ids[0] == result_ids[1]
    assert repository.outbox_size() == 0
