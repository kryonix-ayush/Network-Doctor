"""Durable local result delivery and agent heartbeat client."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Coroutine
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import httpx

from checks.runner import DiagnosticReport
from checks.url_validation import redact_url_query
from config.settings import validate_api_base_url
from storage.repository import ResultRepository


class AgentOutbox:
    """Queue local results before attempting authenticated cloud delivery."""

    def __init__(
        self,
        repository: ResultRepository,
        api_base_url: str,
        agent_token: str,
        agent_id: str,
        agent_name: str,
        location_type: str,
        agent_version: str,
        logger: logging.Logger | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_base_seconds: float = 2.0,
    ) -> None:
        self.repository = repository
        self.api_base_url = validate_api_base_url(api_base_url, location_type)
        self.agent_token = agent_token
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.location_type = location_type
        self.agent_version = agent_version
        self.logger = logger or logging.getLogger("network_doctor.agent")
        self.transport = transport
        self.maximum_attempts = 8
        if retry_base_seconds < 0:
            raise ValueError("retry_base_seconds cannot be negative.")
        self.retry_base_seconds = retry_base_seconds
        self._last_heartbeat = 0.0
        self._flush_lock = asyncio.Lock()
        self._flush_task: asyncio.Task[int] | None = None

    async def enqueue_report(self, report: DiagnosticReport) -> None:
        """Durably enqueue all check results, then opportunistically deliver."""
        timestamp = datetime.now(UTC).isoformat()
        for result in report.results:
            await asyncio.to_thread(
                self.repository.enqueue_result,
                self.agent_id,
                {
                    "result_id": self.repository.new_result_id(),
                    "timestamp_utc": timestamp,
                    "target_url": report.target.url,
                    "check_type": result.check_type,
                    "success": result.success,
                    "duration_ms": result.duration_ms,
                    "status_code": result.status_code,
                    "error_code": result.error_code,
                    "error_message": result.error_message,
                    "addresses": list(result.addresses),
                },
            )
        if self.agent_token and (
            self._flush_task is None or self._flush_task.done()
        ):
            self._flush_task = asyncio.create_task(self._flush_pending())
            self._flush_task.add_done_callback(self._log_background_failure)

    async def heartbeat_if_due(self, interval_seconds: int = 30) -> None:
        """Send a heartbeat at the configured cadence without blocking checks."""
        if not self.agent_token:
            return
        now = time.monotonic()
        if now - self._last_heartbeat < interval_seconds:
            return
        self._last_heartbeat = now
        self._spawn(self._send_heartbeat())

    async def _send_heartbeat(self) -> None:
        try:
            async with httpx.AsyncClient(
                timeout=1.0,
                transport=self.transport,
                verify=True,
            ) as client:
                response = await client.post(
                    f"{self.api_base_url}/api/v1/agents/heartbeat",
                    headers={"Authorization": f"Bearer {self.agent_token}"},
                    json={
                        "agent_id": self.agent_id,
                        "name": self.agent_name,
                        "location_type": self.location_type,
                        "agent_version": self.agent_version,
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.logger.warning(
                "agent_heartbeat_delivery_failed",
                extra={"error_type": type(exc).__name__},
            )

    async def flush(self, batch_size: int = 100) -> int:
        """Retry due results with exponential backoff and stable idempotency keys."""
        if not self.agent_token:
            return 0
        async with self._flush_lock:
            return await self._flush_due(batch_size)

    async def _flush_due(self, batch_size: int) -> int:
        due = await asyncio.to_thread(self.repository.outbox_due, time.time(), batch_size)
        due = [item for item in due if item["attempt_count"] < self.maximum_attempts]
        if not due:
            await asyncio.to_thread(
                self.repository.discard_exhausted_outbox,
                self.maximum_attempts,
            )
            return 0

        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in due:
            grouped.setdefault(record["agent_id"], []).append(record)
        accepted_count = 0
        async with httpx.AsyncClient(
            timeout=1.0,
            transport=self.transport,
            verify=True,
        ) as client:
            for agent_id, records in grouped.items():
                result_ids = [record["result_id"] for record in records]
                try:
                    response = await client.post(
                        f"{self.api_base_url}/api/v1/results/batch",
                        headers={"Authorization": f"Bearer {self.agent_token}"},
                        json={
                            "agent_id": agent_id,
                            "results": [record["payload"] for record in records],
                        },
                    )
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    attempt = max(record["attempt_count"] for record in records) + 1
                    delay = min(300.0, self.retry_base_seconds * 2 ** min(attempt - 1, 8))
                    await asyncio.to_thread(
                        self.repository.defer_outbox,
                        result_ids,
                        time.time() + delay,
                        type(exc).__name__,
                    )
                    self.logger.warning(
                        "result_delivery_deferred",
                        extra={"pending_count": len(records), "error_type": type(exc).__name__},
                    )
                else:
                    await asyncio.to_thread(self.repository.remove_outbox, result_ids)
                    accepted_count += len(records)
        await asyncio.to_thread(
            self.repository.discard_exhausted_outbox,
            self.maximum_attempts,
        )
        return accepted_count

    async def _flush_pending(self) -> int:
        delivered = 0
        while count := await self.flush():
            delivered += count
        return delivered

    async def fetch_settings(self) -> Mapping[str, Any] | None:
        """Fetch authenticated monitoring settings; keep current settings on outage."""
        if not self.agent_token:
            return None
        try:
            async with httpx.AsyncClient(
                timeout=1.0,
                transport=self.transport,
                verify=True,
            ) as client:
                response = await client.get(
                    f"{self.api_base_url}/api/v1/settings",
                    headers={"Authorization": f"Bearer {self.agent_token}"},
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            self.logger.warning(
                "monitoring_settings_unavailable_using_current_values",
                extra={"error_type": type(exc).__name__},
            )
            return None
        if not isinstance(payload, dict):
            raise ValueError("The API returned an invalid monitoring settings object.")
        return payload

    def _spawn(self, coroutine: Coroutine[Any, Any, Any]) -> None:
        task = asyncio.create_task(coroutine)
        task.add_done_callback(self._log_background_failure)

    def _log_background_failure(self, task: asyncio.Task[Any]) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            self.logger.error(
                "agent_delivery_task_failed",
                extra={"error_type": type(error).__name__},
            )

    def pending_summary(self) -> str:
        """Return a concise, target-query-safe outbox status."""
        return f"{self.repository.outbox_size()} result(s) pending for {self.agent_id}"


def safe_report_url(report: DiagnosticReport) -> str:
    """Expose a query-redacted target URL for logs and CLI output."""
    return redact_url_query(report.target.url)
