"""FastAPI service for authenticated Network Doctor agents and dashboard."""

from __future__ import annotations

import logging
import secrets
import asyncio
from contextlib import asynccontextmanager
from datetime import UTC
from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from backend.auth import (
    RequestGuard,
    api_or_agent_authentication_dependency,
    agent_authentication_dependency,
    authentication_dependency,
)
from backend.schemas import Heartbeat, MonitoringSettingsPatch, ResultBatch, TargetCreate
from checks.url_validation import URLValidationError, validate_url
from checks.models import CheckResult
from config.settings import Settings
from diagnosis.incident_manager import IncidentManager, IncidentTransition
from diagnosis.correlator import DiagnosisCorrelator
from diagnosis.rules import Diagnosis
from notifications.dispatcher import NotificationDispatcher
from storage.repository import ResultRepository

logger = logging.getLogger("network_doctor.api")
settings = Settings.from_env()
repository = ResultRepository(settings.database_path, database_url=settings.database_url)
correlator = DiagnosisCorrelator(repository)
require_token = authentication_dependency(settings) if settings.api_token else None
require_agent_token = agent_authentication_dependency(settings)
require_settings_token = api_or_agent_authentication_dependency(settings)
notifier = NotificationDispatcher(repository)


def _verify_agent_identity(agent_id: str, token: str) -> None:
    from backend.auth import _agent_tokens

    configured = _agent_tokens().get(agent_id)
    if configured is None or not secrets.compare_digest(configured, token):
        raise HTTPException(status_code=401, detail="Agent credential does not match the agent ID.")


async def _notify_persisted_incident(
    incident_id: int,
    event_type: Literal["incident_opened", "incident_resolved"],
) -> None:
    incidents = await asyncio.to_thread(repository.list_incidents, 1000)
    incident = next((item for item in incidents if item["id"] == incident_id), None)
    if incident is None:
        return
    await notifier.dispatch(
        IncidentTransition(
            event_type,
            incident_id,
            incident["target_url"],
            Diagnosis(
                incident["diagnosis_code"],
                incident["summary"],
                incident["confidence"],
                tuple(incident["evidence"]),
            ),
        )
    )


async def _maintenance_loop() -> None:
    cleanup_at = 0.0
    while True:
        try:
            stale_ids = await asyncio.to_thread(
                repository.mark_stale_agents,
                settings.agent_stale_after_seconds,
            )
            if stale_ids:
                active_incidents = await asyncio.to_thread(
                    repository.list_incidents,
                    1000,
                    True,
                )
                stale_targets = {f"agent://{agent_id}" for agent_id in stale_ids}
                for incident in active_incidents:
                    if (
                        incident["diagnosis_code"] == "local_agent_stale"
                        and incident["target_url"] in stale_targets
                    ):
                        await notifier.dispatch(
                            IncidentTransition(
                                "incident_opened",
                                incident["id"],
                                incident["target_url"],
                                Diagnosis(
                                    incident["diagnosis_code"],
                                    incident["summary"],
                                    incident["confidence"],
                                    tuple(incident["evidence"]),
                                ),
                            )
                        )
            now = asyncio.get_running_loop().time()
            if now >= cleanup_at:
                removed = await asyncio.to_thread(
                    repository.retention_cleanup,
                    int(_monitoring_settings()["retention_days"]),
                )
                logger.info("retention_cleanup_completed", extra={"removed_results": removed})
                cleanup_at = now + 86400
        except Exception as exc:
            logger.error(
                "maintenance_cycle_failed",
                extra={"error_type": type(exc).__name__},
            )
        await asyncio.sleep(min(settings.heartbeat_interval_seconds, 60))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not settings.api_token or len(settings.api_token) < 32:
        raise RuntimeError("Set API_TOKEN to a random secret of at least 32 characters.")
    maintenance = asyncio.create_task(_maintenance_loop())
    try:
        yield
    finally:
        maintenance.cancel()
        try:
            await maintenance
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Network Doctor API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    RequestGuard,
    rate_limit_per_minute=settings.request_rate_limit_per_minute,
    max_request_bytes=settings.max_request_bytes,
)


def _normalize_target(url: str) -> str:
    try:
        return validate_url(url).url
    except URLValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def readiness() -> dict[str, str]:
    try:
        repository.list_targets()
    except Exception as exc:
        logger.error("readiness_database_unavailable: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Storage is unavailable.") from exc
    return {"status": "ready"}


@app.post("/api/v1/agents/heartbeat")
def heartbeat(
    payload: Heartbeat,
    background_tasks: BackgroundTasks,
    token: str = Depends(require_agent_token),
) -> dict[str, str]:
    _verify_agent_identity(payload.agent_id, token)
    resolved_incident = repository.record_heartbeat(
        payload.agent_id,
        payload.name,
        payload.location_type,
        payload.agent_version,
    )
    if resolved_incident is not None:
        background_tasks.add_task(
            _notify_persisted_incident,
            resolved_incident,
            "incident_resolved",
        )
    return {"status": "accepted"}


@app.post("/api/v1/results/batch")
def results_batch(
    payload: ResultBatch,
    background_tasks: BackgroundTasks,
    token: str = Depends(require_agent_token),
) -> dict[str, int]:
    _verify_agent_identity(payload.agent_id, token)
    normalized: list[dict[str, Any]] = []
    for item in payload.results:
        target_url = _normalize_target(item.target_url)
        target = repository.get_target_by_url(target_url)
        if target is None or not target["enabled"]:
            raise HTTPException(status_code=403, detail="Result target is not authorized.")
        record = item.model_dump()
        record["target_url"] = target_url
        record["timestamp_utc"] = item.timestamp_utc.astimezone(UTC).isoformat()
        normalized.append(record)
    inserted = repository.save_agent_results(payload.agent_id, normalized)
    location = repository.get_agent_location(payload.agent_id) or "local"
    grouped: dict[str, list[Any]] = {}
    for record in normalized:
        grouped.setdefault(record["target_url"], []).append(record)
    policy = _monitoring_settings()
    manager = IncidentManager(
        repository,
        int(policy["failures_to_open_incident"]),
        int(policy["successes_to_resolve_incident"]),
    )
    for target_url, records in grouped.items():
        check_results = tuple(
            CheckResult(
                record["check_type"],
                record["success"],
                record["duration_ms"],
                record["error_code"],
                record["error_message"],
                record["status_code"],
                tuple(record["addresses"]),
            )
            for record in records
        )
        diagnosis, combined_outcome = correlator.diagnose(
            target_url,
            check_results,
            location,
        )
        current_https = next(
            (result for result in check_results if result.check_type == "https"),
            None,
        )
        current_outcome = current_https.success if current_https is not None else None
        if current_outcome == combined_outcome and combined_outcome is not None:
            transition = manager.observe(
                target_url,
                check_results,
                counter_key=f"{target_url}|{payload.agent_id}",
                diagnosis=diagnosis,
                effective_outcome=combined_outcome,
            )
            if transition is not None:
                background_tasks.add_task(
                    _notify_persisted_incident,
                    transition.incident_id,
                    transition.event_type,
                )
    return {"accepted": len(normalized), "inserted": inserted}


@app.get("/api/v1/targets")
def list_targets(
    _token: str = Depends(require_settings_token),
) -> list[dict[str, Any]]:
    return repository.list_targets()


def _monitoring_settings() -> dict[str, Any]:
    return {
        "interval_seconds": settings.interval_seconds,
        "dns_timeout_seconds": settings.dns_timeout,
        "tcp_timeout_seconds": settings.tcp_timeout,
        "http_timeout_seconds": settings.http_timeout,
        "max_concurrent_checks": settings.max_concurrent_checks,
        "failures_to_open_incident": settings.failures_to_open_incident,
        "successes_to_resolve_incident": settings.successes_to_resolve_incident,
        "retention_days": settings.retention_days,
        **repository.get_application_settings(),
    }


@app.get("/api/v1/settings")
def get_settings(
    _token: str = Depends(require_settings_token),
) -> dict[str, Any]:
    return _monitoring_settings()


@app.patch("/api/v1/settings")
def patch_settings(
    payload: MonitoringSettingsPatch,
    _token: str = Depends(authentication_dependency(settings)),
) -> dict[str, Any]:
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="Provide at least one settings value.")
    repository.update_application_settings(updates)
    return _monitoring_settings()


@app.post("/api/v1/targets", status_code=201)
def create_target(
    payload: TargetCreate,
    _token: str = Depends(authentication_dependency(settings)),
) -> dict[str, Any]:
    normalized_url = _normalize_target(payload.url)
    target_id = repository.upsert_target(
        payload.name,
        normalized_url,
        payload.expected_status_codes,
        payload.enabled,
    )
    return next(item for item in repository.list_targets() if item["id"] == target_id)


@app.patch("/api/v1/targets/{target_id}")
def update_target(
    target_id: int,
    enabled: bool = Query(...),
    _token: str = Depends(authentication_dependency(settings)),
) -> dict[str, bool]:
    if not repository.set_target_enabled(target_id, enabled):
        raise HTTPException(status_code=404, detail="Target not found.")
    return {"updated": True, "enabled": enabled}


@app.get("/api/v1/status")
def current_status(
    _token: str = Depends(authentication_dependency(settings)),
) -> list[dict[str, Any]]:
    repository.mark_stale_agents(settings.agent_stale_after_seconds)
    return repository.recent_target_status()


@app.get("/api/v1/agents")
def agents(
    _token: str = Depends(authentication_dependency(settings)),
) -> list[dict[str, Any]]:
    repository.mark_stale_agents(settings.agent_stale_after_seconds)
    return repository.list_agents()


@app.get("/api/v1/history")
def history(
    limit: int = Query(default=500, ge=1, le=5000),
    target_url: str | None = Query(default=None, max_length=2048),
    _token: str = Depends(authentication_dependency(settings)),
) -> list[dict[str, Any]]:
    normalized = _normalize_target(target_url) if target_url else None
    return repository.get_recent(limit, normalized)


@app.get("/api/v1/incidents")
def incidents(
    limit: int = Query(default=100, ge=1, le=1000),
    active_only: bool = False,
    _token: str = Depends(authentication_dependency(settings)),
) -> list[dict[str, Any]]:
    records = repository.list_incidents(limit, active_only)
    for incident in records:
        incident["notification_status"] = repository.notification_status(incident["id"])
    return records


@app.post("/api/v1/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: int,
    _token: str = Depends(authentication_dependency(settings)),
) -> dict[str, bool]:
    if not repository.acknowledge_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"acknowledged": True}


@app.exception_handler(Exception)
async def unexpected_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled_api_error", extra={"error_type": type(exc).__name__})
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})
