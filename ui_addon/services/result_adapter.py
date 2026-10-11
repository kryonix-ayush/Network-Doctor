"""Adapt Network Doctor API results for a separate UI addon."""

from __future__ import annotations

from typing import Any

from checks.url_validation import redact_url_query
from diagnosis.remediation import recommend_solutions


def status_metrics(status: list[dict[str, Any]]) -> dict[str, int]:
    metrics = {"healthy": 0, "failing": 0, "unknown": 0}
    for target in status or []:
        summary = str(target.get("status") or "unknown").lower()
        if summary in {"up", "healthy", "ok", "pass"}:
            metrics["healthy"] += 1
        elif summary in {"down", "failed", "failing", "error"}:
            metrics["failing"] += 1
        else:
            metrics["unknown"] += 1
    return metrics


def observed_target_rows(status: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in status or []:
        name = target.get("name") or target.get("url") or "Unknown target"
        observations = target.get("observations") or {}
        rows.append(
            {
                "name": name,
                "url": redact_url_query(str(target.get("url") or "")),
                "status": str(target.get("status") or "unknown"),
                "local": _status_from_observations(observations.get("local")),
                "cloud": _status_from_observations(observations.get("cloud")),
                "observations": observations,
                "latest_timestamp": target.get("latest_check_at") or target.get("last_seen_at"),
            }
        )
    return rows


def _status_from_observations(observations: Any) -> str:
    if not isinstance(observations, dict):
        return "unknown"
    for result in observations.values():
        if isinstance(result, dict) and result.get("success") is False:
            return "failing"
        if isinstance(result, dict) and result.get("success") is True:
            return "healthy"
    return "unknown"


def incident_issue_rows(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for incident in incidents or []:
        rows.append(
            {
                "target": incident.get("target_url") or "unknown",
                "diagnosis_code": incident.get("diagnosis_code") or "unknown",
                "summary": incident.get("summary") or "No diagnosis summary available.",
                "confidence": incident.get("confidence") or "low",
                "status": incident.get("status") or "open",
                "updated_at": incident.get("updated_at") or incident.get("last_seen_at"),
                "evidence": incident.get("evidence") or [],
            }
        )
    return rows


def recommendations_for_target(target: dict[str, Any]) -> list[dict[str, Any]]:
    observations = target.get("observations") or {}
    if not observations:
        return []
    normalized: dict[str, tuple[Any, ...]] = {}
    for location, values in observations.items():
        if not isinstance(values, dict):
            continue
        checks: list[Any] = []
        for check_type, result in values.items():
            if isinstance(result, dict):
                checks.append({**result, "check_type": check_type})
            else:
                checks.append(result)
        normalized[str(location)] = tuple(checks)
    if not normalized:
        return []
    return recommend_solutions(normalized)


def history_rows(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in history or []:
        rows.append(
            {
                "target_url": row.get("target_url") or "unknown",
                "check_type": row.get("check_type") or "unknown",
                "success": row.get("success"),
                "duration_ms": row.get("duration_ms"),
                "status_code": row.get("status_code"),
                "timestamp_utc": row.get("timestamp_utc") or row.get("checked_at"),
            }
        )
    return rows
