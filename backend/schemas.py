"""Strict API request and response schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

CheckType = Literal["dns", "tcp", "https", "tls_certificate", "icmp_ping"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Heartbeat(StrictModel):
    agent_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    name: str = Field(min_length=1, max_length=128)
    location_type: Literal["local", "cloud"]
    agent_version: str = Field(min_length=1, max_length=32)


class TargetCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=2048)
    expected_status_codes: list[int] = Field(default_factory=lambda: [200, 201, 202, 204, 301, 302, 304], min_length=1, max_length=20)
    enabled: bool = True

    @field_validator("expected_status_codes")
    @classmethod
    def valid_status_codes(cls, values: list[int]) -> list[int]:
        if any(code < 100 or code > 599 for code in values):
            raise ValueError("Status codes must be between 100 and 599.")
        return list(dict.fromkeys(values))


class ResultItem(StrictModel):
    result_id: str = Field(min_length=1, max_length=128)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_url: str = Field(min_length=1, max_length=2048)
    check_type: CheckType
    success: bool | None
    duration_ms: float = Field(ge=0, le=3_600_000)
    status_code: int | None = Field(default=None, ge=100, le=599)
    error_code: str | None = Field(default=None, max_length=128)
    error_message: str | None = Field(default=None, max_length=2048)
    addresses: list[str] = Field(default_factory=list, max_length=32)


class ResultBatch(StrictModel):
    agent_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    results: list[ResultItem] = Field(min_length=1, max_length=500)


class MonitoringSettingsPatch(StrictModel):
    interval_seconds: float | None = Field(default=None, ge=1, le=3600)
    dns_timeout_seconds: float | None = Field(default=None, ge=0.1, le=120)
    tcp_timeout_seconds: float | None = Field(default=None, ge=0.1, le=120)
    http_timeout_seconds: float | None = Field(default=None, ge=0.1, le=120)
    max_concurrent_checks: int | None = Field(default=None, ge=1, le=1000)
    failures_to_open_incident: int | None = Field(default=None, ge=1, le=100)
    successes_to_resolve_incident: int | None = Field(default=None, ge=1, le=100)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
