"""Environment-based settings and safe deployment defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

load_dotenv()

def _integer(name: str, default: int, minimum: int = 1) -> int:
    value = int(os.getenv(name, str(default)))
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}.")
    return value


def _float(name: str, default: float, minimum: float = 0.1) -> float:
    value = float(os.getenv(name, str(default)))
    if value < minimum or value == float("inf") or value != value:
        raise ValueError(f"{name} must be a finite number greater than or equal to {minimum}.")
    return value


@dataclass(frozen=True)
class Settings:
    """Application configuration; secrets are read only from environment."""

    database_path: Path
    database_url: str | None
    api_token: str
    api_base_url: str
    agent_id: str
    agent_name: str
    agent_location: str
    agent_version: str
    interval_seconds: float
    dns_timeout: float
    tcp_timeout: float
    http_timeout: float
    heartbeat_interval_seconds: int
    agent_stale_after_seconds: int
    max_concurrent_checks: int
    failures_to_open_incident: int
    successes_to_resolve_incident: int
    retention_days: int
    allow_private_cloud_targets: bool
    request_rate_limit_per_minute: int
    max_request_bytes: int

    @classmethod
    def from_env(cls, require_api_token: bool = False) -> Settings:
        token = os.getenv("API_TOKEN", "")
        if require_api_token and len(token or os.getenv("AGENT_TOKEN", "")) < 32:
            raise ValueError("Set API_TOKEN or AGENT_TOKEN to a random secret of at least 32 characters.")
        location = os.getenv("AGENT_LOCATION", "local")
        if location not in {"local", "cloud"}:
            raise ValueError("AGENT_LOCATION must be either 'local' or 'cloud'.")
        return cls(
            database_path=Path(os.getenv("DATABASE_PATH", "network_doctor.sqlite3")),
            database_url=os.getenv("DATABASE_URL") or None,
            api_token=token,
            api_base_url=os.getenv("API_BASE_URL", "http://127.0.0.1:8000"),
            agent_id=os.getenv("AGENT_ID", f"network-doctor-{location}"),
            agent_name=os.getenv("AGENT_NAME", f"Network Doctor {location.title()} Agent"),
            agent_location=location,
            agent_version=os.getenv("AGENT_VERSION", "1.0.0"),
            interval_seconds=_float("MONITOR_INTERVAL_SECONDS", 10.0),
            dns_timeout=_float("DNS_TIMEOUT_SECONDS", 2.0),
            tcp_timeout=_float("TCP_TIMEOUT_SECONDS", 3.0),
            http_timeout=_float("HTTP_TIMEOUT_SECONDS", 5.0),
            heartbeat_interval_seconds=_integer("AGENT_HEARTBEAT_INTERVAL_SECONDS", 30),
            agent_stale_after_seconds=_integer("AGENT_STALE_AFTER_SECONDS", 90),
            max_concurrent_checks=_integer("MAX_CONCURRENT_CHECKS", 20),
            failures_to_open_incident=_integer("FAILURES_TO_OPEN_INCIDENT", 3),
            successes_to_resolve_incident=_integer("SUCCESSES_TO_RESOLVE_INCIDENT", 2),
            retention_days=_integer("RETENTION_DAYS", 30),
            allow_private_cloud_targets=_private_targets_allowed(),
            request_rate_limit_per_minute=_integer("API_RATE_LIMIT_PER_MINUTE", 120),
            max_request_bytes=_integer("API_MAX_REQUEST_BYTES", 1_048_576),
        )


def _private_targets_allowed() -> bool:
    allowed = os.getenv("ALLOW_PRIVATE_CLOUD_TARGETS", "").lower() in {"1", "true", "yes"}
    if allowed and os.getenv("CLOUD_PRIVATE_TARGETS_ACK") != "I understand this allows private cloud probing":
        raise ValueError(
            "Set CLOUD_PRIVATE_TARGETS_ACK to the documented phrase before allowing private cloud targets."
        )
    return allowed


def validate_api_base_url(value: str, location_type: str = "local") -> str:
    """Require TLS for non-loopback API connections."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("API_BASE_URL must be an absolute HTTP(S) URL.")
    loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not loopback:
        raise ValueError("API_BASE_URL must use HTTPS except on loopback.")
    if location_type == "cloud" and not parsed.scheme == "https":
        raise ValueError("Cloud agents must connect to the API using HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in API_BASE_URL.")
    return value.rstrip("/")
