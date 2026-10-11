"""Structured JSON logging configuration."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

_EXTRA_FIELDS = (
    "target_host",
    "success",
    "checks_saved",
    "target_count",
    "cycle_duration_ms",
    "interval_seconds",
)


class JSONFormatter(logging.Formatter):
    """Format only explicitly selected diagnostic fields as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        return json.dumps(payload, separators=(",", ":"))


def get_logger() -> logging.Logger:
    """Return the configured project logger."""
    logger = logging.getLogger("network_doctor")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
