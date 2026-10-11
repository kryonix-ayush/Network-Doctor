"""Shared result models for diagnostic checks."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Literal

CheckStatus = Literal["passed", "failed", "skipped"]


def validate_timeout(timeout: float) -> None:
    """Reject invalid timeout values before starting network work."""
    if not isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be a finite number greater than zero.")


@dataclass(frozen=True)
class CheckResult:
    """A single check outcome with timing and optional diagnostic details."""

    check_type: str
    success: bool | None
    duration_ms: float
    error_code: str | None = None
    error_message: str | None = None
    status_code: int | None = None
    addresses: tuple[str, ...] = ()

    @property
    def status(self) -> CheckStatus:
        if self.success is None:
            return "skipped"
        return "passed" if self.success else "failed"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "check_type": self.check_type,
            "status": self.status,
            "success": self.success,
            "duration_ms": round(self.duration_ms, 2),
            "error_code": self.error_code,
            "error_message": self.error_message,
            "status_code": self.status_code,
            "addresses": list(self.addresses),
        }
