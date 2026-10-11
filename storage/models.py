"""Persistence-facing domain models."""

from __future__ import annotations

from dataclasses import dataclass

from checks.models import CheckResult


@dataclass(frozen=True)
class StoredReport:
    """A target report tagged with its monitoring agent."""

    target_url: str
    agent_id: str
    results: tuple[CheckResult, ...]
