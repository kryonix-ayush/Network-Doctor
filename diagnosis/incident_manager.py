"""Consecutive-failure incident lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from checks.models import CheckResult
from diagnosis.rules import Diagnosis, diagnose_results
from storage.repository import ResultRepository

IncidentStatus = Literal["open", "resolved"]


@dataclass(frozen=True)
class IncidentTransition:
    """Incident state change emitted once when a threshold is crossed."""

    event_type: Literal["incident_opened", "incident_resolved"]
    incident_id: int
    target_url: str
    diagnosis: Diagnosis | None


class IncidentManager:
    """Track consecutive availability outcomes and persist incident transitions."""

    def __init__(
        self,
        repository: ResultRepository,
        failures_to_open: int = 3,
        successes_to_resolve: int = 2,
    ) -> None:
        if failures_to_open < 1 or successes_to_resolve < 1:
            raise ValueError("Incident thresholds must be positive integers.")
        self.repository = repository
        self.failures_to_open = failures_to_open
        self.successes_to_resolve = successes_to_resolve

    def observe(
        self,
        target_url: str,
        results: tuple[CheckResult, ...],
        counter_key: str | None = None,
        diagnosis: Diagnosis | None = None,
        effective_outcome: bool | None = None,
    ) -> IncidentTransition | None:
        """Record a cycle and emit an incident transition only at a threshold."""
        outcome = effective_outcome
        if outcome is None:
            outcome = _availability_outcome(results)
        if outcome is None:
            return None

        counter_key = counter_key or target_url
        self.repository.record_observation(counter_key, outcome)
        state = self.repository.get_incident_state(counter_key)
        active = self.repository.get_active_incident(target_url)

        if outcome is False and active is None:
            if state["failure_count"] >= self.failures_to_open:
                inferred_diagnosis = diagnosis or diagnose_results(results)
                incident_id = self.repository.open_incident(
                    target_url,
                    inferred_diagnosis or Diagnosis(
                        "repeated_check_failures",
                        "Repeated monitoring checks failed.",
                        "low",
                        ("The configured consecutive-failure threshold was reached.",),
                    ),
                )
                return IncidentTransition(
                    "incident_opened",
                    incident_id,
                    target_url,
                    inferred_diagnosis,
                )

        if outcome is True and active is not None:
            if state["success_count"] >= self.successes_to_resolve:
                self.repository.resolve_incident(active["id"])
                return IncidentTransition(
                    "incident_resolved",
                    active["id"],
                    target_url,
                    Diagnosis(
                        active["diagnosis_code"],
                        active["summary"],
                        active["confidence"],
                        tuple(active["evidence"]),
                    ),
                )
        return None


def _availability_outcome(results: tuple[CheckResult, ...]) -> bool | None:
    checks = {result.check_type: result for result in results}
    https = checks.get("https")
    if https is not None and https.success is not None:
        return https.success
    tcp = checks.get("tcp")
    if tcp is not None and tcp.success is not None:
        return tcp.success
    return None
