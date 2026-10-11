"""Correlate recent per-agent results using configured location types."""

from __future__ import annotations

from checks.models import CheckResult
from diagnosis.rules import Diagnosis, diagnose_locations
from storage.repository import ResultRepository


class DiagnosisCorrelator:
    """Build recent local/cloud evidence for one authorized target."""

    def __init__(self, repository: ResultRepository) -> None:
        self.repository = repository

    def diagnose(
        self,
        target_url: str,
        current_results: tuple[CheckResult, ...],
        current_location: str,
    ) -> tuple[Diagnosis | None, bool | None]:
        """Return the best evidence-based diagnosis and combined availability."""
        observations = self.repository.latest_results_by_location(target_url)
        observations[current_location] = current_results
        diagnosis = diagnose_locations(observations)
        https_outcomes = [
            checks_by_type.get("https").success
            for checks_by_type in (
                {result.check_type: result for result in results}
                for results in observations.values()
            )
            if checks_by_type.get("https") is not None
            and checks_by_type["https"].success is not None
        ]
        if not https_outcomes:
            return diagnosis, None
        return diagnosis, all(https_outcomes)
