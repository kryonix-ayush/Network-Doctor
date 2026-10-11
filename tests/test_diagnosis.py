from checks.models import CheckResult
from diagnosis.incident_manager import IncidentManager
from diagnosis.remediation import recommend_solutions
from diagnosis.rules import diagnose_locations, diagnose_results
from storage.repository import ResultRepository


def test_http_5xx_diagnosis_reports_server_response_not_root_cause() -> None:
    diagnosis = diagnose_results((CheckResult("https", False, 20, status_code=503),))
    assert diagnosis is not None
    assert diagnosis.code == "http_5xx"
    assert diagnosis.confidence == "high"
    assert "ultimate" not in diagnosis.summary


def test_ping_failure_alone_does_not_report_target_down() -> None:
    assert diagnose_results((CheckResult("icmp_ping", False, 10, "timeout"),)) is None


def test_ping_failure_with_https_success_is_likely_filtered_icmp() -> None:
    diagnosis = diagnose_results(
        (
            CheckResult("icmp_ping", False, 10, "timeout"),
            CheckResult("https", True, 30, status_code=200),
        )
    )
    assert diagnosis is not None
    assert diagnosis.code == "icmp_blocked_https_available"
    assert diagnosis.confidence == "high"


def test_correlates_local_dns_failure_with_cloud_success() -> None:
    diagnosis = diagnose_locations(
        {
            "local": (CheckResult("dns", False, 10, "dns_timeout"),),
            "cloud": (CheckResult("dns", True, 10, addresses=("203.0.113.1",)),),
        }
    )
    assert diagnosis is not None
    assert diagnosis.code == "dns_local_fails_cloud_passes"
    assert diagnosis.confidence == "medium"


def test_incident_opens_once_and_resolves_after_recovery(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "incidents.sqlite3")
    manager = IncidentManager(repository, failures_to_open=3, successes_to_resolve=2)
    target = "https://example.com/"
    failed = (CheckResult("https", False, 100, "https_timeout"),)
    passed = (CheckResult("https", True, 80, status_code=200),)

    assert manager.observe(target, failed) is None
    assert manager.observe(target, failed) is None
    opened = manager.observe(target, failed)
    assert opened is not None and opened.event_type == "incident_opened"
    assert manager.observe(target, failed) is None
    assert len(repository.list_incidents()) == 1

    assert manager.observe(target, passed) is None
    resolved = manager.observe(target, passed)
    assert resolved is not None and resolved.event_type == "incident_resolved"
    incidents = repository.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["status"] == "resolved"
    assert incidents[0]["resolved_at"] is not None


def test_failure_and_recovery_counters_reset_on_opposite_observation(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "counters.sqlite3")
    manager = IncidentManager(repository, failures_to_open=2, successes_to_resolve=2)
    target = "https://example.com/"
    failed = (CheckResult("https", False, 100, "https_timeout"),)
    passed = (CheckResult("https", True, 80, status_code=200),)

    manager.observe(target, failed)
    manager.observe(target, passed)
    assert manager.observe(target, failed) is None
    assert repository.list_incidents() == []


def test_notification_claim_is_deduplicated_by_transition_and_channel(tmp_path) -> None:
    repository = ResultRepository(tmp_path / "notifications.sqlite3")
    incident_id = repository.open_incident(
        "https://example.com/",
        diagnose_results((CheckResult("https", False, 10, "https_timeout"),)),
    )
    assert repository.claim_notification(incident_id, "incident_opened", "telegram")
    assert not repository.claim_notification(incident_id, "incident_opened", "telegram")
    assert repository.claim_notification(incident_id, "incident_opened", "email")


def test_recommendations_for_dns_failure_are_evidence_based() -> None:
    recommendations = recommend_solutions((CheckResult("dns", False, 20, "dns_timeout"),))
    assert recommendations
    assert recommendations[0]["id"] == "dns_failure"
    assert recommendations[0]["source_check"] == "dns"
    assert recommendations[0]["automatic_action"] is False
    assert "Compare resolution from the local and cloud agents" in recommendations[0]["steps"][1]


def test_recommendations_for_icmp_filtered_state_are_low_risk() -> None:
    recommendations = recommend_solutions(
        (
            CheckResult("icmp_ping", False, 10, "timeout"),
            CheckResult("https", True, 30, status_code=200),
        )
    )
    assert recommendations
    assert recommendations[0]["id"] == "icmp_blocked_https_available"
    assert recommendations[0]["priority"] == "low"
    assert recommendations[0]["risk"].startswith("Low")


def test_recommendations_for_agent_stale_are_actionable_but_non_destructive() -> None:
    recommendations = recommend_solutions({"local": (CheckResult("agent_heartbeat", False, 0, "stale"),)})
    assert recommendations
    assert recommendations[0]["id"] == "insufficient_evidence"
    assert recommendations[0]["source_check"] == "unknown"
    assert recommendations[0]["automatic_action"] is False


def test_recommendations_for_local_cloud_dns_disagreement() -> None:
    recommendations = recommend_solutions(
        {
            "local": (CheckResult("dns", False, 12, "dns_timeout"),),
            "cloud": (CheckResult("dns", True, 10, addresses=("203.0.113.1",)),),
        }
    )
    assert recommendations
    assert recommendations[0]["id"] == "dns_local_fails_cloud_passes"
    assert recommendations[0]["requires_admin"] is True
    assert "local DNS" in recommendations[0]["title"]


def test_recommendations_ignore_unsafe_manual_remediation() -> None:
    recommendations = recommend_solutions((CheckResult("https", False, 25, "tls_error"),))
    assert recommendations
    assert all(not item["automatic_action"] for item in recommendations)
    text = " ".join(" ".join(item["steps"]).lower() for item in recommendations)
    assert "disable certificate validation" in text
    assert "hostname checks" in text
