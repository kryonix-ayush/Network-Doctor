from __future__ import annotations

from ui_addon.services.api_client import UIAPIClient
from ui_addon.services.result_adapter import (
    incident_issue_rows,
    recommendations_for_target,
    status_metrics,
)


def test_ui_api_client_rejects_insecure_urls() -> None:
    try:
        UIAPIClient("http://localhost.attacker.example", "a-very-long-secret-token-123456")
    except ValueError:
        return
    raise AssertionError("Expected insecure URL validation to fail.")


def test_status_metrics_count_healthy_and_failed_targets() -> None:
    metrics = status_metrics([
        {"status": "healthy"},
        {"status": "down"},
        {"status": "unknown"},
    ])
    assert metrics == {"healthy": 1, "failing": 1, "unknown": 1}


def test_incident_rows_are_normalized() -> None:
    rows = incident_issue_rows([
        {
            "target_url": "https://example.com/",
            "diagnosis_code": "dns_failure",
            "summary": "Possible DNS resolver or hostname configuration issue.",
            "confidence": "medium",
            "status": "open",
            "evidence": ["DNS resolution failed."],
        }
    ])
    assert rows[0]["target"] == "https://example.com/"
    assert rows[0]["diagnosis_code"] == "dns_failure"


def test_recommendations_for_target_are_read_only() -> None:
    target = {
        "url": "https://example.com/",
        "observations": {
            "local": {
                "dns": {"success": False, "duration_ms": 50, "error_message": "dns_timeout"},
            },
            "cloud": {
                "dns": {"success": True, "duration_ms": 10, "addresses": ["203.0.113.1"]},
            },
        },
    }
    recommendations = recommendations_for_target(target)
    assert recommendations
    assert recommendations[0]["id"] == "dns_local_fails_cloud_passes"
    assert recommendations[0]["automatic_action"] is False
    assert recommendations[0]["requires_admin"] is True
