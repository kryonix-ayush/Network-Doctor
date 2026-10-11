import pytest

from checks.models import CheckResult
from checks.runner import DiagnosticReport
from checks.url_validation import URLValidationError, redact_url_query, validate_url
from network_doctor import format_report


@pytest.mark.parametrize(
    ("value", "expected_host", "expected_port", "expected_url"),
    [
        ("https://Example.COM", "example.com", 443, "https://example.com/"),
        ("https://example.com:8443/health?full=1", "example.com", 8443, "https://example.com:8443/health?full=1"),
        ("https://[2001:db8::1]/", "2001:db8::1", 443, "https://[2001:db8::1]/"),
    ],
)
def test_validate_url_normalizes_supported_https_targets(
    value: str,
    expected_host: str,
    expected_port: int,
    expected_url: str,
) -> None:
    target = validate_url(value)
    assert target.hostname == expected_host
    assert target.port == expected_port
    assert target.url == expected_url


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example.com",
        "http://example.com",
        "https://",
        "https:///missing-host",
        "https://user:password@example.com/",
        "https://example.com:99999/",
        "https://bad host/",
        "https://example.com/#fragment",
        " https://example.com/",
    ],
)
def test_validate_url_rejects_invalid_or_unsafe_values(value: str) -> None:
    with pytest.raises(URLValidationError):
        validate_url(value)


def test_report_and_history_url_redaction_hides_query_values() -> None:
    target = validate_url("https://example.com/health?token=do-not-print")
    report = DiagnosticReport(
        target,
        (CheckResult("https", True, 1.0, status_code=200),),
    )

    assert redact_url_query(target.url) == "https://example.com/health?[redacted]"
    assert "do-not-print" not in format_report(report)
