"""Evidence-based diagnosis rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from checks.models import CheckResult

Confidence = Literal["low", "low_to_medium", "medium", "high"]


@dataclass(frozen=True)
class Diagnosis:
    """A likely cause with explicit evidence and confidence."""

    code: str
    summary: str
    confidence: Confidence
    evidence: tuple[str, ...]


def diagnose_results(results: tuple[CheckResult, ...]) -> Diagnosis | None:
    """Apply single-location rules without overstating the root cause."""
    checks = {result.check_type: result for result in results}
    dns = checks.get("dns")
    tcp = checks.get("tcp")
    https = checks.get("https")

    if https and https.status_code is not None and 500 <= https.status_code <= 599:
        return Diagnosis(
            "http_5xx",
            f"The HTTP service returned status {https.status_code}.",
            "high",
            (f"HTTPS returned HTTP {https.status_code}.",),
        )
    if dns and dns.success is False:
        return Diagnosis(
            "dns_failure",
            "Possible DNS resolver or hostname configuration issue.",
            "medium",
            (dns.error_message or "DNS resolution failed.",),
        )
    if https and https.error_code == "tls_error":
        return Diagnosis(
            "tls_validation_failure",
            "TLS certificate or handshake validation failed.",
            "medium",
            (https.error_message or "TLS validation failed.",),
        )
    if tcp and tcp.success is False:
        return Diagnosis(
            "tcp_connectivity_failure",
            "Possible server, firewall, route, port or local network problem.",
            "low_to_medium",
            (tcp.error_message or "TCP connection failed.",),
        )
    if https and https.success is False:
        return Diagnosis(
            "https_request_failure",
            "The HTTPS request failed; inspect connection and service evidence.",
            "low_to_medium",
            (https.error_message or "HTTPS request failed.",),
        )

    ping = checks.get("icmp_ping")
    if ping and ping.success is False and https and https.success is True:
        return Diagnosis(
            "icmp_blocked_https_available",
            "ICMP may be blocked or deprioritized while HTTPS remains available.",
            "high",
            ("ICMP failed.", "HTTPS request succeeded."),
        )
    return None


def diagnose_locations(
    observations: dict[str, tuple[CheckResult, ...]],
    unrelated_targets: tuple[str, ...] = (),
) -> Diagnosis | None:
    """Compare local/cloud observations while keeping the diagnosis qualified."""
    local = observations.get("local", ())
    cloud = observations.get("cloud", ())
    local_by_type = {result.check_type: result for result in local}
    cloud_by_type = {result.check_type: result for result in cloud}

    local_dns = local_by_type.get("dns")
    cloud_dns = cloud_by_type.get("dns")
    if local_dns and local_dns.success is False and cloud_dns and cloud_dns.success is True:
        return Diagnosis(
            "dns_local_fails_cloud_passes",
            "Possible local resolver or DNS configuration issue.",
            "medium",
            ("Local DNS failed.", "Cloud DNS succeeded."),
        )

    local_https = local_by_type.get("https")
    cloud_https = cloud_by_type.get("https")
    if local_https and local_https.success is False and cloud_https and cloud_https.success is True:
        if unrelated_targets:
            return Diagnosis(
                "local_multiple_targets_fail_cloud_passes",
                "Possible local connectivity, local DNS, gateway or ISP issue.",
                "medium",
                (
                    f"Local HTTPS failed for this target and {len(unrelated_targets)} unrelated target(s).",
                    "Cloud HTTPS passed.",
                ),
            )
    if local_https and local_https.success is False and cloud_https and cloud_https.success is False:
        return Diagnosis(
            "same_target_fails_both_locations",
            "Possible target-specific outage, service issue, access policy or shared upstream issue.",
            "medium",
            ("Local HTTPS failed.", "Cloud HTTPS failed."),
        )
    return diagnose_results(local)


def elevated_response_time(
    duration_ms: float,
    threshold_ms: float,
) -> Diagnosis | None:
    """Report a configured response-time threshold breach."""
    if duration_ms <= threshold_ms:
        return None
    return Diagnosis(
        "response_time_elevated",
        "Response time exceeded the configured threshold.",
        "medium",
        (f"Measured {duration_ms:.1f} ms; configured threshold {threshold_ms:.1f} ms.",),
    )
