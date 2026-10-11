"""Evidence-based troubleshooting recommendations for diagnostic outcomes."""

from __future__ import annotations

from typing import Any

from checks.models import CheckResult
from diagnosis.rules import Diagnosis, diagnose_locations, diagnose_results


def _coerce_check_result(value: Any, default_check_type: str | None = None) -> CheckResult:
    if isinstance(value, CheckResult):
        return value
    if not isinstance(value, dict):
        raise TypeError(f"Unsupported diagnostic value: {type(value)!r}")
    check_type = str(value.get("check_type") or default_check_type or "unknown")
    addresses = value.get("addresses") or ()
    return CheckResult(
        check_type,
        value.get("success"),
        float(value.get("duration_ms") or 0.0),
        value.get("error_code"),
        value.get("error_message"),
        value.get("status_code"),
        tuple(addresses),
    )


def _coerce_results(diagnostic_result: Any) -> tuple[CheckResult, ...]:
    if isinstance(diagnostic_result, tuple):
        return tuple(_coerce_check_result(item) for item in diagnostic_result)
    if isinstance(diagnostic_result, list):
        return tuple(_coerce_check_result(item) for item in diagnostic_result)
    if isinstance(diagnostic_result, dict):
        if not diagnostic_result:
            return ()
        if all(isinstance(value, dict) for value in diagnostic_result.values()):
            normalized: list[CheckResult] = []
            for check_type, checks in diagnostic_result.items():
                if isinstance(checks, dict):
                    normalized.extend(
                        _coerce_check_result(item, default_check_type=check_type)
                        for item in checks.values()
                    )
            return tuple(normalized)
        if all(isinstance(value, (tuple, list)) for value in diagnostic_result.values()):
            normalized = []
            for values in diagnostic_result.values():
                normalized.extend(_coerce_check_result(item) for item in values)
            return tuple(normalized)
        return tuple(_coerce_check_result(value) for value in diagnostic_result.values())
    return ()


def _coerce_diagnosis(diagnosis: Diagnosis | dict[str, Any] | None) -> Diagnosis | None:
    if diagnosis is None:
        return None
    if isinstance(diagnosis, Diagnosis):
        return diagnosis
    if isinstance(diagnosis, dict):
        evidence = tuple(diagnosis.get("evidence") or ())
        return Diagnosis(
            str(diagnosis.get("code") or "unknown"),
            str(diagnosis.get("summary") or "Diagnosis unavailable."),
            str(diagnosis.get("confidence") or "low"),
            evidence,
        )
    return None


def _builder(
    *,
    diagnosis_code: str,
    title: str,
    reason: str,
    evidence: tuple[str, ...],
    steps: list[str],
    verification: str,
    source_check: str,
    priority: str = "medium",
    confidence: str = "medium",
    requires_admin: bool = False,
    risk: str = "Low - no automatic change is made.",
) -> dict[str, Any]:
    return {
        "id": diagnosis_code,
        "title": title,
        "priority": priority,
        "confidence": confidence,
        "reason": reason,
        "evidence": list(evidence),
        "steps": steps,
        "verification": verification,
        "requires_admin": requires_admin,
        "risk": risk,
        "automatic_action": False,
        "source_check": source_check,
    }


def recommend_solutions(diagnostic_result: Any, diagnosis: Diagnosis | dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return evidence-based, read-only troubleshooting steps for a diagnosis."""
    if diagnosis is not None:
        diagnosis_obj = _coerce_diagnosis(diagnosis)
    else:
        normalized = _coerce_results(diagnostic_result)
        diagnosis_obj = diagnose_results(normalized)
        if diagnosis_obj is None and isinstance(diagnostic_result, dict):
            location_results = {}
            for location, checks in diagnostic_result.items():
                if isinstance(checks, dict):
                    location_results[str(location)] = tuple(
                        _coerce_check_result(item, default_check_type=check_type)
                        for check_type, item in checks.items()
                    )
                elif isinstance(checks, (tuple, list)):
                    location_results[str(location)] = tuple(
                        _coerce_check_result(item) for item in checks
                    )
            if location_results:
                diagnosis_obj = diagnose_locations(location_results)
    if diagnosis_obj is None:
        return [
            _builder(
                diagnosis_code="insufficient_evidence",
                title="Collect additional diagnostic evidence",
                reason=(
                    "The current observations do not support a confident configuration change. "
                    "A single failed check is not enough to infer the root cause."
                ),
                evidence=(
                    "No diagnosis could be determined from the currently available results.",
                    "The first failing stage and the last successful measurement are still unknown.",
                ),
                steps=[
                    "Confirm which stage failed first: DNS, TCP, TLS, or HTTPS.",
                    "Compare results from the local and cloud agents for the same target.",
                    "Repeat the check after a short interval to distinguish a transient issue from a persistent problem.",
                    "Capture the exact status code, timeout, or error message before making any service or network change.",
                ],
                verification=(
                    "Hold off on configuration changes until the first failing stage and the relevant evidence are narrowed to one clear path."
                ),
                source_check="unknown",
                priority="medium",
                confidence="low",
                risk="Low - no changes are recommended without specific evidence.",
            )
        ]

    code = diagnosis_obj.code
    evidence = tuple(diagnosis_obj.evidence)
    confidence = diagnosis_obj.confidence
    if code == "dns_failure":
        return [
            _builder(
                diagnosis_code=code,
                title="Verify hostname and DNS configuration",
                reason=(
                    "The DNS check failed from the agent's current vantage point. "
                    "This is evidence of a hostname or resolver issue, but it does not prove the target server is down."
                ),
                evidence=evidence,
                steps=[
                    "Check the hostname for typos and confirm the domain is intended to exist.",
                    "Compare resolution from the local and cloud agents before making any change.",
                    "Review the configured DNS resolver and whether other known domains resolve correctly.",
                    "If the domain was recently updated, verify the authoritative DNS records and allow for propagation time where appropriate.",
                ],
                verification=(
                    "A DNS issue is resolved when the hostname resolves consistently from the monitored vantage points and the service endpoint is reachable."
                ),
                source_check="dns",
                priority="high",
                confidence=confidence,
                requires_admin=False,
                risk="Low - read-only checks are preferred before any DNS change is approved.",
            )
        ]
    if code == "dns_local_fails_cloud_passes":
        return [
            _builder(
                diagnosis_code=code,
                title="Check local DNS and network path",
                reason=(
                    "The local agent could not resolve the hostname while the cloud agent succeeded. "
                    "This points to a local resolver, VPN, or outbound path problem rather than a confirmed target outage."
                ),
                evidence=evidence,
                steps=[
                    "Compare local DNS results with cloud DNS results for the same target and hostname.",
                    "Check local network connectivity and whether other known destinations resolve correctly.",
                    "Review VPN, proxy, endpoint security policy, and local firewall settings that could affect the local agent.",
                    "Test from another authorized device on the same local network to narrow the scope of the issue.",
                ],
                verification=(
                    "The local-only issue is narrowed and resolved when the local agent and cloud agent both resolve the hostname and reach the same endpoint."
                ),
                source_check="dns",
                priority="medium",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - local firewall, VPN, or proxy policies may require admin review.",
            )
        ]
    if code == "tcp_connectivity_failure":
        return [
            _builder(
                diagnosis_code=code,
                title="Confirm the target host and port are reachable",
                reason=(
                    "The TCP connection failed or timed out. This is consistent with an unreachable, filtered, or non-listening destination port and does not by itself prove the service is offline."
                ),
                evidence=evidence,
                steps=[
                    "Confirm the target host and HTTPS port are correct; for HTTPS this is typically 443.",
                    "Check whether the service is running and listening on the destination server if the operator administers it.",
                    "Review host firewall, cloud security-group, router, and outbound network rules for the specific destination and port.",
                    "Compare local and cloud TCP results to determine whether the issue is vantage-point-specific.",
                ],
                verification=(
                    "TCP connectivity is corrected only when the expected port accepts connections consistently from the required monitoring location."
                ),
                source_check="tcp",
                priority="high",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - firewall or service rules may need an admin approval before change.",
            )
        ]
    if code == "tls_validation_failure":
        return [
            _builder(
                diagnosis_code=code,
                title="Inspect the certificate chain and hostname validity",
                reason=(
                    "The TLS handshake or certificate verification failed. This supports a certificate, hostname, or trust-chain problem; it does not justify disabling verification."
                ),
                evidence=evidence,
                steps=[
                    "Inspect certificate validity dates and confirm the certificate matches the expected hostname and SAN entries.",
                    "Verify the server presents the complete certificate chain and any required intermediate certificates.",
                    "Do not disable certificate validation, skip hostname checks, or bypass trust checks to hide the error.",
                    "Renew or correctly install the certificate through the authorized hosting or certificate-management process if the evidence confirms a certificate problem.",
                    "Check system clock accuracy if the certificate appears expired or not yet valid despite a correct installation.",
                ],
                verification=(
                    "The TLS issue is fixed only after one clean certificate validation runs successfully and the certificate chain matches the configured host."
                ),
                source_check="tls_certificate",
                priority="high",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - certificate changes affect service trust and may require production approval.",
            )
        ]
    if code in {"http_5xx", "https_request_failure"}:
        return [
            _builder(
                diagnosis_code=code,
                title="Review application and proxy health",
                reason=(
                    "The HTTPS request failed or returned an unexpected server-side status. "
                    "This suggests the service or reverse proxy may be unhealthy or rejecting requests, but it is still important to verify the expected status behavior before concluding the failure is persistent."
                ),
                evidence=evidence,
                steps=[
                    "Check whether the service and reverse proxy are healthy at the measured time.",
                    "Review application and proxy logs for the relevant timestamp and recent HTTP errors.",
                    "Compare the observed status code with the target's configured expected HTTP status codes.",
                    "Check latency trends and repeat the request before concluding the issue is persistent.",
                    "If a redirect is expected, inspect the configured endpoint manually because the diagnostic does not follow redirects.",
                ],
                verification=(
                    "The endpoint is considered healthy when repeated checks show the expected status code and the response completes within the configured threshold."
                ),
                source_check="https",
                priority="high",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - application or proxy changes are not automatic and require operator approval.",
            )
        ]
    if code == "icmp_blocked_https_available":
        return [
            _builder(
                diagnosis_code=code,
                title="Treat ICMP as a secondary signal",
                reason=(
                    "ICMP failed while HTTPS succeeded. This is consistent with filtered ICMP and does not by itself indicate an HTTPS outage."
                ),
                evidence=evidence,
                steps=[
                    "Treat HTTPS availability as the primary availability signal for this target.",
                    "Only investigate ICMP policy if ping visibility is explicitly required by the operator or monitoring goal.",
                    "Compare current performance and error evidence before making a network or firewall change.",
                ],
                verification=(
                    "No issue is reported when HTTPS continues to succeed and the operator confirms ICMP is intentionally filtered or not required."
                ),
                source_check="icmp_ping",
                priority="low",
                confidence=confidence,
                requires_admin=False,
                risk="Low - no change to production network policy is recommended without a specific operational requirement.",
            )
        ]
    if code == "same_target_fails_both_locations":
        return [
            _builder(
                diagnosis_code=code,
                title="Identify the first failing stage and review target-side health",
                reason=(
                    "The same target failed from both vantage points. This suggests a target-side outage, shared DNS or upstream issue, or a common dependency problem, but the evidence still needs to be narrowed to the first failing layer."
                ),
                evidence=evidence,
                steps=[
                    "Identify the first failing diagnostic stage: DNS, TCP, TLS, or HTTPS.",
                    "Check service status and authorized server-side logs for the target.",
                    "Compare timestamps and error details across agents to confirm the failure window.",
                    "Repeat the checks after a short interval to distinguish a transient incident from a persistent outage.",
                ],
                verification=(
                    "The investigation is complete when one clear stage is identified as failing consistently and the target's logs or service state confirm the issue."
                ),
                source_check="https",
                priority="high",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - target-side service or endpoint changes require explicit owner approval.",
            )
        ]
    if code == "local_multiple_targets_fail_cloud_passes":
        return [
            _builder(
                diagnosis_code=code,
                title="Review local connectivity and policy",
                reason=(
                    "The local monitoring path failed while the cloud agent succeeded. This supports a local network, VPN, proxy, or DNS issue rather than a confirmed target outage."
                ),
                evidence=evidence,
                steps=[
                    "Check local network connectivity and whether other HTTPS destinations succeed from the local agent.",
                    "Compare local DNS and TCP results with cloud results for the same target.",
                    "Review VPN, proxy, local firewall, and outbound policy settings.",
                    "Test from another authorized device on the same local network to narrow scope.",
                ],
                verification=(
                    "The local issue is resolved when the local agent reaches the same target with the same DNS/TCP/TLS/HTTPS behavior as the cloud agent."
                ),
                source_check="https",
                priority="medium",
                confidence=confidence,
                requires_admin=True,
                risk="Medium - local proxy or firewall changes require admin review and approval.",
            )
        ]
    if code == "local_agent_stale":
        return [
            _builder(
                diagnosis_code=code,
                title="Verify the agent is running and reaching the API",
                reason=(
                    "The agent heartbeat is stale or missing. This suggests the agent is offline, disconnected, or unable to reach the API, but it does not reveal the service being monitored."
                ),
                evidence=evidence,
                steps=[
                    "Check whether the relevant agent process or container is running.",
                    "Inspect logs for authentication, API connectivity, DNS, TLS, and timeout errors.",
                    "Verify API_BASE_URL and confirm any non-loopback destinations use the expected HTTPS endpoint.",
                    "Confirm the agent-specific token and agent ID mapping are correct without exposing secret values.",
                ],
                verification=(
                    "The agent is healthy again when heartbeats are received and the API shows recent online status with no stale state."
                ),
                source_check="agent_heartbeat",
                priority="medium",
                confidence=confidence,
                requires_admin=True,
                risk="Low - no credential or token values should be exposed or reused.",
            )
        ]
    return [
        _builder(
            diagnosis_code=code,
            title="Investigate the observed failure with more evidence",
            reason=(
                "The diagnosis is recorded but the current evidence is not sufficient for a specific corrective action without more validation."
            ),
            evidence=evidence,
            steps=[
                "Inspect the exact failure stage and error details recorded by the check.",
                "Compare the current result with the adjacent local and cloud measurements.",
                "Repeat the measurement after a short interval before changing any production configuration.",
                "Escalate to the service owner only after the first failing stage and the impact window are confirmed.",
            ],
            verification=(
                "The issue should be treated as resolved only after the relevant check succeeds consistently and the effect is confirmed by direct observation."
            ),
            source_check=source_check_from_code(code),
            priority="medium",
            confidence=confidence,
            requires_admin=False,
            risk="Low - no automatic remediation is performed.",
        )
    ]


def source_check_from_code(code: str) -> str:
    mapping = {
        "dns_failure": "dns",
        "dns_local_fails_cloud_passes": "dns",
        "tcp_connectivity_failure": "tcp",
        "tls_validation_failure": "tls_certificate",
        "http_5xx": "https",
        "https_request_failure": "https",
        "icmp_blocked_https_available": "icmp_ping",
        "same_target_fails_both_locations": "https",
        "local_multiple_targets_fail_cloud_passes": "https",
        "local_agent_stale": "agent_heartbeat",
    }
    return mapping.get(code, "unknown")
