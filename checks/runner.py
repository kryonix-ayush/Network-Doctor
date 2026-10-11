"""Orchestrate the required local DNS, TCP, and HTTPS checks."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from collections.abc import Awaitable, Callable
from typing import TypeVar

from checks.dns_check import check_dns
from checks.https_check import check_https
from checks.models import CheckResult
from checks.ping_check import check_ping
from checks.tcp_check import check_tcp
from checks.tls_check import check_tls
from checks.traceroute_check import check_traceroute
from checks.url_validation import TargetURL, validate_url

_Result = TypeVar("_Result", bound=CheckResult)


async def _run_limited(
    semaphore: asyncio.Semaphore | None,
    check: Callable[[], Awaitable[_Result]],
) -> _Result:
    if semaphore is None:
        return await check()
    async with semaphore:
        return await check()


@dataclass(frozen=True)
class DiagnosticReport:
    """The validated target and the results of its diagnostic checks."""

    target: TargetURL
    results: tuple[CheckResult, ...]

    @property
    def success(self) -> bool:
        https = next(
            (result for result in self.results if result.check_type == "https"),
            None,
        )
        if https is not None:
            return https.success is True
        return all(result.success is not False for result in self.results)


async def run_diagnostics(
    url: str,
    dns_timeout: float = 2.0,
    tcp_timeout: float = 3.0,
    https_timeout: float = 5.0,
    check_semaphore: asyncio.Semaphore | None = None,
    include_ping: bool = False,
    include_traceroute: bool = False,
) -> DiagnosticReport:
    """Validate a target and run DNS, TCP, and HTTPS checks."""
    target = validate_url(url)
    dns_result, https_result = await asyncio.gather(
        _run_limited(
            check_semaphore,
            lambda: check_dns(target.hostname, dns_timeout),
        ),
        _run_limited(
            check_semaphore,
            lambda: check_https(target.url, https_timeout),
        ),
    )
    if dns_result.success:
        tcp_result, tls_result = await asyncio.gather(
            _run_limited(
                check_semaphore,
                lambda: check_tcp(target.port, dns_result.addresses, tcp_timeout),
            ),
            check_tls(
                target.hostname,
                target.port,
                dns_result.addresses,
                https_timeout,
                check_semaphore,
            ),
        )
    else:
        tcp_result = CheckResult(
            "tcp",
            None,
            0.0,
            "dns_dependency_failed",
            "TCP check skipped because DNS resolution failed.",
        )
        tls_result = CheckResult(
            "tls_certificate",
            None,
            0.0,
            "dns_dependency_failed",
            "TLS verification skipped because DNS resolution failed.",
        )
    results = [dns_result, tcp_result, https_result, tls_result]
    if include_ping:
        results.append(
            await _run_limited(
                check_semaphore,
                lambda: check_ping(
                    target.hostname,
                    dns_result.addresses,
                    timeout=tcp_timeout,
                ),
            )
        )
    if include_traceroute:
        results.append(
            await _run_limited(
                check_semaphore,
                lambda: check_traceroute(
                    target.hostname,
                    timeout=min(30.0, https_timeout * 6),
                ),
            )
        )
    return DiagnosticReport(target, tuple(results))
