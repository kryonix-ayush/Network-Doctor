"""Asynchronous DNS address lookup."""

from __future__ import annotations

import asyncio
import ipaddress
import time

import dns.asyncresolver
import dns.exception
import dns.resolver

from checks.models import CheckResult, validate_timeout


async def _query_family(
    hostname: str,
    record_type: str,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> tuple[list[str], Exception | None]:
    try:
        if semaphore is None:
            answer = await asyncio.wait_for(
                dns.asyncresolver.resolve(hostname, record_type, lifetime=timeout),
                timeout=timeout,
            )
        else:
            async with semaphore:
                answer = await asyncio.wait_for(
                    dns.asyncresolver.resolve(hostname, record_type, lifetime=timeout),
                    timeout=timeout,
                )
    except (
        asyncio.TimeoutError,
        dns.exception.Timeout,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        OSError,
    ) as exc:
        return [], exc
    return [record.address for record in answer], None


async def check_dns(
    hostname: str,
    timeout: float = 2.0,
    semaphore: asyncio.Semaphore | None = None,
) -> CheckResult:
    """Resolve a hostname to IPv4 and IPv6 addresses."""
    validate_timeout(timeout)
    started = time.perf_counter()

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        return CheckResult(
            check_type="dns",
            success=True,
            duration_ms=(time.perf_counter() - started) * 1000,
            addresses=(address.compressed,),
        )

    family_results = await asyncio.gather(
        _query_family(hostname, "A", timeout, semaphore),
        _query_family(hostname, "AAAA", timeout, semaphore),
    )
    addresses = tuple(dict.fromkeys(address for values, _ in family_results for address in values))
    duration_ms = (time.perf_counter() - started) * 1000

    if addresses:
        return CheckResult(
            check_type="dns",
            success=True,
            duration_ms=duration_ms,
            addresses=addresses,
        )

    errors = [error for _, error in family_results if error is not None]
    if any(isinstance(error, (asyncio.TimeoutError, dns.exception.Timeout)) for error in errors):
        return CheckResult(
            "dns",
            False,
            duration_ms,
            "dns_timeout",
            f"DNS lookup exceeded the {timeout:g}-second timeout.",
        )
    if any(isinstance(error, dns.resolver.NXDOMAIN) for error in errors):
        code, message = "dns_nxdomain", "The hostname does not exist in DNS."
    elif any(isinstance(error, dns.resolver.NoNameservers) for error in errors):
        code, message = "dns_no_nameservers", "No configured DNS server returned an answer."
    else:
        code, message = "dns_no_address", "DNS returned no IPv4 or IPv6 addresses."
    return CheckResult("dns", False, duration_ms, code, message)
