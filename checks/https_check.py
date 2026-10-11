"""HTTPS request check with normal TLS certificate verification enabled."""

from __future__ import annotations

import asyncio
import ssl
import time

import httpx

from checks.models import CheckResult, validate_timeout


def _is_tls_error(error: BaseException) -> bool:
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return True
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return False


async def check_https(
    url: str,
    timeout: float = 5.0,
    transport: httpx.AsyncBaseTransport | None = None,
    expected_status_codes: tuple[int, ...] | None = None,
) -> CheckResult:
    """Request a URL without following redirects or disabling TLS verification."""
    validate_timeout(timeout)
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            transport=transport,
        ) as client:
            async with client.stream("GET", url) as response:
                status_code = response.status_code
    except (httpx.TimeoutException, asyncio.TimeoutError):
        return CheckResult(
            "https",
            False,
            (time.perf_counter() - started) * 1000,
            "https_timeout",
            f"HTTPS request exceeded the {timeout:g}-second timeout.",
        )
    except httpx.ConnectError as exc:
        if _is_tls_error(exc):
            code, message = "tls_error", "TLS certificate or handshake validation failed."
        else:
            code, message = "https_connection_error", "The HTTPS connection could not be established."
        return CheckResult("https", False, (time.perf_counter() - started) * 1000, code, message)
    except httpx.HTTPError:
        return CheckResult(
            "https",
            False,
            (time.perf_counter() - started) * 1000,
            "https_request_error",
            "The HTTPS request could not be completed.",
        )

    successful = (
        status_code in expected_status_codes
        if expected_status_codes is not None
        else status_code < 400
    )
    if not successful:
        return CheckResult(
            "https",
            False,
            (time.perf_counter() - started) * 1000,
            "http_error",
            f"The server returned HTTP {status_code}.",
            status_code=status_code,
        )
    return CheckResult(
        "https",
        True,
        (time.perf_counter() - started) * 1000,
        status_code=status_code,
    )
