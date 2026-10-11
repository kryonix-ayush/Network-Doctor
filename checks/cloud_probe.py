"""SSRF-resistant cloud checks pinned to addresses validated by DNS."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit

from checks.dns_check import check_dns
from checks.models import CheckResult, validate_timeout
from checks.runner import DiagnosticReport
from checks.tls_check import check_tls
from checks.url_validation import validate_url

_MAX_RESPONSE_HEADERS = 65536


def _address_is_allowed(address_text: str, allow_private: bool) -> bool:
    address = ipaddress.ip_address(address_text)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return allow_private or address.is_global


async def _pinned_https_request(
    hostname: str,
    port: int,
    address: str,
    path: str,
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> int:
    """Send a minimal GET over TLS to one already-validated IP address."""
    ip = ipaddress.ip_address(address)
    context = ssl.create_default_context()
    if semaphore is None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=ip.compressed,
                port=port,
                family=socket.AF_INET if ip.version == 4 else socket.AF_INET6,
                ssl=context,
                server_hostname=hostname,
                ssl_handshake_timeout=timeout,
                limit=_MAX_RESPONSE_HEADERS,
            ),
            timeout=timeout,
        )
    else:
        async with semaphore:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip.compressed,
                    port=port,
                    family=socket.AF_INET if ip.version == 4 else socket.AF_INET6,
                    ssl=context,
                    server_hostname=hostname,
                    ssl_handshake_timeout=timeout,
                    limit=_MAX_RESPONSE_HEADERS,
                ),
                timeout=timeout,
            )
    try:
        host_header = f"[{hostname}]" if ":" in hostname else hostname
        if port != 443:
            host_header = f"{host_header}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: NetworkDoctor/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        header_block = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=timeout,
        )
        if len(header_block) > _MAX_RESPONSE_HEADERS:
            raise ValueError("HTTPS response headers exceed the configured limit.")
        status_line = header_block.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        parts = status_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise ValueError("HTTPS server returned a malformed status line.")
        return int(parts[1])
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def run_cloud_diagnostics(
    url: str,
    dns_timeout: float = 2.0,
    tcp_timeout: float = 3.0,
    https_timeout: float = 5.0,
    allow_private: bool = False,
    check_semaphore: asyncio.Semaphore | None = None,
    expected_status_codes: tuple[int, ...] | None = None,
) -> DiagnosticReport:
    """Run cloud checks only against authorized HTTPS targets and safe DNS IPs."""
    target = validate_url(url)
    dns_result = await check_dns(target.hostname, dns_timeout, check_semaphore)
    if not dns_result.success:
        skipped = CheckResult(
            "tcp",
            None,
            0,
            "dns_dependency_failed",
            "TCP check skipped because DNS resolution failed.",
        )
        https = CheckResult(
            "https",
            False,
            0,
            "dns_dependency_failed",
            "HTTPS check skipped because DNS resolution failed.",
        )
        tls = CheckResult(
            "tls_certificate",
            None,
            0,
            "dns_dependency_failed",
            "TLS check skipped because DNS resolution failed.",
        )
        return DiagnosticReport(target, (dns_result, skipped, https, tls))

    rejected = tuple(
        address
        for address in dns_result.addresses
        if not _address_is_allowed(address, allow_private)
    )
    if rejected:
        blocked = CheckResult(
            "tcp",
            None,
            0,
            "cloud_ssrf_blocked",
            "Cloud probing is blocked because DNS resolved to a non-public address.",
            addresses=rejected,
        )
        https = CheckResult(
            "https",
            False,
            0,
            "cloud_ssrf_blocked",
            "HTTPS check skipped by cloud destination policy.",
        )
        tls = CheckResult(
            "tls_certificate",
            None,
            0,
            "cloud_ssrf_blocked",
            "TLS check skipped by cloud destination policy.",
        )
        return DiagnosticReport(target, (dns_result, blocked, https, tls))

    tcp_result = await asyncio.wait_for(
        _tcp_any(target.port, dns_result.addresses, tcp_timeout, check_semaphore),
        timeout=tcp_timeout + 0.1,
    )
    parsed = urlsplit(target.url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    started = time.perf_counter()
    status_code: int | None = None
    last_error: BaseException | None = None
    try:
        async with asyncio.timeout(https_timeout):
            for address in dns_result.addresses:
                try:
                    status_code = await _pinned_https_request(
                        target.hostname,
                        target.port,
                        address,
                        path,
                        https_timeout,
                        check_semaphore,
                    )
                    break
                except asyncio.TimeoutError as exc:
                    last_error = exc
                except (ssl.SSLError, OSError, ValueError) as exc:
                    last_error = exc
    except TimeoutError as exc:
        last_error = exc

    duration_ms = (time.perf_counter() - started) * 1000
    if status_code is None:
        if isinstance(last_error, asyncio.TimeoutError):
            https_result = CheckResult(
                "https", False, duration_ms, "https_timeout",
                f"HTTPS request exceeded the {https_timeout:g}-second timeout.",
            )
        elif isinstance(last_error, ssl.SSLError):
            https_result = CheckResult(
                "https", False, duration_ms, "tls_error",
                "TLS certificate or handshake validation failed.",
            )
        else:
            https_result = CheckResult(
                "https", False, duration_ms, "https_connection_error",
                "Pinned HTTPS connection could not be established.",
            )
    elif (
        status_code not in expected_status_codes
        if expected_status_codes is not None
        else status_code >= 400
    ):
        https_result = CheckResult(
            "https", False, duration_ms, "http_error",
            f"The server returned HTTP {status_code}.", status_code=status_code,
        )
    else:
        https_result = CheckResult(
            "https", True, duration_ms, status_code=status_code,
        )
    tls_result = await check_tls(
        target.hostname,
        target.port,
        dns_result.addresses,
        https_timeout,
        check_semaphore,
    )
    return DiagnosticReport(target, (dns_result, tcp_result, https_result, tls_result))


async def _tcp_any(
    port: int,
    addresses: tuple[str, ...],
    timeout: float,
    semaphore: asyncio.Semaphore | None = None,
) -> CheckResult:
    validate_timeout(timeout)
    start = time.perf_counter()
    deadline = asyncio.get_running_loop().time() + timeout
    connection_errors: list[OSError] = []
    for address_text in addresses:
        address = ipaddress.ip_address(address_text)
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            if semaphore is None:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        address.compressed,
                        port,
                        family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
                    ),
                    timeout=remaining,
                )
            else:
                async with semaphore:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            address.compressed,
                            port,
                            family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
                        ),
                        timeout=remaining,
                    )
        except asyncio.TimeoutError:
            break
        except OSError as exc:
            connection_errors.append(exc)
            continue
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return CheckResult(
            "tcp", True, (time.perf_counter() - start) * 1000,
            addresses=(address.compressed,),
        )
    if connection_errors and all(
        error.errno in {111, 10061} or getattr(error, "winerror", None) == 10061
        for error in connection_errors
    ):
        return CheckResult(
            "tcp", False, (time.perf_counter() - start) * 1000,
            "connection_refused", "The destination refused the TCP connection.",
        )
    return CheckResult(
        "tcp", False, (time.perf_counter() - start) * 1000,
        "tcp_connect_error", "A TCP connection could not be established.",
    )
