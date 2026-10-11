"""TLS certificate verification over a DNS-resolved address."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time

from checks.models import CheckResult, validate_timeout


async def _connect_tls(
    hostname: str,
    port: int,
    address_text: str,
    timeout: float,
    semaphore: asyncio.Semaphore | None,
) -> None:
    address = ipaddress.ip_address(address_text)
    context = ssl.create_default_context()
    connect = asyncio.open_connection(
        host=address.compressed,
        port=port,
        family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
        ssl=context,
        server_hostname=hostname,
        ssl_handshake_timeout=timeout,
    )
    if semaphore is None:
        _, writer = await asyncio.wait_for(connect, timeout=timeout)
    else:
        async with semaphore:
            _, writer = await asyncio.wait_for(connect, timeout=timeout)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def check_tls(
    hostname: str,
    port: int,
    addresses: tuple[str, ...],
    timeout: float = 5.0,
    semaphore: asyncio.Semaphore | None = None,
) -> CheckResult:
    """Verify the TLS handshake and certificate chain without disabling checks."""
    validate_timeout(timeout)
    started = time.perf_counter()
    if not addresses:
        return CheckResult(
            "tls_certificate",
            None,
            0,
            "no_addresses",
            "TLS check skipped because DNS produced no addresses.",
        )

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last_error: BaseException | None = None
    for address in addresses:
        remaining = deadline - loop.time()
        if remaining <= 0:
            last_error = asyncio.TimeoutError()
            break
        try:
            await _connect_tls(hostname, port, address, remaining, semaphore)
        except asyncio.TimeoutError as exc:
            last_error = exc
            break
        except ssl.SSLCertVerificationError as exc:
            last_error = exc
            break
        except (ssl.SSLError, OSError) as exc:
            last_error = exc
            continue
        return CheckResult(
            "tls_certificate",
            True,
            (time.perf_counter() - started) * 1000,
            addresses=(address,),
        )

    duration_ms = (time.perf_counter() - started) * 1000
    if isinstance(last_error, asyncio.TimeoutError):
        return CheckResult(
            "tls_certificate",
            False,
            duration_ms,
            "tls_timeout",
            f"TLS verification exceeded the {timeout:g}-second timeout.",
        )
    if isinstance(last_error, ssl.SSLCertVerificationError):
        return CheckResult(
            "tls_certificate",
            False,
            duration_ms,
            "tls_certificate_invalid",
            "TLS certificate verification failed.",
        )
    return CheckResult(
        "tls_certificate",
        False,
        duration_ms,
        "tls_handshake_error",
        "A TLS handshake could not be completed.",
    )
