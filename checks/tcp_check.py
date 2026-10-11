"""Asynchronous TCP connection check."""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import socket
import time

from checks.models import CheckResult, validate_timeout


async def check_tcp(
    port: int,
    addresses: tuple[str, ...],
    timeout: float = 3.0,
) -> CheckResult:
    """Attempt a TCP connection to resolved addresses within one total timeout."""
    validate_timeout(timeout)
    if not 1 <= port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    started = time.perf_counter()
    if not addresses:
        return CheckResult(
            "tcp",
            None,
            0.0,
            "no_addresses",
            "TCP check skipped because DNS produced no addresses.",
        )

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    errors: list[OSError] = []

    for address_text in addresses:
        address = ipaddress.ip_address(address_text)
        remaining = deadline - loop.time()
        if remaining <= 0:
            return CheckResult(
                "tcp",
                False,
                (time.perf_counter() - started) * 1000,
                "connection_timeout",
                f"TCP connection exceeded the {timeout:g}-second timeout.",
            )

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=address.compressed,
                    port=port,
                    family=socket.AF_INET if address.version == 4 else socket.AF_INET6,
                ),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            return CheckResult(
                "tcp",
                False,
                (time.perf_counter() - started) * 1000,
                "connection_timeout",
                f"TCP connection exceeded the {timeout:g}-second timeout.",
            )
        except OSError as exc:
            errors.append(exc)
            continue
        else:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            return CheckResult(
                "tcp",
                True,
                (time.perf_counter() - started) * 1000,
                addresses=(address.compressed,),
            )

    refused = any(
        error.errno == errno.ECONNREFUSED or getattr(error, "winerror", None) == 10061
        for error in errors
    )
    code = "connection_refused" if refused else "tcp_connect_error"
    message = (
        "The destination refused the TCP connection."
        if refused
        else "A TCP connection could not be established."
    )
    return CheckResult("tcp", False, (time.perf_counter() - started) * 1000, code, message)
