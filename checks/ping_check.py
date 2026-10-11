"""Optional platform-aware ICMP reachability check."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import sys
import time

from checks.models import CheckResult, validate_timeout

_LATENCY = re.compile(r"(?:time|time[=<])\s*[=<]?\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


async def check_ping(
    hostname: str,
    addresses: tuple[str, ...],
    timeout: float = 3.0,
) -> CheckResult:
    """Run one system ping without a shell; ping failure is not website failure."""
    validate_timeout(timeout)
    started = time.perf_counter()
    if not addresses:
        return CheckResult(
            "icmp_ping",
            None,
            0,
            "dns_dependency_failed",
            "ICMP check skipped because DNS returned no addresses.",
        )

    address = ipaddress.ip_address(addresses[0]).compressed
    wait_ms = max(1, int(timeout * 1000))
    if sys.platform == "win32":
        command = ["ping", "-n", "1", "-w", str(wait_ms), address]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), address]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout + 0.5)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return CheckResult(
            "icmp_ping",
            False,
            (time.perf_counter() - started) * 1000,
            "ping_timeout",
            f"ICMP ping exceeded the {timeout:g}-second timeout.",
        )
    except OSError:
        return CheckResult(
            "icmp_ping",
            None,
            (time.perf_counter() - started) * 1000,
            "ping_unavailable",
            "The system ping utility is unavailable.",
        )

    duration_ms = (time.perf_counter() - started) * 1000
    if process.returncode != 0:
        return CheckResult(
            "icmp_ping",
            False,
            duration_ms,
            "icmp_unreachable",
            "The destination did not respond to ICMP ping.",
        )
    match = _LATENCY.search(output.decode(errors="replace"))
    latency = float(match.group(1)) if match else None
    return CheckResult(
        "icmp_ping",
        True,
        duration_ms,
        addresses=(address,),
        error_message=None if latency is None else f"Round-trip time: {latency:g} ms.",
    )
