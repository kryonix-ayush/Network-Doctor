"""On-demand bounded traceroute utility."""

from __future__ import annotations

import asyncio
import ipaddress
import sys
import time

from checks.models import CheckResult, validate_timeout


async def check_traceroute(
    hostname: str,
    timeout: float = 30.0,
    max_hops: int = 20,
) -> CheckResult:
    """Run tracert/traceroute on demand and retain only a compact summary."""
    validate_timeout(timeout)
    if not 1 <= max_hops <= 30:
        raise ValueError("max_hops must be between 1 and 30.")
    try:
        address = ipaddress.ip_address(hostname).compressed
    except ValueError:
        address = hostname

    if sys.platform == "win32":
        command = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", address]
    else:
        command = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", address]

    started = time.perf_counter()
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return CheckResult(
            "traceroute",
            False,
            (time.perf_counter() - started) * 1000,
            "traceroute_timeout",
            f"Traceroute exceeded the {timeout:g}-second timeout.",
        )
    except OSError:
        return CheckResult(
            "traceroute",
            None,
            (time.perf_counter() - started) * 1000,
            "traceroute_unavailable",
            "The platform traceroute utility is unavailable.",
        )

    if process.returncode != 0:
        return CheckResult(
            "traceroute",
            False,
            (time.perf_counter() - started) * 1000,
            "traceroute_failed",
            "The operating system traceroute utility failed.",
        )
    hop_count = sum(1 for line in output.splitlines() if line.lstrip()[:1].isdigit())
    return CheckResult(
        "traceroute",
        True,
        (time.perf_counter() - started) * 1000,
        error_message=f"Traceroute returned {min(hop_count, max_hops)} hop line(s).",
    )
