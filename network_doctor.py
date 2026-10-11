"""Command-line entry point for the Network Doctor local diagnostic checks."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from checks.models import CheckResult
from checks.runner import DiagnosticReport, run_diagnostics
from checks.url_validation import URLValidationError, redact_url_query


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number greater than zero") from exc
    if timeout <= 0 or timeout == float("inf") or timeout != timeout:
        raise argparse.ArgumentTypeError("timeout must be a finite number greater than zero")
    return timeout


def _format_result(result: CheckResult) -> str:
    label = result.status.upper()
    detail = f"{result.duration_ms:.1f} ms"
    if result.addresses:
        detail += f" - {', '.join(result.addresses)}"
    if result.status_code is not None:
        detail += f" - HTTP {result.status_code}"
    if result.error_message:
        detail += f" - {result.error_message}"
    return f"{result.check_type.upper():<6} {label:<7} {detail}"


def format_report(report: DiagnosticReport) -> str:
    """Format a report for an interactive terminal."""
    lines = [
        f"Network Doctor - {redact_url_query(report.target.url)}",
        *(_format_result(result) for result in report.results),
        "Overall: " + ("PASS" if report.success else "ISSUES DETECTED"),
    ]
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local DNS, TCP, and HTTPS diagnostics for an authorized HTTPS target."
    )
    parser.add_argument("url", help="HTTPS URL to check, for example https://example.com/")
    parser.add_argument("--dns-timeout", type=_positive_timeout, default=2.0, metavar="SECONDS")
    parser.add_argument("--tcp-timeout", type=_positive_timeout, default=3.0, metavar="SECONDS")
    parser.add_argument("--https-timeout", type=_positive_timeout, default=5.0, metavar="SECONDS")
    parser.add_argument("--ping", action="store_true", help="also run one optional ICMP ping")
    parser.add_argument(
        "--traceroute",
        action="store_true",
        help="run one bounded traceroute on demand",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(
            run_diagnostics(
                args.url,
                dns_timeout=args.dns_timeout,
                tcp_timeout=args.tcp_timeout,
                https_timeout=args.https_timeout,
                include_ping=args.ping,
                include_traceroute=args.traceroute,
            )
        )
    except URLValidationError as exc:
        parser.error(str(exc))
    print(format_report(report))
    return 0 if report.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
