import asyncio
import errno

import dns.exception
import dns.resolver
import httpx
import pytest

from checks import dns_check, tcp_check
from checks.dns_check import check_dns
from checks.https_check import check_https
from checks.models import CheckResult
from checks.runner import run_diagnostics
from checks.tls_check import check_tls


@pytest.mark.asyncio
async def test_dns_returns_ipv4_and_ipv6_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(hostname: str, record_type: str, lifetime: float):
        assert hostname == "example.com"
        assert lifetime == 1
        values = {"A": ["203.0.113.10"], "AAAA": ["2001:db8::10"]}[record_type]
        return [type("Record", (), {"address": value})() for value in values]

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", fake_resolve)

    result = await check_dns("example.com", timeout=1)
    assert result.success is True
    assert result.addresses == ("203.0.113.10", "2001:db8::10")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (dns.resolver.NXDOMAIN(), "dns_nxdomain"),
        (dns.exception.Timeout(), "dns_timeout"),
    ],
)
async def test_dns_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_code: str,
) -> None:
    async def fake_resolve(*_args: object, **_kwargs: object):
        raise error

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", fake_resolve)

    result = await check_dns("missing.example", timeout=0.1)
    assert result.success is False
    assert result.error_code == expected_code


@pytest.mark.asyncio
async def test_dns_timeout_cancels_a_slow_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    async def slow_resolve(*_args: object, **_kwargs: object):
        await asyncio.sleep(1)

    monkeypatch.setattr(dns_check.dns.asyncresolver, "resolve", slow_resolve)
    result = await check_dns("slow.example", timeout=0.01)
    assert result.error_code == "dns_timeout"
    assert result.duration_ms < 500


@pytest.mark.asyncio
async def test_tcp_connects_to_a_local_listener() -> None:
    server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await tcp_check.check_tcp(port, ("127.0.0.1",), timeout=1)
    finally:
        server.close()
        await server.wait_closed()
    assert result.success is True
    assert result.addresses == ("127.0.0.1",)


@pytest.mark.asyncio
async def test_tcp_connection_refusal_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse_connection(*_args: object, **_kwargs: object):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")

    monkeypatch.setattr(tcp_check.asyncio, "open_connection", refuse_connection)
    result = await tcp_check.check_tcp(443, ("127.0.0.1",), timeout=1)
    assert result.success is False
    assert result.error_code == "connection_refused"


@pytest.mark.asyncio
async def test_tcp_timeout_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    async def slow_connection(*_args: object, **_kwargs: object):
        await asyncio.sleep(1)

    monkeypatch.setattr(tcp_check.asyncio, "open_connection", slow_connection)
    result = await tcp_check.check_tcp(443, ("203.0.113.1",), timeout=0.01)
    assert result.success is False
    assert result.error_code == "connection_timeout"
    assert result.duration_ms < 500


@pytest.mark.asyncio
async def test_https_success_and_http_error_statuses() -> None:
    success_transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    success = await check_https("https://example.com/", transport=success_transport)
    assert success.success is True
    assert success.status_code == 200

    not_found_transport = httpx.MockTransport(lambda request: httpx.Response(404, request=request))
    not_found = await check_https("https://example.com/missing", transport=not_found_transport)
    assert not_found.success is False
    assert not_found.error_code == "http_error"
    assert not_found.status_code == 404

    server_error_transport = httpx.MockTransport(lambda request: httpx.Response(503, request=request))
    server_error = await check_https("https://example.com/", transport=server_error_transport)
    assert server_error.success is False
    assert server_error.error_code == "http_error"
    assert server_error.status_code == 503


@pytest.mark.asyncio
async def test_https_timeout_is_distinct() -> None:
    async def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    result = await check_https(
        "https://example.com/",
        timeout=0.01,
        transport=httpx.MockTransport(timeout_handler),
    )
    assert result.success is False
    assert result.error_code == "https_timeout"


@pytest.mark.asyncio
async def test_https_expected_status_codes_are_configurable() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(404, request=request))
    result = await check_https(
        "https://example.com/health",
        transport=transport,
        expected_status_codes=(200, 404),
    )
    assert result.success is True
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_tls_timeout_and_dns_dependency_failure_are_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def timeout_connect(*_args: object, **_kwargs: object) -> None:
        raise asyncio.TimeoutError

    monkeypatch.setattr("checks.tls_check._connect_tls", timeout_connect)
    timeout = await check_tls("example.com", 443, ("203.0.113.1",), timeout=0.01)
    skipped = await check_tls("example.com", 443, (), timeout=1)
    assert timeout.error_code == "tls_timeout"
    assert skipped.status == "skipped"
    assert skipped.error_code == "no_addresses"


@pytest.mark.asyncio
async def test_runner_rejects_invalid_url_before_network_activity() -> None:
    with pytest.raises(ValueError):
        await run_diagnostics("http://example.com")


@pytest.mark.asyncio
async def test_runner_skips_tcp_when_dns_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failed_dns(_hostname: str, _timeout: float) -> CheckResult:
        return CheckResult("dns", False, 1, "dns_nxdomain", "No DNS name.")

    async def failed_https(_url: str, _timeout: float) -> CheckResult:
        return CheckResult("https", False, 1, "https_connection_error", "No connection.")

    monkeypatch.setattr("checks.runner.check_dns", failed_dns)
    monkeypatch.setattr("checks.runner.check_https", failed_https)
    report = await run_diagnostics("https://missing.example/")
    assert report.results[0].error_code == "dns_nxdomain"
    assert report.results[1].status == "skipped"
    assert report.results[1].error_code == "dns_dependency_failed"
    assert report.success is False


@pytest.mark.asyncio
async def test_successful_run_produces_all_three_measurements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def successful_https(_url: str, _timeout: float) -> CheckResult:
        return CheckResult("https", True, 8.5, status_code=200)

    async def successful_tls(
        _hostname: str,
        _port: int,
        _addresses: tuple[str, ...],
        _timeout: float,
        _semaphore=None,
    ) -> CheckResult:
        return CheckResult("tls_certificate", True, 5.0)

    server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr("checks.runner.check_https", successful_https)
    monkeypatch.setattr("checks.runner.check_tls", successful_tls)
    try:
        report = await run_diagnostics(f"https://127.0.0.1:{port}/")
    finally:
        server.close()
        await server.wait_closed()

    assert report.success is True
    assert [result.check_type for result in report.results] == [
        "dns",
        "tcp",
        "https",
        "tls_certificate",
    ]
    assert all(result.success is True for result in report.results)
