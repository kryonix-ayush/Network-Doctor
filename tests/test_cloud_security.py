import ipaddress

import pytest

from checks import cloud_probe
from checks.models import CheckResult
from checks.url_validation import URLValidationError, validate_url


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
    ],
)
def test_cloud_address_policy_blocks_non_public_addresses(address: str) -> None:
    assert ipaddress.ip_address(address).is_global is False
    assert cloud_probe._address_is_allowed(address, allow_private=False) is False
    assert cloud_probe._address_is_allowed(address, allow_private=True) is True


@pytest.mark.asyncio
async def test_cloud_probe_blocks_private_dns_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def private_dns(hostname: str, timeout: float, semaphore=None) -> CheckResult:
        return CheckResult("dns", True, 1, addresses=("127.0.0.1",))

    async def should_not_connect(*_args, **_kwargs):
        raise AssertionError("A private destination must never be contacted.")

    monkeypatch.setattr(cloud_probe, "check_dns", private_dns)
    monkeypatch.setattr(cloud_probe, "_tcp_any", should_not_connect)
    report = await cloud_probe.run_cloud_diagnostics("https://example.com/")

    assert report.results[1].error_code == "cloud_ssrf_blocked"
    assert report.results[1].status == "skipped"
    assert report.results[2].error_code == "cloud_ssrf_blocked"


@pytest.mark.asyncio
async def test_cloud_probe_uses_validated_public_ip_for_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def public_dns(hostname: str, timeout: float, semaphore=None) -> CheckResult:
        return CheckResult("dns", True, 1, addresses=("8.8.8.8",))

    async def successful_tcp(
        _port: int,
        addresses: tuple[str, ...],
        _timeout: float,
        semaphore=None,
    ):
        assert addresses == ("8.8.8.8",)
        return CheckResult("tcp", True, 1, addresses=("8.8.8.8",))

    async def successful_https(
        hostname: str,
        _port: int,
        address: str,
        path: str,
        _timeout: float,
        semaphore=None,
    ) -> int:
        assert (hostname, address, path) == ("example.com", "8.8.8.8", "/health?q=1")
        return 200

    monkeypatch.setattr(cloud_probe, "check_dns", public_dns)
    monkeypatch.setattr(cloud_probe, "_tcp_any", successful_tcp)
    monkeypatch.setattr(cloud_probe, "_pinned_https_request", successful_https)
    async def successful_tls(
        _hostname: str,
        _port: int,
        _addresses: tuple[str, ...],
        _timeout: float,
        _semaphore=None,
    ) -> CheckResult:
        return CheckResult("tls_certificate", True, 1)

    monkeypatch.setattr(cloud_probe, "check_tls", successful_tls)
    report = await cloud_probe.run_cloud_diagnostics("https://example.com/health?q=1")
    assert [result.check_type for result in report.results] == [
        "dns",
        "tcp",
        "https",
        "tls_certificate",
    ]
    assert report.results[-1].success is True


def test_cloud_probe_requires_validated_https_url() -> None:
    with pytest.raises(URLValidationError):
        validate_url("http://example.com/")
