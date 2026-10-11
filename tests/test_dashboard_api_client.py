import pytest

from dashboard.api_client import DashboardAPI


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost.attacker.example",
        "http://127.0.0.1.attacker.example",
        "http://user:password@localhost:8000",
    ],
)
def test_dashboard_rejects_insecure_or_credentialed_api_urls(base_url: str) -> None:
    with pytest.raises(ValueError):
        DashboardAPI(base_url, "dashboard-token")


def test_dashboard_allows_loopback_http_for_local_development() -> None:
    client = DashboardAPI("http://127.0.0.1:8000/", "dashboard-token")
    assert client.base_url == "http://127.0.0.1:8000"
