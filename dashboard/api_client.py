"""Authenticated read-only API client for the dashboard."""

from __future__ import annotations

import httpx

from config.settings import validate_api_base_url


class DashboardAPI:
    """Call the dashboard API using a bearer token."""

    def __init__(self, base_url: str, token: str, timeout: float = 5.0) -> None:
        self.base_url = validate_api_base_url(base_url)
        if not token:
            raise ValueError("Set API_TOKEN for dashboard authentication.")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.timeout = timeout

    def get(self, path: str, params: dict[str, object] | None = None) -> object:
        response = httpx.get(
            f"{self.base_url}{path}",
            headers=self.headers,
            params=params,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
