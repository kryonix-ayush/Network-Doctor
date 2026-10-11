"""Read-only authenticated API client for the Network Doctor addon."""

from __future__ import annotations

import os
from typing import Any

import httpx

from config.settings import validate_api_base_url


class UIAPIClient:
    """Fetch read-only Network Doctor data from the authenticated API."""

    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: float = 10.0) -> None:
        configured_base = base_url or os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
        self.base_url = validate_api_base_url(configured_base)
        self.token = token if token is not None else os.getenv("API_TOKEN", "")
        if not self.token:
            raise ValueError("API_TOKEN must be configured in the environment for the UI addon.")
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.timeout = timeout

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = httpx.get(
            f"{self.base_url}{path}",
            headers=self.headers,
            params=params,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def ping(self) -> bool:
        try:
            payload = self.get("/health")
            return bool(payload and payload.get("status") == "ok")
        except (httpx.HTTPError, TypeError, ValueError):
            return False
