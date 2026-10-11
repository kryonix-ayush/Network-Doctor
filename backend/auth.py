"""Bearer-token authentication and API request guards."""

from __future__ import annotations

import secrets
import time
import json
import os
from collections import deque
from collections.abc import Callable

from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config.settings import Settings

_bearer = HTTPBearer(auto_error=False)


def authentication_dependency(settings: Settings) -> Callable[..., str]:
    """Create a dependency that validates bearer tokens in constant time."""

    def require_token(
        credentials: HTTPAuthorizationCredentials | None = None,
    ) -> str:
        if credentials is None or not secrets.compare_digest(
            credentials.credentials,
            settings.api_token,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials

    from fastapi import Depends

    def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> str:
        return require_token(credentials)

    return dependency


def agent_authentication_dependency(settings: Settings) -> Callable[..., str]:
    """Require a bearer token from the configured per-agent token registry."""
    from fastapi import Depends

    def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> str:
        tokens = _agent_tokens()
        if not tokens:
            raise HTTPException(status_code=503, detail="Agent credentials are not configured.")
        if credentials is None or not any(
            secrets.compare_digest(credentials.credentials, token)
            for token in tokens.values()
        ):
            raise HTTPException(
                status_code=401,
                detail="Agent authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials

    return dependency


def api_or_agent_authentication_dependency(settings: Settings) -> Callable[..., str]:
    """Permit authenticated dashboard or agent clients to read shared settings."""
    from fastapi import Depends

    def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> str:
        valid_tokens = [settings.api_token, *_agent_tokens().values()]
        if credentials is None or not any(
            token and secrets.compare_digest(credentials.credentials, token)
            for token in valid_tokens
        ):
            raise HTTPException(
                status_code=401,
                detail="Authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials

    return dependency


def _agent_tokens() -> dict[str, str]:
    raw = os.getenv("AGENT_TOKENS", "")
    if not raw:
        return {}
    try:
        tokens = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AGENT_TOKENS must be a JSON object keyed by agent ID.") from exc
    if not isinstance(tokens, dict) or any(
        not isinstance(agent_id, str)
        or not isinstance(token, str)
        or len(token) < 32
        for agent_id, token in tokens.items()
    ):
        raise RuntimeError("Each AGENT_TOKENS value must be a secret of at least 32 characters.")
    return tokens


class RequestGuard:
    """Enforce payload size and per-client in-memory request rate limits."""

    def __init__(
        self,
        app,
        rate_limit_per_minute: int,
        max_request_bytes: int,
    ) -> None:
        self.app = app
        self.rate_limit = rate_limit_per_minute
        self.max_request_bytes = max_request_bytes
        self.requests: dict[str, deque[float]] = {}

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
        }
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                size = int(content_length.decode("ascii"))
            except ValueError:
                await _send_error(send, 400, "Invalid Content-Length header.")
                return
            if size < 0 or size > self.max_request_bytes:
                await _send_error(send, 413, "Request body exceeds the configured limit.")
                return

        now = time.monotonic()
        client_data = scope.get("client")
        client = client_data[0] if client_data else "unknown"
        for known_client in tuple(self.requests):
            if not self.requests[known_client] or now - self.requests[known_client][-1] >= 60:
                self.requests.pop(known_client)
        timestamps = self.requests.setdefault(client, deque())
        while timestamps and now - timestamps[0] >= 60:
            timestamps.popleft()
        if len(timestamps) >= self.rate_limit:
            await _send_error(send, 429, "Request rate limit exceeded.")
            return
        timestamps.append(now)

        is_loopback = client in {"127.0.0.1", "::1", "localhost"}
        if not is_loopback and scope.get("scheme") != "https":
            await _send_error(send, 400, "HTTPS is required for non-loopback API clients.")
            return

        method = scope.get("method", "GET").upper()
        replay_body: bytes | None = None
        if method in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > self.max_request_bytes:
                    await _send_error(send, 413, "Request body exceeds the configured limit.")
                    return
                if not message.get("more_body", False):
                    break
            replay_body = bytes(body)

        body_sent = False

        async def replay_receive():
            nonlocal body_sent
            if replay_body is not None and not body_sent:
                body_sent = True
                return {"type": "http.request", "body": replay_body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive if replay_body is not None else receive, send)


async def _send_error(send, code: int, detail: str) -> None:
    from json import dumps

    content = dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": code,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(content)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": content})
