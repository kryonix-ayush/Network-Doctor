"""Deduplicated, bounded-retry notification dispatcher."""

from __future__ import annotations

import asyncio
import httpx
import os
import smtplib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from diagnosis.incident_manager import IncidentTransition
from checks.url_validation import redact_url_query
from notifications.email import send_email
from notifications.telegram import send_telegram
from storage.repository import ResultRepository

Sender = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class Channel:
    """Configured alert sender."""

    name: str
    sender: Sender


class NotificationDispatcher:
    """Send incident transitions once per channel with bounded exponential retries."""

    def __init__(
        self,
        repository: ResultRepository,
        channels: tuple[Channel, ...] | None = None,
        attempts: int = 3,
        base_delay_seconds: float = 1.0,
    ) -> None:
        if attempts < 1 or base_delay_seconds < 0:
            raise ValueError("Notification retry settings must be valid positive bounds.")
        self.repository = repository
        self.channels = channels if channels is not None else configured_channels()
        self.attempts = attempts
        self.base_delay_seconds = base_delay_seconds

    async def dispatch(self, transition: IncidentTransition) -> None:
        """Reserve and deliver an incident event independently for each channel."""
        incident = next(
            (
                item
                for item in self.repository.list_incidents()
                if item["id"] == transition.incident_id
            ),
            None,
        )
        if incident is None:
            raise ValueError("Cannot notify about an incident that is not persisted.")
        message = (
            f"Network Doctor: {transition.event_type.replace('_', ' ')}\n"
            f"Target: {redact_url_query(transition.target_url)}\n"
            f"Diagnosis: {incident['summary']}\n"
            f"Confidence: {incident['confidence']}"
        )

        for channel in self.channels:
            claimed = await asyncio.to_thread(
                self.repository.claim_notification,
                transition.incident_id,
                transition.event_type,
                channel.name,
            )
            if not claimed:
                continue
            error_summary: str | None = None
            delivered = False
            for attempt in range(self.attempts):
                try:
                    await channel.sender(message)
                except (
                    httpx.HTTPError,
                    smtplib.SMTPException,
                    OSError,
                    ValueError,
                    RuntimeError,
                ) as exc:
                    error_summary = type(exc).__name__
                    if attempt + 1 < self.attempts:
                        await asyncio.sleep(self.base_delay_seconds * (2**attempt))
                else:
                    delivered = True
                    error_summary = None
                    break
            await asyncio.to_thread(
                self.repository.finish_notification,
                transition.incident_id,
                transition.event_type,
                channel.name,
                delivered,
                error_summary,
            )


def configured_channels() -> tuple[Channel, ...]:
    """Build channels from environment variables; missing channels remain disabled."""
    channels: list[Channel] = []
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    if telegram_token and telegram_chat_id:
        channels.append(
            Channel(
                "telegram",
                lambda message: send_telegram(telegram_token, telegram_chat_id, message),
            )
        )

    smtp_host = os.getenv("SMTP_HOST", "")
    sender = os.getenv("ALERT_FROM_EMAIL", "")
    recipient = os.getenv("ALERT_TO_EMAIL", "")
    if smtp_host and sender and recipient:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        channels.append(
            Channel(
                "email",
                lambda message: send_email(
                    smtp_host,
                    smtp_port,
                    smtp_username,
                    smtp_password,
                    sender,
                    recipient,
                    "Network Doctor alert",
                    message,
                ),
            )
        )
    return tuple(channels)
