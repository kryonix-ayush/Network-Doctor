"""Telegram bot notification channel."""

from __future__ import annotations

import httpx


async def send_telegram(
    bot_token: str,
    chat_id: str,
    message: str,
    timeout: float = 5.0,
) -> None:
    """Send a message through Telegram without logging credentials."""
    if not bot_token or not chat_id:
        raise ValueError("Telegram bot token and chat ID must both be configured.")
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        response = await client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "disable_web_page_preview": True},
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get("ok"):
            raise RuntimeError("Telegram rejected the notification request.")
