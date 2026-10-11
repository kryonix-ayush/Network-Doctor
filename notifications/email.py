"""SMTP email notification channel."""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage


def _send_email_sync(
    host: str,
    port: int,
    username: str,
    password: str,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    timeout: float,
) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=timeout) as server:
        server.starttls(context=context)
        if username:
            server.login(username, password)
        server.send_message(message)


async def send_email(
    host: str,
    port: int,
    username: str,
    password: str,
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    timeout: float = 5.0,
) -> None:
    """Send email using SMTP STARTTLS without blocking the event loop."""
    if not host or not sender or not recipient:
        raise ValueError("SMTP host and sender/recipient addresses must be configured.")
    await asyncio.to_thread(
        _send_email_sync,
        host,
        port,
        username,
        password,
        sender,
        recipient,
        subject,
        body,
        timeout,
    )
