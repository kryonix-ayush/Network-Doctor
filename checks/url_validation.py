"""Validation and normalization for monitored HTTPS targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class URLValidationError(ValueError):
    """Raised when a target is not a safe, well-formed HTTPS URL."""


@dataclass(frozen=True)
class TargetURL:
    """A validated target URL and its connection endpoint."""

    url: str
    hostname: str
    port: int


def validate_url(value: str) -> TargetURL:
    """Validate an HTTPS URL and return its normalized connection details."""
    if not value or value != value.strip():
        raise URLValidationError("Enter a complete HTTPS URL without surrounding whitespace.")
    if any(ord(character) <= 32 or ord(character) == 127 for character in value):
        raise URLValidationError("The URL must not contain whitespace or control characters.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("The URL contains an invalid host or port.") from exc

    if parsed.scheme.lower() != "https":
        raise URLValidationError("Only HTTPS URLs are supported.")
    if not parsed.netloc or not parsed.hostname:
        raise URLValidationError("The URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("Credentials must not be embedded in the URL.")
    if parsed.fragment:
        raise URLValidationError("URL fragments are not sent to servers; remove the fragment.")

    raw_hostname = parsed.hostname
    if "%" in raw_hostname:
        raise URLValidationError("Scoped IP addresses are not supported.")

    try:
        address = ipaddress.ip_address(raw_hostname)
        hostname = address.compressed
        host_for_url = f"[{hostname}]" if address.version == 6 else hostname
    except ValueError:
        try:
            hostname = raw_hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLValidationError("The hostname is not a valid internationalized domain name.") from exc

        domain = hostname[:-1] if hostname.endswith(".") else hostname
        labels = domain.split(".")
        if (
            len(domain) > 253
            or not domain
            or any(not _DNS_LABEL.fullmatch(label) for label in labels)
        ):
            raise URLValidationError("The URL contains an invalid hostname.")
        host_for_url = hostname

    effective_port = port if port is not None else 443
    netloc = host_for_url if port in (None, 443) else f"{host_for_url}:{port}"
    normalized_url = urlunsplit(
        ("https", netloc, parsed.path or "/", parsed.query, "")
    )
    return TargetURL(url=normalized_url, hostname=hostname, port=effective_port)


def redact_url_query(value: str) -> str:
    """Hide query parameter values when displaying a target URL."""
    parsed = urlsplit(value)
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "[redacted]" if parsed.query else "", "")
    )
