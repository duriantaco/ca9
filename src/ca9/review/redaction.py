"""URL display redaction; comparison uses the original values before this step."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>\\]+")


def redact_text(value: str) -> str:
    """Remove URL credentials and query/fragment values, including in previews."""
    return _URL.sub(lambda match: _redact_url(match.group()), value)


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.hostname:
            return "[redacted URL]"
        if (
            parts.username is None
            and parts.password is None
            and not parts.query
            and not parts.fragment
        ):
            return value
        # Retain the caller's host/port spelling and path for useful source context.
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc.rsplit("@", 1)[-1],
                parts.path,
                "[redacted]" if parts.query else "",
                "[redacted]" if parts.fragment else "",
            )
        )
    except ValueError:
        return "[redacted URL]"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {redact_text(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value
