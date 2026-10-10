from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


def mask_secret(value: str | None) -> str:
    if value is None:
        return ""
    value = str(value)
    if value == "":
        return "<empty>"
    return "*" * min(max(len(value), 8), 16)


def safe_credential(username: str, password: str) -> str:
    return f"{username}:{mask_secret(password)}"


def normalize_text(text: str, limit: int = 12000) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value[:limit]


def safe_url(url: str) -> str:
    """Remove fragments and userinfo; preserve path/query because they can be useful evidence."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))
    except Exception:
        return str(url or "")


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        value = str(item)
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output
