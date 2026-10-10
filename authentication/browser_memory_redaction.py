from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

_SECRETISH_KEY_RE = re.compile(
    r"(?:pass|password|passwd|pwd|secret|token|authorization|cookie|session|credential|api[-_ ]?key|private[-_ ]?key)",
    re.I,
)


def secret_fingerprint(value: str) -> str:
    """Return a non-reversible identifier for an observed secret value."""
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def redact_text(value: Any, *, secrets: Iterable[str] = ()) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def redact_mapping(value: Any, *, secrets: Iterable[str] = (), depth: int = 0, max_depth: int = 3) -> Any:
    """Safely redact report metadata without recursively dumping page secrets."""
    if depth > max_depth:
        return "<truncated>"

    secret_values = tuple(secret for secret in secrets if secret)

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _SECRETISH_KEY_RE.search(str(key)):
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = redact_mapping(
                    item,
                    secrets=secret_values,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
        return result

    if isinstance(value, (list, tuple, set)):
        return [
            redact_mapping(
                item,
                secrets=secret_values,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item in list(value)[:200]
        ]

    if isinstance(value, str):
        return redact_text(value, secrets=secret_values)

    return value


def safe_evidence(label: str, *, matched: bool, location: str = "", value_fingerprint: str | None = None) -> str:
    parts = [label, f"matched={matched}"]
    if location:
        parts.append(f"location={location}")
    if value_fingerprint:
        parts.append(f"value_sha256_prefix={value_fingerprint}")
    return " | ".join(parts)
