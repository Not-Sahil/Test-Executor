"""Shared Evidence Sanitization and Evidence Validation Framework.

Provides deterministic evidence validation rules, baseline comparisons
(soft-404 and SPA generic fallback detection), and sensitive secret redaction.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Sensitive key names to redact
SENSITIVE_KEYS = {
    "password", "passwd", "passphrase", "secret", "token",
    "access_token", "refresh_token", "authorization", "cookie",
    "set-cookie", "api_key", "client_secret", "nonce", "state",
    "code", "auth_code", "session", "sessionid", "sid"
}

_REDACTION_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(authorization\s*:\s*basic\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password|passwd|secret|api[_-]?key|client_secret|token)(\s*[=:]\s*)[^\s,;&\"']+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
]


def redact_text_secrets(text: str) -> str:
    """Redact sensitive passwords, tokens, and authorization strings from text."""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in _REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact sensitive keys and values from dictionaries, lists, or strings."""
    if isinstance(value, dict):
        sanitized = {}
        for k, v in value.items():
            key_clean = str(k).strip().lower().replace("-", "_")
            if key_clean in SENSITIVE_KEYS or any(s in key_clean for s in ("password", "secret", "token", "apikey")):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_sensitive_data(v)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, str):
        return redact_text_secrets(value)
    return value


def sanitize_url_parameters(url: str) -> str:
    """Sanitize sensitive query parameters (e.g. state, nonce, code, token) from a URL."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return redact_text_secrets(url)
        clean_query = []
        for key, val in parse_qsl(parsed.query, keep_blank_values=True):
            k_lower = key.lower().replace("-", "_")
            if k_lower in SENSITIVE_KEYS or any(s in k_lower for s in ("token", "secret", "password", "nonce", "state", "code")):
                clean_query.append((key, "[REDACTED]"))
            else:
                clean_query.append((key, val))
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(clean_query),
            parsed.fragment
        ))
    except Exception:
        return redact_text_secrets(url)


def is_soft_404_or_spa_fallback(
    response_body: str | bytes,
    response_status: int,
    baseline_body: str | bytes | None = None,
    content_type: str = "",
) -> bool:
    """Determine whether a response is a soft-404, WAF rejection, or SPA fallback.

    An HTTP 200 is NOT proof that a file or resource genuinely exists.
    """
    if response_status == 404:
        return True

    text = response_body.decode("utf-8", errors="replace") if isinstance(response_body, bytes) else str(response_body or "")
    text_lower = text.lower()

    # WAF rejection indicators
    waf_indicators = [
        "request rejected",
        "access denied",
        "the requested url was rejected",
        "attention required! | cloudflare",
        "security check",
        "403 forbidden",
    ]
    if any(w in text_lower for w in waf_indicators):
        return True

    # SPA shell indicators (e.g. <div id="root"> or <div id='app'> without actual resource content)
    if re.search(r"<div\b[^>]*\bid\s*=\s*['\"](root|app)['\"]", text_lower):
        if "<script" in text_lower and not ("<?php" in text_lower or "db_password" in text_lower):
            return True

    # Generic soft 404 template indicators
    generic_404_markers = [
        "page not found",
        "404 not found",
        "we can't find that page",
        "the page you were looking for doesn't exist",
        "document not found",
        "error 404",
    ]
    if any(m in text_lower for m in generic_404_markers):
        return True

    # Direct baseline similarity check
    if baseline_body is not None:
        base_text = baseline_body.decode("utf-8", errors="replace") if isinstance(baseline_body, bytes) else str(baseline_body or "")
        # If lengths are within 5% and body is identical in major markup
        if abs(len(text) - len(base_text)) < max(50, int(len(base_text) * 0.05)):
            return True

    return False
