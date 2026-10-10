from __future__ import annotations

import base64
import binascii
import math
import re
from collections import defaultdict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
    same_origin,
)


# ============================================================
# CONFIGURATION / SAFETY LIMITS
# ============================================================

DEFAULT_MAX_ASSETS = 20
DEFAULT_MAX_BODY_PER_ASSET = 750_000
DEFAULT_MAX_TOTAL_BYTES = 10_000_000
DEFAULT_MAX_FINDINGS = 100
DEFAULT_MAX_SOURCE_MAPS = 10
DEFAULT_ENTROPY_MIN_LENGTH = 20


# ============================================================
# PLACEHOLDERS / TEST VALUES
# ============================================================

GENERIC_PLACEHOLDERS = {
    "",
    "password",
    "passwd",
    "pwd",
    "secret",
    "changeme",
    "change_me",
    "example",
    "example.com",
    "test",
    "testing",
    "dummy",
    "sample",
    "demo",
    "placeholder",
    "your_password",
    "your-password",
    "your_password_here",
    "your-secret",
    "your_secret",
    "your-api-key",
    "your_api_key",
    "your_token",
    "your-token",
    "replace_me",
    "replace-this",
    "replace_this",
    "insert_here",
    "insert-value",
    "insert_value",
    "xxx",
    "xxxx",
    "xxxxx",
    "null",
    "undefined",
    "none",
    "nil",
    "true",
    "false",
    "foobar",
}


PLACEHOLDER_PATTERNS = [
    re.compile(r"^<[^>]{1,100}>$"),
    re.compile(r"^\$\{[^}]+\}$"),
    re.compile(r"^\{\{[^}]+\}\}$"),
    re.compile(r"^\{\{.*\}\}$"),
    re.compile(r"^YOUR[_ -]?[A-Z0-9_-]+$", re.I),
    re.compile(r"^YOUR[A-Z0-9_-]+$", re.I),
    re.compile(r"^REPLACE[_ -]?ME$", re.I),
    re.compile(r"^CHANGE[_ -]?ME$", re.I),
    re.compile(r"^[xX*._-]{3,}$"),
]


# ============================================================
# HIGH-CONFIDENCE SECRET PATTERNS
# ============================================================

HIGH_CONFIDENCE_PATTERNS: dict[str, re.Pattern[str]] = {

    # Private keys
    "private_key": re.compile(
        r"-----BEGIN\s+"
        r"(?:RSA |EC |DSA |OPENSSH |PGP )?"
        r"PRIVATE KEY-----",
        re.I,
    ),

    # Basic authentication embedded in URL
    "basic_auth_url": re.compile(
        r"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+",
        re.I,
    ),

    # AWS access-key ID
    "aws_access_key": re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    ),

    # GitHub tokens
    "github_token": re.compile(
        r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"
    ),

    # Slack tokens
    "slack_token": re.compile(
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
    ),

    # Stripe secret keys
    "stripe_secret_key": re.compile(
        r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"
    ),

    # npm token
    "npm_token": re.compile(
        r"\bnpm_[A-Za-z0-9]{20,}\b"
    ),

    # Google API key
    "google_api_key": re.compile(
        r"\bAIza[0-9A-Za-z_-]{20,}\b"
    ),

    # JWT
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\."
        r"[A-Za-z0-9_-]{5,}\b"
    ),

    # Private-ish connection strings
    "postgres_connection_string": re.compile(
        r"\bpostgres(?:ql)?://[^/\s:@]+:[^/\s@]+@[^/\s]+",
        re.I,
    ),

    "mysql_connection_string": re.compile(
        r"\bmysql://[^/\s:@]+:[^/\s@]+@[^/\s]+",
        re.I,
    ),

    "mongodb_connection_string": re.compile(
        r"\bmongodb(?:\+srv)?://[^/\s:@]+:[^/\s@]+@[^/\s]+",
        re.I,
    ),

    "redis_connection_string": re.compile(
        r"\bredis://[^/\s:@]+:[^/\s@]+@[^/\s]+",
        re.I,
    ),

    # Authorization-bearing values
    "bearer_token": re.compile(
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b",
        re.I,
    ),

    "basic_authorization": re.compile(
        r"\bBasic\s+[A-Za-z0-9+/=]{12,}\b",
        re.I,
    ),

    # Generic private certificate
    "certificate_private_material": re.compile(
        r"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----",
        re.I,
    ),
}


# ============================================================
# SECRET ASSIGNMENTS
# ============================================================

SECRET_ASSIGNMENT = re.compile(
    r"""
    \b
    (?:
        password|
        passwd|
        pwd|
        passphrase|
        secret|
        api[_-]?key|
        apikey|
        access[_-]?token|
        auth[_-]?token|
        refresh[_-]?token|
        id[_-]?token|
        bearer[_-]?token|
        client[_-]?secret|
        private[_-]?key|
        signing[_-]?key|
        encryption[_-]?key|
        service[_-]?account|
        service[_-]?password|
        database[_-]?password|
        db[_-]?password|
        connection[_-]?string|
        credential|
        credentials|
        authorization
    )
    \b
    \s*
    (?:
        :|=|=>|
        \b(?:is|was)\b
    )
    \s*
    (?:
        (?P<quote>["'])
        (?P<quoted>.{6,500}?)
        (?P=quote)
        |
        (?P<bare>[A-Za-z0-9_./+=:@$%&!?~*-]{8,500})
    )
    """,
    re.I | re.X,
)


# ============================================================
# HEADER / CONFIG PATTERNS
# ============================================================

AUTH_HEADER_PATTERN = re.compile(
    r"""
    (?:
        ["']Authorization["']|
        Authorization
    )
    \s*[:=]\s*
    ["']
    (?:
        Bearer\s+|
        Basic\s+
    )
    [^"']{10,}
    ["']
    """,
    re.I | re.X,
)


CONFIG_KEY_PATTERN = re.compile(
    r"""
    \b
    (?:
        api[_-]?key|
        secret[_-]?key|
        client[_-]?secret|
        access[_-]?token|
        refresh[_-]?token|
        auth[_-]?token|
        private[_-]?key|
        password|
        passwd|
        db[_-]?password|
        database[_-]?password
    )
    \b
    """,
    re.I | re.X,
)


# ============================================================
# OTHER SENSITIVE CONFIGURATION
# ============================================================

SENSITIVE_URL_PATTERN = re.compile(
    r"""
    https?://
    [^\s/:]+
    :
    [^\s/@]+
    @
    [^\s]+
    """,
    re.I | re.X,
)


# ============================================================
# HTML PARSER
# ============================================================

class ScriptParser(HTMLParser):
    """
    Extracts client-accessible resources from HTML.

    The parser intentionally remains lightweight and does not attempt
    full JavaScript parsing.
    """

    def __init__(self) -> None:
        super().__init__()

        self.script_sources: list[str] = []
        self.inline_scripts: list[str] = []
        self.inline_json: list[str] = []

        self.meta_values: list[str] = []
        self.comments: list[str] = []

        self._inside_script = False
        self._current_script_type = ""
        self._current_script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_dict = dict(attrs)

        if tag_lower == "script":
            self._inside_script = True
            self._current_script_parts = []

            script_type = (
                attr_dict.get("type")
                or attr_dict.get("application")
                or ""
            )

            self._current_script_type = script_type.lower()

            src = attr_dict.get("src")
            if src:
                self.script_sources.append(src)

        elif tag_lower == "meta":
            for key, value in attrs:
                if key.lower() in {
                    "content",
                    "value",
                    "name",
                    "property",
                } and value:
                    self.meta_values.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script" or not self._inside_script:
            return

        text = "".join(self._current_script_parts).strip()

        if text:
            if (
                "application/json" in self._current_script_type
                or "application/ld+json" in self._current_script_type
                or "application/config" in self._current_script_type
            ):
                self.inline_json.append(text)
            else:
                self.inline_scripts.append(text)

        self._inside_script = False
        self._current_script_type = ""
        self._current_script_parts = []

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self._current_script_parts.append(data)

    def handle_comment(self, data: str) -> None:
        if data and data.strip():
            self.comments.append(data)


# ============================================================
# BASIC UTILITIES
# ============================================================

def _is_placeholder(value: str) -> bool:
    value = value.strip()

    if not value:
        return True

    normalized = value.lower().strip()

    if normalized in GENERIC_PLACEHOLDERS:
        return True

    for pattern in PLACEHOLDER_PATTERNS:
        if pattern.fullmatch(value):
            return True

    return False


def _looks_like_encoded_secret(value: str) -> bool:
    """
    Detects values that plausibly look like Base64 encoded data.

    This does NOT classify something as a secret by itself.
    """
    value = value.strip()

    if len(value) < 20:
        return False

    if len(value) % 4 != 0:
        return False

    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return False

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return False

    if len(decoded) < 10:
        return False

    printable = sum(
        1
        for byte in decoded
        if byte in (9, 10, 13) or 32 <= byte <= 126
    )

    return printable / max(len(decoded), 1) >= 0.75


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = defaultdict(int)

    for char in value:
        counts[char] += 1

    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _looks_random(value: str) -> bool:
    value = value.strip()

    if len(value) < DEFAULT_ENTROPY_MIN_LENGTH:
        return False

    if _is_placeholder(value):
        return False

    unique_ratio = len(set(value)) / len(value)
    entropy = _entropy(value)

    return (
        entropy >= 3.5
        and unique_ratio >= 0.45
        and not value.isalpha()
    )


def _redact_secret(value: str) -> str:
    value = value.strip()

    if not value:
        return "[REDACTED]"

    if len(value) <= 8:
        return "[REDACTED]"

    return (
        value[:4]
        + ("*" * min(12, max(4, len(value) - 8)))
        + value[-4:]
    )


def _normalize_secret_for_dedupe(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def _get_context(text: str, start: int, end: int, radius: int = 100) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)

    return text[left:right].replace("\n", " ").replace("\r", " ")


def _source_score(
    *,
    source_type: str,
    match_type: str,
    context: str,
    value: str,
) -> tuple[int, str]:
    """
    Returns (confidence score, reason).
    """

    score = 0
    reasons: list[str] = []

    context_lower = context.lower()
    value_lower = value.lower()

    if match_type in {
        "private_key",
        "certificate_private_material",
        "basic_auth_url",
        "postgres_connection_string",
        "mysql_connection_string",
        "mongodb_connection_string",
        "redis_connection_string",
        "aws_access_key",
        "github_token",
        "slack_token",
        "stripe_secret_key",
        "npm_token",
    }:
        score += 90
        reasons.append("high-confidence credential format")

    elif match_type in {
        "jwt",
        "bearer_token",
        "basic_authorization",
        "secret_assignment",
        "generic_secret_assignment",
    }:
        score += 55
        reasons.append("credential-like content")

    if source_type == "source-map":
        score += 10
        reasons.append("found in source map")

    if source_type in {"inline-json", "html-config"}:
        score += 5
        reasons.append("found in client configuration")

    if "production" in context_lower:
        score += 5
        reasons.append("production context")

    if any(
        marker in context_lower
        for marker in [
            "authorization",
            "bearer",
            "client_secret",
            "private_key",
            "access_token",
            "refresh_token",
            "database",
            "postgres",
            "mysql",
            "mongodb",
            "redis",
        ]
    ):
        score += 15
        reasons.append("credential-related surrounding context")

    if _looks_random(value):
        score += 10
        reasons.append("high-entropy/random-looking value")

    if _is_placeholder(value):
        score -= 80
        reasons.append("placeholder-like value")

    if any(
        marker in context_lower
        for marker in [
            "example",
            "sample",
            "demo",
            "mock",
            "fixture",
            "test data",
            "testdata",
            "documentation",
            "docs",
            "placeholder",
        ]
    ):
        score -= 50
        reasons.append("example/test/documentation context")

    if value_lower in GENERIC_PLACEHOLDERS:
        score -= 100

    return score, "; ".join(reasons)


# ============================================================
# SOURCE MAP SUPPORT
# ============================================================

SOURCE_MAPPING_URL = re.compile(
    r"(?:\/\/[#@]\s*sourceMappingURL=|sourceMappingURL\s*=\s*)([^\s\"']+)",
    re.I,
)


def _extract_source_map_reference(js_text: str) -> str | None:
    matches = SOURCE_MAPPING_URL.findall(js_text or "")

    if not matches:
        return None

    return matches[-1].strip()


def _extract_source_map_text(
    source_map_data: str,
) -> list[str]:
    """
    Extracts sourcesContent from a source map without depending on
    a JavaScript parser.

    If the map is malformed, simply return no recovered source.
    """
    import json

    try:
        data = json.loads(source_map_data)
    except Exception:
        return []

    contents = data.get("sourcesContent")

    if not isinstance(contents, list):
        return []

    output: list[str] = []

    for item in contents:
        if isinstance(item, str) and item.strip():
            output.append(item)

    return output


# ============================================================
# GENERIC FINDING BUILDER
# ============================================================

def _build_finding(
    *,
    finding_type: str,
    source_type: str,
    location: str,
    text: str,
    start: int,
    end: int,
    value: str,
) -> dict[str, Any]:

    context = _get_context(text, start, end)

    score, score_reason = _source_score(
        source_type=source_type,
        match_type=finding_type,
        context=context,
        value=value,
    )

    if score >= 80:
        severity = "HIGH"
        confidence = "HIGH"
    elif score >= 45:
        severity = "MEDIUM"
        confidence = "MEDIUM"
    else:
        severity = "LOW"
        confidence = "LOW"

    line_number = text.count("\n", 0, start) + 1

    return {
        "type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "location": location,
        "source_type": source_type,
        "line": line_number,
        "offset": start,
        "value_redacted": _redact_secret(value),
        "context": _redact_secret(context[:300]),
        "reason": score_reason,
    }


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def _analyze_text(
    *,
    text: str,
    location: str,
    source_type: str,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    if not text:
        return findings

    # --------------------------------------------------------
    # 1. High-confidence known secret patterns
    # --------------------------------------------------------

    for pattern_name, pattern in HIGH_CONFIDENCE_PATTERNS.items():
        for match in pattern.finditer(text):

            value = match.group(0)

            finding = _build_finding(
                finding_type=pattern_name,
                source_type=source_type,
                location=location,
                text=text,
                start=match.start(),
                end=match.end(),
                value=value,
            )

            findings.append(finding)

            if len(findings) >= DEFAULT_MAX_FINDINGS:
                return findings

    # --------------------------------------------------------
    # 2. Generic secret assignments
    # --------------------------------------------------------

    for match in SECRET_ASSIGNMENT.finditer(text):

        value = (
            match.group("quoted")
            or match.group("bare")
            or ""
        ).strip()

        if not value:
            continue

        key_name = (
            match.group(0)
            .split("=", 1)[0]
            .split(":", 1)[0]
            .strip()
        )

        context = _get_context(
            text,
            match.start(),
            match.end(),
        )

        score, reason = _source_score(
            source_type=source_type,
            match_type="secret_assignment",
            context=context,
            value=value,
        )

        if score < 20:
            continue

        finding = _build_finding(
            finding_type="secret_assignment",
            source_type=source_type,
            location=location,
            text=text,
            start=match.start(),
            end=match.end(),
            value=value,
        )

        finding["key"] = key_name[:100]
        finding["score"] = score
        finding["reason"] = reason

        findings.append(finding)

        if len(findings) >= DEFAULT_MAX_FINDINGS:
            return findings

    # --------------------------------------------------------
    # 3. Authorization header detection
    # --------------------------------------------------------

    for match in AUTH_HEADER_PATTERN.finditer(text):

        value = match.group(0)

        finding = _build_finding(
            finding_type="authorization_header",
            source_type=source_type,
            location=location,
            text=text,
            start=match.start(),
            end=match.end(),
            value=value,
        )

        findings.append(finding)

        if len(findings) >= DEFAULT_MAX_FINDINGS:
            return findings

    # --------------------------------------------------------
    # 4. Sensitive URL detection
    # --------------------------------------------------------

    for match in SENSITIVE_URL_PATTERN.finditer(text):

        value = match.group(0)

        finding = _build_finding(
            finding_type="credential_url",
            source_type=source_type,
            location=location,
            text=text,
            start=match.start(),
            end=match.end(),
            value=value,
        )

        findings.append(finding)

        if len(findings) >= DEFAULT_MAX_FINDINGS:
            return findings

    # --------------------------------------------------------
    # 5. Suspicious encoded values
    # --------------------------------------------------------

    # Look specifically around credential-related assignments.
    encoded_assignment = re.compile(
        r"""
        \b
        (?:
            token|
            secret|
            password|
            api[_-]?key|
            access[_-]?token|
            auth[_-]?token|
            client[_-]?secret
        )
        \b
        \s*[:=]\s*
        ["']
        ([A-Za-z0-9+/]{20,}={0,2})
        ["']
        """,
        re.I | re.X,
    )

    for match in encoded_assignment.finditer(text):

        encoded = match.group(1)

        if not _looks_like_encoded_secret(encoded):
            continue

        finding = _build_finding(
            finding_type="encoded_secret_candidate",
            source_type=source_type,
            location=location,
            text=text,
            start=match.start(),
            end=match.end(),
            value=encoded,
        )

        findings.append(finding)

        if len(findings) >= DEFAULT_MAX_FINDINGS:
            return findings

    return findings


# ============================================================
# DEDUPLICATION
# ============================================================

def _deduplicate_findings(
    findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    unique: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:

        key = (
            finding.get("type", ""),
            finding.get("location", ""),
            _normalize_secret_for_dedupe(
                finding.get("value_redacted", "")
            ),
        )

        existing = unique.get(key)

        if existing is None:
            unique[key] = finding
            continue

        # Keep the strongest severity/confidence.
        severity_rank = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
        }

        current_rank = severity_rank.get(
            finding.get("severity", "LOW"),
            1,
        )

        old_rank = severity_rank.get(
            existing.get("severity", "LOW"),
            1,
        )

        if current_rank > old_rank:
            unique[key] = finding

    return list(unique.values())


# ============================================================
# ASSET COLLECTION
# ============================================================

def _collect_same_origin_assets(
    *,
    base: str,
    root_html: str,
    verify_tls: bool,
    timeout: float,
    max_assets: int,
    max_body_per_asset: int,
    max_total_bytes: int,
) -> tuple[list[dict[str, Any]], list[str]]:

    parser = ScriptParser()

    try:
        parser.feed(root_html or "")
    except Exception:
        pass

    assets: list[dict[str, Any]] = []
    warnings: list[str] = []

    seen_urls: set[str] = set()
    total_bytes = 0

    candidate_urls: list[tuple[str, str]] = []

    # --------------------------------------------------------
    # JavaScript sources from <script src>
    # --------------------------------------------------------

    for src in parser.script_sources:

        absolute = urljoin(base, src)

        if same_origin(base, absolute):
            candidate_urls.append(
                (absolute, "external-js")
            )

    # --------------------------------------------------------
    # Inline source-map references cannot be fetched directly
    # here; they are handled after each JS asset is retrieved.
    # --------------------------------------------------------

    for js_url, source_type in candidate_urls:

        if len(assets) >= max_assets:
            break

        if js_url in seen_urls:
            continue

        seen_urls.add(js_url)

        if total_bytes >= max_total_bytes:
            warnings.append(
                "Maximum total JavaScript scan budget reached."
            )
            break

        try:
            response = request(
                js_url,
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                max_body=max_body_per_asset,
            )
        except Exception:
            continue

        if response.status_code < 200 or response.status_code >= 300:
            continue

        content_type = (
            response.headers.get("Content-Type", "")
            .lower()
        )

        # Don't assume extension is enough.
        # Accept common JS MIME types and also JS-like .js URLs.
        is_js = (
            "javascript" in content_type
            or "ecmascript" in content_type
            or js_url.split("?", 1)[0].lower().endswith(".js")
        )

        if not is_js:
            continue

        text = response.text or ""

        encoded_size = len(text.encode("utf-8", errors="ignore"))

        remaining = max_total_bytes - total_bytes

        if encoded_size > remaining:
            text = text[:remaining]
            encoded_size = len(
                text.encode("utf-8", errors="ignore")
            )

        total_bytes += encoded_size

        assets.append(
            {
                "url": js_url,
                "source_type": source_type,
                "text": text,
                "content_type": content_type,
            }
        )

    return assets, warnings


# ============================================================
# SOURCE MAP COLLECTION
# ============================================================

def _collect_source_maps(
    *,
    assets: list[dict[str, Any]],
    base: str,
    verify_tls: bool,
    timeout: float,
    max_source_maps: int,
    max_body: int,
) -> list[dict[str, Any]]:

    source_maps: list[dict[str, Any]] = []

    seen_maps: set[str] = set()

    for asset in assets:

        if len(source_maps) >= max_source_maps:
            break

        js_url = asset["url"]
        js_text = asset["text"]

        reference = _extract_source_map_reference(js_text)

        if not reference:
            continue

        map_url = urljoin(js_url, reference)

        if not same_origin(base, map_url):
            continue

        if map_url in seen_maps:
            continue

        seen_maps.add(map_url)

        try:
            response = request(
                map_url,
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                max_body=max_body,
            )
        except Exception:
            continue

        if response.status_code != 200:
            continue

        content = response.text or ""

        recovered_sources = _extract_source_map_text(
            content
        )

        for index, source in enumerate(
            recovered_sources
        ):
            source_maps.append(
                {
                    "url": map_url,
                    "source_type": "source-map",
                    "text": source,
                    "source_index": index,
                }
            )

            if len(source_maps) >= max_source_maps:
                break

    return source_maps


# ============================================================
# EXTRA CLIENT-SIDE CONTENT
# ============================================================

def _build_extra_blobs(
    *,
    html: str,
    parser: ScriptParser,
) -> list[tuple[str, str, str]]:

    blobs: list[tuple[str, str, str]] = []

    # HTML comments
    for index, comment in enumerate(parser.comments):
        blobs.append(
            (
                f"#html-comment-{index + 1}",
                comment,
                "html-comment",
            )
        )

    # Meta tags
    for index, value in enumerate(parser.meta_values):
        blobs.append(
            (
                f"#meta-{index + 1}",
                value,
                "html-meta",
            )
        )

    # Inline JS
    for index, script in enumerate(parser.inline_scripts):
        blobs.append(
            (
                f"#inline-script-{index + 1}",
                script,
                "inline-js",
            )
        )

    # Inline JSON/config
    for index, blob in enumerate(parser.inline_json):
        blobs.append(
            (
                f"#inline-json-{index + 1}",
                blob,
                "inline-json",
            )
        )

    # Raw HTML itself.
    blobs.append(
        (
            "#document",
            html or "",
            "html",
        )
    )

    return blobs


# ============================================================
# SUMMARY / CLASSIFICATION
# ============================================================

def _classify_overall(
    findings: list[dict[str, Any]],
) -> str:

    if not findings:
        return "SAFE"

    high = [
        x for x in findings
        if x.get("severity") == "HIGH"
    ]

    medium = [
        x for x in findings
        if x.get("severity") == "MEDIUM"
    ]

    if high:
        return "UNSAFE"

    if medium:
        return "REVIEW REQUIRED"

    return "REVIEW REQUIRED"


def _finding_summary(
    findings: list[dict[str, Any]]
) -> str:

    if not findings:
        return (
            "No strong hardcoded credential or secret pattern "
            "was detected in the bounded client-accessible content."
        )

    high = sum(
        1
        for x in findings
        if x.get("severity") == "HIGH"
    )

    medium = sum(
        1
        for x in findings
        if x.get("severity") == "MEDIUM"
    )

    return (
        f"Detected {len(findings)} credential/secret candidate(s) "
        f"within the tested client-accessible content "
        f"({high} high-confidence, {medium} medium-confidence). "
        "Manual validation is required before treating candidates "
        "as confirmed live credentials."
    )


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_hardcoded_credentials(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
    max_assets: int = DEFAULT_MAX_ASSETS,
    max_body_per_asset: int = DEFAULT_MAX_BODY_PER_ASSET,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> dict:

    base = normalize_url(url)

    # --------------------------------------------------------
    # FETCH ROOT DOCUMENT
    # --------------------------------------------------------

    try:
        root = request(
            base,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            max_body=max_body_per_asset,
        )
    except Exception as exc:
        return connection_result(exc)

    if root.status_code < 200 or root.status_code >= 300:
        return result(
            "INCOMPLETE",
            (
                "The target root response could not be reliably "
                "assessed for client-side hardcoded credentials."
            ),
            details={
                "status_code": root.status_code,
                "url": base,
            },
        )

    root_text = root.text or ""

    parser = ScriptParser()

    try:
        parser.feed(root_text)
    except Exception:
        parser = ScriptParser()

    # --------------------------------------------------------
    # COLLECT INITIAL CONTENT BLOBS
    # --------------------------------------------------------

    blobs: list[tuple[str, str, str]] = _build_extra_blobs(
        html=root_text,
        parser=parser,
    )

    # --------------------------------------------------------
    # COLLECT SAME-ORIGIN JS
    # --------------------------------------------------------

    assets, collection_warnings = _collect_same_origin_assets(
        base=base,
        root_html=root_text,
        verify_tls=verify_tls,
        timeout=timeout,
        max_assets=max_assets,
        max_body_per_asset=max_body_per_asset,
        max_total_bytes=max_total_bytes,
    )

    # Add external JS blobs.
    for asset in assets:
        blobs.append(
            (
                asset["url"],
                asset["text"],
                asset["source_type"],
            )
        )

    # --------------------------------------------------------
    # SOURCE MAPS
    # --------------------------------------------------------

    source_maps = _collect_source_maps(
        assets=assets,
        base=base,
        verify_tls=verify_tls,
        timeout=timeout,
        max_source_maps=DEFAULT_MAX_SOURCE_MAPS,
        max_body=max_body_per_asset,
    )

    for source_map in source_maps:
        blobs.append(
            (
                f"{source_map['url']}#source-{source_map['source_index']}",
                source_map["text"],
                "source-map",
            )
        )

    # --------------------------------------------------------
    # ANALYZE EVERYTHING
    # --------------------------------------------------------

    findings: list[dict[str, Any]] = []

    for location, text, source_type in blobs:

        if not text:
            continue

        current = _analyze_text(
            text=text,
            location=location,
            source_type=source_type,
        )

        findings.extend(current)

        if len(findings) >= DEFAULT_MAX_FINDINGS:
            findings = findings[:DEFAULT_MAX_FINDINGS]
            break

    # --------------------------------------------------------
    # DEDUPLICATION
    # --------------------------------------------------------

    findings = _deduplicate_findings(findings)

    # --------------------------------------------------------
    # FINAL CLASSIFICATION
    # --------------------------------------------------------

    overall_status = _classify_overall(findings)

    evidence: list[str] = []

    for finding in findings[:50]:

        evidence.append(
            (
                f"{finding['type']} detected in "
                f"{finding['source_type']} at "
                f"{finding['location']} "
                f"(severity={finding['severity']}, "
                f"confidence={finding['confidence']})"
            )
        )

    details: dict[str, Any] = {
        "target": base,
        "root_status_code": root.status_code,

        "javascript_assets_checked": [
            asset["url"]
            for asset in assets
        ],

        "javascript_asset_count": len(assets),

        "source_maps_checked": [
            item["url"]
            for item in source_maps
        ],

        "source_map_count": len(source_maps),

        "content_types": {
            asset["url"]: asset["content_type"]
            for asset in assets
        },

        "findings": findings,

        "scan_limits": {
            "max_assets": max_assets,
            "max_body_per_asset": max_body_per_asset,
            "max_total_bytes": max_total_bytes,
            "max_source_maps": DEFAULT_MAX_SOURCE_MAPS,
            "max_findings": DEFAULT_MAX_FINDINGS,
        },

        "warnings": collection_warnings,
    }

    if overall_status == "UNSAFE":
        summary = (
            "High-confidence hardcoded credential or secret "
            "patterns were detected in client-accessible content. "
            "The affected values must be manually validated and "
            "rotated/revoked where they are confirmed to be real."
        )

    elif overall_status == "REVIEW REQUIRED":
        summary = _finding_summary(findings)

    else:
        summary = _finding_summary(findings)

    return result(
        overall_status,
        summary,
        details=details,
        evidence=evidence,
    )