from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import unescape
from typing import Any
from urllib.parse import urlparse

from payloads.manager import load_lines, load_optional_sample, load_optional_lines

from .common import (
    absolute,
    normalize_url,
    origin_root_url,
    request,
    result,
    connection_result,
)


# ============================================================================
# Limits
# ============================================================================

MAX_PROBES = 60
MAX_BODY_BYTES = 64_000
MAX_TEXT_CHARS = 80_000


# ============================================================================
# Directly interesting resources
# ============================================================================

def _direct_probes(seed: str = "") -> tuple[str, ...]:
    """Combine sensitive-file sources without always selecting the wordlist head."""
    upstream = (
        load_optional_sample(
            "upstream/SecLists/Discovery/Web-Content/common.txt",
            28,
            seed=f"{seed}:seclists-common",
        )
        + load_optional_sample(
            "upstream/SecLists/Discovery/Web-Content/raft-small-files.txt",
            28,
            seed=f"{seed}:seclists-files",
        )
        + load_optional_sample(
            "upstream/FuzzDB/discovery/predictable-filepaths/Randomfiles.txt",
            10,
            seed=f"{seed}:fuzzdb-files",
        )
    )
    curated = (
        load_lines("seclists/discovery/sensitive_file_candidates.txt", limit=40)
        + load_lines("fuzzdb/discovery/predictable_filepaths_curated.txt", limit=20)
    )
    return tuple(dict.fromkeys(curated + upstream))


# Backup/source variants are file-backed so the scanner contains no embedded
# path/suffix wordlists. These are small, bounded discovery candidates only.
BACKUP_SUFFIXES = tuple(load_lines("seclists/discovery/backup_suffixes.txt", limit=10))
SOURCE_CONFIG_BASES = tuple(load_lines("seclists/discovery/source_config_bases.txt", limit=20))

def _build_probe_list(seed: str = "") -> list[str]:
    probes = list(_direct_probes(seed))

    for base in SOURCE_CONFIG_BASES:
        for suffix in BACKUP_SUFFIXES:
            probes.append(
                f"{base}{suffix}"
            )

    return list(dict.fromkeys(probes))[:MAX_PROBES]


# ============================================================================
# Content signatures
# ============================================================================

ENV_ASSIGNMENT_RE = re.compile(
    r"(?m)^[A-Z][A-Z0-9_]{2,64}\s*=\s*(?:.+)$"
)

SECRET_KEY_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|passphrase|"
    r"secret|secret_key|"
    r"api[_-]?key|"
    r"access[_-]?key|"
    r"private[_-]?key|"
    r"token|"
    r"auth[_-]?token|"
    r"client[_-]?secret"
    r")\s*[:=]\s*"
)

CONNECTION_STRING_RE = re.compile(
    r"(?i)\b("
    r"jdbc:[^\s\"']+|"
    r"mysql://[^\s\"']+|"
    r"postgres(?:ql)?://[^\s\"']+|"
    r"mongodb(?:\+srv)?://[^\s\"']+|"
    r"redis://[^\s\"']+"
    r")"
)

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    re.IGNORECASE,
)

AWS_ACCESS_KEY_RE = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
)

JWT_RE = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{10,}\."
)

PHP_SOURCE_RE = re.compile(
    r"(?i)<\?(?:php|=)|\b(?:require|include|mysqli|PDO)\s*\("
)

JAVA_PROPERTIES_RE = re.compile(
    r"(?im)^\s*(?:spring\.|datasource\.|server\.|management\.)[^=\r\n]*="
)

GIT_HEAD_RE = re.compile(
    r"(?im)^ref:\s+refs/"
)

GIT_CONFIG_RE = re.compile(
    r"(?im)^\s*\[(?:core|remote|branch|user|credential)"
)

PHPINFO_RE = re.compile(
    r"(?i)"
    r"phpinfo\(\)|"
    r"php version|"
    r"configuration directive|"
    r"loaded configuration file"
)

SERVER_STATUS_RE = re.compile(
    r"(?i)"
    r"server status|"
    r"apache server status|"
    r"requests currently being processed"
)


# ============================================================================
# Data structure
# ============================================================================

@dataclass
class ContentFinding:
    category: str
    confidence: str
    description: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
        }


# ============================================================================
# Redaction
# ============================================================================

def _redact_value(value: str) -> str:
    """
    Do not expose actual secrets in scanner output.
    """

    value = value.strip()

    if len(value) <= 6:
        return "***"

    return (
        value[:2]
        + "***"
        + value[-2:]
    )


def _redact_sensitive_assignments(
    text: str,
) -> str:

    def replacement(
        match: re.Match,
    ) -> str:

        key = match.group(1)
        separator = match.group(2)
        value = match.group(3)

        return (
            f"{key}{separator}"
            f"{_redact_value(value)}"
        )

    return re.sub(
        r"(?im)^(\s*[A-Za-z_][A-Za-z0-9_.-]*)"
        r"(\s*[:=]\s*)"
        r"(.+?)\s*$",
        replacement,
        text,
    )


# ============================================================================
# HTML helpers
# ============================================================================

def _extract_title(
    body: str,
) -> str:

    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return ""

    title = re.sub(
        r"<[^>]+>",
        " ",
        match.group(1),
    )

    return re.sub(
        r"\s+",
        " ",
        unescape(title),
    ).strip()[:300]


def _looks_like_application_html(
    body: str,
) -> bool:

    lower = body.lower()

    indicators = (
        "<html",
        "<body",
        "<head",
        "<script",
        "webpack",
        "__next_data__",
        "ng-version",
        "react",
        "vue",
        "angular",
    )

    return any(
        indicator in lower
        for indicator in indicators
    )


# ============================================================================
# Binary/content helpers
# ============================================================================

def _looks_like_zip(
    content: bytes,
) -> bool:

    return (
        content.startswith(
            b"PK\x03\x04"
        )
        or content.startswith(
            b"PK\x05\x06"
        )
        or content.startswith(
            b"PK\x07\x08"
        )
    )


def _looks_like_gzip(
    content: bytes,
) -> bool:

    return content.startswith(
        b"\x1f\x8b"
    )


def _looks_like_pdf(
    content: bytes,
) -> bool:

    return content.startswith(
        b"%PDF-"
    )


def _looks_like_tar(
    content: bytes,
) -> bool:

    if len(content) < 265:
        return False

    return (
        content[257:262]
        in {
            b"ustar",
            b"ustar ",
        }
    )


# ============================================================================
# Sensitive-content analysis
# ============================================================================

def _analyse_text(
    path: str,
    text: str,
    content_type: str,
) -> list[ContentFinding]:

    findings: list[ContentFinding] = []

    sample = text[
        :MAX_TEXT_CHARS
    ]

    lower = sample.lower()

    # ------------------------------------------------------------
    # .env-like content
    # ------------------------------------------------------------

    env_matches = ENV_ASSIGNMENT_RE.findall(
        sample
    )

    secret_matches = SECRET_KEY_RE.findall(
        sample
    )

    if (
        path.lower().startswith("/.env")
        and len(env_matches) >= 2
    ):

        findings.append(
            ContentFinding(
                category="environment_configuration",
                confidence="high",
                description=(
                    "The response resembles an environment "
                    "configuration file."
                ),
                evidence=(
                    f"{len(env_matches)} environment-style "
                    "assignments detected; values redacted."
                ),
            )
        )

    # ------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------

    if secret_matches:

        findings.append(
            ContentFinding(
                category="credential_or_secret",
                confidence="high",
                description=(
                    "Credential/secret-style configuration "
                    "assignments were detected."
                ),
                evidence=(
                    "Sensitive key names were detected; "
                    "actual values are intentionally redacted."
                ),
            )
        )

    # ------------------------------------------------------------
    # Connection strings
    # ------------------------------------------------------------

    if CONNECTION_STRING_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="connection_string",
                confidence="high",
                description=(
                    "A database/service connection string "
                    "was detected."
                ),
                evidence=(
                    "Connection-string pattern detected; "
                    "the value is intentionally not recorded."
                ),
            )
        )

    # ------------------------------------------------------------
    # Private keys
    # ------------------------------------------------------------

    if PRIVATE_KEY_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="private_key",
                confidence="high",
                description=(
                    "A private-key PEM marker was detected "
                    "in a publicly accessible resource."
                ),
                evidence=(
                    "Private-key header detected; key material "
                    "was not retained."
                ),
            )
        )

    # ------------------------------------------------------------
    # AWS access-key pattern
    # ------------------------------------------------------------

    if AWS_ACCESS_KEY_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="cloud_credential",
                confidence="high",
                description=(
                    "A credential-like cloud access-key pattern "
                    "was detected."
                ),
                evidence=(
                    "Access-key pattern detected; the value "
                    "was not retained."
                ),
            )
        )

    # ------------------------------------------------------------
    # JWT-like token
    # ------------------------------------------------------------

    if JWT_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="token",
                confidence="medium",
                description=(
                    "A JWT-like token pattern was detected."
                ),
                evidence=(
                    "Token-like structure detected; actual token "
                    "was not retained."
                ),
            )
        )

    # ------------------------------------------------------------
    # PHP source
    # ------------------------------------------------------------

    if PHP_SOURCE_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="source_code",
                confidence="high",
                description=(
                    "Server-side PHP source-code patterns "
                    "were returned as content."
                ),
                evidence=(
                    "PHP source markers detected."
                ),
            )
        )

    # ------------------------------------------------------------
    # Java/Spring configuration
    # ------------------------------------------------------------

    if JAVA_PROPERTIES_RE.search(
        sample
    ):

        findings.append(
            ContentFinding(
                category="application_configuration",
                confidence="high",
                description=(
                    "Java/Spring-style application "
                    "configuration was exposed."
                ),
                evidence=(
                    "Spring/application property assignments detected."
                ),
            )
        )

    # ------------------------------------------------------------
    # phpinfo
    # ------------------------------------------------------------

    if (
        "phpinfo.php"
        in path.lower()
        and PHPINFO_RE.search(
            sample
        )
    ):

        findings.append(
            ContentFinding(
                category="diagnostic_information",
                confidence="high",
                description=(
                    "A PHP diagnostic information page "
                    "appears to be publicly accessible."
                ),
                evidence=(
                    "phpinfo-related markers detected."
                ),
            )
        )

    # ------------------------------------------------------------
    # server-status
    # ------------------------------------------------------------

    if (
        "server-status"
        in path.lower()
        and SERVER_STATUS_RE.search(
            sample
        )
    ):

        findings.append(
            ContentFinding(
                category="server_status",
                confidence="high",
                description=(
                    "A server-status/diagnostic page "
                    "appears to be publicly accessible."
                ),
                evidence=(
                    "Server-status markers detected."
                ),
            )
        )

    # ------------------------------------------------------------
    # Generic config files
    # ------------------------------------------------------------

    config_names = (
        "config.php",
        "config.yml",
        "config.yaml",
        "config.json",
        "application.properties",
        "application.yml",
        "application.yaml",
        "web.config",
    )

    if any(
        name in path.lower()
        for name in config_names
    ):

        if (
            secret_matches
            or CONNECTION_STRING_RE.search(
                sample
            )
            or "=" in sample
            or (
                "{" in sample
                and "}" in sample
            )
        ):

            findings.append(
                ContentFinding(
                    category="configuration_file",
                    confidence="high",
                    description=(
                        "A configuration-like resource "
                        "was directly returned."
                    ),
                    evidence=(
                        "Configuration syntax detected; "
                        "sensitive values are not retained."
                    ),
                )
            )

    # ------------------------------------------------------------
    # Package metadata
    # ------------------------------------------------------------

    if path.lower().endswith(
        (
            "package.json",
            "composer.json",
        )
    ):

        try:
            parsed_json = json.loads(
                sample
            )

            if isinstance(
                parsed_json,
                dict,
            ):

                interesting = any(
                    key in parsed_json
                    for key in (
                        "name",
                        "version",
                        "dependencies",
                        "devDependencies",
                    )
                )

                if interesting:

                    findings.append(
                        ContentFinding(
                            category="project_metadata",
                            confidence="medium",
                            description=(
                                "Project/package metadata is publicly "
                                "accessible."
                            ),
                            evidence=(
                                "Application dependency metadata detected."
                            ),
                        )
                    )

        except (
            ValueError,
            TypeError,
        ):
            pass

    return findings


# ============================================================================
# Git detection
# ============================================================================

def _analyse_git_resource(
    path: str,
    text: str,
) -> list[ContentFinding]:

    findings: list[
        ContentFinding
    ] = []

    if path.lower() == "/.git/head":

        if GIT_HEAD_RE.search(
            text[:10_000]
        ):

            findings.append(
                ContentFinding(
                    category="version_control_metadata",
                    confidence="high",
                    description=(
                        "A readable Git HEAD reference was returned."
                    ),
                    evidence=(
                        "Valid Git ref: syntax detected."
                    ),
                )
            )

    elif path.lower() == "/.git/config":

        if GIT_CONFIG_RE.search(
            text[:20_000]
        ):

            findings.append(
                ContentFinding(
                    category="version_control_metadata",
                    confidence="high",
                    description=(
                        "A readable Git configuration file "
                        "was returned."
                    ),
                    evidence=(
                        "Git configuration sections detected."
                    ),
                )
            )

    return findings


# ============================================================================
# Main scanner
# ============================================================================

def scan_sensitive_file_exposure(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
    max_file_bytes: int = MAX_BODY_BYTES,
) -> dict:
    """
    TC13 - Sensitive File Exposure

    Scope:
        Identify publicly accessible sensitive/configuration/backup/
        diagnostic/version-control resources using a bounded set of
        targeted probes.

    Safety:
        - Uses GET only for content inspection.
        - Does not attempt authentication.
        - Does not brute-force arbitrary filenames.
        - Does not recursively download Git repositories.
        - Does not download large archives in full.
        - Never stores actual detected secret values in evidence.
    """

    input_target = normalize_url(url)
    base = origin_root_url(input_target)

    probes = _build_probe_list(base)

    details: dict[str, Any] = {
        "input_target": input_target,
        "target": base,
        "probe_count": len(probes),
        "tested": [],
        "findings": [],
        "payload_library": {
            "sources": ["SecLists (curated subset)", "FuzzDB (curated subset)"],
            "files": ["payloads/seclists/discovery/sensitive_file_candidates.txt", "payloads/seclists/discovery/source_config_bases.txt", "payloads/seclists/discovery/backup_suffixes.txt", "payloads/fuzzdb/discovery/predictable_filepaths_curated.txt"],
            "optional_upstream_files": ["payloads/upstream/SecLists/Discovery/Web-Content/common.txt", "payloads/upstream/FuzzDB/discovery/predictable-filepaths/Randomfiles.txt"],
            "max_probes": MAX_PROBES,
        },
        "limits": {
            "max_probes": MAX_PROBES,
            "max_file_bytes": max_file_bytes,
        },
    }

    unsafe_findings: list[
        dict[str, Any]
    ] = []

    review_findings: list[
        dict[str, Any]
    ] = []

    completed_count = 0
    failed_count = 0

    # ========================================================================
    # Probe each resource
    # ========================================================================

    for path in probes:

        target = absolute(
            base,
            path,
        )

        try:

            response = request(
                target,
                method="GET",
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                headers={
                    # Ask for a bounded range when the underlying server
                    # supports it. Some servers may ignore Range.
                    "Range": (
                        f"bytes=0-{max_file_bytes - 1}"
                    ),
                },
                max_body=max_file_bytes,
            )

            completed_count += 1

        except Exception as exc:

            failed_count += 1

            details["tested"].append(
                {
                    "path": path,
                    "requested_url": target,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
            )

            continue

        body_bytes = (
            getattr(
                response,
                "content",
                b"",
            )
            or b""
        )

        # Protect memory/reporting.
        body_bytes = body_bytes[
            :max_file_bytes
        ]

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        content_disposition = (
            response.headers.get(
                "Content-Disposition",
                "",
            )
        )

        location = response.headers.get(
            "Location",
            "",
        )

        status_code = response.status_code

        entry: dict[str, Any] = {
            "path": path,
            "requested_url": target,
            "status_code": status_code,
            "content_type": content_type,
            "content_disposition": (
                content_disposition[:1000]
            ),
            "content_length": response.headers.get(
                "Content-Length"
            ),
            "content_range": response.headers.get(
                "Content-Range"
            ),
            "location": location[:2000],
            "sample_bytes": len(
                body_bytes
            ),
        }

        # ====================================================================
        # HTTP status handling
        # ====================================================================

        if status_code in {
            401,
            403,
        }:

            entry[
                "access_controlled"
            ] = True

            details["tested"].append(
                entry
            )

            continue

        if status_code in {
            404,
            410,
        }:

            entry[
                "resource_not_found"
            ] = True

            details["tested"].append(
                entry
            )

            continue

        if 300 <= status_code < 400:

            entry[
                "redirect_only"
            ] = True

            # A redirect to login or another same-site application route
            # does not establish sensitive-file exposure.
            details["tested"].append(
                entry
            )

            continue

        if status_code >= 500:

            entry[
                "server_error"
            ] = True

            review_findings.append(
                {
                    "path": path,
                    "status_code": status_code,
                    "reason": (
                        "Server returned an error while probing "
                        "a potentially sensitive resource."
                    ),
                }
            )

            details["tested"].append(
                entry
            )

            continue

        if status_code not in {
            200,
            206,
        }:

            entry[
                "unexpected_status"
            ] = True

            details["tested"].append(
                entry
            )

            continue

        # ====================================================================
        # Binary resource detection
        # ====================================================================

        binary_signatures: list[str] = []

        if _looks_like_zip(
            body_bytes
        ):
            binary_signatures.append(
                "ZIP"
            )

        if _looks_like_gzip(
            body_bytes
        ):
            binary_signatures.append(
                "GZIP"
            )

        if _looks_like_tar(
            body_bytes
        ):
            binary_signatures.append(
                "TAR"
            )

        if _looks_like_pdf(
            body_bytes
        ):
            binary_signatures.append(
                "PDF"
            )

        entry[
            "binary_signatures"
        ] = binary_signatures

        # ====================================================================
        # Archive handling
        # ====================================================================

        archive_path = path.lower().endswith(
            (
                ".zip",
                ".tar",
                ".tar.gz",
                ".tgz",
                ".gz",
            )
        )

        if (
            archive_path
            or binary_signatures
        ):

            if binary_signatures:

                finding = {
                    "path": path,
                    "status_code": status_code,
                    "category": "archive_or_binary_resource",
                    "reason": (
                        "A publicly accessible binary/archive "
                        "resource was identified."
                    ),
                    "signatures": binary_signatures,
                }

                # An openly accessible backup archive is a meaningful
                # security finding; however we avoid claiming the archive
                # contains secrets until its contents are safely inspected.
                if any(
                    token in path.lower()
                    for token in (
                        "backup",
                        "site",
                        "www",
                    )
                ):

                    unsafe_findings.append(
                        finding
                    )

                else:

                    review_findings.append(
                        finding
                    )

            else:

                review_findings.append(
                    {
                        "path": path,
                        "status_code": status_code,
                        "category": "binary_resource",
                        "reason": (
                            "A resource expected to be binary "
                            "was publicly accessible, but its "
                            "content signature could not be "
                            "confirmed within the bounded sample."
                        ),
                    }
                )

            entry[
                "analysis_skipped_as_binary"
            ] = True

            details["tested"].append(
                entry
            )

            if (
                unsafe_findings
                and unsafe_findings[-1].get(
                    "path"
                ) == path
            ):
                details["findings"].append(
                    unsafe_findings[-1]
                )

            continue

        # ====================================================================
        # Decode text safely
        # ====================================================================

        text = body_bytes.decode(
            "utf-8",
            errors="replace",
        )

        entry[
            "title"
        ] = _extract_title(
            text
        )

        entry[
            "looks_like_html"
        ] = _looks_like_application_html(
            text
        )

        # ====================================================================
        # SPA/generic application fallback
        # ====================================================================

        if (
            entry["looks_like_html"]
            and not content_type.lower().startswith(
                (
                    "text/plain",
                    "application/octet-stream",
                )
            )
        ):

            title = entry[
                "title"
            ].lower()

            # Generic HTML page can be a route fallback.
            #
            # We do not flag it simply because the requested sensitive path
            # returned HTTP 200.
            generic_app_page = (
                title
                not in {
                    "",
                    "index of /",
                    "directory listing",
                }
                and (
                    "<html"
                    in text[:10_000].lower()
                )
            )

            entry[
                "generic_application_html"
            ] = generic_app_page

        # ====================================================================
        # Content analysis
        # ====================================================================

        findings = _analyse_text(
            path,
            text,
            content_type,
        )

        findings.extend(
            _analyse_git_resource(
                path,
                text,
            )
        )

        entry[
            "content_findings"
        ] = [
            finding.as_dict()
            for finding in findings
        ]

        # ====================================================================
        # Generic application fallback protection
        # ====================================================================

        if (
            entry.get(
                "generic_application_html",
                False,
            )
            and not findings
        ):

            entry[
                "likely_application_fallback"
            ] = True

            details["tested"].append(
                entry
            )

            continue

        # ====================================================================
        # High-confidence exposure
        # ====================================================================

        high_confidence = [
            finding
            for finding in findings
            if finding.confidence == "high"
        ]

        medium_confidence = [
            finding
            for finding in findings
            if finding.confidence == "medium"
        ]

        if high_confidence:

            finding_record = {
                "path": path,
                "status_code": status_code,
                "category": (
                    high_confidence[0].category
                ),
                "reason": (
                    high_confidence[0].description
                ),
                "matches": [
                    finding.as_dict()
                    for finding in high_confidence
                ],
            }

            unsafe_findings.append(
                finding_record
            )

            details["findings"].append(
                finding_record
            )

        elif medium_confidence:

            finding_record = {
                "path": path,
                "status_code": status_code,
                "category": (
                    medium_confidence[0].category
                ),
                "reason": (
                    medium_confidence[0].description
                ),
                "matches": [
                    finding.as_dict()
                    for finding in medium_confidence
                ],
            }

            review_findings.append(
                finding_record
            )

        details["tested"].append(
            entry
        )

    # ========================================================================
    # Final classification
    # ========================================================================

    details[
        "statistics"
    ] = {
        "total_probes": len(
            probes
        ),
        "completed": completed_count,
        "failed": failed_count,
        "unsafe_count": len(
            unsafe_findings
        ),
        "review_count": len(
            review_findings
        ),
    }

    # ------------------------------------------------------------------------
    # Confirmed sensitive exposure
    # ------------------------------------------------------------------------

    if unsafe_findings:

        evidence = []

        for finding in unsafe_findings:

            evidence.append(
                (
                    f"{finding['path']} -> "
                    f"HTTP {finding['status_code']}: "
                    f"{finding['reason']}"
                )
            )

            for match in finding.get(
                "matches",
                [],
            )[:5]:

                evidence.append(
                    (
                        f"{finding['path']}: "
                        f"{match['evidence']}"
                    )
                )

        return result(
            "UNSAFE",
            "One or more publicly accessible resources were confirmed to expose sensitive configuration, source code, version-control metadata, diagnostics, credentials, or potentially sensitive backup content.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Review-only findings
    # ------------------------------------------------------------------------

    if review_findings:

        details[
            "review_findings"
        ] = review_findings

        return result(
            "REVIEW REQUIRED",
            "One or more resources require manual review because they were publicly reachable or produced suspicious content, but the scanner could not safely establish a high-confidence sensitive-data exposure.",
            details=details,
            evidence=[
                (
                    f"{finding.get('path')}: "
                    f"{finding.get('reason')}"
                )
                for finding in review_findings[:30]
            ],
        )

    # ------------------------------------------------------------------------
    # No probes succeeded
    # ------------------------------------------------------------------------

    if completed_count == 0:

        return result(
            "INCOMPLETE",
            "None of the configured sensitive-resource probes completed successfully, so sensitive-file exposure could not be assessed reliably.",
            details=details,
        )

    # ------------------------------------------------------------------------
    # Safe
    # ------------------------------------------------------------------------

    return result(
        "SAFE",
        "No high-confidence sensitive file, source-code, configuration, version-control, credential, diagnostic, or backup exposure was confirmed by the bounded probes.",
        details=details,
    )