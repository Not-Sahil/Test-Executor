from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from html import unescape
from typing import Optional
from urllib.parse import urlparse, urlsplit, urlunsplit

from .common import absolute, normalize_url, request, result, connection_result, text_sample

# ---------------------------------------------------------------------------
# TC04 - robots.txt / review web-server metafiles for information leakage
#
# Scope:
#   * Retrieve /robots.txt from the supplied target.
#   * Validate that the response actually resembles robots.txt.
#   * Parse User-agent / Allow / Disallow / Sitemap directives.
#   * Identify potentially interesting paths disclosed by robots.txt.
#   * Probe only paths that were actually disclosed, with a strict cap.
#   * Classify the probed resource using status, content type, title and
#     conservative content indicators.
#
# This is intentionally bounded. It is not a directory brute-forcer.
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 10.0
MAX_DISCLOSED_PATHS = 50
MAX_PROBES = 12
MAX_BODY_FOR_ANALYSIS = 80_000
MAX_SAMPLE_CHARS = 700

SENSITIVE_HINTS = (
    "admin",
    "administrator",
    "backend",
    "backup",
    "backups",
    "config",
    "configuration",
    "database",
    "db",
    "debug",
    "dev",
    "development",
    "internal",
    "private",
    "secret",
    "secrets",
    "staging",
    "stage",
    "test",
    "testing",
    "upload",
    "uploads",
    "logs",
    "server-status",
    ".git",
    ".env",
    "phpmyadmin",
    "phpinfo",
    "dump",
    "dumps",
    "old",
)

# Files/paths where a 200 response is much more meaningful than a generic
# sensitive-looking directory returning a public login shell or home page.
HIGH_RISK_FILE_HINTS = (
    ".env",
    ".git/",
    ".git\\",
    "config.php",
    "config.yml",
    "config.yaml",
    "application.properties",
    "application.yml",
    "application.yaml",
    "wp-config.php",
    "database.sql",
    "backup.sql",
    "dump.sql",
    "phpinfo.php",
    "server-status",
)

DIRECTORY_INDEX_MARKERS = (
    "index of /",
    "directory listing for",
    "parent directory",
    "name last modified size description",
    "directory /",
)

SENSITIVE_CONTENT_MARKERS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "-----begin private key-----",
    "database_password",
    "db_password",
    "password=",
    "passwd=",
    "secret_key",
    "client_secret",
    "authorization: bearer",
    "jdbc:",
    "mysql://",
    "postgres://",
    "mongodb://",
    "redis://",
)

ADMIN_PAGE_MARKERS = (
    "admin dashboard",
    "administrator dashboard",
    "management console",
    "control panel",
    "admin panel",
    "user management",
    "system management",
)

LOGIN_PAGE_MARKERS = (
    "login",
    "sign in",
    "signin",
    "authenticate",
    "username",
    "password",
)

CONTENT_TYPES_TEXT = (
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "text/xml",
    "application/x-yaml",
)


@dataclass
class RobotsGroup:
    user_agents: list[str]
    allow: list[str]
    disallow: list[str]


@dataclass
class DisclosedPath:
    path: str
    user_agents: list[str]
    directive: str
    sensitive_hints: list[str]
    probeable: bool


@dataclass
class PathProbe:
    path: str
    url: str
    status_code: Optional[int]
    content_type: str
    final_url: str
    title: Optional[str]
    content_length: int
    classification: str
    evidence: list[str]
    body_sample: str = ""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _strip_inline_comment(value: str) -> str:
    # robots comments begin with #. Preserve encoded fragments and only strip
    # an actual literal # comment delimiter.
    return value.split("#", 1)[0].strip()


def _normalise_robot_path(value: str) -> str | None:
    """Return a local path suitable for a bounded probe."""
    raw = _strip_inline_comment(value).strip()
    if not raw:
        return None

    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        # Do not follow absolute/cross-origin entries from robots.txt.
        return None

    if not raw.startswith("/"):
        raw = "/" + raw

    # Robots patterns may contain '*' and '$'. They are valid robots syntax,
    # but they are not literal URLs we should request blindly.
    if "*" in raw or "$" in raw:
        return None

    return raw.split("#", 1)[0]


def _sensitive_hints(path: str) -> list[str]:
    lowered = path.lower()
    return [hint for hint in SENSITIVE_HINTS if hint in lowered]


def _looks_like_robots(body: str, content_type: str) -> bool:
    if not body.strip():
        return True

    ct = (content_type or "").lower()
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    directive_lines = 0

    for line in lines[:200]:
        if re.match(r"^(user-agent|allow|disallow|sitemap|crawl-delay|host|clean-param)\s*:", line, re.I):
            directive_lines += 1

    if "text/plain" in ct and directive_lines >= 1:
        return True
    if directive_lines >= 2:
        return True
    if re.search(r"(?im)^\s*user-agent\s*:\s*\*\s*$", body):
        return True
    if re.search(r"(?im)^\s*disallow\s*:\s*", body):
        return True
    return False


def _parse_robots(body: str) -> tuple[list[RobotsGroup], list[dict], list[str]]:
    groups: list[RobotsGroup] = []
    directives: list[dict] = []
    sitemap_urls: list[str] = []

    current_agents: list[str] = []
    current_allow: list[str] = []
    current_disallow: list[str] = []

    def flush_group() -> None:
        nonlocal current_agents, current_allow, current_disallow
        if current_agents or current_allow or current_disallow:
            groups.append(
                RobotsGroup(
                    user_agents=list(current_agents or ["*"]),
                    allow=list(current_allow),
                    disallow=list(current_disallow),
                )
            )
        current_agents = []
        current_allow = []
        current_disallow = []

    previous_was_rule = False

    for raw_line in body.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            # A blank line normally separates record groups. Keep sitemap
            # lines independent from user-agent groups.
            if previous_was_rule:
                flush_group()
            previous_was_rule = False
            continue

        line = _strip_inline_comment(raw_line)
        if not line or ":" not in line:
            continue

        key, value = [part.strip() for part in line.split(":", 1)]
        key_l = key.lower()
        previous_was_rule = True

        if key_l == "user-agent":
            # A consecutive User-agent line belongs to the same group.
            if current_agents and (current_allow or current_disallow):
                flush_group()
            current_agents.append(value or "*")
            directives.append({"directive": "user-agent", "value": value or "*"})

        elif key_l in {"allow", "disallow"}:
            path = value.strip()
            directives.append({
                "directive": key_l,
                "path": path,
                "user_agents": list(current_agents or ["*"]),
            })
            if key_l == "allow":
                current_allow.append(path)
            else:
                current_disallow.append(path)

        elif key_l == "sitemap":
            if value:
                sitemap_urls.append(value)
            directives.append({"directive": "sitemap", "value": value})

        else:
            directives.append({
                "directive": key_l,
                "value": value,
                "user_agents": list(current_agents or ["*"]),
            })

    flush_group()
    return groups, directives, sitemap_urls


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------


def _extract_title(body: str) -> str | None:
    if not body:
        return None
    match = re.search(r"<title\b[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return None
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:250] if title else None


def _looks_like_html(body: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if "html" in ct:
        return True
    sample = body[:400].lstrip().lower()
    return sample.startswith("<!doctype html") or sample.startswith("<html") or "<body" in sample


def _is_directory_listing(body: str, title: str | None) -> bool:
    text = (body[:30_000] or "").lower()
    title_l = (title or "").lower()
    return any(marker in text or marker in title_l for marker in DIRECTORY_INDEX_MARKERS)


def _has_sensitive_content(body: str) -> list[str]:
    text = (body[:MAX_BODY_FOR_ANALYSIS] or "").lower()
    return [marker for marker in SENSITIVE_CONTENT_MARKERS if marker in text]


def _has_admin_page(body: str, title: str | None) -> list[str]:
    text = (body[:MAX_BODY_FOR_ANALYSIS] or "").lower()
    title_l = (title or "").lower()
    return [marker for marker in ADMIN_PAGE_MARKERS if marker in text or marker in title_l]


def _looks_like_login_shell(body: str, title: str | None) -> bool:
    text = (body[:25_000] or "").lower()
    title_l = (title or "").lower()
    marker_count = sum(1 for marker in LOGIN_PAGE_MARKERS if marker in text or marker in title_l)
    return marker_count >= 2 and (
        "type=\"password\"" in text
        or "type='password'" in text
        or 'name="password"' in text
        or "name='password'" in text
    )


def _classify_probe(path: str, status_code: int | None, content_type: str, final_url: str, body: str) -> tuple[str, list[str]]:
    evidence: list[str] = []
    title = _extract_title(body)
    path_l = path.lower()
    final = urlsplit(final_url)
    final_path = (final.path or "").lower()
    hints = _sensitive_hints(path)
    is_high_risk_file = any(token in path_l for token in HIGH_RISK_FILE_HINTS)

    if status_code is None:
        return "request_failed", ["No HTTP status was available for the disclosed path."]

    if status_code in {401, 403}:
        evidence.append(f"HTTP {status_code}: resource is access-controlled.")
        return "protected", evidence

    if status_code in {404, 410}:
        evidence.append(f"HTTP {status_code}: disclosed path is not currently available.")
        return "not_found", evidence

    if 300 <= status_code < 400:
        if final.scheme.lower() == "https" and "login" in final_path:
            evidence.append(f"HTTP {status_code}: request redirected to an HTTPS login/authentication page.")
            return "protected", evidence
        evidence.append(f"HTTP {status_code}: disclosed path redirects to {final_url}.")
        if final.scheme.lower() == "http":
            evidence.append("Final redirect destination remains on HTTP.")
            return "ambiguous_redirect", evidence
        return "redirected", evidence

    if not 200 <= status_code < 300:
        evidence.append(f"HTTP {status_code}: resource did not return a normal successful response.")
        return "non_success", evidence

    body_limited = body[:MAX_BODY_FOR_ANALYSIS]
    sensitive_markers = _has_sensitive_content(body_limited)
    admin_markers = _has_admin_page(body_limited, title)
    directory_listing = _is_directory_listing(body_limited, title)
    login_shell = _looks_like_login_shell(body_limited, title)
    ct = (content_type or "").lower()

    evidence.append("HTTP 2xx: disclosed resource is directly reachable without authentication being established by the probe.")
    if title:
        evidence.append(f"Page title: {title}")
    if content_type:
        evidence.append(f"Content-Type: {content_type}")

    if directory_listing:
        evidence.append("Directory-index/listing indicators were detected in the response.")
        return "public_sensitive_resource", evidence

    if sensitive_markers:
        evidence.append("Sensitive configuration/secret/connection-string indicators were detected in the response.")
        evidence.extend(f"Sensitive marker: {marker}" for marker in sensitive_markers[:8])
        return "public_sensitive_resource", evidence

    if is_high_risk_file and not _looks_like_html(body_limited, ct):
        evidence.append("A high-risk configuration/metadata file was returned as a non-HTML resource.")
        return "public_sensitive_resource", evidence

    if admin_markers and not login_shell:
        evidence.append("Administrative/management-page indicators were detected without a login-form-only response.")
        evidence.extend(f"Admin marker: {marker}" for marker in admin_markers[:5])
        return "public_sensitive_resource", evidence

    if hints:
        if login_shell:
            evidence.append("The disclosed path appears to be a public login/authentication shell rather than an authenticated administrative resource.")
            return "public_login_shell", evidence
        evidence.append("The path name looks sensitive, but the response did not contain enough evidence to confirm sensitive content exposure.")
        return "public_sensitive_path", evidence

    evidence.append("The disclosed path returned a normal successful response but did not appear sensitive from the available evidence.")
    return "public_normal_resource", evidence


def _probe_disclosed_path(base: str, item: DisclosedPath, verify_tls: bool, timeout: float) -> PathProbe:
    path = item.path
    probe_url = absolute(base, path)

    try:
        response = request(
            probe_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception as exc:
        return PathProbe(
            path=path,
            url=probe_url,
            status_code=None,
            content_type="",
            final_url=probe_url,
            title=None,
            content_length=0,
            classification="request_failed",
            evidence=[f"Request failed: {exc}"],
        )

    body = response.text or ""
    content_type = response.headers.get("Content-Type", "")
    title = _extract_title(body)
    classification, evidence = _classify_probe(
        path,
        response.status_code,
        content_type,
        response.url,
        body,
    )

    return PathProbe(
        path=path,
        url=probe_url,
        status_code=response.status_code,
        content_type=content_type,
        final_url=response.url,
        title=title,
        content_length=len(body),
        classification=classification,
        evidence=evidence,
        body_sample=text_sample(body, MAX_SAMPLE_CHARS),
    )


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


def scan_robotstxt(
    url: str,
    verify_tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    max_probes: int = MAX_PROBES,
) -> dict:
    """Execute TC04 against an authorized target."""
    base = normalize_url(url)
    robots_url = absolute(base, "/robots.txt")

    try:
        response = request(
            robots_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception as exc:
        return connection_result(exc, target=robots_url)

    body = response.text or ""
    content_type = response.headers.get("Content-Type", "")
    final_url = response.url

    details: dict = {
        "requested_url": robots_url,
        "final_url": final_url,
        "status_code": response.status_code,
        "content_type": content_type,
        "content_length": len(body),
        "verify_tls": verify_tls,
    }

    # 404/410 are normal for websites without robots.txt.
    if response.status_code in {404, 410}:
        return result(
            "SAFE",
            "robots.txt was not found at the standard location; no robots.txt disclosure was available to assess.",
            details=details,
        )

    if response.status_code != 200:
        details["body_sample"] = text_sample(body, MAX_SAMPLE_CHARS)
        if 400 <= response.status_code < 500:
            return result(
                "REVIEW REQUIRED",
                f"robots.txt returned HTTP {response.status_code}; verify whether access to the crawler policy file is intentional.",
                details=details,
                evidence=[f"robots.txt returned HTTP {response.status_code}"],
            )
        return result(
            "INCOMPLETE",
            f"robots.txt returned HTTP {response.status_code}; the testcase could not be evaluated reliably.",
            details=details,
        )

    if len(body) > MAX_BODY_FOR_ANALYSIS:
        details["body_truncated_for_analysis"] = True

    if not _looks_like_robots(body, content_type):
        details["body_sample"] = text_sample(body, MAX_SAMPLE_CHARS)
        return result(
            "REVIEW REQUIRED",
            "The /robots.txt endpoint returned HTTP 200 but the response did not clearly resemble a robots.txt file. It may be a rewritten page, WAF response, or application route.",
            details=details,
            evidence=[
                f"HTTP 200 from {robots_url}",
                f"Content-Type: {content_type or 'not provided'}",
            ],
        )

    groups, directives, sitemap_urls = _parse_robots(body)

    disclosed: list[DisclosedPath] = []
    sensitive_count = 0
    for item in directives:
        if item.get("directive") != "disallow":
            continue

        raw_path = str(item.get("path") or "").strip()
        path = _normalise_robot_path(raw_path)
        hints = _sensitive_hints(path or raw_path)
        if hints:
            sensitive_count += 1
            disclosed.append(
                DisclosedPath(
                    path=path or raw_path,
                    user_agents=list(item.get("user_agents") or ["*"]),
                    directive="disallow",
                    sensitive_hints=hints,
                    probeable=bool(path),
                )
            )

    # Keep evidence deterministic and bounded.
    unique: dict[str, DisclosedPath] = {}
    for item in disclosed:
        key = item.path.lower()
        if key not in unique:
            unique[key] = item

    disclosed = list(unique.values())[:MAX_DISCLOSED_PATHS]

    details["groups"] = [asdict(group) for group in groups[:50]]
    details["directive_count"] = len(directives)
    details["sitemap_urls"] = sitemap_urls[:20]
    details["sensitive_disallow_count"] = sensitive_count
    details["sensitive_paths"] = [asdict(item) for item in disclosed]

    # Only probe literal, same-origin paths that were explicitly disclosed.
    probe_candidates = [item for item in disclosed if item.probeable]
    # Prioritize high-risk files and then the remaining sensitive paths.
    probe_candidates.sort(
        key=lambda item: (
            0 if any(token in item.path.lower() for token in HIGH_RISK_FILE_HINTS) else 1,
            len(item.path),
        )
    )
    probe_candidates = probe_candidates[: max(0, min(max_probes, MAX_PROBES))]

    probes: list[PathProbe] = []
    for item in probe_candidates:
        probes.append(_probe_disclosed_path(base, item, verify_tls, timeout))

    details["probes_performed"] = len(probes)
    details["path_probes"] = [asdict(probe) for probe in probes]

    strong_public_exposure = [
        probe for probe in probes
        if probe.classification == "public_sensitive_resource"
    ]
    public_sensitive_paths = [
        probe for probe in probes
        if probe.classification == "public_sensitive_path"
    ]
    protected = [
        probe for probe in probes
        if probe.classification == "protected"
    ]
    not_found = [
        probe for probe in probes
        if probe.classification == "not_found"
    ]
    failed = [
        probe for probe in probes
        if probe.classification == "request_failed"
    ]

    evidence: list[str] = []
    if sitemap_urls:
        evidence.append(f"robots.txt declares {len(sitemap_urls)} sitemap URL(s). Sitemap analysis is handled separately by TC20.")

    for item in disclosed[:15]:
        evidence.append(
            f"Sensitive robots.txt path disclosed: {item.path} "
            f"(user-agent: {', '.join(item.user_agents)})"
        )

    for probe in strong_public_exposure[:10]:
        status = probe.status_code if probe.status_code is not None else "ERR"
        evidence.append(
            f"Disclosed path returned confirmed sensitive content: {probe.path} -> HTTP {status}"
        )
        evidence.extend(probe.evidence[:4])

    if strong_public_exposure:
        return result(
            "UNSAFE",
            "robots.txt disclosed at least one sensitive resource that was directly accessible and returned evidence consistent with sensitive content exposure.",
            details=details,
            evidence=evidence,
        )

    if public_sensitive_paths:
        return result(
            "REVIEW REQUIRED",
            "robots.txt disclosed potentially sensitive paths that were reachable, but the returned content was not sufficient to confirm sensitive information exposure automatically.",
            details=details,
            evidence=evidence,
        )

    if disclosed:
        if protected and not failed:
            evidence.append("Probed sensitive paths were protected with authentication/authorization responses.")
            return result(
                "SAFE",
                "robots.txt disclosed some potentially sensitive paths, but the tested resources were protected or unavailable. No confirmed public sensitive resource was identified.",
                details=details,
                evidence=evidence,
            )

        if not_found and not failed:
            evidence.append("Probed sensitive paths were not currently available.")
            return result(
                "SAFE",
                "robots.txt disclosed potentially sensitive paths, but the tested resources were not publicly available during this assessment.",
                details=details,
                evidence=evidence,
            )

        if failed:
            evidence.append("At least one disclosed path could not be validated due to a request error.")
            return result(
                "REVIEW REQUIRED",
                "robots.txt disclosed potentially sensitive paths, but one or more resource checks could not be completed reliably.",
                details=details,
                evidence=evidence,
            )

        return result(
            "REVIEW REQUIRED",
            "robots.txt contains potentially sensitive paths. The file itself is reconnaissance information; manual validation is recommended to determine whether any disclosure is security-relevant.",
            details=details,
            evidence=evidence,
        )

    return result(
        "SAFE",
        "robots.txt was retrieved successfully and no obviously sensitive path disclosure was identified.",
        details=details,
        evidence=evidence or ["No sensitive Disallow path was identified in the parsed robots.txt content."],
    )


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TC04 - robots.txt security check")
    parser.add_argument("url")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for authorized testing")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-probes", type=int, default=MAX_PROBES)
    args = parser.parse_args()

    output = scan_robotstxt(
        args.url,
        verify_tls=not args.insecure,
        timeout=args.timeout,
        max_probes=args.max_probes,
    )
    print(json.dumps(output, indent=2, default=str))
