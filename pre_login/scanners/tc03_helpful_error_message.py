"""
Helpful / Improper Error Message Scanner (WSTG-ERRH-01 oriented)

Authorized, low-impact web testing only.

Purpose
-------
Trigger a small set of controlled error conditions and determine whether the
application exposes useful internal implementation details such as:
- stack traces / exception dumps
- source-code locations
- local filesystem paths
- database/SQL errors
- framework/debugger pages
- internal hostnames or private IP addresses
- secrets or connection-string fragments

The scanner deliberately avoids exploit payloads, brute force, destructive
methods, file reads, command execution, or state-changing requests. It mainly
uses GET requests and a very small number of candidate URL mutations.

Result model
------------
SAFE            = controlled error responses; no sensitive technical detail found
UNSAFE          = strong evidence of sensitive technical information disclosure
REVIEW REQUIRED = suspicious/weak evidence that needs manual validation
INCOMPLETE      = target/request could not be tested reliably
"""

from __future__ import annotations

import argparse
import html
import json
import re
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse, urlunsplit

import requests

from payloads.manager import load_lines
from requests import Response
from requests.exceptions import RequestException


DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_CASES = 10
DEFAULT_MAX_BODY = 200_000
DEFAULT_MAX_SNIPPET = 500
DEFAULT_USER_AGENT = "SecurityAssessmentScanner/1.0"
MAX_FUZZDB_ERROR_SIGNATURES = 100

# FuzzDB's response-analysis dictionary is a set of literal error strings, not
# executable payloads. We escape each entry so punctuation in the upstream file
# cannot become an unintended regular expression.
FUZZDB_ERROR_SIGNATURES = tuple(
    re.compile(re.escape(item), re.I)
    for item in load_lines(
        "upstream/FuzzDB/regex/errors.txt",
        limit=MAX_FUZZDB_ERROR_SIGNATURES,
    )
)

# High-confidence disclosures. These are intentionally descriptive rather than
# exploit-oriented signatures.
PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "stack_trace": [
        re.compile(r"traceback \(most recent call last\)", re.I),
        re.compile(r"(?m)^\s*at\s+[A-Za-z0-9_.$<>]+\([^\n]{0,180}:\d+(?::\d+)?\)", re.I),
        re.compile(r"(?:java\.lang\.)?[A-Za-z]+Exception\b", re.I),
        re.compile(r"(?:System\.|Microsoft\.)[A-Za-z]+Exception\b", re.I),
        re.compile(r"stack\s+trace\b", re.I),
        re.compile(r"exception\s+details?\b", re.I),
    ],
    "source_code_location": [
        re.compile(r"[A-Za-z]:\\[^\n]{0,240}(?:\.py|\.java|\.cs|\.php|\.js|\.rb):\d+", re.I),
        re.compile(r"/(?:var|opt|srv|home|usr|app|workspace|work)/[^\n]{0,240}(?:\.py|\.java|\.cs|\.php|\.js|\.rb):\d+", re.I),
        re.compile(r"\b(?:[A-Za-z0-9_./-]+\.(?:py|java|cs|php|js|rb)):\d+", re.I),
    ],
    "filesystem_path": [
        re.compile(r"[A-Za-z]:\\(?:Users|Windows|inetpub|Apache|Tomcat|xampp|wamp|Program Files|wwwroot)[^\n<]{0,240}", re.I),
        re.compile(r"/(?:var/www|var/log|etc|opt|srv|home|usr/local|tmp|app|workspace|www)[^\n<]{0,240}", re.I),
    ],
    "database_error": [
        re.compile(r"SQLSTATE\[[0-9A-Z]+\]", re.I),
        re.compile(r"(?:mysql|mysqli|postgres(?:ql)?|sqlite|oracle|jdbc|sql server|mssql).{0,100}(?:error|exception|syntax|connection|query)", re.I),
        re.compile(r"(?:ORA-\d{4,6}|SQL syntax|syntax error at or near|unknown column|relation .* does not exist)", re.I),
        re.compile(r"PDOException\b", re.I),
    ],
    "debug_framework": [
        re.compile(r"werkzeug debugger", re.I),
        re.compile(r"django debug", re.I),
        re.compile(r"debug\s+(?:toolbar|mode|page)", re.I),
        re.compile(r"laravel ignition", re.I),
        re.compile(r"whoops, looks like something went wrong", re.I),
        re.compile(r"rails application trace", re.I),
        re.compile(r"express error", re.I),
        re.compile(r"spring boot error page", re.I),
        re.compile(r"asp\.net yellow screen", re.I),
    ],
    "internal_network": [
        re.compile(r"\b10\.\d{1,3}(?:\.\d{1,3}){2}\b"),
        re.compile(r"\b192\.168\.\d{1,3}(?:\.\d{1,3})\b"),
        re.compile(r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b"),
        re.compile(r"\b(?:localhost|127\.0\.0\.1|ip6-localhost)\b", re.I),
        re.compile(r"\b[a-z0-9.-]+\.(?:internal|local|lan|corp|intranet)\b", re.I),
    ],
    "secret_disclosure": [
        re.compile(r"\b(?:api[_ -]?key|access[_ -]?key|secret[_ -]?key|client[_ -]?secret)\s*[:=]\s*[^\s<]{6,}", re.I),
        re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s<]{4,}", re.I),
        re.compile(r"(?:postgres(?:ql)?|mysql|sqlserver)://[^\s<]{1,240}", re.I),
    ],
    "template_error": [
        re.compile(r"template(?:syntax|render|not found)\s*(?:error)?", re.I),
        re.compile(r"jinja2\.exceptions?\.[A-Za-z]+", re.I),
        re.compile(r"twig\\?error", re.I),
        re.compile(r"ejs(?:error|exception)", re.I),
    ],
}

# These framework names alone are weak evidence. We treat them as REVIEW, not
# UNSAFE, unless they appear with stronger diagnostics.
WEAK_TECH_PATTERNS: dict[str, re.Pattern[str]] = {
    "framework_name": re.compile(
        r"\b(?:apache tomcat|jetty|spring|django|flask|werkzeug|laravel|rails|express|asp\.net|php)\b",
        re.I,
    ),
}


@dataclass
class TestCaseResult:
    case_id: str
    description: str
    url: str
    method: str
    status_code: Optional[int]
    elapsed_ms: Optional[float]
    final_url: Optional[str]
    error: Optional[str] = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    response_preview: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HelpfulErrorResult:
    key: str = "helpful_error_messages"
    name: str = "Helpful Error Messages"
    status: str = "INCOMPLETE"
    summary: str = ""
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class HelpfulErrorScanner:
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
        max_cases: int = DEFAULT_MAX_CASES,
        max_body: int = DEFAULT_MAX_BODY,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.timeout = max(1.0, float(timeout))
        self.verify_tls = bool(verify_tls)
        self.max_cases = max(3, min(int(max_cases), 20))
        self.max_body = max(10_000, min(int(max_body), 1_000_000))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    @staticmethod
    def _normalize_url(url: str) -> str:
        raw = (url or "").strip()
        if not raw:
            return ""
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        return urlunparse(parsed)

    @staticmethod
    def _safe_preview(text: str, limit: int = DEFAULT_MAX_SNIPPET) -> str:
        text = html.unescape(text or "")
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > limit:
            text = text[:limit] + "..."
        # Redact obvious secret-like assignments from stored evidence.
        text = re.sub(
            r"(password|passwd|pwd|api[_ -]?key|secret[_ -]?key|client[_ -]?secret)\s*[:=]\s*[^\s<]+",
            r"\1=<redacted>",
            text,
            flags=re.I,
        )
        return text

    def _response_text(self, response: Response) -> str:
        content = response.content[: self.max_body]
        try:
            return content.decode(response.encoding or "utf-8", errors="replace")
        except Exception:
            return content.decode("utf-8", errors="replace")

    def _scan_text(self, text: str, headers: dict[str, str], status_code: Optional[int]) -> list[dict[str, Any]]:
        combined = text[: self.max_body]
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for category, patterns in PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(combined)
                if not match:
                    continue
                snippet = self._safe_preview(combined[max(0, match.start() - 120): match.end() + 180])
                key = (category, snippet)
                if key in seen:
                    continue
                seen.add(key)
                confidence = "high" if category in {
                    "stack_trace", "source_code_location", "secret_disclosure", "database_error"
                } else "medium"
                findings.append({
                    "type": category,
                    "confidence": confidence,
                    "status_code": status_code,
                    "evidence": snippet,
                })
                break

        # FuzzDB response signatures are supplemental evidence. Generic error
        # strings are deliberately medium-confidence rather than automatically
        # treated as sensitive disclosures; stronger categories above still
        # determine UNSAFE classification.
        fuzzdb_seen = 0
        for pattern in FUZZDB_ERROR_SIGNATURES:
            match = pattern.search(combined)
            if not match:
                continue
            snippet = self._safe_preview(combined[max(0, match.start() - 120): match.end() + 180])
            findings.append({
                "type": "fuzzdb_error_signature",
                "confidence": "medium",
                "status_code": status_code,
                "evidence": snippet,
                "source": "FuzzDB regex/errors.txt",
            })
            fuzzdb_seen += 1
            if fuzzdb_seen >= 8:
                break

        # Only use weak technology disclosure to support manual review.
        for category, pattern in WEAK_TECH_PATTERNS.items():
            match = pattern.search(combined)
            if match:
                snippet = self._safe_preview(combined[max(0, match.start() - 100): match.end() + 160])
                findings.append({
                    "type": category,
                    "confidence": "low",
                    "status_code": status_code,
                    "evidence": snippet,
                })
                break

        # Headers may contain error metadata. Avoid duplicating generic Server
        # banner information because Banner Disclosure is a separate testcase.
        for header_name in ("X-Debug", "X-Debug-Token", "X-Exception", "X-Generator"):
            value = headers.get(header_name)
            if value:
                findings.append({
                    "type": "debug_header",
                    "confidence": "medium",
                    "header": header_name,
                    "evidence": self._safe_preview(f"{header_name}: {value}", 300),
                })

        return findings

    def _request_case(
        self,
        case_id: str,
        description: str,
        url: str,
    ) -> TestCaseResult:
        start = time.perf_counter()
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_tls,
            )
            elapsed = round((time.perf_counter() - start) * 1000, 2)
            text = self._response_text(response)
            findings = self._scan_text(text, dict(response.headers), response.status_code)
            return TestCaseResult(
                case_id=case_id,
                description=description,
                url=url,
                method="GET",
                status_code=response.status_code,
                elapsed_ms=elapsed,
                final_url=response.url,
                findings=findings,
                response_preview=self._safe_preview(text),
            )
        except RequestException as exc:
            elapsed = round((time.perf_counter() - start) * 1000, 2)
            return TestCaseResult(
                case_id=case_id,
                description=description,
                url=url,
                method="GET",
                status_code=None,
                elapsed_ms=elapsed,
                final_url=None,
                error=str(exc),
            )

    @staticmethod
    def _build_cases(target: str, max_cases: int) -> list[tuple[str, str, str]]:
        parsed = urlparse(target)
        # Resource error probes are rooted at the origin to avoid invalid paths
        # like /login.jsp/login.jsp when a login URL was provided.
        path = "/"
        base = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

        cases: list[tuple[str, str, str]] = []
        sentinel_tokens = load_lines(
            "fuzzdb/response_patterns/helpful_error_probe_tokens.txt",
            limit=4,
        )
        token_map = {"not_found": sentinel_tokens[0], "malformed": sentinel_tokens[1],
                     "unknown": sentinel_tokens[2], "invalid_param": sentinel_tokens[3]}

        # 1. Nonexistent resource: reliable, read-only, low-impact.
        not_found_path = path.rstrip("/") + "/" + token_map["not_found"]
        cases.append((
            "ERR-404",
            "Request a deliberately nonexistent resource to inspect the 404 error response.",
            urljoin(base, not_found_path.lstrip("/")),
        ))

        # 2. Malformed percent-encoding: encourages a controlled URL parser error.
        malformed_path = path.rstrip("/") + "/" + token_map["malformed"]
        cases.append((
            "ERR-URL-ENCODING",
            "Request a malformed percent-encoded path to inspect URL parsing errors.",
            urljoin(base, malformed_path.lstrip("/")),
        ))

        # 3. Unsupported-but-benign extension. This remains a GET and usually
        # produces a normal 404/415/400 page without touching application state.
        cases.append((
            "ERR-UNKNOWN-RESOURCE",
            "Request an unusual nonexistent resource name to inspect generic error handling.",
            urljoin(base, (path.rstrip("/") + "/" + token_map["unknown"]).lstrip("/")),
        ))

        # 4. Mutate an existing query parameter when one is already present.
        # We do not invent business endpoints or send write requests.
        if parsed.query:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for index, (key, value) in enumerate(params):
                mutated = list(params)
                mutated[index] = (key, token_map["invalid_param"])
                new_query = urlencode(mutated, doseq=True)
                mutated_url = urlunparse(parsed._replace(query=new_query))
                cases.append((
                    "ERR-INVALID-PARAM",
                    f"Replace existing query parameter '{key}' with a clearly invalid value.",
                    mutated_url,
                ))
                break

        # Deduplicate and respect cap.
        unique: list[tuple[str, str, str]] = []
        seen = set()
        for item in cases:
            if item[2] in seen:
                continue
            seen.add(item[2])
            unique.append(item)
            if len(unique) >= max_cases:
                break
        return unique

    def scan(self, target: str) -> HelpfulErrorResult:
        normalized = self._normalize_url(target)
        if not normalized:
            return HelpfulErrorResult(
                status="INCOMPLETE",
                summary="The target URL is invalid or empty; error-message testing could not start.",
                details={"error": "invalid_target_url"},
            )

        cases = self._build_cases(normalized, self.max_cases)
        sentinel_tokens = load_lines(
            "fuzzdb/response_patterns/helpful_error_probe_tokens.txt",
            limit=4,
        )
        results: list[TestCaseResult] = []
        raw_lines = [
            "=" * 78,
            "HELPFUL ERROR MESSAGE SCANNER (WSTG-ERRH-01 ORIENTED)",
            "=" * 78,
            f"Target: {normalized}",
            f"TLS verification: {'enabled' if self.verify_tls else 'disabled (authorized testing mode)'}",
            f"Cases planned: {len(cases)}",
        ]

        for case_id, description, url in cases:
            case = self._request_case(case_id, description, url)
            results.append(case)
            raw_lines.append("")
            raw_lines.append(f"[{case.case_id}] {case.description}")
            raw_lines.append(f"URL: {case.url}")
            raw_lines.append(f"Status: {case.status_code}")
            if case.error:
                raw_lines.append(f"ERROR: {case.error}")
            else:
                raw_lines.append(f"Final URL: {case.final_url}")
                raw_lines.append(f"Elapsed: {case.elapsed_ms} ms")
                if case.findings:
                    for finding in case.findings:
                        raw_lines.append(
                            f"Finding: {finding['type']} ({finding.get('confidence', 'unknown')})"
                        )
                        raw_lines.append(f"Evidence: {finding.get('evidence', '')}")
                else:
                    raw_lines.append("Finding: none")

        successful_cases = [r for r in results if r.status_code is not None and not r.error]
        failed_cases = [r for r in results if r.error]
        all_findings = [f for r in results for f in r.findings]
        high_conf = [f for f in all_findings if f.get("confidence") == "high"]
        medium_conf = [f for f in all_findings if f.get("confidence") == "medium"]
        weak = [f for f in all_findings if f.get("confidence") == "low"]

        # Strong finding => UNSAFE. Weak-only technology disclosure => REVIEW.
        if high_conf:
            status = "UNSAFE"
            summary = (
                "One or more controlled error responses exposed sensitive technical "
                "information such as stack traces, source locations, database errors, "
                "filesystem paths, or secret-like values."
            )
        elif medium_conf or weak:
            status = "REVIEW REQUIRED"
            summary = (
                "The tested error responses exposed some technical diagnostic information. "
                "Manual validation is recommended to determine whether the disclosure is security-relevant."
            )
        elif failed_cases and not successful_cases:
            status = "INCOMPLETE"
            summary = (
                "The scanner could not obtain usable responses from the controlled error cases. "
                "This is not a SAFE or UNSAFE finding."
            )
        elif failed_cases:
            status = "REVIEW REQUIRED"
            summary = (
                f"{len(successful_cases)} controlled error case(s) returned usable responses, "
                f"but {len(failed_cases)} case(s) failed. Manual review is recommended."
            )
        else:
            status = "SAFE"
            summary = (
                "The tested error conditions returned controlled responses without exposing "
                "high-confidence sensitive implementation details."
            )

        evidence: list[str] = []
        for finding in all_findings:
            evidence.append(
                f"{finding.get('type')} ({finding.get('confidence')}): {finding.get('evidence', '')}"
            )
        for case in failed_cases:
            evidence.append(f"{case.case_id}: request failed: {case.error}")

        details = {
            "wstg": "WSTG-ERRH-01",
            "target": normalized,
            "tls_verification": self.verify_tls,
            "cases_planned": len(cases),
            "cases_completed": len(successful_cases),
            "cases_failed": len(failed_cases),
            "high_confidence_findings": len(high_conf),
            "medium_confidence_findings": len(medium_conf),
            "low_confidence_findings": len(weak),
            "cases": [r.as_dict() for r in results],
            "payload_library": {
                "sources": ["FuzzDB response-pattern dictionary; project-curated non-destructive probes"],
                "files": [
                    "payloads/fuzzdb/response_patterns/helpful_error_probe_tokens.txt",
                    "payloads/upstream/FuzzDB/regex/errors.txt",
                ],
                "items_used": len(sentinel_tokens),
                "response_signatures_loaded": len(FUZZDB_ERROR_SIGNATURES),
            },
        }

        return HelpfulErrorResult(
            status=status,
            summary=summary,
            raw_output="\n".join(raw_lines),
            evidence=evidence,
            details=details,
        )


def scan_helpful_error_messages(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    max_cases: int = DEFAULT_MAX_CASES,
) -> dict[str, Any]:
    """Convenience wrapper returning a JSON-serializable dictionary."""
    return HelpfulErrorScanner(
        timeout=timeout,
        verify_tls=verify_tls,
        max_cases=max_cases,
    ).scan(url).as_dict()


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-impact helpful error message scanner")
    parser.add_argument("url", help="Authorized target URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--no-verify-tls", action="store_true")
    parser.add_argument("--max-cases", type=int, default=DEFAULT_MAX_CASES)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    result = HelpfulErrorScanner(
        timeout=args.timeout,
        verify_tls=not args.no_verify_tls,
        max_cases=args.max_cases,
    ).scan(args.url)

    if args.as_json:
        print(json.dumps(result.as_dict(), indent=2, default=str))
    else:
        print(result.raw_output)
        print("\n" + "=" * 78)
        print(f"OVERALL STATUS: {result.status}")
        print(f"SUMMARY: {result.summary}")
        print("=" * 78)

    return 0 if result.status != "ERROR" else 1


if __name__ == "__main__":
    raise SystemExit(main())
