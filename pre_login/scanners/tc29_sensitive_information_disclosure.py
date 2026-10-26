"""TC29 - Application Discloses Sensitive Information Scanner.

Identifies sensitive information exposed through responses, error pages, headers,
and client-side metadata, including stack traces, private IP addresses, internal paths,
and credentials with automatic redaction.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import requests

from core.http_client import effective_verify_tls
from core.sqli_engine import (
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_disclosure_signatures() -> list[dict[str, Any]]:
    return load_json_records(
        "fuzzdb/response_patterns/sensitive_disclosure_signatures.json",
        limit=None,
    )


def _redact_sensitive(text: str) -> str:
    """Redact keys, tokens, and credentials from evidence strings."""
    t = re.sub(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", "AKIA<REDACTED_AWS_KEY>", text)
    t = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n]+", "-----BEGIN PRIVATE KEY-----<REDACTED>", t)
    t = re.sub(r"(?i)[\"']?(api[_-]?key|secret[_-]?key|password)[\"']?\s*[:=]\s*['\"][^'\"]+['\"]", r"\1=<redacted>", t)
    return t[:250]


def scan_sensitive_information_disclosure(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Execute sensitive information disclosure assessment."""
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    verify_tls, _ = effective_verify_tls(target_url, verify_tls)
    session = requests.Session()
    headers = {"User-Agent": "SecurityAssessmentTestExecutor-TC29/1.0"}

    # Probe target pages and an intentional 404/malformed path to inspect error handling
    test_urls = [
        target_url,
        urljoin(target_url, "/nonexistent_error_trigger_404_tc29"),
    ]

    responses: list[requests.Response] = []
    for u in test_urls:
        try:
            r = session.get(u, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
            responses.append(r)
        except Exception:
            pass

    if not responses:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": f"Could not connect to {target_url} to assess information disclosure.",
            "evidence": ["Connection failed to target."],
            "details": {"url": target_url},
        }

    signatures = _load_disclosure_signatures()
    compiled_sigs = [
        (s, re.compile(s["pattern"], re.MULTILINE))
        for s in signatures
    ]

    evidence: list[str] = []
    confirmed_disclosures: list[dict[str, Any]] = []
    review_disclosures: list[dict[str, Any]] = []

    for resp in responses:
        body = resp.text or ""
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        # Check response body and headers against signatures
        for sig_meta, rx in compiled_sigs:
            match_body = rx.search(body)
            match_head = rx.search(header_text)
            match = match_body or match_head
            if match:
                matched_snippet = _redact_sensitive(match.group(0))
                category = sig_meta.get("category", "info_leak")
                severity = sig_meta.get("severity", "medium")
                location = "response_body" if match_body else "response_headers"

                disclosure_record = {
                    "url": resp.url,
                    "signature": sig_meta["name"],
                    "category": category,
                    "severity": severity,
                    "location": location,
                    "snippet": matched_snippet,
                    "description": sig_meta.get("description", ""),
                }

                if severity in {"critical", "high"}:
                    confirmed_disclosures.append(disclosure_record)
                    evidence.append(
                        f"Confirmed {category.replace('_', ' ')} ({sig_meta['name']}) at {resp.url} in {location}: {matched_snippet!r}"
                    )
                else:
                    review_disclosures.append(disclosure_record)
                    evidence.append(
                        f"Potential {category.replace('_', ' ')} ({sig_meta['name']}) at {resp.url} in {location}: {matched_snippet!r}"
                    )

    details = {
        "target": target_url,
        "urls_inspected": [r.url for r in responses],
        "signatures_inspected": len(signatures),
        "probe_cap": len(signatures),
        "executed_probe_count": len(responses) * len(signatures),
        "payloads_used": [
            {"name": s["name"], "payload": s["pattern"][:60], "kind": s.get("category", "info_leak")}
            for s in signatures[:20]
        ],
        "confirmed_disclosures": confirmed_disclosures,
        "review_disclosures": review_disclosures,
    }
    if confirmed_disclosures:
        details["triggering_payload"] = {
            "name": confirmed_disclosures[0]["signature"],
            "payload": confirmed_disclosures[0]["snippet"],
            "parameter": confirmed_disclosures[0]["location"],
            "kind": confirmed_disclosures[0]["category"],
            "verdict": "UNSAFE",
        }

    if confirmed_disclosures:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Application Discloses Sensitive Information confirmed on {target_url}: "
                f"identified {len(confirmed_disclosures)} high/critical information disclosure issue(s) "
                f"including stack traces, database errors, or credentials."
            ),
            "evidence": evidence,
            "details": details,
        }

    if review_disclosures:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"The application disclosed internal infrastructure or metadata on {target_url} "
                f"(internal IPs or filesystem paths) that should be reviewed."
            ),
            "evidence": evidence,
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No sensitive information disclosure (stack traces, credentials, or private infrastructure) was identified in inspected responses.",
        "evidence": [f"Inspected {len(responses)} endpoint response(s) and headers against {len(signatures)} sensitive disclosure signatures."],
        "details": details,
    }
