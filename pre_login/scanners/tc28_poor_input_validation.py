"""TC28 - Poor Input Validation Scanner.

Evaluates whether the application properly validates user-controlled inputs server-side
across empty values, type mismatches, boundary conditions, unexpected encodings, and
malformed structured payloads, distinguishing proper validation from unhandled crashes.
"""
from __future__ import annotations

from typing import Any
import requests

from core.http_client import effective_verify_tls
from core.sqli_engine import (
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
    detect_sql_errors,
    discover_targets,
    execute_probe,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_validation_scenarios(limit: int = 10) -> list[dict[str, Any]]:
    return load_json_records(
        "fuzzdb/input_validation/validation_scenarios.json",
        limit=limit if not is_exhaustive_mode() else None,
    )


def scan_poor_input_validation(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
    max_targets: int = 4,
) -> dict[str, Any]:
    """Execute Poor Input Validation security assessment."""
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    verify_tls, _ = effective_verify_tls(target_url, verify_tls)
    session = requests.Session()

    try:
        resp = session.get(target_url, timeout=timeout, verify=verify_tls, allow_redirects=True)
    except Exception as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": f"Could not establish baseline connection to {target_url}: {exc}",
            "evidence": [f"Connection error: {exc}"],
            "details": {"url": target_url, "error": str(exc)},
        }

    targets = discover_targets(target_url, resp)[:max_targets]
    if not targets:
        return {
            "status": STATUS_SAFE,
            "summary": "No user-controlled form or query parameters discovered to evaluate input validation.",
            "evidence": [],
            "details": {"url": target_url},
        }

    scenarios = _load_validation_scenarios()
    evidence: list[str] = []
    unhandled_exceptions: list[dict[str, Any]] = []
    suspicious_behaviors: list[dict[str, Any]] = []
    proper_validations: list[dict[str, Any]] = []
    tested_fields_records: list[dict[str, Any]] = []

    for target in targets:
        for item in scenarios:
            name = item["name"]
            val = item["value"]
            cat = item.get("category", "generic")

            resp_probe, _, err = execute_probe(session, target, val, timeout=timeout, verify=verify_tls)
            if err or resp_probe is None:
                continue

            status = resp_probe.status_code
            body = resp_probe.text or ""

            # Check if input triggered an unhandled exception / server crash (500)
            has_stack = any(token in body.lower() for token in ("traceback (most recent call last)", "fatal error:", "unhandled exception", "system.exception", "at java."))
            has_sql_error = bool(detect_sql_errors(body))

            record = {
                "field": target.name,
                "scenario": name,
                "category": cat,
                "input_value": val[:100],
                "response_status": status,
                "unhandled_crash": status >= 500 or has_stack,
            }
            tested_fields_records.append(record)

            if status >= 500 or has_stack:
                unhandled_exceptions.append(record)
                evidence.append(
                    f"Field '{target.name}' produced unhandled server crash (HTTP {status}) with input category '{cat}' ({name})."
                )
            elif has_sql_error:
                unhandled_exceptions.append(record)
                evidence.append(
                    f"Field '{target.name}' disclosed raw database errors when sent invalid input '{name}'."
                )
            elif status in {400, 422} or any(msg in body.lower() for msg in ("invalid", "required", "validation error", "must be")):
                proper_validations.append(record)
            else:
                # 200 OK without apparent validation on malformed input (e.g. null bytes or broken JSON)
                if cat in {"unexpected_encoding", "malformed_structured"}:
                    suspicious_behaviors.append(record)

    details = {
        "target": target_url,
        "parameters_tested": [t.name for t in targets],
        "scenarios_executed": len(tested_fields_records),
        "unhandled_exception_count": len(unhandled_exceptions),
        "proper_validation_count": len(proper_validations),
        "tested_records": tested_fields_records,
    }

    if unhandled_exceptions:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Poor Input Validation identified on {target_url}: malformed inputs caused unhandled server exceptions, "
                f"stack traces, or database errors across {len(unhandled_exceptions)} test condition(s)."
            ),
            "evidence": evidence,
            "details": details,
        }

    if suspicious_behaviors:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Input validation behavior on {target_url} returned 200 OK for malformed inputs "
                f"(unexpected encoding or malformed structured input) without explicit rejection."
            ),
            "evidence": evidence or ["Application accepted boundary or encoded inputs without clear validation errors."],
            "details": details,
        }

    if not tested_fields_records:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Could not complete input validation test probes against discovered targets.",
            "evidence": [],
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "The application enforced appropriate server-side validation and handled invalid inputs safely.",
        "evidence": [f"Tested {len(tested_fields_records)} input validation scenario(s) across {len(targets)} parameter(s); all handled safely without crashes."],
        "details": details,
    }
