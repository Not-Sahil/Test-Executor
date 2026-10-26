"""TC27 - UNION-Based SQL Injection Scanner.

Assesses whether controlled input can alter a SQL query through UNION-based behavior.
Uses controlled canary values and rigorously distinguishes input reflection from
genuine database interpretation.
"""
from __future__ import annotations

import secrets
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
    normalize_body,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_union_probes(limit: int = 8) -> list[dict[str, Any]]:
    return load_json_records(
        "payloads_all_the_things/sql_injection/union_probes.json",
        limit=limit if not is_exhaustive_mode() else None,
    )


def scan_union_sql_injection(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
    max_targets: int = 3,
) -> dict[str, Any]:
    """Execute UNION-based SQL injection assessment."""
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

    baseline_errors = set(detect_sql_errors(resp.text or ""))
    targets = discover_targets(target_url, resp)[:max_targets]

    if not targets:
        return {
            "status": STATUS_SAFE,
            "summary": "No injectable query or form parameters were discovered on the target.",
            "evidence": [],
            "details": {"url": target_url},
        }

    probes = _load_union_probes()
    evidence: list[str] = []
    union_confirmed = False
    suspicious_union = False
    confirmed_findings: list[dict[str, Any]] = []
    executed_count = 0

    for target in targets:
        # Step 1: Reflection check using a benign, non-SQL canary token
        reflection_token = f"refchk_{secrets.token_hex(4)}"
        resp_ref, _, err_ref = execute_probe(session, target, reflection_token, timeout=timeout, verify=verify_tls)
        is_reflected = False
        if resp_ref is not None and reflection_token in (resp_ref.text or ""):
            is_reflected = True

        # Step 2: ORDER BY column boundary check
        order_low = next((p for p in probes if p.get("kind") == "column_order_low"), None)
        order_high = next((p for p in probes if p.get("kind") == "column_order_high"), None)
        if order_low and order_high:
            resp_low, _, _ = execute_probe(session, target, order_low["value"], timeout=timeout, verify=verify_tls)
            resp_high, _, _ = execute_probe(session, target, order_high["value"], timeout=timeout, verify=verify_tls)
            executed_count += 2
            if resp_low is not None and resp_high is not None:
                errs_high = detect_sql_errors(resp_high.text or "", baseline_errors)
                # If ORDER BY 1 is successful (200) and ORDER BY 100 triggers SQL column error or 500
                if resp_low.status_code == 200 and (resp_high.status_code >= 500 or errs_high):
                    suspicious_union = True
                    evidence.append(
                        f"Parameter '{target.name}': ORDER BY boundary difference observed (ORDER BY 1 returned 200, ORDER BY 100 produced error/500)."
                    )

        # Step 3: UNION SELECT canary probes
        for probe in probes:
            if probe.get("kind") != "union_select":
                continue

            canary = probe.get("canary", "")
            if not canary:
                continue

            resp_u, _, err_u = execute_probe(session, target, probe["value"], timeout=timeout, verify=verify_tls)
            if err_u or resp_u is None:
                continue

            executed_count += 1
            body_text = resp_u.text or ""

            # Check if canary is returned in response
            if canary in body_text:
                if is_reflected:
                    # Input is reflected in general; an echo alone does not confirm UNION execution
                    suspicious_union = True
                    evidence.append(
                        f"Parameter '{target.name}': Canary '{canary}' appeared in response, but parameter reflects input in general. Unconfirmed."
                    )
                else:
                    # Input is NOT reflected, but UNION query caused the canary to be rendered!
                    union_confirmed = True
                    confirmed_findings.append({
                        "parameter": target.name,
                        "probe": probe["name"],
                        "payload": probe["value"],
                        "canary": canary,
                        "columns": probe.get("columns"),
                        "reflection_control_passed": True,
                    })
                    evidence.append(
                        f"Parameter '{target.name}': Confirmed UNION-based SQL injection using probe '{probe['name']}'. "
                        f"Canary '{canary}' appeared in query output while benign input was not reflected."
                    )
                    break

            # Check if probe discloses new SQL syntax/column mismatch errors
            new_errs = detect_sql_errors(body_text, baseline_errors)
            if new_errs:
                suspicious_union = True
                evidence.append(
                    f"Parameter '{target.name}': UNION probe '{probe['name']}' disclosed database error ({', '.join(new_errs)})."
                )

        if union_confirmed:
            break

    details = {
        "target": target_url,
        "parameters_tested": [t.name for t in targets],
        "probe_cap": len(probes),
        "executed_probe_count": executed_count,
        "payloads_used": [
            {"name": p["name"], "payload": p["value"], "kind": p.get("kind", "union_probe")}
            for p in probes[:max(executed_count, 4)]
        ],
        "confirmed_findings": confirmed_findings,
    }
    if confirmed_findings:
        details["triggering_payload"] = {
            "name": confirmed_findings[0]["probe"],
            "payload": confirmed_findings[0]["payload"],
            "parameter": confirmed_findings[0]["parameter"],
            "kind": "union_select",
            "verdict": "UNSAFE",
        }

    if union_confirmed:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"UNION-based SQL injection was confirmed on {target_url}: "
                f"controlled canary was successfully extracted via database-executed UNION SELECT query."
            ),
            "evidence": evidence,
            "details": details,
        }

    if suspicious_union:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Suspicious UNION-related indicators observed on {target_url} (input reflection or column errors), "
                f"but database interpretation could not be conclusively confirmed."
            ),
            "evidence": evidence or ["Observed column boundary variance or reflected tokens without proven query execution."],
            "details": details,
        }

    if executed_count == 0:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Could not complete UNION-based SQL injection probes against target parameters.",
            "evidence": [],
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No UNION-based SQL injection indicators were observed across tested parameters.",
        "evidence": [f"Tested {len(targets)} parameter(s) with {executed_count} UNION probes; no database query modification observed."],
        "details": details,
    }
