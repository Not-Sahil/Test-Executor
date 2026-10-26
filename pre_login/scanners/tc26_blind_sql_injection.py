"""TC26 - Blind SQL Injection Scanner.

Detects SQL-dependent inference behavior when direct database errors or query results
are NOT exposed to the client, utilizing content differential and conditional error techniques.
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
    calculate_similarity,
    detect_sql_errors,
    discover_targets,
    execute_probe,
    normalize_body,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_blind_scenarios(limit: int = 6) -> list[dict[str, Any]]:
    return load_json_records(
        "payloads_all_the_things/sql_injection/blind_sqli_scenarios.json",
        limit=limit if not is_exhaustive_mode() else None,
    )


def scan_blind_sql_injection(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
    max_targets: int = 3,
) -> dict[str, Any]:
    """Execute Blind SQL injection inference assessment."""
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

    baseline_norm = normalize_body(resp.text or "")
    targets = discover_targets(target_url, resp)[:max_targets]

    if not targets:
        return {
            "status": STATUS_SAFE,
            "summary": "No injectable query or form parameters were discovered on the target.",
            "evidence": [],
            "details": {"url": target_url},
        }

    scenarios = _load_blind_scenarios()
    pairs: dict[str, dict[str, Any]] = {}
    for s in scenarios:
        pid = s.get("pair_id", s["name"])
        if pid not in pairs:
            pairs[pid] = {}
        if "true" in s.get("kind", ""):
            pairs[pid]["true"] = s
        elif "false" in s.get("kind", ""):
            pairs[pid]["false"] = s

    evidence: list[str] = []
    blind_confirmed = False
    suspicious_blind = False
    confirmed_findings: list[dict[str, Any]] = []
    technique_used = "none"
    executed_count = 0

    for target in targets:
        for pid, pair in pairs.items():
            true_item = pair.get("true")
            false_item = pair.get("false")
            if not true_item or not false_item:
                continue

            resp_true, time_true, err_true = execute_probe(session, target, true_item["value"], timeout=timeout, verify=verify_tls)
            resp_false, time_false, err_false = execute_probe(session, target, false_item["value"], timeout=timeout, verify=verify_tls)

            if err_true or err_false or resp_true is None or resp_false is None:
                continue

            executed_count += 2
            norm_true = normalize_body(resp_true.text or "")
            norm_false = normalize_body(resp_false.text or "")
            technique = true_item.get("technique", "inference")

            # Check if direct errors are disclosed (if errors are disclosed, it's not blind SQLi)
            has_direct_errors = bool(detect_sql_errors(resp_true.text or "") or detect_sql_errors(resp_false.text or ""))

            # Technique 1: Conditional error inference (e.g. TRUE returns 200, FALSE triggers 500 divide-by-zero)
            if technique == "conditional_error_boolean":
                if resp_true.status_code == 200 and resp_false.status_code >= 500:
                    blind_confirmed = True
                    technique_used = "conditional_error_inference"
                    confirmed_findings.append({
                        "parameter": target.name,
                        "technique": technique_used,
                        "true_payload": true_item["value"],
                        "false_payload": false_item["value"],
                        "true_status": resp_true.status_code,
                        "false_status": resp_false.status_code,
                    })
                    evidence.append(
                        f"Parameter '{target.name}': Confirmed blind SQL injection via conditional error inference. "
                        f"TRUE condition returned HTTP 200 while FALSE condition triggered server error (HTTP {resp_false.status_code}) "
                        f"without exposing raw database errors."
                    )
                    break

            # Technique 2: Content differential inference
            elif technique == "content_differential":
                sim_tf = calculate_similarity(norm_true, norm_false)
                sim_tb = calculate_similarity(norm_true, baseline_norm)
                sim_fb = calculate_similarity(norm_false, baseline_norm)
                if sim_tf < 0.95 and sim_tb > 0.95 and sim_fb < 0.90:
                    blind_confirmed = True
                    technique_used = "content_differential_inference"
                    confirmed_findings.append({
                        "parameter": target.name,
                        "technique": technique_used,
                        "true_payload": true_item["value"],
                        "false_payload": false_item["value"],
                        "similarity_tf": sim_tf,
                    })
                    evidence.append(
                        f"Parameter '{target.name}': Confirmed blind SQL injection via content differential inference. "
                        f"TRUE condition aligned with baseline while FALSE condition produced consistent application state change "
                        f"(Differential ratio: {sim_tf})."
                    )
                    break
                elif sim_tf < 0.99 and norm_true != norm_false:
                    suspicious_blind = True

        if blind_confirmed:
            break

    details = {
        "target": target_url,
        "technique_used": technique_used,
        "probe_cap": len(scenarios),
        "executed_probe_count": executed_count,
        "parameters_tested": [t.name for t in targets],
        "payloads_used": [
            {"name": s["name"], "payload": s["value"], "kind": s.get("kind", "blind_sqli")}
            for s in scenarios[:max(executed_count, 4)]
        ],
        "confirmed_findings": confirmed_findings,
    }
    if confirmed_findings:
        details["triggering_payload"] = {
            "name": confirmed_findings[0]["technique"],
            "payload": confirmed_findings[0]["true_payload"],
            "parameter": confirmed_findings[0]["parameter"],
            "kind": confirmed_findings[0]["technique"],
            "verdict": "UNSAFE",
        }

    if blind_confirmed:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Blind SQL injection confirmed on {target_url} using {technique_used.replace('_', ' ')}. "
                f"Application behavior correlates with injected conditions without disclosing database errors or raw data."
            ),
            "evidence": evidence,
            "details": details,
        }

    if suspicious_blind:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Suspicious blind differential indicators were observed on {target_url}, "
                f"but evidence was inconclusive without direct inference confirmation."
            ),
            "evidence": evidence or ["Responses differed between inference probes without full condition alignment."],
            "details": details,
        }

    if executed_count == 0:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Could not complete blind SQL injection probes against target parameters.",
            "evidence": [],
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No blind SQL injection indicators were observed across tested parameters.",
        "evidence": [f"Tested {len(targets)} parameter(s) with {executed_count} inference probes; no blind SQL condition confirmed."],
        "details": details,
    }
