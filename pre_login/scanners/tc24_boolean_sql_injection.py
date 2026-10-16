"""TC24 - Boolean-Based SQL Injection Scanner.

Evaluates whether changing SQL-related Boolean conditions causes reproducible,
SQL-dependent differences in application behavior using paired TRUE and FALSE probes.
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
    calculate_similarity,
    detect_sql_errors,
    discover_targets,
    execute_probe,
    normalize_body,
)
from payloads.manager import load_json_records, is_exhaustive_mode


def _load_paired_probes(limit: int = 10) -> list[dict[str, Any]]:
    records = load_json_records(
        "payloads_all_the_things/sql_injection/boolean_differential_probes.json",
        limit=limit if not is_exhaustive_mode() else None,
    )
    return records


def scan_boolean_sql_injection(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
    max_targets: int = 4,
) -> dict[str, Any]:
    """Execute Boolean-based SQL injection assessment."""
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    verify_tls, _ = effective_verify_tls(target_url, verify_tls)
    session = requests.Session()

    # 1. Baseline collection
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
    baseline_errors = set(detect_sql_errors(resp.text or ""))
    targets = discover_targets(target_url, resp)[:max_targets]

    if not targets:
        return {
            "status": STATUS_SAFE,
            "summary": "No injectable query or form parameters were discovered on the target.",
            "evidence": [],
            "details": {"url": target_url, "targets_found": 0},
        }

    all_probes = _load_paired_probes()
    # Group into pairs by pair_id
    pairs: dict[str, dict[str, Any]] = {}
    for p in all_probes:
        pid = p.get("pair_id", p["name"])
        if pid not in pairs:
            pairs[pid] = {}
        if p.get("kind") == "boolean_true":
            pairs[pid]["true"] = p
        elif p.get("kind") == "boolean_false":
            pairs[pid]["false"] = p

    evidence: list[str] = []
    differential_confirmed = False
    suspicious_differences = False
    confirmed_pair_details: list[dict[str, Any]] = []
    executed_probes = 0

    for target in targets:
        for pid, pair in pairs.items():
            true_probe = pair.get("true")
            false_probe = pair.get("false")
            if not true_probe or not false_probe:
                continue

            # Execute TRUE probe
            resp_true, _, err_true = execute_probe(session, target, true_probe["value"], timeout=timeout, verify=verify_tls)
            # Execute FALSE probe
            resp_false, _, err_false = execute_probe(session, target, false_probe["value"], timeout=timeout, verify=verify_tls)

            if err_true or err_false or resp_true is None or resp_false is None:
                continue

            executed_probes += 2
            norm_true = normalize_body(resp_true.text or "")
            norm_false = normalize_body(resp_false.text or "")

            # Check new SQL errors
            errs_true = detect_sql_errors(resp_true.text or "", baseline_errors)
            errs_false = detect_sql_errors(resp_false.text or "", baseline_errors)
            if errs_true or errs_false:
                err_fams = sorted(set(errs_true + errs_false))
                evidence.append(
                    f"Parameter '{target.name}' disclosed database error ({', '.join(err_fams)}) with boolean probe."
                )
                differential_confirmed = True

            # Differential comparison
            status_differed = resp_true.status_code != resp_false.status_code
            similarity_tf = calculate_similarity(norm_true, norm_false)
            similarity_true_base = calculate_similarity(norm_true, baseline_norm)
            similarity_false_base = calculate_similarity(norm_false, baseline_norm)

            # Meaningful SQL-dependent differential:
            # TRUE matches baseline closely while FALSE differs meaningfully (or vice versa),
            # with body similarity between TRUE and FALSE dropping significantly.
            if status_differed or (similarity_tf < 0.95 and abs(similarity_true_base - similarity_false_base) >= 0.05):
                differential_confirmed = True
                confirmed_pair_details.append({
                    "parameter": target.name,
                    "pair_id": pid,
                    "true_payload": true_probe["value"],
                    "false_payload": false_probe["value"],
                    "status_code_true": resp_true.status_code,
                    "status_code_false": resp_false.status_code,
                    "similarity_tf": similarity_tf,
                    "similarity_true_baseline": similarity_true_base,
                    "similarity_false_baseline": similarity_false_base,
                })
                evidence.append(
                    f"Parameter '{target.name}': Paired condition '{true_probe['value']}' vs '{false_probe['value']}' "
                    f"produced a reproducible SQL-dependent differential (Similarity ratio: {similarity_tf})."
                )
                break
            elif similarity_tf < 0.99 and norm_true != norm_false:
                suspicious_differences = True

        if differential_confirmed:
            break

    details = {
        "target": target_url,
        "parameters_tested": [t.name for t in targets],
        "executed_probe_count": executed_probes,
        "confirmed_pairs": confirmed_pair_details,
    }

    if differential_confirmed:
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Boolean-based SQL injection was confirmed on {target_url}: "
                f"reproducible differential application behavior observed between paired TRUE and FALSE conditions."
            ),
            "evidence": evidence,
            "details": details,
        }

    if suspicious_differences:
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Response differences were observed for boolean probes on {target_url}, "
                f"but evidence was insufficient to conclusively prove a SQL-dependent condition."
            ),
            "evidence": evidence or ["Responses differed between probes without matching expected boolean behavior."],
            "details": details,
        }

    if executed_probes == 0:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Could not complete boolean SQL injection probes against target parameters.",
            "evidence": [],
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No boolean-based SQL injection indicators were observed across tested parameters.",
        "evidence": [f"Tested {len(targets)} parameter(s) with {executed_probes} paired boolean probes; no differential found."],
        "details": details,
    }
