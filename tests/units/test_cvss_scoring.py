from __future__ import annotations

from core.cvss_scoring import build_cvss4_vector, score_finding


REQUIRED_METRICS = {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}


def test_cvss_vector_contains_all_required_base_metrics():
    result = {"key": "tc14_sql_injection", "name": "SQL Injection", "status": "UNSAFE", "evidence": ["confirmed controlled differential"], "details": {}}
    vector = build_cvss4_vector(result)
    assert vector.startswith("CVSS:4.0/")
    parts = vector.split("/")[1:]
    assert {item.split(":", 1)[0] for item in parts} == REQUIRED_METRICS


def test_safe_or_review_result_does_not_get_cvss_score():
    for status in ("SAFE", "REVIEW REQUIRED", "NOT ASSESSED", "ERROR"):
        assert score_finding({"key": "tc14_sql_injection", "status": status}) is None


def test_unsafe_finding_has_nist_calculator_reference():
    scored = score_finding({"key": "tc14_sql_injection", "name": "SQL Injection", "status": "UNSAFE", "evidence": ["test"], "details": {}})
    assert scored is not None
    assert scored["standard"] == "CVSS v4.0 Base (CVSS-B)"
    assert scored["vector"].startswith("CVSS:4.0/")
    assert "nvd.nist.gov/vuln-metrics/cvss/v4-calculator" in scored["calculator_url"]
    # Without the `cvss` dependency installed, the vector and official calculator
    # link remain available but the application never invents a numeric score.
    if scored.get("base_score") is not None:
        assert 0.0 <= scored["base_score"] <= 10.0
    else:
        assert scored.get("calculation_state") == "dependency_missing"
