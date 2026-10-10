"""CVSS v4.0 Base scoring for confirmed findings.

CVSS numbers are estimates for findings emitted by this scanner; analysts must
validate all metrics before client delivery. Unconfirmed REVIEW REQUIRED/Safe
results are intentionally not assigned a severity score.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

NIST_CALCULATOR = "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"

# Each profile supplies every CVSS v4.0 Base metric. Profiles are conservative
# initial assumptions, not a substitute for impact verification by a reviewer.
DEFAULT_IMPACT = {"VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"}
PROFILES: dict[str, dict[str, str]] = {
    "tc01_banner_grabbing": {**DEFAULT_IMPACT, "VC": "L"},
    "tc02_default_credentials": {**DEFAULT_IMPACT, "VC": "H", "VI": "H", "VA": "L"},
    "tc03_blank_credentials": {**DEFAULT_IMPACT, "VC": "H", "VI": "H", "VA": "L"},
    "tc03_helpful_error_message": {**DEFAULT_IMPACT, "VC": "L"},
    "tc04_user_enumeration": {**DEFAULT_IMPACT, "VC": "L"},
    "tc05_password_validation": {**DEFAULT_IMPACT, "VC": "L", "VI": "L"},
    "tc07_weak_cipher": {**DEFAULT_IMPACT, "VC": "L"},
    "tc08_login_over_http": {**DEFAULT_IMPACT, "VC": "H"},
    "tc09_cleartext_traffic": {**DEFAULT_IMPACT, "VC": "H"},
    "tc09_certificate_expiry": {**DEFAULT_IMPACT, "VC": "L"},
    "tc10_directory_listing": {**DEFAULT_IMPACT, "VC": "L"},
    "tc12_host_header_injection": {**DEFAULT_IMPACT, "VC": "L", "VI": "L"},
    "tc13_sensitive_file_exposure": {**DEFAULT_IMPACT, "VC": "H"},
    "tc13_cors": {**DEFAULT_IMPACT, "VC": "H", "VI": "L"},
    "tc14_sql_injection": {**DEFAULT_IMPACT, "VC": "L", "VI": "L"},
    "tc15_ldap_ad": {**DEFAULT_IMPACT, "VC": "L", "VI": "L"},
    "tc15_internal_ip_disclosure": {**DEFAULT_IMPACT, "VC": "L"},
    "tc16_clickjacking": {**DEFAULT_IMPACT, "VC": "L"},
    "tc17_website_accessible_over_ip": {**DEFAULT_IMPACT, "VC": "L"},
    "tc18_missing_security_headers": {**DEFAULT_IMPACT, "VC": "L"},
    "tc19_hardcoded_credentials": {**DEFAULT_IMPACT, "VC": "H", "VI": "H", "VA": "L"},
    "tc23_internal_path_disclosure": {**DEFAULT_IMPACT, "VC": "L"},
    "tls00": {**DEFAULT_IMPACT, "VC": "L"},
    "tls01": {**DEFAULT_IMPACT, "VC": "H"},
    "tls02": {**DEFAULT_IMPACT, "VC": "H"},
    "tls03": {**DEFAULT_IMPACT, "VC": "H"},
    "tls04": {**DEFAULT_IMPACT, "VC": "L"},
    "tls05": {**DEFAULT_IMPACT, "VC": "L"},
    "tls06": {**DEFAULT_IMPACT, "VC": "H"},
}


def _metrics_for(result: dict[str, Any]) -> dict[str, str]:
    key = str(result.get("key", ""))
    name = str(result.get("name", "")).lower()
    profile = dict(PROFILES.get(key, DEFAULT_IMPACT))
    # Impact adjustments only use supported evidence terms, and remain estimates.
    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    evidence = " ".join(str(x) for x in (result.get("evidence") or []))
    details_text = str(details).lower() + " " + evidence.lower()
    if any(term in name for term in ("clickjacking",)):
        profile["UI"] = "A"
    if any(term in name for term in ("banner", "etag", "internal ip", "internal path")):
        profile.update({k: "N" for k in ("VI", "VA", "SC", "SI", "SA")})
        profile["VC"] = profile.get("VC", "L")
    # Confirmed exposed credentials or successful authentication justify a higher
    # impact estimate; the report still labels the score as analyst-reviewable.
    if any(term in details_text for term in ("credential accepted", "authentication succeeded", "successful_pairs", "secret value redacted")):
        profile.update({"VC": "H", "VI": "H", "VA": "L"})
    if key in {"tc02_default_credentials", "tc03_blank_credentials", "tc19_hardcoded_credentials"}:
        profile.update({"VC": "H", "VI": "H", "VA": "L"})
    if key in {"tc08_login_over_http", "tc09_cleartext_traffic", "tls01", "tls02", "tls03", "tls06"}:
        profile["VC"] = "H"
    metrics = {
        "AV": "N",  # network reachable target
        "AC": "L",  # no special condition observed
        "AT": "N",  # no additional attack requirement established
        "PR": "N",  # unauthenticated attack path unless confirmed otherwise
        "UI": profile.pop("UI", "N"),
        **profile,
    }
    return metrics


def build_cvss4_vector(result: dict[str, Any]) -> str:
    """Build a CVSS v4.0 vector from an evidence-linked conservative profile."""
    metric_order = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
    m = _metrics_for(result)
    return "CVSS:4.0/" + "/".join(f"{key}:{m[key]}" for key in metric_order)


def score_finding(result: dict[str, Any]) -> dict[str, Any] | None:
    """Return CVSS metadata for UNSAFE findings only; None for unconfirmed cases."""
    status = str(result.get("status", "")).strip().upper().replace("_", " ")
    if status != "UNSAFE":
        return None
    vector = build_cvss4_vector(result)
    encoded = quote(vector, safe=":/")
    calculator_url = f"{NIST_CALCULATOR}?vector={encoded}&version=4.0"
    out: dict[str, Any] = {
        "standard": "CVSS v4.0 Base (CVSS-B)",
        "vector": vector,
        "base_score": None,
        "severity": "Pending calculation",
        "calculator_url": calculator_url,
        "confidence": "Provisional estimate",
        "method": "Evidence-linked conservative profile; verify metrics and impact before external reporting.",
    }
    try:
        from cvss import CVSS4  # provided by the `cvss` PyPI package
        parsed = CVSS4(vector)
        score = float(parsed.base_score)
        out["base_score"] = round(score, 1)
        out["severity"] = str(parsed.severity)
        out["library"] = "cvss.CVSS4"
        # Prefer library's normalized vector, if available.
        try:
            out["vector"] = parsed.clean_vector()
        except Exception:
            pass
    except ImportError:
        out["calculation_state"] = "dependency_missing"
        out["method"] = "Vector prepared, but local CVSS library is not installed; open the NIST calculator or install project requirements to calculate the numeric score."
    except Exception as exc:
        out["calculation_state"] = "calculation_error"
        out["calculation_error"] = f"{type(exc).__name__}: {exc}"
    return out


def annotate_result(result: Any) -> Any:
    """Attach scoring details to a ScanResult-like object without changing verdict."""
    if str(getattr(result, "status", "")).strip().upper().replace("_", " ") != "UNSAFE":
        return result
    details = getattr(result, "details", None)
    if not isinstance(details, dict):
        details = {}
        setattr(result, "details", details)
    payload = score_finding({
        "key": getattr(result, "key", ""),
        "name": getattr(result, "name", ""),
        "status": getattr(result, "status", ""),
        "evidence": getattr(result, "evidence", []),
        "details": details,
    })
    if payload:
        details["cvss"] = payload
    return result
