"""CVSS v4.0 Base scoring for confirmed findings.

Calculates realistic CVSS v4.0 vectors and scores tailored to each testcase's
true exploit conditions (e.g. Physical for Shoulder Surfing, Local for Memory
Dump, High impact for confirmed Credential/SQLi compromises).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

NIST_CALCULATOR = "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"

# ==============================================================================
# INDIVIDUAL TESTCASE CVSS v4.0 PROFILES
#
# Metrics:
#   AV (Attack Vector):       N (Network), A (Adjacent), L (Local), P (Physical)
#   AC (Attack Complexity):   L (Low), H (High)
#   AT (Attack Requirements): N (None), P (Present)
#   PR (Privileges Req):      N (None), L (Low), H (High)
#   UI (User Interaction):    N (None), P (Passive), A (Active)
#   VC/VI/VA (Vuln Impact):   H (High), L (Low), N (None)
#   SC/SI/SA (Subseq Impact): H (High), L (Low), N (None)
# ==============================================================================
PROFILES: dict[str, dict[str, str]] = {
    # --- TC01: Autocomplete Security ---
    # Requires local/shared browser session and active user interaction (~4.6 Medium)
    "tc01_autocomplete": {
        "AV": "L", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC02: Default Credentials ---
    # Unauthenticated remote login with known defaults -> Full account takeover (~9.3 Critical)
    "tc02_default_credentials": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "L", "SC": "L", "SI": "L", "SA": "N"
    },

    # --- TC03: Blank Credentials ---
    # Unauthenticated login with blank password -> Account takeover (~9.3 Critical)
    "tc03_blank_credentials": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "L", "SC": "L", "SI": "L", "SA": "N"
    },

    # --- TC04: User Enumeration ---
    # Leaks valid usernames; confidentiality low, no integrity impact (~6.9 Medium)
    "tc04_user_enumeration": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC05: Weak Password Validation ---
    # Weak policy requires subsequent brute-force/guessing (AT:P) (~5.9 Medium)
    "tc05_password_validation": {
        "AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
        "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC06: Method Interchange ---
    # Login accepts GET/HEAD, leaking credentials into server/proxy logs & referrers (~7.1 High)
    "tc06_method_interchange": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC07: Browser Memory Dump ---
    # Passwords lingering in client memory/DOM; requires local terminal/process access (~4.8 Medium)
    "tc07_browser_memory_dump": {
        "AV": "L", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC08: Login Over HTTP ---
    # Unencrypted transport; exploitable by on-path/adjacent network MitM (~6.8 Medium)
    "tc08_login_over_http": {
        "AV": "A", "AC": "L", "AT": "P", "PR": "N", "UI": "P",
        "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC09: Cleartext Traffic ---
    # Unencrypted credential parameters in transport (~6.0 Medium)
    "tc09_cleartext_traffic": {
        "AV": "A", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC10: Remember Me Weakness ---
    # Insecure or persistent remember-me tokens allowing session hijack (~7.7 High)
    "tc10_remember_me": {
        "AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
        "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC11: Shoulder Surfing ---
    # Password visible in plaintext on screen; requires physical bystander proximity (~2.0 Low)
    "tc11_shoulder_surfing": {
        "AV": "P", "AC": "L", "AT": "N", "PR": "N", "UI": "P",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC12: Missing CAPTCHA ---
    # Absence of automated abuse prevention; allows credential stuffing (~5.3 Medium)
    "tc12_captcha_missing": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "N", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC13: Cross-Origin Resource Sharing (CORS) ---
    # Permissive origin reflection with credentials; requires victim to visit attacker site (~7.1 High)
    "tc13_cors": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC14: SQL Injection ---
    # Remote database query injection on authentication (~8.7 High to ~9.3 Critical)
    "tc14_sql_injection": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC15: LDAP / Active Directory Injection ---
    # Authentication bypass / directory object enumeration (~9.2 Critical)
    "tc15_ldap_ad": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "N", "SC": "L", "SI": "L", "SA": "N"
    },

    # --- TC16: Weak Password Encoding ---
    # Base64/plain reversible obfuscation of passwords in transit (~7.7 High)
    "tc16_weak_password_encoding": {
        "AV": "N", "AC": "L", "AT": "P", "PR": "N", "UI": "N",
        "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- TC17: Missing Rate Limiting ---
    # Unlimited brute-force attempts possible; integrity and availability impact (~5.3 Medium)
    "tc17_rate_limit": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "N", "VI": "L", "VA": "L", "SC": "N", "SI": "N", "SA": "N"
    },

    # --- Supporting TLS/General checks ---
    "tc16_clickjacking": {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },
    "tc18_missing_security_headers": {
        "AV": "N", "AC": "H", "AT": "N", "PR": "N", "UI": "P",
        "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
    },
}

DEFAULT_METRICS = {
    "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
    "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"
}


def _metrics_for(result: dict[str, Any]) -> dict[str, str]:
    """Derive authentic CVSS v4.0 metrics from testcase profile and observed evidence."""
    # Normalize key: handle 'login.tc11_shoulder_surfing' -> 'tc11_shoulder_surfing'
    raw_key = str(result.get("key", "")).lower()
    normalized_key = raw_key.split(".")[-1]

    profile = dict(PROFILES.get(normalized_key, PROFILES.get(raw_key, DEFAULT_METRICS)))

    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    exploit_ctx = details.get("exploit_context") if isinstance(details.get("exploit_context"), dict) else {}

    # 1. Structure-driven adjustments from exploit_context (e.g. TC02, TC14)
    if exploit_ctx:
        # SQL Injection granular severity
        if normalized_key == "tc14_sql_injection":
            if exploit_ctx.get("auth_bypassed"):
                profile.update({"VC": "H", "VI": "H", "VA": "L", "SC": "L", "SI": "L"})
            elif exploit_ctx.get("blind_differential"):
                profile.update({"VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N"})
            elif exploit_ctx.get("syntax_error_leak"):
                profile.update({"VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N"})

        # Default / Blank Credentials granular severity
        elif normalized_key in ("tc02_default_credentials", "tc03_blank_credentials"):
            role = str(exploit_ctx.get("role", "admin")).lower()
            if role in ("admin", "root", "operator", "administrator"):
                profile.update({"VC": "H", "VI": "H", "VA": "L", "SC": "L", "SI": "L"})
            else:
                profile.update({"VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N"})

        # Asset exposure / network reachability
        if exploit_ctx.get("exposure") == "internal":
            profile["AV"] = "A"

    # 2. Text-based heuristic fallback if structured exploit_context is absent
    evidence_text = " ".join(str(x) for x in (result.get("evidence") or [])).lower()
    if details:
        evidence_text += " " + str(details).lower()

    if any(term in evidence_text for term in (
        "credential accepted", "authentication succeeded", "bypass confirmed", "successful_pairs"
    )):
        profile.update({"VC": "H", "VI": "H", "VA": "L", "SC": "L", "SI": "L"})
    elif "reflected payload only" in evidence_text or "heuristics detected" in evidence_text:
        if profile.get("VC") == "H":
            profile["VC"] = "L"
        if profile.get("VI") == "H":
            profile["VI"] = "L"

    return profile


def build_cvss4_vector(result: dict[str, Any]) -> str:
    """Build an official CVSS v4.0 vector string."""
    metric_order = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
    m = _metrics_for(result)
    return "CVSS:4.0/" + "/".join(f"{key}:{m.get(key, 'N')}" for key in metric_order)


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
        "confidence": "Evidence-linked profile",
        "method": "Vulnerability-specific vector based on attack vector, interaction, and verified impact.",
    }

    try:
        from cvss import CVSS4
        parsed = CVSS4(vector)
        score = float(parsed.base_score)
        out["base_score"] = round(score, 1)
        out["severity"] = str(parsed.severity)
        out["library"] = "cvss.CVSS4"
        try:
            out["vector"] = parsed.clean_vector()
        except Exception:
            pass
    except ImportError:
        out["calculation_state"] = "dependency_missing"
        out["method"] = "Vector prepared; open the NIST calculator or install the 'cvss' package."
    except Exception as exc:
        out["calculation_state"] = "calculation_error"
        out["calculation_error"] = f"{type(exc).__name__}: {exc}"

    return out


def annotate_result(result: Any) -> Any:
    """Attach scoring details to a ScanResult-like object without modifying verdict."""
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
