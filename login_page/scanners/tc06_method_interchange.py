from __future__ import annotations

from pathlib import Path
from typing import Any

from authentication.method_interchange_analyzer import assess_method_interchange
from authentication.method_interchange_client import MethodInterchangeClient
from authentication.method_interchange_discovery import discover_login_form
from authentication.method_interchange_models import (
    MethodInterchangeConfig,
    MethodObservation,
    MethodInterchangeResult,
)

try:
    from authentication.login_applicability import federated_login_skip
except Exception:
    federated_login_skip = None

try:
    from authentication.lockout_guard import LockoutGuard
except Exception:
    LockoutGuard = None

def _safe_credential_presence(username: str | None, password: str | None) -> str:
    return (
        f"username_supplied={bool(username)}, "
        f"password_supplied={bool(password)}"
    )

def _severity_metadata() -> dict[str, Any]:
    """
    Keep severity optional so this scanner does not force a breaking change on
    the project's current core.models.ScanResult.
    """
    return {
        "severity": None,
        "risk_score": None,
        "severity_rationale": "",
        "severity_components": {},
        "severity_metrics": {},
    }

def _build_result(
    *,
    result: MethodInterchangeResult,
) -> dict[str, Any]:
    payload = result.as_dict()
    payload.update(_severity_metadata())
    payload["key"] = "tc06_method_interchange"
    payload["name"] = "Method Interchange"
    payload["raw_output"] = ""
    return payload

def _not_assessed(reason: str, target: str) -> dict[str, Any]:
    return _build_result(
        result=MethodInterchangeResult(
            status="NOT ASSESSED",
            assessment_state="NOT_ASSESSED",
            summary="TC06 is not applicable because the login flow is federated SSO/IdP.",
            target=target,
            evidence=[reason],
        )
    )

def _incomplete(reason: str, target: str, *, evidence: list[str] | None = None) -> dict[str, Any]:
    return _build_result(
        result=MethodInterchangeResult(
            status="INCOMPLETE",
            assessment_state="INCOMPLETE",
            summary=reason,
            target=target,
            evidence=evidence or [reason],
        )
    )

def _apply_attempt_delay(seconds: float) -> None:
    if seconds > 0:
        import time
        time.sleep(seconds)

def _probe(
    client: MethodInterchangeClient,
    discovered,
    *,
    method: str,
    username: str,
    password: str,
    case_id: str,
    credential_profile: str,
    preserve_hidden_fields: bool,
) -> MethodObservation:
    return client.submit_form(
        discovered,
        method=method,
        username=username,
        password=password,
        preserve_hidden_fields=preserve_hidden_fields,
        case_id=case_id,
        credential_profile=credential_profile,
    )

def scan_method_interchange(
    target: str,
    *,
    config: MethodInterchangeConfig | None = None,
    progress=None,
) -> dict[str, Any]:
    cfg = (config or MethodInterchangeConfig()).normalized()
    target = target.strip()

    if not target:
        return _incomplete("No target URL was supplied.", target)

    synthetic_username = "tc06-method-interchange-invalid-user"
    synthetic_password = "Tc06-Wrong-Password-7F3A"
    has_authorized = bool(cfg.authorized_username and cfg.authorized_password)
    if not has_authorized:
        cfg.authorized_username = synthetic_username
        cfg.authorized_password = synthetic_password

    if progress:
        progress("Discovering login method for Method Interchange")

    # SSO applicability: skip local-method testing.
    if federated_login_skip is not None:
        try:
            skip = federated_login_skip(target, cfg.login_path, probe=True)
            if skip:
                reason = "Federated/hosted identity-provider login detected."
                return _not_assessed(reason, target)
        except Exception:
            # Discovery below remains authoritative for technical execution.
            pass

    discovered, discovery_evidence, final_page = discover_login_form(
        target,
        cfg.login_path,
        timeout=cfg.timeout,
        verify_tls=cfg.verify_tls,
    )

    if discovered is None:
        return _incomplete(
            "TC06 could not discover a usable local GET/POST login form.",
            final_page or target,
            evidence=discovery_evidence,
        )

    expected_method = discovered.method.upper()
    if expected_method not in {"GET", "POST"}:
        return _incomplete(
            f"The discovered login form uses unsupported method {expected_method!r}. "
            "TC06 only performs safe GET/POST interchange.",
            discovered.action_url,
            evidence=discovery_evidence,
        )

    alternate_method = "GET" if expected_method == "POST" else "POST"

    client = MethodInterchangeClient(
        timeout=cfg.timeout,
        verify_tls=cfg.verify_tls,
        auth_cookie_hints=cfg.auth_cookie_hints,
    )

    observations: list[MethodObservation] = []
    attempts = 0

    # The four core observations:
    # 1. expected + valid (must establish a valid-auth control)
    # 2. expected + wrong (must establish normal rejection)
    # 3. alternate + valid
    # 4. alternate + wrong (the security-critical comparison)
    if has_authorized:
        cases = [
            ("TC06-EV", expected_method, cfg.authorized_username, cfg.authorized_password, "expected_valid"),
            ("TC06-EW", expected_method, cfg.authorized_username, cfg.probe_password, "expected_wrong"),
            ("TC06-AV", alternate_method, cfg.authorized_username, cfg.authorized_password, "alternate_valid"),
            ("TC06-AW", alternate_method, cfg.authorized_username, cfg.probe_password, "alternate_wrong"),
        ]
    else:
        # Without a known-valid account, still compare GET vs POST using invalid credentials.
        cases = [
            ("TC06-EW", expected_method, cfg.authorized_username, cfg.probe_password, "expected_wrong"),
            ("TC06-AW", alternate_method, cfg.authorized_username, cfg.probe_password, "alternate_wrong"),
        ]

    for index, (case_id, method, username, password, profile) in enumerate(cases):
        if attempts >= cfg.max_attempts:
            break

        if index:
            _apply_attempt_delay(cfg.min_delay_seconds)

        if progress:
            progress(f"Testing {profile.replace('_', ' ')} using {method}")

        observation = _probe(
            client,
            discovered,
            method=method,
            username=username,
            password=password,
            case_id=case_id,
            credential_profile=profile,
            preserve_hidden_fields=cfg.preserve_hidden_fields,
        )
        observations.append(observation)
        attempts += 1

        if observation.rate_limited:
            break

    by_profile = {obs.credential_profile: obs for obs in observations}

    decision = assess_method_interchange(
        expected_valid=by_profile.get("expected_valid"),
        expected_wrong=by_profile.get("expected_wrong"),
        alternate_valid=by_profile.get("alternate_valid"),
        alternate_wrong=by_profile.get("alternate_wrong"),
    )

    evidence = [
        f"Expected login method: {expected_method}.",
        f"Alternate method tested: {alternate_method}.",
        *discovery_evidence,
        _safe_credential_presence(cfg.authorized_username, cfg.authorized_password),
    ]

    for observation in observations:
        evidence.extend(observation.evidence)

    expected_valid = by_profile.get("expected_valid")
    expected_wrong = by_profile.get("expected_wrong")
    alternate_valid = by_profile.get("alternate_valid")
    alternate_wrong = by_profile.get("alternate_wrong")

    result = MethodInterchangeResult(
        status=decision["status"],
        assessment_state=decision["assessment_state"],
        summary=(
            "The alternate HTTP method accepted an incorrect credential, "
            "demonstrating a method-specific authentication control bypass."
            if decision["finding_confirmed"]
            else decision["reason"]
        ),
        target=discovered.action_url,
        expected_method=expected_method,
        alternate_method=alternate_method,
        authenticated_expected=bool(
            expected_valid and expected_valid.authenticated_signal
        ),
        rejected_expected=bool(
            expected_wrong and expected_wrong.rejected_signal
        ),
        accepted_wrong_alternate=bool(
            alternate_wrong and alternate_wrong.authenticated_signal
        ),
        accepted_valid_alternate=bool(
            alternate_valid and alternate_valid.authenticated_signal
        ),
        security_control_bypass=bool(decision["finding_confirmed"]),
        attempts_made=attempts,
        observations=observations,
        evidence=evidence,
        details={
            "test_identity": "Login Page TC06 - Method Interchange",
            "expected_method": expected_method,
            "alternate_method": alternate_method,
            "login_endpoint": discovered.action_url,
            "login_page": discovered.page_url,
            "username_field": discovered.username_field,
            "password_field": discovered.password_field,
            "hidden_field_count": len(discovered.hidden_fields),
            "probe_password_is_masked": True,
            "protected_urls_configured": list(cfg.protected_urls),
            "method_scope": "GET/POST only",
            "scope_boundary": [
                "TC06 does not test PUT/PATCH/DELETE/TRACE or arbitrary verbs.",
                "TC11 owns arbitrary HTTP method behavior.",
                "TC05 owns ordinary incorrect-password validation.",
                "TC03 owns blank/missing credential acceptance.",
                "CSRF is recorded as evidence when method handling differs, but not independently scored by TC06.",
            ],
        },
    )

    # Severity remains unassigned here unless a confirmed bypass is available.
    return _build_result(result=result)

scan = scan_method_interchange
