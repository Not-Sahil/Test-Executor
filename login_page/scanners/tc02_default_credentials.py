from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authentication.auth_client import create_session, submit_credentials
from authentication.auth_discovery import discover_authentication, normalize_login_url
from authentication.baseline import establish_auth_failure_baseline
from authentication.credential_registry import filter_credentials_by_product, load_authorized_credentials
from authentication.lockout_guard import LockoutGuard, is_rate_limited_response
from authentication.login_applicability import federated_login_skip
from authentication.models import AuthenticationAttempt, CredentialCandidate, TC02Result
from authentication.privilege import determine_privilege
from authentication.success_verifier import verify_authentication

try:
    from core.severity_engine import SeverityInput, calculate_severity
except ImportError:  # pragma: no cover - keeps scanner importable before severity engine is wired in
    SeverityInput = None  # type: ignore[assignment]
    calculate_severity = None  # type: ignore[assignment]


@dataclass(frozen=True)
class TC02Config:
    login_path: str = "/login"
    max_attempts: int = 10
    timeout: float = 8.0
    min_delay_seconds: float = 0.5
    verify_tls: bool = True
    stop_on_first_confirmed: bool = False
    product_hint: str | None = None
    protected_urls: tuple[str, ...] = ()
    allow_lab_profile: bool = False
    attack_vector: str = "NETWORK"
    asset_exposure: str = "PUBLIC"
    scope: str = "SAME_SYSTEM"


def _status_for_failure(state: str) -> str:
    if state in {"RATE_LIMITED", "MFA_REQUIRED", "PASSWORD_CHANGE_REQUIRED", "AMBIGUOUS"}:
        return "REVIEW"
    if state in {"ERROR", "UNRESOLVED"}:
        return "INCOMPLETE"
    return "SAFE"


def _severity_for_privilege(privilege: str, config: TC02Config) -> Any:
    """Map confirmed TC02 facts into the application-owned severity engine."""
    if SeverityInput is None or calculate_severity is None:
        return None

    privilege = privilege.lower()
    if privilege == "admin":
        confidentiality = integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "HIGH"
    elif privilege == "operator":
        confidentiality = integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "MODERATE"
    elif privilege == "standard":
        confidentiality = "LOW"
        integrity = "LOW"
        authorization = "LIMITED"
        sensitivity = "LOW"
    else:
        confidentiality = integrity = "LOW"
        authorization = "LIMITED"
        sensitivity = "LOW"

    metrics = SeverityInput(
        attack_vector=config.attack_vector,
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        asset_exposure=config.asset_exposure,
        confidentiality=confidentiality,
        integrity=integrity,
        availability="LOW",
        authorization=authorization,
        data_sensitivity=sensitivity,
        scope=config.scope,
        rationale=(
            "Confirmed default authentication was accepted over a network-exposed login. "
            f"Privilege level was assessed as {privilege}."
        ),
    )
    return calculate_severity(metrics, assessment_state="CONFIRMED")


def _build_confirmed_summary(attempt: AuthenticationAttempt) -> str:
    privilege = attempt.privilege if attempt.privilege != "unknown" else "unknown privilege"
    return (
        "A configured default/predictable credential was confirmed to authenticate successfully. "
        f"Account privilege assessment: {privilege}."
    )


def scan_default_credentials(
    target: str,
    credentials: list[CredentialCandidate],
    config: TC02Config | None = None,
) -> TC02Result:
    config = config or TC02Config()
    result = TC02Result()
    login_url = normalize_login_url(target, config.login_path)

    # 1) Applicability: hosted IdP / OAuth is not a local default-credential test.
    skip = federated_login_skip(target, config.login_path, probe=True)
    if skip:
        result.status = "NOT_ASSESSED"
        result.summary = "Not applicable: federated identity-provider authentication was detected."
        result.evidence.extend([
            f"classification={skip.get('classification')}",
            f"login_url={skip.get('login_url')}",
            f"reason={skip.get('reason')}",
        ])
        result.details["assessment_state"] = "NOT_ASSESSED"
        return result

    # 2) Credential availability is a test precondition, not a vulnerability verdict.
    candidates = filter_credentials_by_product(credentials, config.product_hint)
    if not candidates:
        result.status = "INCOMPLETE"
        result.summary = "No authorized credential candidates were supplied for TC02."
        result.evidence.append("credential registry produced zero eligible candidates")
        result.details["assessment_state"] = "INCOMPLETE"
        return result

    # 3) Discover the real authentication mechanism.
    mechanism, discovery = discover_authentication(
        target,
        login_hint=config.login_path,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )
    result.details["discovery"] = discovery
    if mechanism is None:
        result.status = "INCOMPLETE"
        result.summary = "Authentication mechanism could not be resolved reliably."
        result.evidence.append("login discovery returned no supported mechanism")
        result.details["assessment_state"] = "INCOMPLETE"
        return result

    result.details["auth_mechanism"] = mechanism.as_dict()
    result.evidence.extend(mechanism.evidence)

    # 4) Establish a negative baseline before trusting any real credential response.
    baseline = establish_auth_failure_baseline(
        mechanism,
        verify_tls=config.verify_tls,
        timeout=config.timeout,
    )
    result.details["baseline"] = {
        "established": baseline.established,
        "state": baseline.state,
        "http_status": baseline.http_status,
        "final_url": baseline.final_url,
        "evidence": list(baseline.evidence),
    }
    result.evidence.extend(baseline.evidence)

    if not baseline.established:
        result.status = "REVIEW" if baseline.state == "RATE_LIMITED" else "INCOMPLETE"
        result.summary = (
            "TC02 stopped because the scanner could not establish a reliable invalid-credential baseline."
        )
        result.details["assessment_state"] = "REVIEW_REQUIRED" if result.status == "REVIEW" else "INCOMPLETE"
        return result

    # 5) Guarded bounded attempts.
    guard = LockoutGuard(
        max_attempts=min(config.max_attempts, len(candidates)),
        min_delay_seconds=config.min_delay_seconds,
    )
    session = create_session(config.verify_tls)
    attempts: list[AuthenticationAttempt] = []

    for candidate in candidates:
        if not guard.before_attempt():
            result.status = "REVIEW"
            result.summary = "Testing stopped at the configured authentication-attempt limit."
            result.evidence.append("lockout/attempt guard reached the configured limit")
            break

        auth_response = submit_credentials(
            session,
            mechanism,
            candidate,
            timeout=config.timeout,
            allow_redirects=True,
        )

        if auth_response.response is None:
            attempt = AuthenticationAttempt(
                credential=candidate,
                http_status=None,
                final_url=auth_response.final_url,
                candidate_state="ERROR",
                authentication_confirmed=False,
                evidence=(f"authentication request failed: {auth_response.error}",),
            )
            attempts.append(attempt)
            continue

        response = auth_response.response
        rate_limited = is_rate_limited_response(response)
        verification = verify_authentication(response, mechanism, baseline.final_url)

        privilege = "unknown"
        privilege_evidence: list[str] = []
        if verification.confirmed and config.protected_urls:
            privilege, privilege_evidence = determine_privilege(
                session,
                response.url,
                config.protected_urls,
                timeout=config.timeout,
            )

        attempt = AuthenticationAttempt(
            credential=candidate,
            http_status=response.status_code,
            final_url=auth_response.final_url,
            candidate_state=verification.state,
            authentication_confirmed=verification.confirmed,
            mfa_required=verification.mfa_required,
            password_change_required=verification.password_change_required,
            rate_limited=rate_limited,
            privilege=privilege,
            evidence=tuple([verification.reason] + list(privilege_evidence)),
        )
        attempts.append(attempt)

        result.evidence.append(
            f"{candidate.masked()} source={candidate.credential_source} "
            f"state={verification.state} http={response.status_code}"
        )
        if rate_limited or verification.state == "RATE_LIMITED":
            result.status = "REVIEW"
            result.summary = "Testing stopped because the target signaled rate limiting or lockout."
            break

        if verification.confirmed:
            # Use a fresh session is intentionally avoided: this preserves the authenticated state
            # needed for configured privilege probes.
            result.details["confirmed"] = attempt.as_dict()
            result.details["exploit_context"] = {
                "login_succeeded": True,
                "role": str(privilege).lower(),
                "username": attempt.username,
                "auth_bypassed": True,
                "exposure": config.asset_exposure.lower() if hasattr(config, "asset_exposure") else "public",
                "scope": config.scope.lower() if hasattr(config, "scope") else "same_system",
            }
            result.status = "UNSAFE"
            result.summary = _build_confirmed_summary(attempt)
            severity = _severity_for_privilege(privilege, config)
            if severity is not None:
                result.details["assessment_state"] = severity.assessment_state
                result.details["severity"] = severity.severity
                result.details["risk_score"] = severity.score
                result.details["severity_rationale"] = severity.rationale
                result.details["severity_components"] = severity.components
                result.details["severity_metrics"] = severity.metrics
            if config.stop_on_first_confirmed:
                break

    result.details["attempts"] = [item.as_dict() for item in attempts]
    result.details["attempts_made"] = len(attempts)

    if result.status == "UNSAFE":
        result.details.setdefault("assessment_state", "CONFIRMED")
        result.details["confirmed_count"] = sum(a.authentication_confirmed for a in attempts)
        return result

    if result.status == "REVIEW":
        result.details.setdefault("assessment_state", "REVIEW_REQUIRED")
        return result

    # If no credential was confirmed and testing completed normally, this is a genuine NOT_A_FINDING.
    unresolved_attempt = any(a.candidate_state in {"AMBIGUOUS", "MFA_REQUIRED", "PASSWORD_CHANGE_REQUIRED", "ERROR"} for a in attempts)
    if unresolved_attempt:
        result.status = "REVIEW"
        result.summary = "No default credential was confirmed, but one or more attempts were inconclusive."
        result.details["assessment_state"] = "REVIEW_REQUIRED"
    else:
        result.status = "SAFE"
        result.summary = "No authorized default credential candidate was confirmed to authenticate."
        result.details["assessment_state"] = "NOT_A_FINDING"

    return result


def to_scan_result(result: TC02Result):
    """Adapt the standalone TC02 result into the project's shared ScanResult."""
    from core.models import ScanResult

    return ScanResult(
        key=result.key,
        name=result.name,
        status=result.status,
        summary=result.summary,
        raw_output=result.raw_output,
        evidence=result.evidence,
        details=result.details,
    )



def scan_default_credentials_from_file(
    target: str,
    credential_file: str | Path,
    config: TC02Config | None = None,
) -> TC02Result:
    config = config or TC02Config()
    credentials = load_authorized_credentials(
        credential_file,
        allow_lab_profile=config.allow_lab_profile,
    )
    return scan_default_credentials(target, credentials, config)
