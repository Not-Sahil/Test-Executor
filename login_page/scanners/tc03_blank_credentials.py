from __future__ import annotations

from dataclasses import dataclass, field, make_dataclass
from pathlib import Path
from typing import Any

from authentication.auth_discovery import discover_authentication, normalize_login_url
from authentication.blank_credential_client import submit_variant
from authentication.blank_response_verifier import (
    has_explicit_authentication_signal,
    verify_blank_response,
    verify_protected_access,
)
from authentication.browser_blank_client import run_browser_variant
from authentication.credential_variants import (
    AuthorizedCredential,
    CredentialState,
    CredentialVariant,
    TC03_MANDATORY_VARIANTS,
    TC03_OPTIONAL_VARIANTS,
)
from authentication.lockout_guard import LockoutGuard, is_rate_limited_response
from authentication.login_applicability import captcha_marker_from_html, captcha_marker_from_url, federated_login_skip
from authentication.models import AuthMechanism
from authentication.privilege import determine_privilege

try:
    from core.models import ScanResult
except ImportError:  # pragma: no cover
    _FallbackScanResult = make_dataclass(
        "_FallbackScanResult",
        [
            ("key", str),
            ("name", str),
            ("status", str),
            ("summary", str),
            ("raw_output", str, field(default="")),
            ("evidence", list, field(default_factory=list)),
            ("details", dict, field(default_factory=dict)),
        ],
    )
    ScanResult = _FallbackScanResult

try:
    from core.severity_engine import SeverityInput, calculate_severity
except ImportError:  # pragma: no cover
    SeverityInput = None  # type: ignore[assignment]
    calculate_severity = None  # type: ignore[assignment]


@dataclass(frozen=True)
class TC03Config:
    login_path: str = "/login"
    timeout: float = 8.0
    verify_tls: bool = True
    min_delay_seconds: float = 0.5
    max_attempts: int = 10
    include_optional_variants: bool = True
    stop_on_confirmed: bool = True
    probe_password: str = "__tc03_blank_probe_password__"
    authorized_username: str | None = None
    authorized_password: str | None = None
    protected_urls: tuple[str, ...] = ()
    allow_browser_fallback: bool = True
    browser_timeout_ms: int = 20_000
    attack_vector: str = "NETWORK"
    asset_exposure: str = "PUBLIC"
    scope: str = "SAME_SYSTEM"
    requested_whitespace_variants: bool = True
    requested_json_null_variant: bool = True


@dataclass
class VariantObservation:
    variant: CredentialVariant
    state: str
    authenticated: bool = False
    candidate_success: bool = False
    mfa_required: bool = False
    password_change_required: bool = False
    captcha_blocked: bool = False
    rate_limited: bool = False
    privilege: str = "unknown"
    final_url: str = ""
    http_status: int | None = None
    error: str = ""
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "variant": self.variant.as_dict(),
            "state": self.state,
            "authenticated": self.authenticated,
            "candidate_success": self.candidate_success,
            "mfa_required": self.mfa_required,
            "password_change_required": self.password_change_required,
            "captcha_blocked": self.captcha_blocked,
            "rate_limited": self.rate_limited,
            "privilege": self.privilege,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "error": self.error,
            "evidence": self.evidence,
        }


def _applicable_variants(
    mechanism: AuthMechanism,
    config: TC03Config,
) -> list[CredentialVariant]:
    variants: list[CredentialVariant] = list(TC03_MANDATORY_VARIANTS)
    if config.include_optional_variants:
        variants.extend(TC03_OPTIONAL_VARIANTS)

    output: list[CredentialVariant] = []
    for variant in variants:
        if variant.json_only and mechanism.type != "json_api":
            continue
        if variant.html_only and mechanism.type != "html_form":
            continue
        if variant.username_state == CredentialState.VALUE and not config.authorized_username:
            continue
        if variant.password_state == CredentialState.VALUE and not config.authorized_password:
            continue
        if variant.username_state == CredentialState.WHITESPACE and not config.requested_whitespace_variants:
            continue
        if variant.password_state == CredentialState.WHITESPACE and not config.requested_whitespace_variants:
            continue
        if variant.username_state == CredentialState.NULL and not config.requested_json_null_variant:
            continue
        if variant.password_state == CredentialState.NULL and not config.requested_json_null_variant:
            continue
        output.append(variant)
    return output


def _severity_for_privilege(privilege: str, config: TC03Config):
    if SeverityInput is None or calculate_severity is None:
        return None

    p = privilege.lower()
    if p == "admin":
        confidentiality = integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "HIGH"
    elif p == "operator":
        confidentiality = integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "MODERATE"
    elif p == "standard":
        confidentiality = integrity = "LOW"
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
            "Blank or missing credential input was confirmed to establish an authenticated session. "
            f"Privilege level was assessed as {p}."
        ),
    )
    return calculate_severity(metrics, assessment_state="CONFIRMED")


def _result(
    *,
    status: str,
    summary: str,
    evidence: list[str] | None = None,
    details: dict[str, Any] | None = None,
):
    return ScanResult(
        key="login.tc03_blank_credentials",
        name="Blank Credentials",
        status=status,
        summary=summary,
        evidence=evidence or [],
        details=details or {},
    )


def _candidate_to_authenticated_result(
    observation: VariantObservation,
    mechanism: AuthMechanism,
    config: TC03Config,
    protected_verification: tuple[bool, str, list[str]] | None,
    *,
    session: Any = None,
) -> None:
    if protected_verification is not None:
        confirmed, reason, evidence = protected_verification
        observation.authenticated = confirmed
        observation.evidence.extend(evidence)
        if not confirmed:
            observation.state = "CANDIDATE_SUCCESS"
            observation.evidence.append(f"independent protected-resource verification: {reason}")
            return
    else:
        observation.state = "CANDIDATE_SUCCESS"


def _run_http_variant(
    mechanism: AuthMechanism,
    variant: CredentialVariant,
    config: TC03Config,
    target_base_url: str,
) -> VariantObservation:
    obs = VariantObservation(variant=variant, state="STARTED")
    request = submit_variant(
        mechanism,
        variant,
        authorized_username=config.authorized_username or "",
        authorized_password=config.authorized_password or "",
        probe_password=config.probe_password,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )

    if request.response is None:
        obs.state = "ERROR"
        obs.error = request.error
        obs.evidence.append(f"request_error={request.error}")
        return obs

    response = request.response
    obs.http_status = response.status_code
    obs.final_url = request.final_url
    obs.evidence.append(f"http_status={response.status_code}")
    obs.evidence.append(f"final_url={request.final_url}")
    obs.evidence.append(f"username_presence={request.prepared_fields.get('username_present')}")
    obs.evidence.append(f"password_presence={request.prepared_fields.get('password_present')}")

    if is_rate_limited_response(response):
        obs.state = "RATE_LIMITED"
        obs.rate_limited = True
        obs.evidence.append("rate_limit_or_lockout_signal_detected")
        return obs

    verification = verify_blank_response(response, mechanism)
    obs.state = verification.state
    obs.candidate_success = verification.state == "CANDIDATE_SUCCESS"
    obs.mfa_required = verification.mfa_required
    obs.password_change_required = verification.password_change_required
    obs.captcha_blocked = verification.captcha_blocked
    obs.evidence.append(verification.reason)
    obs.evidence.extend(verification.evidence)

    # Requests uses one isolated Session inside submit_variant; retrieve a fresh
    # protected resource only by explicitly re-running the same variant is not
    # possible. For TC03, a strong HTTP success signal is therefore confirmed
    # only when the authentication endpoint itself returns an explicit token or
    # equivalent success state. Browser fallback handles cookie-backed session
    # verification separately. For operator-configured protected URLs, perform
    # a second isolated authenticated transaction below via a session-aware path.
    if obs.candidate_success:
        if mechanism.type == "json_api" and has_explicit_authentication_signal(response):
            obs.authenticated = True
            obs.state = "AUTHENTICATED"
            obs.evidence.append("authentication endpoint explicitly reported an authenticated/token success signal")
        elif request.session is not None and config.protected_urls:
            confirmed, reason, protected_evidence = verify_protected_access(
                request.session,
                target_base_url,
                config.protected_urls,
                timeout=config.timeout,
            )
            obs.authenticated = confirmed
            obs.state = "AUTHENTICATED" if confirmed else "CANDIDATE_SUCCESS"
            obs.evidence.append(f"protected_verification={reason}")
            obs.evidence.extend(protected_evidence)
        else:
            obs.evidence.append(
                "candidate authentication could not be independently confirmed because no explicit auth signal or protected URL was available"
            )

        if obs.authenticated and request.session is not None and config.protected_urls:
            try:
                privilege, privilege_evidence = determine_privilege(
                    request.session,
                    target_base_url,
                    config.protected_urls,
                    timeout=config.timeout,
                )
                obs.privilege = privilege
                obs.evidence.extend(privilege_evidence)
            except Exception as exc:
                obs.evidence.append(f"privilege_probe_error={exc}")
    return obs


def _run_browser_variant_if_needed(
    target_login_url: str,
    variant: CredentialVariant,
    config: TC03Config,
) -> VariantObservation:
    obs = VariantObservation(variant=variant, state="STARTED")
    result = run_browser_variant(
        target_login_url,
        variant,
        authorized_username=config.authorized_username or "",
        authorized_password=config.authorized_password or "",
        probe_password=config.probe_password,
        verify_tls=config.verify_tls,
        timeout_ms=config.browser_timeout_ms,
        protected_urls=config.protected_urls,
    )
    obs.state = result.state
    obs.candidate_success = result.authenticated_candidate
    obs.captcha_blocked = result.captcha_blocked
    obs.final_url = result.final_url
    obs.error = result.error
    obs.evidence.extend(result.evidence)
    if result.error:
        obs.evidence.append(f"browser_error={result.error}")
    return obs


def scan_blank_credentials(
    target: str,
    config: TC03Config | None = None,
):
    config = config or TC03Config()
    login_url = normalize_login_url(target, config.login_path)
    evidence: list[str] = []
    details: dict[str, Any] = {
        "assessment_state": "INCOMPLETE",
        "target": target,
        "login_url": login_url,
        "test_case": "TC03",
        "test_variants": [],
    }

    # 1) Applicability.
    skip = federated_login_skip(target, config.login_path, probe=True)
    if skip:
        details["assessment_state"] = "NOT_ASSESSED"
        details["applicability"] = skip
        return _result(
            status="NOT_ASSESSED",
            summary="Not applicable: federated identity-provider authentication was detected.",
            evidence=[
                f"classification={skip.get('classification')}",
                f"reason={skip.get('reason')}",
            ],
            details=details,
        )

    # 2) Discovery.
    mechanism, discovery = discover_authentication(
        target,
        login_hint=config.login_path,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )
    details["discovery"] = discovery

    if mechanism is None:
        # Optional rendered-browser fallback is especially useful for SPAs and
        # username-first flows that have no conventional server-rendered form.
        if config.allow_browser_fallback:
            variants = list(TC03_MANDATORY_VARIANTS)
            browser_observations: list[VariantObservation] = []
            for variant in variants:
                if variant.username_state == CredentialState.VALUE and not config.authorized_username:
                    continue
                if variant.password_state == CredentialState.VALUE and not config.authorized_password:
                    continue
                browser_observations.append(_run_browser_variant_if_needed(login_url, variant, config))
                if browser_observations[-1].authenticated and config.stop_on_confirmed:
                    break

            details["browser_observations"] = [item.as_dict() for item in browser_observations]
            if any(item.authenticated for item in browser_observations):
                confirmed = next(item for item in browser_observations if item.authenticated)
                privilege = "unknown"
                severity = _severity_for_privilege(privilege, config)
                details["assessment_state"] = "CONFIRMED"
                details["confirmed_variant"] = confirmed.as_dict()
                if severity is not None:
                    details["severity"] = severity.severity
                    details["risk_score"] = severity.score
                    details["severity_rationale"] = severity.rationale
                    details["severity_components"] = severity.components
                    details["severity_metrics"] = severity.metrics
                return _result(
                    status="UNSAFE",
                    summary=f"Blank credential condition {confirmed.variant.case_id} reached an authenticated browser state.",
                    evidence=confirmed.evidence,
                    details=details,
                )

            if browser_observations and any(o.state in {"CAPTCHA_BLOCKED", "AMBIGUOUS", "ERROR", "UNRESOLVED", "BROWSER_UNAVAILABLE"} for o in browser_observations):
                details["assessment_state"] = "REVIEW_REQUIRED"
                return _result(
                    status="REVIEW",
                    summary="No blank-credential authentication was confirmed, but rendered-login testing was inconclusive or blocked.",
                    evidence=[e for o in browser_observations for e in o.evidence],
                    details=details,
                )

        details["assessment_state"] = "INCOMPLETE"
        return _result(
            status="INCOMPLETE",
            summary="Authentication mechanism could not be resolved reliably for TC03.",
            evidence=["login discovery returned no supported mechanism"],
            details=details,
        )

    details["auth_mechanism"] = mechanism.as_dict()
    evidence.extend(mechanism.evidence)

    # 3) Explicit CAPTCHA marker before active testing.
    if mechanism.source_url:
        marker = None
        try:
            import requests
            response = requests.get(mechanism.source_url, timeout=config.timeout, verify=config.verify_tls)
            marker = captcha_marker_from_html(response.text) or captcha_marker_from_url(response.url)
        except requests.RequestException:
            marker = None
        if marker:
            details["captcha_marker"] = marker
            details["assessment_state"] = "REVIEW_REQUIRED"
            return _result(
                status="REVIEW",
                summary="TC03 authentication testing is blocked by a detected CAPTCHA/challenge.",
                evidence=[f"captcha_marker={marker}"],
                details=details,
            )

    # 4) Establish invalid baseline using existing shared baseline module.
    from authentication.baseline import establish_auth_failure_baseline
    baseline = establish_auth_failure_baseline(
        mechanism,
        verify_tls=config.verify_tls,
        timeout=config.timeout,
    )
    details["baseline"] = {
        "established": baseline.established,
        "state": baseline.state,
        "http_status": baseline.http_status,
        "final_url": baseline.final_url,
        "evidence": list(baseline.evidence),
    }
    evidence.extend(baseline.evidence)
    if not baseline.established:
        details["assessment_state"] = "REVIEW_REQUIRED" if baseline.state == "RATE_LIMITED" else "INCOMPLETE"
        return _result(
            status="REVIEW" if baseline.state == "RATE_LIMITED" else "INCOMPLETE",
            summary="TC03 stopped because the scanner could not establish a reliable invalid-credential baseline.",
            evidence=evidence,
            details=details,
        )

    # 5) Build bounded variant matrix.
    variants = _applicable_variants(mechanism, config)
    details["test_variants"] = [v.as_dict() for v in variants]
    guard = LockoutGuard(
        max_attempts=min(config.max_attempts, max(1, len(variants))),
        min_delay_seconds=config.min_delay_seconds,
    )

    observations: list[VariantObservation] = []
    confirmed: list[VariantObservation] = []
    review_required = False

    for variant in variants:
        if not guard.before_attempt():
            review_required = True
            evidence.append("TC03 lockout/attempt guard stopped further testing")
            break

        obs = _run_http_variant(mechanism, variant, config, target)

        # For browser-inaccessible/ambiguous HTTP cases, optionally retry through
        # a rendered browser. This covers SPAs and multi-step login behavior.
        if config.allow_browser_fallback and obs.state in {"AMBIGUOUS", "CANDIDATE_SUCCESS"} and mechanism.type == "html_form":
            browser_obs = _run_browser_variant_if_needed(login_url, variant, config)
            if browser_obs.state not in {"BROWSER_UNAVAILABLE", "ERROR", "UNRESOLVED"}:
                obs.evidence.append("rendered-browser cross-check executed")
                obs.evidence.extend(browser_obs.evidence)
                if browser_obs.authenticated_candidate:
                    obs.candidate_success = True
                    obs.state = "CANDIDATE_SUCCESS"
                    obs.final_url = browser_obs.final_url
                if browser_obs.captcha_blocked:
                    obs.captcha_blocked = True
                    obs.state = "CAPTCHA_BLOCKED"

        if obs.state == "RATE_LIMITED":
            review_required = True
        if obs.state in {"AMBIGUOUS", "MFA_REQUIRED", "PASSWORD_CHANGE_REQUIRED", "CAPTCHA_BLOCKED", "ERROR"}:
            review_required = True
        observations.append(obs)
        evidence.extend([f"{variant.case_id}: {item}" for item in obs.evidence])

        if obs.authenticated:
            confirmed.append(obs)
            if config.stop_on_confirmed:
                break

        # Browser cross-check can produce a candidate success but cannot by itself
        # establish protected authorization unless protected URLs were tested.
        if obs.candidate_success and not obs.authenticated:
            review_required = True

    details["observations"] = [item.as_dict() for item in observations]
    details["attempts_made"] = len(observations)

    # 6) Confirm browser-authenticated candidates only if a strong final-state
    # signal was observed. HTTP candidates remain review unless an explicit
    # protected verification facility is added to the underlying client.
    for obs in confirmed:
        if obs.privilege == "unknown":
            obs.privilege = "unknown"

    if confirmed:
        first = confirmed[0]
        privilege = first.privilege
        details["confirmed_variant"] = first.as_dict()
        details["assessment_state"] = "CONFIRMED"
        severity = _severity_for_privilege(privilege, config)
        if severity is not None:
            details["severity"] = severity.severity
            details["risk_score"] = severity.score
            details["severity_rationale"] = severity.rationale
            details["severity_components"] = severity.components
            details["severity_metrics"] = severity.metrics
        return _result(
            status="UNSAFE",
            summary=(
                f"Blank credential condition {first.variant.case_id} was confirmed to reach an authenticated state."
            ),
            evidence=evidence,
            details=details,
        )

    if review_required:
        details["assessment_state"] = "REVIEW_REQUIRED"
        return _result(
            status="REVIEW",
            summary="No blank-credential authentication was confirmed, but one or more TC03 conditions were inconclusive or blocked.",
            evidence=evidence,
            details=details,
        )

    details["assessment_state"] = "NOT_A_FINDING"
    return _result(
        status="SAFE",
        summary="All applicable bounded blank/missing credential conditions were rejected without confirmed authentication.",
        evidence=evidence,
        details=details,
    )
