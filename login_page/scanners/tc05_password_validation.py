from __future__ import annotations

from dataclasses import asdict, field, make_dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from authentication.auth_discovery import (
    discover_authentication,
    login_page_candidates,
    normalize_login_url,
)
from authentication.auth_client import create_session, submit_credentials
from authentication.lockout_guard import LockoutGuard, is_rate_limited_response
from authentication.login_applicability import (
    captcha_marker_from_html,
    captcha_marker_from_url,
    federated_login_skip,
)
from authentication.models import AuthMechanism, CredentialCandidate
from authentication.password_validation_client import (
    classify_attempt,
    perform_http_attempt,
    verify_protected_access,
    redacted_password,
)
from authentication.password_validation_models import (
    PasswordAttempt,
    PasswordAttemptKind,
    PasswordAttemptState,
    PasswordFieldRules,
    PasswordValidationConfig,
    PasswordValidationResult,
)
from authentication.password_validation_signals import (
    detect_captcha_marker,
    detect_failure_marker,
    detect_mfa_marker,
    detect_password_change_marker,
    normalize_body,
)
from authentication.password_variants import build_password_variants
from authentication.privilege import determine_privilege
from authentication.password_field_inspection import inspect_password_field_rules
from authentication.browser_password_validation import run_browser_password_attempt

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


_LOGIN_PATH_TOKENS = ("login", "signin", "sign-in")


class _SimplePasswordParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.password_found = False
        self.html = ""

    def feed(self, data: str) -> None:  # type: ignore[override]
        self.html = data or ""
        super().feed(data or "")

    def handle_starttag(self, tag, attrs) -> None:
        if tag.lower() != "input":
            return
        attrs_d = {str(k).lower(): (v or "") for k, v in attrs}
        if str(attrs_d.get("type", "text")).lower() == "password":
            self.password_found = True


def _status_for_state(state: PasswordAttemptState) -> str:
    if state == PasswordAttemptState.AUTHENTICATED:
        return "UNSAFE"
    if state in {
        PasswordAttemptState.MFA_REQUIRED,
        PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
    }:
        return "UNSAFE"
    if state in {
        PasswordAttemptState.CAPTCHA_BLOCKED,
        PasswordAttemptState.AMBIGUOUS,
        PasswordAttemptState.RATE_LIMITED,
    }:
        return "REVIEW REQUIRED"
    if state == PasswordAttemptState.ERROR:
        return "INCOMPLETE"
    return "SAFE"


def _assessment_state(status: str) -> str:
    return {
        "UNSAFE": "CONFIRMED",
        "SAFE": "NOT_A_FINDING",
        "REVIEW REQUIRED": "REVIEW_REQUIRED",
        "INCOMPLETE": "INCOMPLETE",
        "NOT ASSESSED": "NOT_ASSESSED",
    }.get(status, "REVIEW_REQUIRED")


def _result(
    status: str,
    summary: str,
    *,
    evidence: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> PasswordValidationResult:
    return PasswordValidationResult(
        status=status,
        assessment_state=_assessment_state(status),
        summary=summary,
        evidence=evidence or [],
        details=details or {},
    )


def _score_confirmed_finding(
    result: PasswordValidationResult,
    *,
    privilege: str,
    config: PasswordValidationConfig,
) -> None:
    if calculate_severity is None or SeverityInput is None:
        return

    p = (privilege or "unknown").lower()
    if p == "admin":
        confidentiality = "HIGH"
        integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "HIGH"
    elif p == "operator":
        confidentiality = "HIGH"
        integrity = "HIGH"
        authorization = "MAJOR"
        sensitivity = "MODERATE"
    elif p == "standard":
        confidentiality = "LOW"
        integrity = "LOW"
        authorization = "LIMITED"
        sensitivity = "LOW"
    else:
        confidentiality = "LOW"
        integrity = "LOW"
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
            "A wrong password was accepted for an authorized account, indicating failure "
            "of password validation at the login authentication boundary. "
            f"Observed privilege={p}."
        ),
        evidence=result.evidence,
    )
    score = calculate_severity(metrics, assessment_state="CONFIRMED")
    result.severity = score.severity
    result.risk_score = score.score
    result.severity_rationale = score.rationale
    result.severity_components = score.components
    result.severity_metrics = score.metrics


def _get_login_page_rules(target: str, login_path: str, timeout: float, verify_tls: bool) -> tuple[list[PasswordFieldRules], str, list[str], str]:
    evidence: list[str] = []
    last_url = normalize_login_url(target, login_path)
    last_error = ""
    for url in login_page_candidates(target, login_path):
        try:
            response = requests.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True)
        except requests.RequestException as exc:
            last_error = str(exc)
            last_url = url
            continue
        last_url = response.url
        rules = inspect_password_field_rules(response.text)
        evidence.append(f"login_page_status={response.status_code}")
        evidence.append(f"login_page_url={last_url}")
        if rules:
            evidence.append(f"password_fields_found={len(rules)}")
            return rules, last_url, evidence, response.text or ""
        evidence.append("password_fields_found=0")
    if last_error:
        evidence.append(f"login_page_inspection_error={last_error}")
    return [], last_url, evidence, ""


def _is_wrong_attempt_state(state: PasswordAttemptState) -> bool:
    return state in {
        PasswordAttemptState.REJECTED,
        PasswordAttemptState.RATE_LIMITED,
        PasswordAttemptState.CAPTCHA_BLOCKED,
        PasswordAttemptState.AMBIGUOUS,
        PasswordAttemptState.ERROR,
    }


def _attempt_from_http(
    mechanism: AuthMechanism,
    username: str,
    password: str,
    kind: PasswordAttemptKind,
    config: PasswordValidationConfig,
) -> PasswordAttempt:
    attempt = perform_http_attempt(
        mechanism,
        username,
        password,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )
    if attempt.response is None:
        return PasswordAttempt(
            kind=kind,
            username=username,
            password_redacted=redacted_password(password),
            state=PasswordAttemptState.ERROR,
            final_url=attempt.final_url,
            error=attempt.error,
            evidence=(f"request_error={attempt.error}",),
        )

    state, metadata = classify_attempt(attempt, mechanism)
    response = attempt.response
    evidence = [
        f"attempt_kind={kind.value}",
        f"http_status={response.status_code}",
        f"final_url={attempt.final_url}",
        f"response_length={len(response.text or '')}",
    ]
    if metadata.get("reason"):
        evidence.append(f"classification_reason={metadata['reason']}")

    candidate_success = state in {
        PasswordAttemptState.AUTHENTICATED,
        PasswordAttemptState.MFA_REQUIRED,
        PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
    }

    protected_confirmed = False

    return PasswordAttempt(
        kind=kind,
        username=username,
        password_redacted=redacted_password(password),
        state=state,
        http_status=response.status_code,
        final_url=attempt.final_url,
        mfa_required=state == PasswordAttemptState.MFA_REQUIRED,
        password_change_required=state == PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
        captcha_blocked=state == PasswordAttemptState.CAPTCHA_BLOCKED,
        candidate_success=candidate_success,
        response_length=len(response.text or ""),
        evidence=tuple(evidence),
        error=attempt.error,
    )


def _valid_control(
    mechanism: AuthMechanism,
    config: PasswordValidationConfig,
) -> tuple[PasswordAttempt | None, requests.Session | None, str]:
    username = config.authorized_username or ""
    password = config.authorized_password
    if not username or password is None or password == "":
        return None, None, "An authorized non-empty username and password are required for TC05."

    session = create_session(config.verify_tls)
    result = submit_credentials(
        session,
        mechanism,
        CredentialCandidate(username=username, password=password),
        timeout=config.timeout,
        allow_redirects=True,
    )
    if result.response is None:
        return (
            PasswordAttempt(
                kind=PasswordAttemptKind.VALID_CONTROL,
                username=username,
                password_redacted=redacted_password(password),
                state=PasswordAttemptState.ERROR,
                final_url=result.final_url,
                error=result.error,
                evidence=(f"valid_control_request_error={result.error}",),
            ),
            session,
            result.error or "valid credential request failed",
        )

    from authentication.password_validation_client import AttemptResponse
    state, metadata = classify_attempt(
        AttemptResponse(result.response, result.final_url, "", session),
        mechanism,
    )
    evidence = [
        "valid_control=true",
        f"http_status={result.response.status_code}",
        f"final_url={result.final_url}",
    ]
    if metadata.get("reason"):
        evidence.append(f"classification_reason={metadata['reason']}")

    candidate_success = state in {
        PasswordAttemptState.AUTHENTICATED,
        PasswordAttemptState.MFA_REQUIRED,
        PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
    }

    return (
        PasswordAttempt(
            kind=PasswordAttemptKind.VALID_CONTROL,
            username=username,
            password_redacted=redacted_password(password),
            state=state,
            http_status=result.response.status_code,
            final_url=result.final_url,
            mfa_required=state == PasswordAttemptState.MFA_REQUIRED,
            password_change_required=state == PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
            candidate_success=candidate_success,
            response_length=len(result.response.text or ""),
            evidence=tuple(evidence),
        ),
        session,
        metadata.get("reason", ""),
    )


def scan_password_validation(
    target: str,
    config: PasswordValidationConfig | None = None,
    *,
    progress=None,
) -> Any:
    config = config or PasswordValidationConfig()
    evidence: list[str] = []

    has_authorized = bool(config.authorized_username and config.authorized_password)
    if config.authorized_password == "":
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                "TC05 requires a non-empty authorized password; blank-password behavior belongs to TC03.",
                evidence=["blank_valid_password_is_out_of_scope_for_tc05"],
            )
        )

    federated = federated_login_skip(target, config.login_path, probe=True)
    if federated:
        return _as_scan_result(
            _result(
                "NOT ASSESSED",
                "TC05 is not applicable to the application's local password validator because the login flow uses federated SSO/OAuth-OIDC.",
                evidence=[f"not_applicable classification={federated.get('classification')}", federated.get("reason", "")],
                details={"federated": federated},
            )
        )

    if progress:
        progress("Discovering the login authentication mechanism")
    mechanism, discovery = discover_authentication(
        target,
        login_hint=config.login_path,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )
    if mechanism is None:
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                "TC05 could not resolve a usable login authentication mechanism.",
                evidence=["authentication_discovery_unresolved"],
                details={"discovery": discovery},
            )
        )

    evidence.extend(str(item) for item in mechanism.evidence)
    evidence.append(f"auth_mechanism={mechanism.type}")
    evidence.append(f"auth_endpoint={mechanism.endpoint}")

    password_rules, rules_url, rules_evidence, rules_html = _get_login_page_rules(
        target,
        config.login_path,
        config.timeout,
        config.verify_tls,
    )
    evidence.extend(rules_evidence)

    page_captcha = captcha_marker_from_url(rules_url) or captcha_marker_from_html(rules_html)
    if page_captcha:
        return _as_scan_result(
            _result(
                "REVIEW REQUIRED",
                "TC05 could not safely complete because the login route is protected by a CAPTCHA challenge.",
                evidence=evidence + [f"captcha_marker={page_captcha}"],
                details={"password_field_rules": [r.as_dict() for r in password_rules]},
            )
        )

    details_base: dict[str, Any] = {
        "auth_mechanism": mechanism.as_dict(),
        "discovery": discovery,
        "password_field_rules": [r.as_dict() for r in password_rules],
        "authorized_control_supplied": has_authorized,
        "scope_boundaries": [
            "TC05 tests whether the login authentication path validates an incorrect password.",
            "Blank/empty password acceptance belongs to TC03.",
            "Default credentials belong to TC02.",
            "Username enumeration belongs to TC04.",
            "Lockout strength belongs to TC17.",
            "Password strength/policy on registration/change/reset belongs outside this login testcase.",
        ],
    }

    if not has_authorized:
        synthetic_user = "tc05-invalid-user"
        synthetic_pass = "Tc05-Wrong-Password-7F3A"
        attempt = _attempt_from_http(
            mechanism,
            synthetic_user,
            synthetic_pass,
            PasswordAttemptKind.WRONG_GENERIC,
            config,
        )
        evidence.extend(attempt.evidence)
        details_base["attempts"] = [attempt.as_dict()]
        details_base["operator_note"] = (
            "No authorized valid account was supplied. TC05 still submitted one synthetic "
            "invalid username/password pair and inspected the password field HTML."
        )
        if attempt.state == PasswordAttemptState.AUTHENTICATED:
            return _as_scan_result(
                _result(
                    "UNSAFE",
                    "The login accepted a synthetic invalid password, so password validation is not enforced.",
                    evidence=evidence,
                    details=details_base,
                )
            )
        if attempt.state == PasswordAttemptState.REJECTED:
            return _as_scan_result(
                _result(
                    "SAFE",
                    "The login rejected a synthetic invalid password. Mutation testing against a known-valid "
                    "account was not performed because no authorized control was supplied.",
                    evidence=evidence,
                    details=details_base,
                )
            )
        return _as_scan_result(
            _result(
                "REVIEW REQUIRED",
                "Password-field HTML was inspected, but the synthetic invalid-password response was inconclusive. "
                "Supply an authorized test account to complete mutation testing.",
                evidence=evidence + [f"synthetic_state={attempt.state.value}"],
                details=details_base,
            )
        )

    if progress:
        progress("Establishing the authorized valid-password control")
    control, control_session, control_reason = _valid_control(mechanism, config)
    if control is None or control_session is None:
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                control_reason,
                evidence=evidence + [control_reason],
                details=details_base,
            )
        )

    evidence.extend(control.evidence)
    details: dict[str, Any] = {
        **details_base,
        "valid_control": control.as_dict(),
        "attempts": [],
    }

    if (
        not control.candidate_success
        and config.allow_browser_fallback
        and mechanism.type == "html_form"
        and control.state in {PasswordAttemptState.AMBIGUOUS, PasswordAttemptState.ERROR}
    ):
        browser = run_browser_password_attempt(
            rules_url,
            config.authorized_username,
            config.authorized_password,
            timeout_ms=config.browser_timeout_ms,
        )
        browser_state = PasswordAttemptState(browser.get("state", PasswordAttemptState.ERROR.value))
        browser_evidence = list(browser.get("evidence") or [])
        control = PasswordAttempt(
            kind=PasswordAttemptKind.VALID_CONTROL,
            username=config.authorized_username,
            password_redacted=redacted_password(config.authorized_password),
            state=browser_state,
            final_url=str(browser.get("final_url") or rules_url),
            mfa_required=browser_state == PasswordAttemptState.MFA_REQUIRED,
            password_change_required=browser_state == PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
            captcha_blocked=browser_state == PasswordAttemptState.CAPTCHA_BLOCKED,
            candidate_success=browser_state in {
                PasswordAttemptState.AUTHENTICATED,
                PasswordAttemptState.MFA_REQUIRED,
                PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
            },
            evidence=tuple(browser_evidence),
            error=str(browser.get("error") or ""),
        )
        evidence.extend(control.evidence)

    if not control.candidate_success:
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                "The authorized valid-password control did not establish a reliable authenticated/primary-authenticated baseline, so TC05 cannot safely judge incorrect passwords.",
                evidence=evidence + [f"valid_control_state={control.state.value}"],
                details=details,
            )
        )

    if config.protected_urls:
        protected, protected_evidence = verify_protected_access(
            control_session,
            target,
            config.protected_urls,
            timeout=config.timeout,
        )
        details["valid_control_protected_access"] = protected
        details["valid_control_protected_evidence"] = protected_evidence
        evidence.extend(protected_evidence)

    variants = build_password_variants(
        config.authorized_password,
        include_same_length=config.test_same_length,
        include_single_mutation=config.test_single_mutation,
        include_case_mutation=config.test_case_mutation,
        include_trailing_whitespace=config.test_trailing_whitespace,
    )
    guard = LockoutGuard(
        max_attempts=max(1, min(config.max_wrong_attempts, len(variants))),
        min_delay_seconds=config.min_delay_seconds,
    )

    confirmed_bad_password: PasswordAttempt | None = None
    any_review = False

    for variant in variants:
        if not guard.before_attempt():
            any_review = True
            evidence.append("TC05 attempt guard exhausted before all variants were tested")
            break

        if progress:
            progress(f"Testing password-validation condition: {variant.kind.value}")

        attempt = _attempt_from_http(
            mechanism,
            config.authorized_username,
            variant.password,
            variant.kind,
            config,
        )

        # Browser fallback is intentionally limited to unresolved HTTP/API cases.
        if (
            attempt.state in {PasswordAttemptState.AMBIGUOUS, PasswordAttemptState.ERROR}
            and config.allow_browser_fallback
            and mechanism.type == "html_form"
        ):
            browser = run_browser_password_attempt(
                rules_url,
                config.authorized_username,
                variant.password,
                timeout_ms=config.browser_timeout_ms,
            )
            browser_state = PasswordAttemptState(browser.get("state", PasswordAttemptState.ERROR.value))
            browser_evidence = list(browser.get("evidence") or [])
            attempt = PasswordAttempt(
                kind=variant.kind,
                username=config.authorized_username,
                password_redacted=redacted_password(variant.password),
                state=browser_state,
                final_url=str(browser.get("final_url") or ""),
                mfa_required=browser_state == PasswordAttemptState.MFA_REQUIRED,
                password_change_required=browser_state == PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
                captcha_blocked=browser_state == PasswordAttemptState.CAPTCHA_BLOCKED,
                candidate_success=browser_state in {
                    PasswordAttemptState.AUTHENTICATED,
                    PasswordAttemptState.MFA_REQUIRED,
                    PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
                },
                evidence=tuple(browser_evidence),
                error=str(browser.get("error") or ""),
            )

        details["attempts"].append(attempt.as_dict())
        evidence.extend(attempt.evidence)

        if attempt.state == PasswordAttemptState.RATE_LIMITED:
            any_review = True
            evidence.append("Target rate-limited or locked authentication attempts; testing stopped")
            break
        if attempt.state == PasswordAttemptState.CAPTCHA_BLOCKED:
            any_review = True
            evidence.append("CAPTCHA blocked further password validation testing")
            break

        if attempt.state in {
            PasswordAttemptState.AUTHENTICATED,
            PasswordAttemptState.MFA_REQUIRED,
            PasswordAttemptState.PASSWORD_CHANGE_REQUIRED,
        }:
            confirmed_bad_password = attempt
            evidence.append(
                f"confirmed_password_validation_failure kind={variant.kind.value} state={attempt.state.value}"
            )
            if config.stop_on_confirmed:
                break
        elif attempt.state in {PasswordAttemptState.AMBIGUOUS, PasswordAttemptState.ERROR}:
            any_review = True

    if confirmed_bad_password is not None:
        status = "UNSAFE"
        result = _result(
            status,
            "The login authentication path accepted an incorrect password for the authorized account, demonstrating a password-validation failure.",
            evidence=evidence,
            details=details,
        )
        _score_confirmed_finding(result, privilege="unknown", config=config)
        details["confirmed_condition"] = confirmed_bad_password.as_dict()
        return _as_scan_result(result)

    if any_review:
        return _as_scan_result(
            _result(
                "REVIEW REQUIRED",
                "The password-validation test could not complete all applicable wrong-password conditions reliably.",
                evidence=evidence,
                details=details,
            )
        )

    return _as_scan_result(
        _result(
            "SAFE",
            "All tested incorrect-password variants were rejected; no password-validation failure was confirmed.",
            evidence=evidence,
            details=details,
        )
    )


def _as_scan_result(result: PasswordValidationResult):
    details = dict(result.details)
    details.update({
        "assessment_state": result.assessment_state,
        "severity": result.severity,
        "risk_score": result.risk_score,
        "severity_rationale": result.severity_rationale,
        "severity_components": result.severity_components,
        "severity_metrics": result.severity_metrics,
    })
    try:
        return ScanResult(
            key=result.key,
            name=result.name,
            status=result.status,
            summary=result.summary,
            assessment_state=result.assessment_state,
            severity=result.severity,
            risk_score=result.risk_score,
            severity_rationale=result.severity_rationale,
            severity_components=result.severity_components,
            severity_metrics=result.severity_metrics,
            raw_output=result.raw_output,
            evidence=result.evidence,
            details=details,
        )
    except TypeError:
        # Preserve compatibility with the legacy core.models.ScanResult used by
        # earlier login/pre-login scanners. Severity metadata stays in details.
        return ScanResult(
            key=result.key,
            name=result.name,
            status=result.status,
            summary=result.summary,
            raw_output=result.raw_output,
            evidence=result.evidence,
            details=details,
        )


def scan(
    target: str,
    *,
    config: PasswordValidationConfig | None = None,
    progress=None,
    **kwargs: Any,
):
    """Compatibility entry point for the login-page runner."""
    if config is None:
        config = PasswordValidationConfig(
            login_path=str(kwargs.get("login_path") or "/login"),
            authorized_username=kwargs.get("authorized_username"),
            authorized_password=kwargs.get("authorized_password"),
        )
    return scan_password_validation(target, config, progress=progress)


if __name__ == "__main__":  # pragma: no cover
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TC05 password validation scanner")
    parser.add_argument("target")
    parser.add_argument("--login-path", default="/login")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    result = scan_password_validation(
        args.target,
        PasswordValidationConfig(
            login_path=args.login_path,
            authorized_username=args.username,
            authorized_password=args.password,
            verify_tls=not args.insecure,
        ),
    )
    print(json.dumps(result.as_dict(), indent=2, default=str))
