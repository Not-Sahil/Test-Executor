from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from authentication.auth_client import create_session, submit_credentials
from authentication.evidence import safe_url
from authentication.lockout_guard import is_rate_limited_response
from authentication.models import AuthMechanism, CredentialCandidate
from authentication.password_validation_models import PasswordAttemptKind, PasswordAttemptState
from authentication.password_validation_signals import (
    detect_captcha_marker,
    detect_failure_marker,
    detect_mfa_marker,
    detect_password_change_marker,
    detect_success_marker,
    normalize_body,
    redact_password_for_evidence,
)
from authentication.success_verifier import verify_authentication


@dataclass(frozen=True)
class AttemptResponse:
    response: requests.Response | None
    final_url: str = ""
    error: str = ""
    session: requests.Session | None = None


def new_attempt_session(verify_tls: bool) -> requests.Session:
    return create_session(verify_tls)


def perform_http_attempt(
    mechanism: AuthMechanism,
    username: str,
    password: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> AttemptResponse:
    session = new_attempt_session(verify_tls)
    result = submit_credentials(
        session,
        mechanism,
        CredentialCandidate(username=username, password=password),
        timeout=timeout,
        allow_redirects=True,
    )
    return AttemptResponse(result.response, result.final_url, result.error, session)


def classify_attempt(
    attempt: AttemptResponse,
    mechanism: AuthMechanism,
) -> tuple[PasswordAttemptState, dict[str, object]]:
    if attempt.response is None:
        return PasswordAttemptState.ERROR, {"reason": attempt.error or "no_response"}

    response = attempt.response
    body = normalize_body(response.text[:20000])

    if is_rate_limited_response(response):
        return PasswordAttemptState.RATE_LIMITED, {"reason": "rate_limited"}

    captcha_marker = detect_captcha_marker(body)
    if captcha_marker:
        return PasswordAttemptState.CAPTCHA_BLOCKED, {"reason": captcha_marker}

    mfa_marker = detect_mfa_marker(body)
    password_change_marker = detect_password_change_marker(body)
    failure_marker = detect_failure_marker(body)
    success_marker = detect_success_marker(body)

    verification = verify_authentication(response, mechanism)

    if mfa_marker:
        return PasswordAttemptState.MFA_REQUIRED, {
            "reason": f"mfa_marker:{mfa_marker}",
            "verifier_state": verification.state,
        }

    if password_change_marker:
        return PasswordAttemptState.PASSWORD_CHANGE_REQUIRED, {
            "reason": f"password_change_marker:{password_change_marker}",
            "verifier_state": verification.state,
        }

    if failure_marker:
        return PasswordAttemptState.REJECTED, {
            "reason": f"failure_marker:{failure_marker}",
            "verifier_state": verification.state,
        }

    if verification.confirmed or success_marker:
        return PasswordAttemptState.AUTHENTICATED, {
            "reason": verification.reason or f"success_marker:{success_marker}",
            "verifier_state": verification.state,
        }

    if response.status_code in {401, 403, 422}:
        return PasswordAttemptState.REJECTED, {
            "reason": f"http_rejection:{response.status_code}",
            "verifier_state": verification.state,
        }

    return PasswordAttemptState.AMBIGUOUS, {
        "reason": verification.reason or "no_strong_authentication_signal",
        "verifier_state": verification.state,
    }


def verify_protected_access(
    session: requests.Session,
    base_url: str,
    protected_urls: tuple[str, ...],
    *,
    timeout: float,
) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    if not protected_urls:
        return False, evidence

    for path in protected_urls:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            evidence.append(f"protected_probe_error={safe_url(url)}:{exc}")
            continue

        final = safe_url(response.url)
        body = normalize_body(response.text[:12000])
        login_like = any(x in final.lower() for x in ("/login", "/signin", "/sign-in"))
        success_marker = bool(detect_success_marker(body))
        if response.status_code < 400 and not login_like and success_marker:
            evidence.append(f"protected_access_confirmed={final}")
            return True, evidence

        evidence.append(
            f"protected_access_not_confirmed={final} status={response.status_code} login_like={login_like}"
        )

    return False, evidence


def redacted_password(password: str) -> str:
    return redact_password_for_evidence(password)
