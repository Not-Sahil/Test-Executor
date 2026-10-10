from __future__ import annotations

import uuid

from .auth_client import create_session, submit_credentials
from .lockout_guard import is_rate_limited_response
from .models import AuthMechanism, AuthenticationBaseline, CredentialCandidate
from .success_verifier import verify_authentication


BASELINE_PASSWORD = "__scanner_invalid_password_9c1b__"


def establish_auth_failure_baseline(
    mechanism: AuthMechanism,
    verify_tls: bool = True,
    timeout: float = 8.0,
) -> AuthenticationBaseline:
    """Require an invalid credential to be rejected before trusting real attempts."""
    username = f"__scanner_nonexistent_{uuid.uuid4().hex[:10]}"
    credential = CredentialCandidate(
        username=username,
        password=BASELINE_PASSWORD,
        credential_source="scanner_baseline",
    )
    session = create_session(verify_tls)
    result = submit_credentials(
        session,
        mechanism,
        credential,
        timeout=timeout,
        allow_redirects=False,
    )

    if result.response is None:
        return AuthenticationBaseline(False, "ERROR", None, result.final_url, (f"baseline request failed: {result.error}",))

    if is_rate_limited_response(result.response):
        return AuthenticationBaseline(False, "RATE_LIMITED", result.response.status_code, result.final_url, ("baseline probe triggered rate limiting/lockout",))

    verification = verify_authentication(result.response, mechanism)
    if verification.state == "REJECTED":
        return AuthenticationBaseline(
            True,
            "ESTABLISHED",
            result.response.status_code,
            result.final_url,
            (f"invalid-credential baseline rejected as expected: {verification.reason}",),
        )

    return AuthenticationBaseline(
        False,
        verification.state,
        result.response.status_code,
        result.final_url,
        (f"invalid-credential baseline was not reliably rejected: {verification.reason}",),
    )
