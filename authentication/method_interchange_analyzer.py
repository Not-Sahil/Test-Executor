from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .method_interchange_models import MethodObservation

@dataclass(frozen=True)
class Comparison:
    expected: MethodObservation | None
    alternate: MethodObservation | None
    response_equivalent: bool
    alternate_wrong_accepted: bool
    alternate_valid_accepted: bool
    alternate_rejected: bool
    execution_blocked: bool
    notes: tuple[str, ...]

def compare_observations(
    expected: MethodObservation | None,
    alternate: MethodObservation | None,
) -> Comparison:
    if expected is None or alternate is None:
        return Comparison(
            expected=expected,
            alternate=alternate,
            response_equivalent=False,
            alternate_wrong_accepted=False,
            alternate_valid_accepted=False,
            alternate_rejected=False,
            execution_blocked=True,
            notes=("One or both method observations are missing.",),
        )

    equivalent = False
    if expected.status_code is not None and alternate.status_code is not None:
        status_same = expected.status_code == alternate.status_code
        length_close = abs(expected.response_length - alternate.response_length) <= 15
        final_path_same = expected.final_url.rstrip("/") == alternate.final_url.rstrip("/")
        equivalent = status_same and length_close and final_path_same

    notes: list[str] = []

    if alternate.authenticated_signal and not alternate.rejected_signal:
        notes.append("Alternate method reached an authentication-success-like state.")

    if alternate.rejected_signal:
        notes.append("Alternate method was rejected by authentication or method handling.")

    if alternate.rate_limited:
        notes.append("Alternate method triggered rate-limit/lockout protection.")

    if alternate.csrf_rejected:
        notes.append("Alternate method was rejected by CSRF/token validation.")

    if equivalent:
        notes.append("Expected and alternate method responses were materially similar.")

    return Comparison(
        expected=expected,
        alternate=alternate,
        response_equivalent=equivalent,
        alternate_wrong_accepted=(
            alternate.authenticated_signal
            and not alternate.rejected_signal
            and not alternate.rate_limited
        ),
        alternate_valid_accepted=(
            alternate.authenticated_signal
            and not alternate.rejected_signal
            and not alternate.rate_limited
        ),
        alternate_rejected=alternate.rejected_signal,
        execution_blocked=alternate.rate_limited,
        notes=tuple(notes),
    )

def assess_method_interchange(
    *,
    expected_valid: MethodObservation | None,
    expected_wrong: MethodObservation | None,
    alternate_valid: MethodObservation | None,
    alternate_wrong: MethodObservation | None,
) -> dict:
    """
    Security decision:
    - The alternate method is not a finding merely because valid credentials work.
    - A confirmed finding requires the alternate method to accept the wrong credential
      after the expected method rejected it.
    - Method-only response differences become REVIEW_REQUIRED when they cannot be
      safely resolved.
    """
    blocked = any(
        obs is not None and obs.rate_limited
        for obs in (
            expected_valid,
            expected_wrong,
            alternate_valid,
            alternate_wrong,
        )
    )

    if blocked:
        return {
            "status": "REVIEW REQUIRED",
            "assessment_state": "REVIEW_REQUIRED",
            "finding_confirmed": False,
            "reason": "Rate-limit/lockout protection interrupted method comparison.",
        }

    expected_valid_ok = bool(
        expected_valid
        and expected_valid.authenticated_signal
        and not expected_valid.rejected_signal
    )
    expected_wrong_ok = bool(
        expected_wrong
        and expected_wrong.rejected_signal
    )

    alternate_wrong_ok = bool(
        alternate_wrong
        and alternate_wrong.authenticated_signal
        and not alternate_wrong.rejected_signal
    )

    alternate_valid_ok = bool(
        alternate_valid
        and alternate_valid.authenticated_signal
        and not alternate_valid.rejected_signal
    )

    if expected_wrong_ok and alternate_wrong_ok:
        return {
            "status": "UNSAFE",
            "assessment_state": "CONFIRMED",
            "finding_confirmed": True,
            "reason": (
                "The expected login method rejected an incorrect credential, "
                "while the alternate GET/POST method reached an authenticated state "
                "with the same incorrect credential."
            ),
        }

    if expected_valid is None and expected_wrong_ok and not alternate_wrong_ok:
        return {
            "status": "SAFE",
            "assessment_state": "NOT_A_FINDING",
            "finding_confirmed": False,
            "reason": (
                "No authorized valid account was supplied. GET/POST interchange with "
                "invalid credentials did not produce an authentication bypass."
            ),
        }

    if not expected_valid_ok and expected_valid is not None:
        return {
            "status": "INCOMPLETE",
            "assessment_state": "INCOMPLETE",
            "finding_confirmed": False,
            "reason": (
                "The authorized valid-credential control did not establish a reliable "
                "authentication baseline."
            ),
        }

    if alternate_wrong is not None and alternate_wrong.error:
        return {
            "status": "REVIEW REQUIRED",
            "assessment_state": "REVIEW_REQUIRED",
            "finding_confirmed": False,
            "reason": "The alternate method could not be evaluated reliably.",
        }

    if alternate_valid_ok and expected_valid_ok:
        return {
            "status": "SAFE",
            "assessment_state": "NOT_A_FINDING",
            "finding_confirmed": False,
            "reason": (
                "The alternate method accepted the authorized credentials, but the "
                "incorrect-credential control was still rejected. Method interchange "
                "was observed without a demonstrated authentication bypass."
            ),
        }

    if alternate_wrong is not None and alternate_wrong.rejected_signal:
        return {
            "status": "SAFE",
            "assessment_state": "NOT_A_FINDING",
            "finding_confirmed": False,
            "reason": "The alternate method rejected the incorrect credential.",
        }

    return {
        "status": "REVIEW REQUIRED",
        "assessment_state": "REVIEW_REQUIRED",
        "finding_confirmed": False,
        "reason": (
            "The target showed alternate-method behavior that could not be "
            "classified confidently as a bypass or safe rejection."
        ),
    }
