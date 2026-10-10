from __future__ import annotations

from authentication.password_validation_models import PasswordAttemptKind, PasswordAttemptState
from authentication.password_validation_signals import detect_failure_marker, detect_mfa_marker
from authentication.password_variants import build_password_variants


def test_same_length_variant_is_really_same_length_and_not_equal():
    variants = build_password_variants("Correct!123", include_case_mutation=False, include_trailing_whitespace=False)
    same_length = next(v for v in variants if v.kind == PasswordAttemptKind.WRONG_SAME_LENGTH)
    assert len(same_length.password) == len("Correct!123")
    assert same_length.password != "Correct!123"


def test_single_mutation_differs_by_one_character():
    variants = build_password_variants("Correct!123", include_same_length=False, include_case_mutation=False, include_trailing_whitespace=False)
    mutation = next(v for v in variants if v.kind == PasswordAttemptKind.WRONG_SINGLE_MUTATION)
    differences = sum(a != b for a, b in zip(mutation.password, "Correct!123"))
    assert differences == 1


def test_case_variant_only_added_when_distinct():
    variants = build_password_variants("AbCd123!", include_same_length=False, include_single_mutation=False, include_trailing_whitespace=False)
    case_variant = next(v for v in variants if v.kind == PasswordAttemptKind.WRONG_CASE_MUTATION)
    assert case_variant.password == "aBcD123!"
    assert case_variant.password != "AbCd123!"


def test_failure_marker_detection():
    assert detect_failure_marker("The password is incorrect") == "password is incorrect"


def test_mfa_marker_detection():
    assert detect_mfa_marker("Enter the verification code from your authenticator app") == "verification code"


def test_attempt_state_contract():
    assert PasswordAttemptState.MFA_REQUIRED.value == "mfa_required"
    assert PasswordAttemptKind.WRONG_SAME_LENGTH.value == "wrong_same_length"
