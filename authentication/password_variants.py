from __future__ import annotations

from dataclasses import dataclass

from .password_validation_models import PasswordAttemptKind


@dataclass(frozen=True)
class PasswordVariant:
    kind: PasswordAttemptKind
    password: str
    description: str


def _different_char(ch: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    for candidate in alphabet:
        if candidate != ch:
            return candidate
    return "X"


def _single_mutation(password: str) -> str | None:
    if not password:
        return None
    index = len(password) - 1
    replacement = _different_char(password[index])
    mutated = password[:index] + replacement + password[index + 1 :]
    return mutated if mutated != password else None


def _same_length_wrong(password: str) -> str | None:
    if not password:
        return None
    # Reverse when possible; if palindrome-like, use a deterministic character mutation.
    candidate = password[::-1]
    if candidate != password:
        return candidate
    return _single_mutation(password)


def build_password_variants(
    valid_password: str,
    *,
    include_same_length: bool = True,
    include_single_mutation: bool = True,
    include_case_mutation: bool = True,
    include_trailing_whitespace: bool = True,
) -> list[PasswordVariant]:
    """Build a very small, deterministic wrong-password matrix.

    No dictionary, brute force, or password spraying is performed.
    """
    variants: list[PasswordVariant] = [
        PasswordVariant(
            PasswordAttemptKind.WRONG_GENERIC,
            "__tc05_definitely_wrong_password_9f31__",
            "bounded generic wrong password",
        )
    ]

    if include_same_length:
        candidate = _same_length_wrong(valid_password)
        if candidate and candidate != valid_password:
            variants.append(
                PasswordVariant(
                    PasswordAttemptKind.WRONG_SAME_LENGTH,
                    candidate,
                    "wrong password with the same length as the valid password",
                )
            )

    if include_single_mutation:
        candidate = _single_mutation(valid_password)
        if candidate and candidate != valid_password and all(v.password != candidate for v in variants):
            variants.append(
                PasswordVariant(
                    PasswordAttemptKind.WRONG_SINGLE_MUTATION,
                    candidate,
                    "valid password with one deterministic character changed",
                )
            )

    if include_case_mutation:
        candidate = valid_password.swapcase()
        if candidate != valid_password and all(v.password != candidate for v in variants):
            variants.append(
                PasswordVariant(
                    PasswordAttemptKind.WRONG_CASE_MUTATION,
                    candidate,
                    "case-mutated password; only meaningful when distinct",
                )
            )

    if include_trailing_whitespace:
        candidate = valid_password + " "
        if candidate != valid_password and all(v.password != candidate for v in variants):
            variants.append(
                PasswordVariant(
                    PasswordAttemptKind.WRONG_TRAILING_WHITESPACE,
                    candidate,
                    "valid password with one trailing space",
                )
            )

    return variants
