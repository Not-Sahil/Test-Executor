from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CredentialState(str, Enum):
    VALUE = "value"
    EMPTY = "empty"
    MISSING = "missing"
    WHITESPACE = "whitespace"
    NULL = "null"  # JSON-only semantic state.


@dataclass(frozen=True)
class CredentialVariant:
    """A bounded TC03 credential-input condition.

    The state describes what is sent, not what the server ultimately does.
    EMPTY and MISSING are deliberately different.
    """

    case_id: str
    username_state: CredentialState
    password_state: CredentialState
    description: str
    requires_authorized_username: bool = False
    requires_authorized_password: bool = False
    json_only: bool = False
    html_only: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "username_state": self.username_state.value,
            "password_state": self.password_state.value,
            "description": self.description,
            "requires_authorized_username": self.requires_authorized_username,
            "requires_authorized_password": self.requires_authorized_password,
            "json_only": self.json_only,
            "html_only": self.html_only,
        }


@dataclass(frozen=True)
class AuthorizedCredential:
    """Explicit operator-authorized credential used only when TC03 needs a value."""

    username: str
    password: str


TC03_MANDATORY_VARIANTS: tuple[CredentialVariant, ...] = (
    CredentialVariant(
        "TC03-A",
        CredentialState.EMPTY,
        CredentialState.EMPTY,
        "Both username and password are present but empty.",
    ),
    CredentialVariant(
        "TC03-B",
        CredentialState.MISSING,
        CredentialState.MISSING,
        "Both credential parameters are omitted entirely.",
    ),
    CredentialVariant(
        "TC03-C",
        CredentialState.EMPTY,
        CredentialState.VALUE,
        "Username is empty while a bounded probe password is supplied.",
        requires_authorized_password=True,
    ),
    CredentialVariant(
        "TC03-D",
        CredentialState.VALUE,
        CredentialState.EMPTY,
        "Password is empty while an explicitly authorized username is supplied.",
        requires_authorized_username=True,
    ),
)

TC03_OPTIONAL_VARIANTS: tuple[CredentialVariant, ...] = (
    CredentialVariant(
        "TC03-E",
        CredentialState.WHITESPACE,
        CredentialState.WHITESPACE,
        "Both credential fields contain bounded whitespace-only values.",
    ),
    CredentialVariant(
        "TC03-F",
        CredentialState.WHITESPACE,
        CredentialState.EMPTY,
        "Username is whitespace-only while password is empty.",
    ),
    CredentialVariant(
        "TC03-G",
        CredentialState.EMPTY,
        CredentialState.WHITESPACE,
        "Username is empty while password is whitespace-only.",
    ),
    CredentialVariant(
        "TC03-H",
        CredentialState.MISSING,
        CredentialState.EMPTY,
        "Username parameter is omitted while password is present but empty.",
    ),
    CredentialVariant(
        "TC03-I",
        CredentialState.EMPTY,
        CredentialState.MISSING,
        "Username is empty while password parameter is omitted.",
    ),
    CredentialVariant(
        "TC03-J",
        CredentialState.NULL,
        CredentialState.NULL,
        "JSON null values are supplied for both credential fields.",
        json_only=True,
    ),
)


def state_value(state: CredentialState, supplied: str = "") -> str | None:
    """Return the concrete wire value; MISSING returns None because the key is absent."""
    if state == CredentialState.MISSING:
        return None
    if state == CredentialState.EMPTY:
        return ""
    if state == CredentialState.WHITESPACE:
        return "   "
    if state == CredentialState.NULL:
        return "__TC03_NULL_SENTINEL__"
    return supplied


def variant_requires_value(variant: CredentialVariant, field: str) -> bool:
    if field == "username":
        return variant.username_state == CredentialState.VALUE
    if field == "password":
        return variant.password_state == CredentialState.VALUE
    raise ValueError(f"Unknown credential field: {field}")
