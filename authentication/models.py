from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass(frozen=True)
class AuthMechanism:
    """Discovered authentication mechanism and the fields/routes required to use it."""

    type: str
    endpoint: str
    method: str = "POST"
    username_field: str | None = None
    password_field: str | None = None
    content_type: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)
    confidence: str = "medium"
    evidence: tuple[str, ...] = ()
    source_url: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CredentialCandidate:
    """One authorized credential candidate. Password is never rendered by as_dict()."""

    username: str
    password: str
    credential_source: str = "operator_supplied"
    product_hint: str | None = None
    account_hint: str | None = None

    def masked(self) -> str:
        if self.password == "":
            password = "<empty>"
        else:
            password = "*" * min(max(len(self.password), 8), 16)
        return f"{self.username}:{password}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": "<redacted>",
            "credential_source": self.credential_source,
            "product_hint": self.product_hint,
            "account_hint": self.account_hint,
        }


@dataclass(frozen=True)
class AuthenticationAttempt:
    credential: CredentialCandidate
    http_status: int | None
    final_url: str
    candidate_state: str
    authentication_confirmed: bool
    mfa_required: bool = False
    password_change_required: bool = False
    rate_limited: bool = False
    privilege: str = "unknown"
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "credential": self.credential.as_dict(),
            "http_status": self.http_status,
            "final_url": self.final_url,
            "candidate_state": self.candidate_state,
            "authentication_confirmed": self.authentication_confirmed,
            "mfa_required": self.mfa_required,
            "password_change_required": self.password_change_required,
            "rate_limited": self.rate_limited,
            "privilege": self.privilege,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class AuthenticationVerification:
    state: str
    confirmed: bool
    mfa_required: bool = False
    password_change_required: bool = False
    reason: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthenticationBaseline:
    established: bool
    state: str
    http_status: int | None
    final_url: str
    evidence: tuple[str, ...] = ()


@dataclass
class TC02Result:
    key: str = "login.tc02_default_credentials"
    name: str = "Default Credentials"
    status: str = "REVIEW"
    summary: str = ""
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "raw_output": self.raw_output,
            "evidence": self.evidence,
            "details": self.details,
        }
