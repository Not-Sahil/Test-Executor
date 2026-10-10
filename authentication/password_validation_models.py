from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class PasswordAttemptKind(str, Enum):
    VALID_CONTROL = "valid_control"
    WRONG_GENERIC = "wrong_generic"
    WRONG_SAME_LENGTH = "wrong_same_length"
    WRONG_SINGLE_MUTATION = "wrong_single_mutation"
    WRONG_CASE_MUTATION = "wrong_case_mutation"
    WRONG_TRAILING_WHITESPACE = "wrong_trailing_whitespace"


class PasswordAttemptState(str, Enum):
    NOT_RUN = "not_run"
    REJECTED = "rejected"
    AUTHENTICATED = "authenticated"
    MFA_REQUIRED = "mfa_required"
    PASSWORD_CHANGE_REQUIRED = "password_change_required"
    RATE_LIMITED = "rate_limited"
    CAPTCHA_BLOCKED = "captcha_blocked"
    AMBIGUOUS = "ambiguous"
    ERROR = "error"


@dataclass(frozen=True)
class PasswordValidationConfig:
    login_path: str = "/login"
    authorized_username: str | None = None
    authorized_password: str | None = None
    timeout: float = 8.0
    verify_tls: bool = True
    max_wrong_attempts: int = 5
    min_delay_seconds: float = 0.75
    test_same_length: bool = True
    test_single_mutation: bool = True
    test_case_mutation: bool = True
    test_trailing_whitespace: bool = True
    stop_on_confirmed: bool = True
    allow_browser_fallback: bool = True
    browser_timeout_ms: int = 20_000
    protected_urls: tuple[str, ...] = ()
    attack_vector: str = "NETWORK"
    asset_exposure: str = "PUBLIC"
    scope: str = "SAME_SYSTEM"


@dataclass(frozen=True)
class PasswordFieldRules:
    found: bool = False
    input_type: str = ""
    required: bool = False
    minlength: int | None = None
    maxlength: int | None = None
    pattern: str | None = None
    autocomplete: str | None = None
    source: str = "static_html"
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PasswordAttempt:
    kind: PasswordAttemptKind
    username: str
    password_redacted: str
    state: PasswordAttemptState
    http_status: int | None = None
    final_url: str = ""
    mfa_required: bool = False
    password_change_required: bool = False
    captcha_blocked: bool = False
    protected_access_confirmed: bool = False
    candidate_success: bool = False
    response_length: int | None = None
    evidence: tuple[str, ...] = ()
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PasswordValidationResult:
    key: str = "login.tc05_password_validation"
    name: str = "Password Validation"
    status: str = "INCOMPLETE"
    assessment_state: str = "INCOMPLETE"
    severity: str | None = None
    risk_score: float | None = None
    severity_rationale: str = ""
    severity_components: dict[str, Any] = field(default_factory=dict)
    severity_metrics: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
