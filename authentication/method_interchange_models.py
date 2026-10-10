from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

HTTPMethod = Literal["GET", "POST"]
AssessmentState = Literal[
    "CONFIRMED",
    "NOT_A_FINDING",
    "REVIEW_REQUIRED",
    "NOT_ASSESSED",
    "INCOMPLETE",
]

@dataclass(frozen=True)
class MethodTestCase:
    case_id: str
    expected_method: str
    alternate_method: str
    credential_profile: str
    expected_transport: str
    purpose: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class MethodObservation:
    case_id: str
    method: str
    credential_profile: str
    status_code: int | None = None
    final_url: str = ""
    response_length: int = 0
    elapsed_ms: float | None = None
    redirected: bool = False
    authenticated_signal: bool = False
    rejected_signal: bool = False
    rate_limited: bool = False
    csrf_rejected: bool = False
    set_cookie_names: list[str] = field(default_factory=list)
    auth_cookie_names: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class MethodInterchangeConfig:
    login_path: str = "/login"
    authorized_username: str | None = None
    authorized_password: str | None = None
    probe_password: str = "__tc06_wrong_password_8f31__"

    timeout: float = 8.0
    verify_tls: bool = True
    max_attempts: int = 6
    min_delay_seconds: float = 0.75

    test_get_post_swap: bool = True
    preserve_hidden_fields: bool = True
    use_browser_fallback: bool = True

    protected_urls: tuple[str, ...] = ("/account", "/dashboard")
    auth_cookie_hints: tuple[str, ...] = (
        "session",
        "sess",
        "auth",
        "token",
        "jwt",
        "sid",
    )

    # Never enable destructive/non-login methods in this testcase.
    allow_non_get_post: bool = False

    def normalized(self) -> "MethodInterchangeConfig":
        return MethodInterchangeConfig(
            login_path=self.login_path.strip() or "/login",
            authorized_username=self.authorized_username,
            authorized_password=self.authorized_password,
            probe_password=self.probe_password,
            timeout=max(1.0, float(self.timeout)),
            verify_tls=bool(self.verify_tls),
            max_attempts=max(2, int(self.max_attempts)),
            min_delay_seconds=max(0.0, float(self.min_delay_seconds)),
            test_get_post_swap=bool(self.test_get_post_swap),
            preserve_hidden_fields=bool(self.preserve_hidden_fields),
            use_browser_fallback=bool(self.use_browser_fallback),
            protected_urls=tuple(self.protected_urls or ()),
            auth_cookie_hints=tuple(self.auth_cookie_hints or ()),
            allow_non_get_post=False,
        )

@dataclass
class MethodInterchangeResult:
    status: str
    assessment_state: AssessmentState
    summary: str
    target: str = ""
    expected_method: str = ""
    alternate_method: str = ""
    authenticated_expected: bool = False
    rejected_expected: bool = False
    accepted_wrong_alternate: bool = False
    accepted_valid_alternate: bool = False
    security_control_bypass: bool = False
    attempts_made: int = 0
    observations: list[MethodObservation] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observations"] = [
            observation.as_dict() for observation in self.observations
        ]
        return payload
