from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class EnumerationClassification(str, Enum):
    LIKELY_VALID = "likely_valid"
    LIKELY_INVALID = "likely_invalid"
    INCONCLUSIVE = "inconclusive"
    CONTROL = "control"


class AssessmentState(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_A_FINDING = "NOT_A_FINDING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_ASSESSED = "NOT_ASSESSED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class EnumerationConfig:
    login_path: str = "/login"
    candidate_usernames: tuple[str, ...] = ()
    known_valid_username: str | None = None
    probe_password: str | None = None
    max_candidates: int = 25
    timeout: float = 8.0
    verify_tls: bool = True
    min_delay_seconds: float = 0.5
    max_attempts: int | None = None
    samples_per_probe: int = 1
    timing_ratio_threshold: float = 1.8
    length_delta_threshold: int = 20
    include_timing: bool = False
    refresh_form_each_attempt: bool = True
    allow_browser_fallback: bool = True
    browser_timeout_ms: int = 20_000
    page_fetch_timeout: float = 8.0

    def normalized_candidates(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for raw in self.candidate_usernames:
            value = str(raw).strip()
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
            if len(result) >= max(1, int(self.max_candidates)):
                break
        return result


@dataclass(frozen=True)
class ResponseFingerprint:
    status: int | None
    final_path: str
    location_path: str
    content_type: str
    body_length: int
    normalized_digest: str
    message_class: str
    password_step: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EnumerationObservation:
    username: str
    classification: str = EnumerationClassification.INCONCLUSIVE.value
    signals: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    response: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "classification": self.classification,
            "signals": dict(self.signals),
            "evidence": list(self.evidence),
            "response": dict(self.response),
        }


@dataclass
class EnumerationResult:
    key: str = "login.tc04_user_enumeration"
    name: str = "User Enumeration"
    status: str = "REVIEW REQUIRED"
    assessment_state: str = AssessmentState.REVIEW_REQUIRED.value
    summary: str = "Username enumeration requires review."
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    observations: list[EnumerationObservation] = field(default_factory=list)
    severity: str | None = None
    risk_score: float | None = None
    severity_rationale: str = ""
    severity_components: dict[str, float] = field(default_factory=dict)
    severity_metrics: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "assessment_state": self.assessment_state,
            "summary": self.summary,
            "raw_output": self.raw_output,
            "evidence": list(self.evidence),
            "details": dict(self.details),
            "observations": [item.as_dict() for item in self.observations],
            "severity": self.severity,
            "risk_score": self.risk_score,
            "severity_rationale": self.severity_rationale,
            "severity_components": dict(self.severity_components),
            "severity_metrics": dict(self.severity_metrics),
        }
