"""
Application-owned vulnerability severity engine.

This module intentionally does NOT calculate CVSS.
It uses CVSS v4.0 as a design reference, but the score here is a
proprietary 0-100 severity score owned by the assessment application.

Design goals:
- deterministic and explainable scoring
- separate assessment state from severity
- no severity assigned to unconfirmed/review/incomplete findings
- metric values are explicit and auditable
- no external dependencies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Product severity scale
# ---------------------------------------------------------------------------

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

# Product-specific thresholds. These are NOT CVSS thresholds.
SEVERITY_THRESHOLDS = (
    (85.0, SEVERITY_CRITICAL),
    (65.0, SEVERITY_HIGH),
    (40.0, SEVERITY_MEDIUM),
    (20.0, SEVERITY_LOW),
    (0.0, SEVERITY_INFO),
)


# ---------------------------------------------------------------------------
# Metric scales
# ---------------------------------------------------------------------------

# Each metric is normalized to a 0-5 severity contribution.
# The names intentionally resemble established vulnerability concepts but the
# values and formula are application-owned.

ATTACK_VECTOR = {
    "PHYSICAL": 0.5,
    "ADJACENT": 2.0,
    "LOCAL": 3.0,
    "NETWORK": 5.0,
}

ATTACK_COMPLEXITY = {
    "HIGH": 1.5,
    "MEDIUM": 3.0,
    "LOW": 5.0,
}

PRIVILEGES_REQUIRED = {
    "HIGH": 1.5,
    "LOW": 3.5,
    "NONE": 5.0,
}

USER_INTERACTION = {
    "ACTIVE": 1.5,
    "PASSIVE": 3.5,
    "NONE": 5.0,
}

ASSET_EXPOSURE = {
    "LOCAL": 1.0,
    "INTERNAL": 2.5,
    "AUTHENTICATED_PUBLIC": 3.5,
    "PUBLIC": 5.0,
}

IMPACT_LEVEL = {
    "NONE": 0.0,
    "LOW": 2.0,
    "HIGH": 5.0,
}

AUTHORIZATION_IMPACT = {
    "NONE": 0.0,
    "LIMITED": 2.5,
    "MAJOR": 5.0,
}

DATA_SENSITIVITY = {
    "NONE": 0.0,
    "LOW": 1.5,
    "MODERATE": 3.0,
    "HIGH": 4.0,
    "CRITICAL": 5.0,
}

SCOPE_IMPACT = {
    "SAME_SYSTEM": 0.0,
    "TRUST_BOUNDARY": 3.0,
    "CROSS_SYSTEM": 5.0,
}


# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------

# Exploitability = 45% of total score.
EXPLOITABILITY_WEIGHTS = {
    "attack_vector": 0.30,
    "attack_complexity": 0.20,
    "privileges_required": 0.20,
    "user_interaction": 0.15,
    "asset_exposure": 0.15,
}

# Impact = 50% of total score.
IMPACT_WEIGHTS = {
    "confidentiality": 0.25,
    "integrity": 0.25,
    "availability": 0.20,
    "authorization": 0.15,
    "data_sensitivity": 0.15,
}

# Scope/context = 5% of total score.
CONTEXT_WEIGHTS = {
    "scope": 1.0,
}

EXPLOITABILITY_SHARE = 0.45
IMPACT_SHARE = 0.50
CONTEXT_SHARE = 0.05


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeverityInput:
    """All facts required to score one confirmed vulnerability."""

    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    asset_exposure: str = "PUBLIC"

    confidentiality: str = "NONE"
    integrity: str = "NONE"
    availability: str = "NONE"
    authorization: str = "NONE"
    data_sensitivity: str = "NONE"

    scope: str = "SAME_SYSTEM"

    # Optional metadata for the report; it does not alter the score.
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SeverityResult:
    """Structured output from the application severity engine."""

    score: float | None
    severity: str | None
    assessment_state: str
    rationale: str
    components: dict[str, float]
    metrics: dict[str, str]
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "assessment_state": self.assessment_state,
            "rationale": self.rationale,
            "components": self.components,
            "metrics": self.metrics,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Validation / normalization helpers
# ---------------------------------------------------------------------------


def _normalize(value: str) -> str:
    return str(value or "").strip().upper()


def _lookup(metric_name: str, value: str, table: Mapping[str, float]) -> float:
    normalized = _normalize(value)
    if normalized not in table:
        allowed = ", ".join(sorted(table))
        raise ValueError(
            f"Invalid {metric_name} value {value!r}. Expected one of: {allowed}."
        )
    return float(table[normalized])


def _score_from_components(values: Mapping[str, float], weights: Mapping[str, float]) -> float:
    if not values:
        return 0.0
    if abs(sum(weights.values()) - 1.0) > 1e-9:
        raise ValueError("Metric weights must sum to 1.0.")
    return sum(values[key] * weights[key] for key in weights) * 20.0


def severity_from_score(score: float) -> str:
    """Map our 0-100 score to the product's five severity levels."""
    score = max(0.0, min(100.0, float(score)))
    for minimum, severity in SEVERITY_THRESHOLDS:
        if score >= minimum:
            return severity
    return SEVERITY_INFO


# ---------------------------------------------------------------------------
# Assessment-state handling
# ---------------------------------------------------------------------------


def normalize_assessment_state(status: str | None) -> str:
    """
    Convert the legacy scanner status into the new professional state model.

    The old status is kept compatible so existing scanners do not have to be
    rewritten in one pass.
    """
    value = _normalize(status or "")

    mapping = {
        "UNSAFE": "CONFIRMED",
        "CONFIRMED": "CONFIRMED",
        "SAFE": "NOT_A_FINDING",
        "NOT_A_FINDING": "NOT_A_FINDING",
        "REVIEW REQUIRED": "REVIEW_REQUIRED",
        "REVIEW_REQUIRED": "REVIEW_REQUIRED",
        "INCOMPLETE": "INCOMPLETE",
        "ERROR": "INCOMPLETE",
        "UNKNOWN": "INCOMPLETE",
        "SKIPPED": "NOT_ASSESSED",
        "NOT APPLICABLE": "NOT_ASSESSED",
        "NOT_APPLICABLE": "NOT_ASSESSED",
    }
    return mapping.get(value, "REVIEW_REQUIRED")


def requires_severity(state: str) -> bool:
    return _normalize(state) == "CONFIRMED"


# ---------------------------------------------------------------------------
# Main scoring engine
# ---------------------------------------------------------------------------


def calculate_severity(
    metrics: SeverityInput,
    *,
    assessment_state: str = "CONFIRMED",
) -> SeverityResult:
    """
    Calculate our application-owned severity for a finding.

    Severity is intentionally calculated only for CONFIRMED findings.
    Review/incomplete/not-a-finding results receive no severity score.
    """
    state = normalize_assessment_state(assessment_state)

    if not requires_severity(state):
        return SeverityResult(
            score=None,
            severity=None,
            assessment_state=state,
            rationale=(
                "Severity was not assigned because the finding is not confirmed. "
                "Resolve the assessment state before assigning a technical severity."
            ),
            components={},
            metrics={},
            evidence=list(metrics.evidence),
        )

    # Convert user-facing metric labels into numeric contributions.
    exploit_values = {
        "attack_vector": _lookup("attack_vector", metrics.attack_vector, ATTACK_VECTOR),
        "attack_complexity": _lookup("attack_complexity", metrics.attack_complexity, ATTACK_COMPLEXITY),
        "privileges_required": _lookup("privileges_required", metrics.privileges_required, PRIVILEGES_REQUIRED),
        "user_interaction": _lookup("user_interaction", metrics.user_interaction, USER_INTERACTION),
        "asset_exposure": _lookup("asset_exposure", metrics.asset_exposure, ASSET_EXPOSURE),
    }

    impact_values = {
        "confidentiality": _lookup("confidentiality", metrics.confidentiality, IMPACT_LEVEL),
        "integrity": _lookup("integrity", metrics.integrity, IMPACT_LEVEL),
        "availability": _lookup("availability", metrics.availability, IMPACT_LEVEL),
        "authorization": _lookup("authorization", metrics.authorization, AUTHORIZATION_IMPACT),
        "data_sensitivity": _lookup("data_sensitivity", metrics.data_sensitivity, DATA_SENSITIVITY),
    }

    context_values = {
        "scope": _lookup("scope", metrics.scope, SCOPE_IMPACT),
    }

    exploitability = _score_from_components(exploit_values, EXPLOITABILITY_WEIGHTS)
    impact = _score_from_components(impact_values, IMPACT_WEIGHTS)
    context = _score_from_components(context_values, CONTEXT_WEIGHTS)

    # Our proprietary final score. All three components are already 0-100.
    score = (
        (exploitability * EXPLOITABILITY_SHARE)
        + (impact * IMPACT_SHARE)
        + (context * CONTEXT_SHARE)
    )
    score = round(max(0.0, min(100.0, score)), 1)
    severity = severity_from_score(score)

    components = {
        "exploitability": round(exploitability, 1),
        "impact": round(impact, 1),
        "context": round(context, 1),
        "exploitability_share": EXPLOITABILITY_SHARE,
        "impact_share": IMPACT_SHARE,
        "context_share": CONTEXT_SHARE,
    }

    report_metrics = {
        "attack_vector": _normalize(metrics.attack_vector),
        "attack_complexity": _normalize(metrics.attack_complexity),
        "privileges_required": _normalize(metrics.privileges_required),
        "user_interaction": _normalize(metrics.user_interaction),
        "asset_exposure": _normalize(metrics.asset_exposure),
        "confidentiality": _normalize(metrics.confidentiality),
        "integrity": _normalize(metrics.integrity),
        "availability": _normalize(metrics.availability),
        "authorization": _normalize(metrics.authorization),
        "data_sensitivity": _normalize(metrics.data_sensitivity),
        "scope": _normalize(metrics.scope),
    }

    rationale = metrics.rationale.strip() if metrics.rationale else (
        f"Severity derived from exploitability ({components['exploitability']}/100), "
        f"impact ({components['impact']}/100), and context ({components['context']}/100) "
        f"using the application-owned 0-100 severity model."
    )

    return SeverityResult(
        score=score,
        severity=severity,
        assessment_state=state,
        rationale=rationale,
        components=components,
        metrics=report_metrics,
        evidence=list(metrics.evidence),
    )


# ---------------------------------------------------------------------------
# Convenience integration helpers
# ---------------------------------------------------------------------------


def assess_finding(
    *,
    status: str,
    metrics: SeverityInput,
) -> SeverityResult:
    """Score a scanner finding while honoring its current assessment state."""
    return calculate_severity(metrics, assessment_state=status)


def enrich_result_dict(
    result: Mapping[str, Any],
    *,
    metrics: SeverityInput,
) -> dict[str, Any]:
    """
    Add severity information to an existing scanner result dictionary.

    Existing keys remain intact for backward compatibility.
    """
    output = dict(result)
    scoring = assess_finding(
        status=str(result.get("status") or "INCOMPLETE"),
        metrics=metrics,
    )
    output["assessment_state"] = scoring.assessment_state
    output["severity"] = scoring.severity
    output["risk_score"] = scoring.score
    output["severity_rationale"] = scoring.rationale
    output["severity_components"] = scoring.components
    output["severity_metrics"] = scoring.metrics
    return output