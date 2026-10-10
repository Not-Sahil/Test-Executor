from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable

from .enumeration_models import EnumerationClassification, EnumerationObservation, ResponseFingerprint
from .enumeration_signals import (
    classify_message,
    explicit_username_disclosure,
    is_rate_limited,
    normalize_path,
)


@dataclass(frozen=True)
class ControlSet:
    invalid: object
    known_valid: object | None = None


@dataclass(frozen=True)
class AnalysisThresholds:
    length_delta: int = 20
    timing_ratio: float = 1.8


def _response_body(probe) -> str:
    if getattr(probe, "response", None) is None:
        return ""
    try:
        return probe.response.text[:20000]
    except Exception:
        return ""


def _location(probe) -> str:
    response = getattr(probe, "response", None)
    if response is None:
        return ""
    return response.headers.get("Location", "")


def _fingerprint(probe) -> ResponseFingerprint | None:
    return getattr(probe, "fingerprint", None)


def _same_core(a: ResponseFingerprint, b: ResponseFingerprint) -> bool:
    checks = (
        a.status == b.status,
        a.final_path == b.final_path,
        a.message_class == b.message_class,
        a.normalized_digest == b.normalized_digest,
    )
    return sum(checks) >= 3


def _diff_families(a: ResponseFingerprint, b: ResponseFingerprint, *, length_delta: int) -> set[str]:
    families: set[str] = set()
    if a.status != b.status:
        families.add("status")
    if a.final_path != b.final_path or a.location_path != b.location_path:
        families.add("routing")
    if a.message_class != b.message_class:
        families.add("message")
    if abs(a.body_length - b.body_length) >= length_delta:
        families.add("length")
    if a.normalized_digest != b.normalized_digest:
        families.add("body")
    if a.password_step != b.password_step:
        families.add("password_step")
    return families


def _timing_ratio(candidate_samples: list[float], baseline_samples: list[float]) -> float:
    candidate = median(candidate_samples) if candidate_samples else 0.0
    baseline = median(baseline_samples) if baseline_samples else 0.0
    if baseline <= 0.0:
        return 1.0
    return candidate / baseline


def classify_candidate(
    *,
    username: str,
    candidate,
    invalid_control,
    known_valid_control=None,
    candidate_samples: list[float] | None = None,
    invalid_samples: list[float] | None = None,
    thresholds: AnalysisThresholds = AnalysisThresholds(),
) -> EnumerationObservation:
    candidate_samples = list(candidate_samples or [])
    invalid_samples = list(invalid_samples or [])

    fp = _fingerprint(candidate)
    invalid_fp = _fingerprint(invalid_control)
    valid_fp = _fingerprint(known_valid_control) if known_valid_control is not None else None

    if fp is None or invalid_fp is None:
        return EnumerationObservation(
            username=username,
            classification=EnumerationClassification.INCONCLUSIVE.value,
            signals={"error": "missing_response_fingerprint"},
            evidence=[f"{username}: no usable response fingerprint was available"],
        )

    body = _response_body(candidate)
    response = getattr(candidate, "response", None)
    status = getattr(response, "status_code", None)

    if is_rate_limited(status, body) or getattr(candidate, "rate_limited", False):
        return EnumerationObservation(
            username=username,
            classification=EnumerationClassification.INCONCLUSIVE.value,
            signals={"rate_limited": True},
            evidence=[f"{username}: probe triggered rate limiting/lockout"],
        )

    candidate_to_invalid = _diff_families(fp, invalid_fp, length_delta=thresholds.length_delta)
    message_class = classify_message(body)
    message_signal = message_class == "invalid_password"
    invalid_message = invalid_fp.message_class
    password_step_differs = fp.password_step != invalid_fp.password_step

    candidate_matches_known = False
    known_diff_families: set[str] = set()
    if valid_fp is not None:
        candidate_matches_known = _same_core(fp, valid_fp)
        known_diff_families = _diff_families(fp, valid_fp, length_delta=thresholds.length_delta)

    ratio = _timing_ratio(candidate_samples, invalid_samples)
    timing_enabled = len(candidate_samples) >= 2 and len(invalid_samples) >= 2
    timing_signal = timing_enabled and (
        ratio >= thresholds.timing_ratio or ratio <= 1.0 / thresholds.timing_ratio
    )

    explicit = explicit_username_disclosure(body, username)

    strong_families: set[str] = set()
    if message_signal:
        strong_families.add("message")
    if password_step_differs and fp.password_step:
        strong_families.add("password_step")
    if candidate_matches_known and not _same_core(fp, invalid_fp):
        strong_families.add("known_valid_control")
    if {"status", "routing"}.issubset(candidate_to_invalid):
        strong_families.add("routing")
    if {"body", "length"}.issubset(candidate_to_invalid):
        strong_families.add("body")
    elif {"body", "message"}.issubset(candidate_to_invalid):
        strong_families.add("body_message")
    if timing_signal:
        strong_families.add("timing")

    if explicit:
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "high"
    elif len(strong_families - {"timing"}) >= 2:
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "high" if candidate_matches_known else "medium"
    elif candidate_matches_known and (message_signal or password_step_differs or len(candidate_to_invalid) >= 2):
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "medium"
    elif len(strong_families) == 1 and strong_families != {"timing"}:
        classification = EnumerationClassification.INCONCLUSIVE.value
        confidence = "low"
    elif strong_families == {"timing"}:
        classification = EnumerationClassification.INCONCLUSIVE.value
        confidence = "low"
    elif not candidate_to_invalid and message_class in {"invalid_username", "generic_failure", "none"}:
        classification = EnumerationClassification.LIKELY_INVALID.value
        confidence = "high"
    else:
        classification = EnumerationClassification.LIKELY_INVALID.value
        confidence = "medium"

    evidence = [
        f"{username}: classification={classification} confidence={confidence}",
        f"baseline_diff_families={sorted(candidate_to_invalid) or ['none']}",
        f"message={message_class}",
        f"password_step={fp.password_step} baseline_password_step={invalid_fp.password_step}",
    ]
    if known_valid_control is not None:
        evidence.append(
            f"known_valid_control_match={candidate_matches_known} known_control_diff_families="
            f"{sorted(known_diff_families) or ['none']}"
        )
    if timing_enabled:
        evidence.append(f"timing_ratio={ratio:.3f} timing_signal={timing_signal}")
    if explicit:
        evidence.append("explicit account-existence disclosure pattern matched")

    return EnumerationObservation(
        username=username,
        classification=classification,
        signals={
            "confidence": confidence,
            "status_differs": "status" in candidate_to_invalid,
            "routing_differs": "routing" in candidate_to_invalid,
            "body_differs": "body" in candidate_to_invalid,
            "length_delta": abs(fp.body_length - invalid_fp.body_length),
            "length_differs": "length" in candidate_to_invalid,
            "message": message_class,
            "baseline_message": invalid_message,
            "message_invalid_password": message_signal,
            "password_step_differs": password_step_differs,
            "candidate_password_step": fp.password_step,
            "known_valid_control_match": candidate_matches_known,
            "timing_ratio": round(ratio, 4),
            "timing_enabled": timing_enabled,
            "timing_differs": timing_signal,
            "signals_fired": sorted(strong_families),
            "explicit_disclosure": explicit,
        },
        evidence=evidence,
        response={
            "status": status,
            "final_path": fp.final_path,
            "location_path": fp.location_path,
            "content_type": fp.content_type,
            "message_class": fp.message_class,
        },
    )


def classify_browser_candidate(
    *,
    username: str,
    candidate,
    invalid_control,
    known_valid_control=None,
    thresholds: AnalysisThresholds = AnalysisThresholds(),
) -> EnumerationObservation:
    """Browser-flow counterpart used only when HTTP discovery cannot resolve an auth mechanism."""
    if getattr(candidate, "captcha_blocked", False):
        return EnumerationObservation(
            username=username,
            classification=EnumerationClassification.INCONCLUSIVE.value,
            signals={"captcha_blocked": True},
            evidence=[f"{username}: browser probe reached a CAPTCHA challenge"],
        )
    if getattr(candidate, "error", ""):
        return EnumerationObservation(
            username=username,
            classification=EnumerationClassification.INCONCLUSIVE.value,
            signals={"error": str(candidate.error)},
            evidence=[f"{username}: browser probe failed: {candidate.error}"],
        )

    candidate_body = str(getattr(candidate, "body_text", "") or "")
    invalid_body = str(getattr(invalid_control, "body_text", "") or "")
    candidate_path = normalize_path(getattr(candidate, "final_url", ""))
    invalid_path = normalize_path(getattr(invalid_control, "final_url", ""))
    candidate_message = classify_message(candidate_body)
    invalid_message = classify_message(invalid_body)
    path_differs = candidate_path != invalid_path
    length_delta = abs(len(candidate_body) - len(invalid_body))
    length_differs = length_delta >= thresholds.length_delta
    body_differs = candidate_body != invalid_body
    password_step_differs = bool(getattr(candidate, "password_step", False)) != bool(getattr(invalid_control, "password_step", False))
    message_signal = candidate_message == "invalid_password"

    known_match = False
    if known_valid_control is not None:
        known_body = str(getattr(known_valid_control, "body_text", "") or "")
        known_path = normalize_path(getattr(known_valid_control, "final_url", ""))
        known_message = classify_message(known_body)
        known_match = (
            candidate_path == known_path
            and candidate_message == known_message
            and abs(len(candidate_body) - len(known_body)) < thresholds.length_delta
        )

    families = set()
    if message_signal:
        families.add("message")
    if path_differs:
        families.add("routing")
    if length_differs:
        families.add("length")
    if body_differs:
        families.add("body")
    if password_step_differs and getattr(candidate, "password_step", False):
        families.add("password_step")
    if known_match:
        families.add("known_valid_control")

    if explicit_username_disclosure(candidate_body, username):
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "high"
    elif known_match and len(families) >= 2:
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "medium"
    elif len(families) >= 2:
        classification = EnumerationClassification.LIKELY_VALID.value
        confidence = "medium"
    elif len(families) == 1:
        classification = EnumerationClassification.INCONCLUSIVE.value
        confidence = "low"
    else:
        classification = EnumerationClassification.LIKELY_INVALID.value
        confidence = "medium"

    return EnumerationObservation(
        username=username,
        classification=classification,
        signals={
            "confidence": confidence,
            "status_differs": False,
            "routing_differs": path_differs,
            "body_differs": body_differs,
            "length_delta": length_delta,
            "length_differs": length_differs,
            "message": candidate_message,
            "baseline_message": invalid_message,
            "message_invalid_password": message_signal,
            "password_step_differs": password_step_differs,
            "known_valid_control_match": known_match,
            "signals_fired": sorted(families),
        },
        evidence=[
            f"{username}: browser classification={classification} confidence={confidence}",
            f"browser_diff_families={sorted(families) or ['none']}",
            f"message={candidate_message}",
        ],
        response={
            "status": getattr(candidate, "status", None),
            "final_path": candidate_path,
            "message_class": candidate_message,
        },
    )
