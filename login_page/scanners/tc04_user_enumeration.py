from __future__ import annotations

from dataclasses import asdict
from typing import Callable, Any

from authentication.enumeration_analyzer import (
    AnalysisThresholds,
    classify_browser_candidate,
    classify_candidate,
)
from authentication.enumeration_client import UserEnumerationClient
from authentication.enumeration_models import (
    AssessmentState,
    EnumerationClassification,
    EnumerationConfig,
    EnumerationObservation,
    EnumerationResult,
)
from authentication.enumeration_signals import (
    explicit_username_disclosure,
    is_rate_limited,
    normalize_dynamic_content,
)
from authentication.lockout_guard import LockoutGuard
from authentication.login_applicability import (
    absolute_login_url,
    captcha_marker_from_html,
    captcha_marker_from_url,
    federated_login_skip,
)
from authentication.browser_enumeration import probe_browser_username


TC04_WSTG_ID = "WSTG-IDNT-04"


def _empty_result(**kwargs) -> EnumerationResult:
    return EnumerationResult(details={"wstg_category": TC04_WSTG_ID}, **kwargs)


def _status_for_state(state: str) -> str:
    return {
        AssessmentState.CONFIRMED.value: "UNSAFE",
        AssessmentState.NOT_A_FINDING.value: "SAFE",
        AssessmentState.REVIEW_REQUIRED.value: "REVIEW REQUIRED",
        AssessmentState.NOT_ASSESSED.value: "NOT ASSESSED",
        AssessmentState.INCOMPLETE.value: "INCOMPLETE",
    }.get(state, "REVIEW REQUIRED")


def _summary(state: str, confirmed: list[str], inconclusive: list[str], reason: str = "") -> str:
    if state == AssessmentState.CONFIRMED.value:
        names = ", ".join(confirmed[:5])
        suffix = f" Affected candidate(s): {names}." if names else ""
        return (
            "The authentication flow exposed reliable differences that allow valid "
            "username/account existence to be inferred."
            + suffix
        )
    if state == AssessmentState.NOT_A_FINDING.value:
        return "No reliable username-enumeration condition was identified by the configured signals."
    if state == AssessmentState.NOT_ASSESSED.value:
        return reason or "The configured login flow uses federated authentication; local user enumeration was not assessed."
    if state == AssessmentState.INCOMPLETE.value:
        return reason or "The user-enumeration test could not be completed reliably."
    if inconclusive:
        return "Some username probes produced response differences, but the evidence was not strong enough to confirm enumeration."
    return reason or "Username enumeration requires manual review."


def _severity(result: EnumerationResult, *, confirmed: bool, evidence: list[str]) -> None:
    if not confirmed:
        return
    try:
        from core.severity_engine import SeverityInput, calculate_severity

        scoring = calculate_severity(
            SeverityInput(
                attack_vector="NETWORK",
                attack_complexity="LOW",
                privileges_required="NONE",
                user_interaction="NONE",
                asset_exposure="PUBLIC",
                confidentiality="LOW",
                integrity="NONE",
                availability="NONE",
                authorization="LIMITED",
                data_sensitivity="LOW",
                scope="SAME_SYSTEM",
                rationale=(
                    "Username enumeration was confirmed through repeatable authentication-response "
                    "differences. The finding exposes account-validity information rather than direct authentication."
                ),
                evidence=evidence,
            ),
            assessment_state=AssessmentState.CONFIRMED.value,
        )
        result.severity = scoring.severity
        result.risk_score = scoring.score
        result.severity_rationale = scoring.rationale
        result.severity_components = scoring.components
        result.severity_metrics = scoring.metrics
    except Exception as exc:
        result.details["severity_error"] = str(exc)


def _safe_probe_details(probe) -> dict[str, Any]:
    fp = getattr(probe, "fingerprint", None)
    response = getattr(probe, "response", None)
    return {
        "status": getattr(response, "status_code", None),
        "final_url": getattr(response, "url", "") if response is not None else "",
        "elapsed_ms": round(float(getattr(probe, "elapsed", 0.0)) * 1000, 2),
        "message_class": getattr(fp, "message_class", None),
        "password_step": getattr(fp, "password_step", None),
        "rate_limited": bool(getattr(probe, "rate_limited", False)),
        "error": getattr(probe, "error", ""),
    }


def _html_disclosure_evidence(html: str, candidate_usernames: list[str]) -> list[EnumerationObservation]:
    observations: list[EnumerationObservation] = []
    text = normalize_dynamic_content(html)
    for username in candidate_usernames:
        if explicit_username_disclosure(text, username):
            observations.append(
                EnumerationObservation(
                    username=username,
                    classification=EnumerationClassification.LIKELY_VALID.value,
                    signals={
                        "page_disclosure": True,
                        "disclosure_type": "login_page_account_existence_message",
                    },
                    evidence=[
                        f"{username}: explicit account-existence disclosure was observed on the login page"
                    ],
                    response={"source": "login_page"},
                )
            )
    return observations


def _timing_samples(
    client: UserEnumerationClient,
    mechanism,
    username: str,
    guard: LockoutGuard,
    count: int,
):
    samples = []
    last_probe = None
    for _ in range(max(1, count)):
        last_probe = client.probe(mechanism, username, guard)
        if last_probe.elapsed > 0:
            samples.append(last_probe.elapsed)
        if last_probe.error or last_probe.rate_limited:
            break
    return last_probe, samples


def scan_user_enumeration(
    target: str,
    *,
    config: EnumerationConfig | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """TC04 — WSTG-IDNT-04 Account Enumeration / User Enumeration.

    Scope:
      * configured local login mechanism
      * explicit operator-supplied candidate usernames
      * invalid-username baseline
      * optional known-valid username control
      * response code/length/body/message/redirect/password-step differences
      * optional repeated timing comparison (never sufficient by itself)
      * explicit account-existence disclosure on the login page
      * bounded browser fallback for JS/SPA login pages

    It never guesses passwords and never automatically generates large username
    dictionaries. Candidate usernames must come from an authorized source.
    """
    cfg = config or EnumerationConfig()
    candidates = cfg.normalized_candidates()
    result = _empty_result()

    if progress:
        progress("Running User Enumeration (TC04)")

    skip = federated_login_skip(target, cfg.login_path, probe=True)
    if skip:
        result.assessment_state = AssessmentState.NOT_ASSESSED.value
        result.status = _status_for_state(result.assessment_state)
        result.summary = "Not assessed: " + str(skip.get("reason") or "federated authentication is in use")
        result.evidence.extend([
            f"wstg_category={TC04_WSTG_ID}",
            f"not_applicable_classification={skip.get('classification')}",
            f"login_url={skip.get('login_url')}",
            f"reason={skip.get('reason')}",
        ])
        result.details.update({"not_applicable": True, "skip": skip})
        return result.as_dict()

    if not candidates:
        result.assessment_state = AssessmentState.INCOMPLETE.value
        result.status = _status_for_state(result.assessment_state)
        result.summary = "No authorized candidate usernames were supplied."
        result.details.update({
            "wstg_category": TC04_WSTG_ID,
            "candidate_count": 0,
            "required_input": "candidate_usernames",
        })
        return result.as_dict()

    client = UserEnumerationClient(target, cfg)
    mechanism, discovery = client.discover()
    result.details["discovery"] = discovery
    result.details["candidate_count"] = len(candidates)
    result.details["known_valid_control_configured"] = bool(cfg.known_valid_username)
    result.details["timing_enabled"] = bool(cfg.include_timing and cfg.samples_per_probe >= 2)

    login_url = absolute_login_url(target, cfg.login_path)
    page_response, page_error = client.fetch_page(login_url)
    if page_response is not None:
        html = page_response.text[:20000]
        captcha_marker = captcha_marker_from_html(html) or captcha_marker_from_url(str(page_response.url or login_url))
        if captcha_marker:
            result.assessment_state = AssessmentState.REVIEW_REQUIRED.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = "The login page exposes a CAPTCHA challenge; automated enumeration probes were not submitted."
            result.evidence.extend([
                f"captcha_marker={captcha_marker}",
                "TC04 stopped before credential probes to avoid bypassing the intended human challenge.",
            ])
            result.details["captcha_present"] = True
            return result.as_dict()

        disclosure_obs = _html_disclosure_evidence(html, candidates)
        result.observations.extend(disclosure_obs)
        if disclosure_obs:
            result.evidence.append(
                "The login page explicitly disclosed account-existence information for one or more supplied candidates."
            )

    if mechanism is None:
        if not cfg.allow_browser_fallback:
            result.assessment_state = AssessmentState.INCOMPLETE.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = "Authentication discovery did not resolve a usable login mechanism and browser fallback is disabled."
            result.evidence.append("authentication_mechanism_unresolved")
            return result.as_dict()

        from authentication.browser_enumeration import probe_browser_username

        login_url = absolute_login_url(target, cfg.login_path)
        probe_password = client.probe_password_marker
        browser_candidates = list(candidates)
        if cfg.known_valid_username and cfg.known_valid_username not in browser_candidates:
            browser_candidates.append(cfg.known_valid_username)

        baseline = probe_browser_username(
            login_url,
            "__tc04_nonexistent_user__",
            client.actual_probe_password,
            timeout_ms=cfg.browser_timeout_ms,
            verify_tls=cfg.verify_tls,
        )
        if baseline.captcha_blocked:
            result.assessment_state = AssessmentState.REVIEW_REQUIRED.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = "The browser login flow is protected by a CAPTCHA; enumeration was not completed."
            result.evidence.append("browser_captcha_blocked")
            return result.as_dict()
        if baseline.error:
            result.assessment_state = AssessmentState.INCOMPLETE.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = f"Browser fallback could not establish an enumeration baseline: {baseline.error}"
            return result.as_dict()

        known_control = None
        if cfg.known_valid_username:
            known_control = probe_browser_username(
                login_url,
                cfg.known_valid_username,
                client.actual_probe_password,
                timeout_ms=cfg.browser_timeout_ms,
                verify_tls=cfg.verify_tls,
            )

        confirmed: list[str] = []
        inconclusive: list[str] = []
        for username in candidates:
            if username == cfg.known_valid_username:
                result.observations.append(
                    EnumerationObservation(
                        username=username,
                        classification=EnumerationClassification.CONTROL.value,
                        signals={"control": "known_valid_username"},
                        evidence=[f"{username}: retained only as the known-valid control"],
                    )
                )
                continue
            observation = classify_browser_candidate(
                username=username,
                candidate=probe_browser_username(
                    login_url,
                    username,
                    client.actual_probe_password,
                    timeout_ms=cfg.browser_timeout_ms,
                    verify_tls=cfg.verify_tls,
                ),
                invalid_control=baseline,
                known_valid_control=known_control,
                thresholds=AnalysisThresholds(
                    length_delta=cfg.length_delta_threshold,
                    timing_ratio=cfg.timing_ratio_threshold,
                ),
            )
            result.observations.append(observation)
            if observation.classification == EnumerationClassification.LIKELY_VALID.value:
                confirmed.append(username)
            elif observation.classification == EnumerationClassification.INCONCLUSIVE.value:
                inconclusive.append(username)
        result.details["mechanism"] = "browser_form"
        result.details["browser_fallback"] = True

    else:
        if mechanism.type not in {"html_form", "json_api", "http_basic"}:
            result.assessment_state = AssessmentState.INCOMPLETE.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = f"The discovered authentication mechanism is unsupported for automated TC04 analysis: {mechanism.type}"
            result.evidence.append(f"unsupported_mechanism={mechanism.type}")
            return result.as_dict()

        if mechanism.type != "html_form":
            result.details["mechanism"] = mechanism.type
        else:
            result.details["mechanism"] = "html_form"
        result.details["endpoint"] = mechanism.endpoint
        result.details["username_field"] = mechanism.username_field
        result.details["password_field"] = mechanism.password_field

        required_probes = 1 + (1 if cfg.known_valid_username else 0)
        samples = cfg.samples_per_probe if cfg.include_timing else 1
        max_requests_needed = (len(candidates) + required_probes) * max(1, samples)
        guard_limit = cfg.max_attempts or max_requests_needed
        guard = LockoutGuard(
            max_attempts=min(max_requests_needed, max(1, int(guard_limit))),
            min_delay_seconds=cfg.min_delay_seconds,
        )

        invalid_probe, invalid_samples = _timing_samples(
            client, mechanism, "__tc04_nonexistent_user__", guard, samples
        )
        if invalid_probe is None or invalid_probe.error:
            result.assessment_state = AssessmentState.INCOMPLETE.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = "The invalid-username baseline could not be established."
            result.evidence.append(f"baseline_error={getattr(invalid_probe, 'error', 'no_response')}")
            return result.as_dict()
        if invalid_probe.rate_limited:
            result.assessment_state = AssessmentState.REVIEW_REQUIRED.value
            result.status = _status_for_state(result.assessment_state)
            result.summary = "Enumeration testing stopped because the invalid-username baseline triggered rate limiting/lockout."
            result.evidence.append("baseline_rate_limited")
            return result.as_dict()

        known_probe = None
        known_samples: list[float] = []
        if cfg.known_valid_username:
            known_probe, known_samples = _timing_samples(
                client, mechanism, cfg.known_valid_username, guard, samples
            )
            if known_probe is None or known_probe.error:
                result.evidence.append("known-valid control could not be completed; candidate results will not rely on it")
                known_probe = None

        confirmed: list[str] = []
        inconclusive: list[str] = []

        for username in candidates:
            if username == cfg.known_valid_username:
                result.observations.append(
                    EnumerationObservation(
                        username=username,
                        classification=EnumerationClassification.CONTROL.value,
                        signals={"control": "known_valid_username"},
                        evidence=[f"{username}: retained only as the known-valid control"],
                    )
                )
                continue

            probe, candidate_samples = _timing_samples(
                client, mechanism, username, guard, samples
            )
            if probe is None or probe.error:
                observation = EnumerationObservation(
                    username=username,
                    classification=EnumerationClassification.INCONCLUSIVE.value,
                    signals={"error": getattr(probe, "error", "no_response")},
                    evidence=[f"{username}: probe could not be completed"],
                    response=_safe_probe_details(probe) if probe else {},
                )
            else:
                observation = classify_candidate(
                    username=username,
                    candidate=probe,
                    invalid_control=invalid_probe,
                    known_valid_control=known_probe,
                    candidate_samples=candidate_samples,
                    invalid_samples=invalid_samples,
                    thresholds=AnalysisThresholds(
                        length_delta=cfg.length_delta_threshold,
                        timing_ratio=cfg.timing_ratio_threshold,
                    ),
                )
                observation.response.update(_safe_probe_details(probe))

            result.observations.append(observation)
            if observation.classification == EnumerationClassification.LIKELY_VALID.value:
                confirmed.append(username)
            elif observation.classification == EnumerationClassification.INCONCLUSIVE.value:
                inconclusive.append(username)

            if probe is not None and getattr(probe, "rate_limited", False):
                result.evidence.append(f"{username}: rate limiting/lockout detected; remaining probes were stopped")
                break

        result.details["baseline"] = _safe_probe_details(invalid_probe)
        result.details["known_valid_control"] = _safe_probe_details(known_probe) if known_probe else None
        result.details["guard_attempts"] = guard.attempts
        result.details["guard_max_attempts"] = guard.max_attempts
        result.details["probe_password"] = client.probe_password_marker

    # Merge explicit page disclosure observations with response-based confirmation.
    page_confirmed = [
        o.username
        for o in result.observations
        if (o.signals or {}).get("page_disclosure")
    ]
    confirmed = list(dict.fromkeys(confirmed + page_confirmed))
    inconclusive = list(dict.fromkeys(
        inconclusive + [
            o.username
            for o in result.observations
            if o.classification == EnumerationClassification.INCONCLUSIVE.value
        ]
    ))

    if confirmed:
        result.assessment_state = AssessmentState.CONFIRMED.value
    elif inconclusive:
        result.assessment_state = AssessmentState.REVIEW_REQUIRED.value
    else:
        result.assessment_state = AssessmentState.NOT_A_FINDING.value

    result.status = _status_for_state(result.assessment_state)
    result.summary = _summary(result.assessment_state, confirmed, inconclusive)
    result.details["finding_confirmed"] = bool(confirmed)
    result.details["confirmed_usernames"] = confirmed
    result.details["inconclusive_usernames"] = inconclusive
    result.details["wstg_category"] = TC04_WSTG_ID
    result.evidence.extend([
        f"WSTG category: {TC04_WSTG_ID}",
        f"candidate usernames tested: {len(candidates)}",
        f"confirmed enumeration candidates: {len(confirmed)}",
        f"inconclusive candidates: {len(inconclusive)}",
    ])

    if page_error:
        result.details["page_fetch_error"] = page_error

    if confirmed:
        _severity(result, confirmed=True, evidence=result.evidence)

    return result.as_dict()


# Compatibility aliases for your login-page runner.
scan = scan_user_enumeration
