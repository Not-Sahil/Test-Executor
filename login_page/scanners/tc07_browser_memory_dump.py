from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from authentication.login_applicability import federated_login_skip
except Exception:  # pragma: no cover
    federated_login_skip = None

from authentication.browser_memory_analyzer import analyze_browser_memory
from authentication.browser_memory_browser import run_browser_memory_assessment, sync_playwright
from authentication.browser_memory_models import BrowserMemoryConfig, MemoryProbe


def _severity_metadata() -> dict[str, Any]:
    return {
        "severity": None,
        "risk_score": None,
        "severity_rationale": "",
        "severity_components": {},
        "severity_metrics": {},
    }


def _normalize_target(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an absolute HTTP(S) URL")
    return raw


def _not_assessed(target: str, reason: str, summary: str | None = None) -> dict[str, Any]:
    return {
        "key": "tc07_browser_memory_dump",
        "name": "Browser Memory Dump",
        "status": "NOT ASSESSED",
        "assessment_state": "NOT_ASSESSED",
        "severity": None,
        "risk_score": None,
        "severity_rationale": "",
        "severity_components": {},
        "severity_metrics": {},
        "summary": summary or "TC07 is not applicable: no login form or credentials input found.",
        "raw_output": "",
        "evidence": [reason],
        "details": {"finding_confirmed": False, "not_applicable": True},
    }



def _incomplete(target: str, summary: str, evidence: list[str] | None = None) -> dict[str, Any]:
    result = {
        "key": "tc07_browser_memory_dump",
        "name": "Browser Memory Dump",
        "status": "INCOMPLETE",
        "assessment_state": "INCOMPLETE",
        "summary": summary,
        "target": target,
        "raw_output": "",
        "evidence": evidence or [summary],
        "details": {"finding_confirmed": False},
    }
    result.update(_severity_metadata())
    return result


def _build_probe() -> MemoryProbe:
    # This is deliberately synthetic and unique. It prevents the scanner from
    # copying an operator's real password into a memory-search pipeline.
    suffix = secrets.token_hex(10)
    return MemoryProbe(
        username=f"__tc07_probe_user_{suffix}__",
        password=f"__TC07_MEMORY_PROBE_{suffix}__",
    )


def _run_http_fallback(normalized_target: str, cfg: Any, reason_note: str = "Playwright is not installed") -> dict[str, Any]:
    try:
        import requests
        from authentication.auth_discovery import login_page_candidates, html_has_password_form
        page_url = login_page_candidates(normalized_target, cfg.login_path)[0]
        response = requests.get(
            page_url,
            timeout=cfg.timeout if hasattr(cfg, "timeout") else 10,
            verify=cfg.verify_tls,
            allow_redirects=True,
        )
        html = response.text or ""
        has_password = html_has_password_form(html)
        if not has_password:
            return _not_assessed(
                normalized_target,
                "No password-like form was identified on the HTTP response.",
                summary="No visible login form or password fields were discovered on the target page.",
            )
        cache = str(response.headers.get("Cache-Control") or "")
        autocomplete_off = bool(re.search(r"autocomplete\s*=\s*['\"]off['\"]", html, re.I))
        return {
            "key": "tc07_browser_memory_dump",
            "name": "Browser Memory Dump",
            "status": "REVIEW REQUIRED",
            "assessment_state": "REVIEW_REQUIRED",
            "summary": (
                f"{reason_note}; the login page HTML was inspected via HTTP instead. "
                "Verify password caching headers and form security controls."
            ),
            "raw_output": "",
            "evidence": [
                f"login_candidate={response.url}",
                f"password_field_present={has_password}",
                f"autocomplete_off_observed={autocomplete_off}",
                f"cache_control={cache or '<absent>'}",
                reason_note,
            ],
            "details": {
                "finding_confirmed": False,
                "http_fallback": True,
                "password_field_present": has_password,
                "operator_action": "Inspect browser DOM/heap retention of credential input.",
            },
        }
    except Exception as exc:
        return _incomplete(
            normalized_target,
            "TC07 could not reach the configured login page path.",
            [f"{type(exc).__name__}: {exc}"],
        )



def scan_browser_memory_dump(
    target: str,
    *,
    config: BrowserMemoryConfig | None = None,
    progress=None,
) -> dict[str, Any]:
    cfg = (config or BrowserMemoryConfig()).normalized()

    try:
        normalized_target = _normalize_target(target)
    except Exception as exc:
        return _incomplete(
            target,
            "TC07 could not normalize the configured target URL.",
            [f"{type(exc).__name__}: {exc}"],
        )

    if sync_playwright is None:
        return _run_http_fallback(normalized_target, cfg, "Playwright is not installed")



    from authentication.auth_discovery import login_page_candidates
    candidates = login_page_candidates(normalized_target, cfg.login_path)
    login_url = candidates[0] if candidates else urljoin(normalized_target.rstrip("/") + "/", cfg.login_path.lstrip("/"))

    if federated_login_skip is not None:
        try:
            skip = federated_login_skip(normalized_target, cfg.login_path, probe=True)
            if skip:
                return _not_assessed(
                    normalized_target,
                    f"federated_login={skip.get('classification')}; reason={skip.get('reason') or 'identity-provider login detected'}",
                )
        except Exception:
            # The browser lane below remains authoritative for execution. A
            # failed optional applicability helper must not disable TC07.
            pass

    # TC07 deliberately uses a synthetic credential probe for memory tracing.
    # The supplied authorized credentials are used only in the optional
    # authenticated-control lane and are never copied into heap scanning.
    probe = _build_probe()

    run = run_browser_memory_assessment(
        normalized_target,
        probe=probe,
        config=cfg,
        progress=progress,
    )

    # A missing login form should be reported as not applicable only after the
    # browser execution actually established that no password input exists.
    # We infer this from a clear browser error rather than guessing from HTTP.
    if run.errors and not run.observations:
        if any("visible username/password fields were not discovered" in err for err in run.errors):
            return _not_assessed(
                normalized_target,
                "No visible login or password fields were discovered on the target page.",
                summary="No visible login form or password fields were discovered on the target page.",
            )
        return _run_http_fallback(
            normalized_target,
            cfg,
            f"Browser execution issue ({run.errors[0] if run.errors else 'unavailable'})",
        )



    result = analyze_browser_memory(
        target=normalized_target,
        login_url=login_url,
        observations=run.observations,
        authenticated_completed=run.authenticated or not cfg.perform_authenticated_lane,
        heap_supported=run.heap_supported,
        heap_examined=run.heap_examined,
        direct_issue=run.direct_issue,
        heap_only_issue=run.heap_issue and not run.direct_issue and not run.storage_issue,
        storage_issue=run.storage_issue,
        errors=run.errors,
        require_authenticated_lane=cfg.perform_authenticated_lane,
    )

    payload = result.as_dict()
    payload.update(_severity_metadata())
    payload["key"] = "tc07_browser_memory_dump"
    payload["name"] = "Browser Memory Dump"
    payload["raw_output"] = ""
    payload["details"].update(
        {
            "target": normalized_target,
            "login_url": login_url,
            "probe_username": probe.username,
            "probe_password": "<redacted>",
            "probe_values_are_synthetic": True,
            "perform_authenticated_lane": cfg.perform_authenticated_lane,
            "authorized_credentials_supplied": bool(
                cfg.authorized_username and cfg.authorized_password
            ),
            "scope_boundary": [
                "TC07 evaluates transient and page-owned browser memory retention of credential input.",
                "TC01 owns autocomplete metadata and autofill semantics.",
                "TC06 owns login-method interchange and method-specific request behavior.",
                "TC08/TC09 own transport/TLS controls.",
                "TC10 owns remember-me/session persistence as a separate authentication control.",
                "Browser cache/history/back-button review is not silently classified as TC07; it needs the dedicated cache/history procedure.",
                "The scanner never reports the real authorized password or raw heap contents.",
            ],
            "limitations": [
                "Chromium CDP heap snapshots are used when available; Firefox/WebKit do not receive the same heap-forensics lane.",
                "A heap-only literal match is REVIEW REQUIRED rather than automatically confirmed because browser internals can retain transient allocations.",
                "A clean heap snapshot does not prove that the operating-system renderer process contains no residual bytes; it establishes application-owned evidence at the page/JS heap layer.",
            ],
        }
    )
    return payload


scan = scan_browser_memory_dump
