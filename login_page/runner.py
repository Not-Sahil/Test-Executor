"""Login-Page Testcase Runner.

Orchestrates execution of the 17 canonical login-page blackbox testcases in
deterministic TC01->TC17 order, with target resolution, centralized scope
validation, and structured ScanResult formatting.
"""
from __future__ import annotations

import asyncio
import importlib
import sys
from dataclasses import fields
from typing import Any, Callable, Sequence
from urllib.parse import urljoin, urlparse

from authentication.models import CredentialCandidate
from core.http_client import effective_verify_tls
from core.models import DiscoveredTargetModel, ScanResult, ScopeStatus
from core.scope import ScopeValidator, normalize_origin
from core.status import ResultStatus
from login_page.registry import LOGIN_PAGE_TESTS

# Bounded enumeration probe password
ENUMERATION_PROBE_PASSWORD = "__wrong_password_idnt04__"
MAX_CREDENTIAL_ATTEMPTS = 50


def _normalize_status(val: Any) -> str:
    s = str(val or "INCOMPLETE").strip().upper()
    valid = {
        "SAFE",
        "UNSAFE",
        "REVIEW REQUIRED",
        "INCOMPLETE",
        "SKIPPED",
        "NOT APPLICABLE",
        "NOT ASSESSED",
        "ERROR",
    }
    if s in valid:
        return s
    if s == "CONFIRMED":
        return "UNSAFE"
    if s in ("NOT_A_FINDING", "PASS"):
        return "SAFE"
    return "INCOMPLETE"


def _build_dataclass_config(config_cls: Any, values: dict) -> Any:
    """Instantiate a testcase config using only fields supported by that config."""
    try:
        names = {f.name for f in fields(config_cls)}
        return config_cls(**{k: v for k, v in values.items() if k in names})
    except Exception:
        try:
            return config_cls()
        except Exception:
            return None


def _as_credential_candidates(credentials: list[dict]) -> list[CredentialCandidate]:
    supported = {
        "operator_supplied",
        "product_default",
        "application_default",
        "organization_default",
        "blank_password",
        "lab_profile",
    }
    output = []
    for item in credentials or []:
        username = str(item.get("username") or "").strip()
        if not username:
            continue
        source = str(item.get("credential_source") or item.get("credential_type") or "application_default").strip().lower()
        if source not in supported:
            source = "application_default"
        output.append(
            CredentialCandidate(
                username=username,
                password=str(item.get("password") or ""),
                credential_source=source,
                product_hint=str(item.get("product_hint") or "") or None,
                account_hint=str(item.get("account_hint") or "") or None,
            )
        )
    return output


def _confirmed_pair_from_result(payload: Any, credentials: list[dict]) -> tuple[str, str] | None:
    if hasattr(payload, "as_dict"):
        payload = payload.as_dict()
    if not isinstance(payload, dict):
        return None
    details = payload.get("details") or {}
    usernames: list[str] = []
    confirmed = details.get("confirmed") or {}
    cred = confirmed.get("credential") if isinstance(confirmed, dict) else {}
    if isinstance(cred, dict) and cred.get("username"):
        usernames.append(str(cred.get("username")).strip())
    for attempt in details.get("attempts") or []:
        if isinstance(attempt, dict) and attempt.get("authentication_confirmed"):
            name = str((attempt.get("credential") or {}).get("username") or "").strip()
            if name:
                usernames.append(name)
    for item in details.get("successful_pairs") or []:
        text = str(item)
        if ":" in text:
            usernames.append(text.split(":", 1)[0].strip())
    for username in usernames:
        if not username:
            continue
        for item in credentials or []:
            if str(item.get("username") or "").strip() == username and str(item.get("password") or ""):
                return username, str(item.get("password"))
    return None


def _coerce_login_result(payload: Any, key: str, name: str, resolved_target: str = "") -> ScanResult:
    if hasattr(payload, "as_dict"):
        payload = payload.as_dict()
    elif isinstance(payload, dict):
        payload = dict(payload)
    else:
        payload = {
            "status": str(getattr(payload, "status", "INCOMPLETE")),
            "summary": str(getattr(payload, "summary", f"{name} did not produce a structured result.")),
            "raw_output": str(getattr(payload, "raw_output", "") or ""),
            "evidence": getattr(payload, "evidence", None),
            "details": getattr(payload, "details", None),
        }

    status = _normalize_status(payload.get("status"))
    summary = str(payload.get("summary") or f"{name} completed.")
    evidence = payload.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    details = payload.get("details") or {}

    exec_status = "COMPLETED"
    if status in ("INCOMPLETE", "ERROR"):
        exec_status = "INCOMPLETE"
    elif status in ("SKIPPED", "NOT APPLICABLE", "NOT ASSESSED"):
        exec_status = "SKIPPED"

    return ScanResult(
        key=key,
        name=name,
        status=status,
        summary=summary,
        raw_output=str(payload.get("raw_output") or ""),
        evidence=list(evidence),
        details=dict(details),
        execution_status=exec_status,
        assessment_status=status,
        target_resolution_status="RESOLVED" if resolved_target else "UNRESOLVED",
        resolved_target=resolved_target,
    )


def run_login_page_suite(
    target_url: str,
    *,
    login_path: str = "/login",
    login_url: str | None = None,
    verify_tls: bool = True,
    credentials: list[dict] | None = None,
    candidate_usernames: list[str] | None = None,
    authorized_username: str | None = None,
    authorized_password: str | None = None,
    protected_url: str | None = None,
    progress: Callable[[str], None] | None = None,
    target_inventory: DiscoveredTargetModel | None = None,
    scope_validator: ScopeValidator | None = None,
) -> list[ScanResult]:
    """Run all 17 Login Page testcases with target resolution and scope validation."""
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass

    # Resolve effective login URL and origin
    effective_target = target_url
    effective_login_path = login_path

    if target_inventory and target_inventory.login_url:
        resolved_full = target_inventory.login_url
    elif login_url:
        resolved_full = login_url
    else:
        resolved_full = urljoin(target_url.rstrip("/") + "/", login_path.lstrip("/"))

    try:
        parsed_login = urlparse(resolved_full)
        effective_target = f"{parsed_login.scheme}://{parsed_login.netloc}"
        effective_login_path = parsed_login.path or "/login"
        if parsed_login.query:
            effective_login_path += f"?{parsed_login.query}"
    except Exception:
        pass

    # Scope validation check
    login_origin = normalize_origin(effective_target)
    if scope_validator:
        status, reason = scope_validator.validate_scope(login_origin)
        if status != ScopeStatus.IN_SCOPE:
            if progress:
                progress(f"Discovered login origin '{login_origin}' is OUT OF SCOPE. Skipping login-page tests.")
            skipped_results = []
            for item in LOGIN_PAGE_TESTS:
                key, name = item[0], item[1]
                skipped_results.append(
                    ScanResult(
                        key=key,
                        name=name,
                        status=ResultStatus.SKIPPED.value,
                        summary=f"Skipped: login target origin ({login_origin}) is outside authorized testing scope.",
                        evidence=[f"Scope validation: {reason}"],
                        details={"scope_status": "OUT_OF_SCOPE", "origin": login_origin},
                        execution_status="SKIPPED",
                        assessment_status=ResultStatus.SKIPPED.value,
                        target_resolution_status="OUT_OF_SCOPE",
                        resolved_target=resolved_full,
                    )
                )
            return skipped_results

    # Check TLS
    verify_tls, tls_note = effective_verify_tls(effective_target, verify_tls)
    if tls_note and progress:
        progress(tls_note)

    credentials = credentials or []
    candidate_usernames = candidate_usernames or list(dict.fromkeys(
        str(item.get("username") or "").strip() for item in credentials if str(item.get("username") or "").strip()
    ))

    results: list[ScanResult] = []

    for item in LOGIN_PAGE_TESTS:
        key, name = item[0], item[1]
        common = {
            "login_path": effective_login_path,
            "verify_tls": verify_tls,
            "authorized_username": authorized_username,
            "authorized_password": authorized_password,
            "protected_url": protected_url,
        }
        if progress:
            progress(f"Running {name} ({key.upper()})")

        try:
            module_name = f"login_page.scanners.{key}"
            module = importlib.import_module(module_name)

            if key == "tc01_autocomplete":
                payload = module.scan_autocomplete(
                    resolved_full,
                    timeout=12.0,
                    use_browser=True,
                    verify_tls=verify_tls,
                )

            elif key == "tc02_default_credentials":
                cfg = _build_dataclass_config(
                    module.TC02Config,
                    {
                        **common,
                        "max_attempts": min(MAX_CREDENTIAL_ATTEMPTS, max(1, len(credentials) or 10)),
                        "stop_on_first_confirmed": True,
                    },
                )
                payload = module.scan_default_credentials(
                    effective_target,
                    _as_credential_candidates(credentials),
                    config=cfg,
                )

            elif key == "tc03_blank_credentials":
                cfg = _build_dataclass_config(
                    module.TC03Config,
                    {
                        **common,
                        "max_attempts": 10,
                        "include_optional_variants": True,
                        "stop_on_confirmed": True,
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_blank_credentials(effective_target, cfg)

            elif key == "tc04_user_enumeration":
                from authentication.enumeration_models import EnumerationConfig
                cfg = _build_dataclass_config(
                    EnumerationConfig,
                    {
                        **common,
                        "candidate_usernames": tuple(candidate_usernames),
                        "known_valid_username": authorized_username,
                        "probe_password": ENUMERATION_PROBE_PASSWORD,
                        "max_candidates": min(25, max(1, len(candidate_usernames) or 10)),
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_user_enumeration(effective_target, config=cfg, progress=progress)

            elif key == "tc05_password_validation":
                cfg = _build_dataclass_config(
                    module.PasswordValidationConfig,
                    {
                        **common,
                        "max_wrong_attempts": 5,
                        "min_delay_seconds": 0.75,
                        "protected_urls": (protected_url,) if protected_url else ("/account", "/dashboard"),
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_password_validation(effective_target, cfg, progress=progress)

            elif key == "tc06_method_interchange":
                from authentication.method_interchange_models import MethodInterchangeConfig
                cfg = _build_dataclass_config(
                    MethodInterchangeConfig,
                    {
                        **common,
                        "max_attempts": 6,
                        "min_delay_seconds": 0.75,
                        "use_browser_fallback": True,
                    },
                )
                payload = module.scan_method_interchange(effective_target, config=cfg, progress=progress)

            elif key == "tc07_browser_memory_dump":
                from authentication.browser_memory_models import BrowserMemoryConfig
                cfg = _build_dataclass_config(
                    BrowserMemoryConfig,
                    {
                        **common,
                        "perform_authenticated_lane": bool(authorized_username and authorized_password),
                    },
                )
                payload = module.scan_browser_memory_dump(effective_target, config=cfg, progress=progress)

            elif key == "tc08_login_over_http":
                payload = module.scan_login_over_http(
                    effective_target,
                    login_path=effective_login_path,
                    verify_tls=verify_tls,
                )

            elif key == "tc09_cleartext_traffic":
                payload = module.scan_cleartext_traffic(
                    effective_target,
                    login_path=effective_login_path,
                    verify_tls=verify_tls,
                    progress=progress,
                )

            elif key == "tc10_remember_me":
                payload = module.scan_remember_me(
                    effective_target,
                    login_path=effective_login_path,
                    authorized_username=authorized_username,
                    authorized_password=authorized_password,
                    protected_urls=(protected_url,) if protected_url else (),
                    verify_tls=verify_tls,
                )

            elif key == "tc11_shoulder_surfing":
                payload = module.scan_shoulder_surfing(
                    effective_target,
                    login_path=effective_login_path,
                    verify_tls=verify_tls,
                    allow_browser=True,
                )

            elif key == "tc12_captcha_missing":
                cfg = _build_dataclass_config(
                    module.TC12Config,
                    {
                        **common,
                        "max_failed_probes": 3,
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_captcha_missing(effective_target, config=cfg, progress=progress)

            elif key == "tc13_cors":
                cfg = _build_dataclass_config(
                    module.CORSConfig,
                    {"verify_tls": verify_tls},
                )
                payload = module.scan_cors(effective_target, config=cfg, verify_tls=verify_tls)

            elif key == "tc14_sql_injection":
                cfg = _build_dataclass_config(
                    module.SQLiConfig,
                    {"verify_tls": verify_tls, "login_path": effective_login_path},
                )
                payload = module.scan_sql_injection(effective_target, config=cfg, verify_tls=verify_tls)

            elif key == "tc15_ldap_ad":
                cfg = _build_dataclass_config(
                    module.LDAPConfig,
                    {
                        **common,
                        "login_path": effective_login_path,
                        "allow_active_probes": True,
                    },
                )
                payload = module.scan_ldap_ad(effective_target, config=cfg)

            elif key == "tc16_weak_password_encoding":
                cfg = _build_dataclass_config(
                    module.WeakPasswordConfig,
                    {"verify_tls": verify_tls, "login_path": effective_login_path},
                )
                payload = module.scan_weak_password_encoding(effective_target, config=cfg)

            elif key == "tc17_rate_limit":
                cfg = _build_dataclass_config(
                    module.RateLimitConfig,
                    {
                        **common,
                        "max_wrong_attempts": 6,
                        "min_interval_seconds": 0.75,
                        "allow_browser_fallback": False,
                    },
                )
                payload = module.scan_rate_limit(effective_target, config=cfg, progress=progress)

            else:
                raise RuntimeError(f"No integration handler exists for {key}")

            res = _coerce_login_result(payload, key, name, resolved_target=resolved_full)

            # Re-use confirmed default creds if needed
            if key == "tc02_default_credentials" and not (authorized_username and authorized_password):
                recovered = _confirmed_pair_from_result(payload, credentials)
                if recovered:
                    authorized_username, authorized_password = recovered
                    if progress:
                        progress("Reusing confirmed default-credential pair for later authentication tests.")

            results.append(res)

        except Exception as exc:
            err_msg = str(exc).strip() or type(exc).__name__
            results.append(
                ScanResult(
                    key=key,
                    name=name,
                    status=ResultStatus.ERROR.value,
                    summary=f"{name} failed to execute: {err_msg}",
                    details={
                        "module": f"login_page.scanners.{key}",
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    evidence=[f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__],
                    raw_output="",
                    execution_status="ERROR",
                    assessment_status=ResultStatus.ERROR.value,
                    target_resolution_status="RESOLVED" if resolved_full else "UNRESOLVED",
                    resolved_target=resolved_full,
                )
            )

    return results
