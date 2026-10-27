"""Unified Blackbox Security Assessment Engine.

Orchestrates the unified blackbox workflow:
  Stage 1: Dynamic discovery, origin inventory, redirect/auth flow analysis, scope validation.
  Stage 2: Applicable pre-login blackbox testcases (30 testcases).
  Stage 3: Applicable login-page blackbox testcases (17 testcases) resolved to the in-scope login target.
  Stage 4: Cross-flow validation and evidence reconciliation.
  Stage 5: Evidence validation, overall verdict calculation, and unified report generation.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Sequence
from urllib.parse import urljoin

from core.cvss_scoring import annotate_result
from core.discovery import discover_application_and_auth_flow
from core.evidence import redact_sensitive_data
from core.models import (
    DiscoveredTargetModel,
    ScanResult,
    ScopeStatus,
)
from core.reporting import save_run_output
from core.scope import ScopeValidator, normalize_origin
from core.status import ResultStatus, calculate_overall_status
from login_page.registry import LOGIN_PAGE_TESTS
from login_page.runner import run_login_page_suite
from pre_login.registry import PRE_LOGIN_TESTS
from pre_login.runner import run_pre_login_suite

logger = logging.getLogger(__name__)


def _as_scan_result(item: Any) -> ScanResult:
    if isinstance(item, ScanResult):
        return item
    if hasattr(item, "as_dict"):
        item = item.as_dict()
    if isinstance(item, dict):
        status = str(item.get("status") or "INCOMPLETE").strip().upper()
        return ScanResult(
            key=str(item.get("key") or "test"),
            name=str(item.get("name") or "Test"),
            status=status,
            summary=str(item.get("summary") or ""),
            raw_output=str(item.get("raw_output") or ""),
            evidence=list(item.get("evidence") or []),
            details=dict(item.get("details") or {}),
            execution_status=item.get("execution_status") or ("COMPLETED" if status not in ("INCOMPLETE", "ERROR", "SKIPPED") else status),
            assessment_status=item.get("assessment_status") or status,
            target_resolution_status=item.get("target_resolution_status") or "RESOLVED",
            resolved_target=item.get("resolved_target"),
        )
    return ScanResult(
        key="test",
        name="Test",
        status="INCOMPLETE",
        summary="Unknown result format",
    )


class UnifiedBlackboxExecutor:
    """Coordinates the unified blackbox assessment across pre-login and login-page testcases."""

    def __init__(
        self,
        target_url: str,
        login_path_hint: str = "/login",
        additional_in_scope_origins: list[str] | None = None,
        verify_tls: bool = True,
        use_browser_discovery: bool = True,
        credentials: list[dict] | None = None,
        candidate_usernames: list[str] | None = None,
        authorized_username: str | None = None,
        authorized_password: str | None = None,
        protected_url: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.target_url = target_url.strip()
        self.login_path_hint = login_path_hint.strip() or "/login"
        self.additional_in_scope_origins = list(additional_in_scope_origins or [])
        self.verify_tls = verify_tls
        self.use_browser_discovery = use_browser_discovery
        self.credentials = credentials or []
        self.candidate_usernames = candidate_usernames or []
        self.authorized_username = authorized_username
        self.authorized_password = authorized_password
        self.protected_url = protected_url
        self.progress = progress_callback or (lambda msg: None)

        self.scope_validator = ScopeValidator(
            primary_target=self.target_url,
            additional_in_scope_origins=self.additional_in_scope_origins,
            allow_subdomains=False,
        )

    def execute(self) -> tuple[DiscoveredTargetModel, list[ScanResult], str, Any]:
        """Execute the full 5-stage unified blackbox assessment."""
        start_time = datetime.now()
        
        # -------------------------------------------------------------
        # Stage 1: Discovery and Baseline
        # -------------------------------------------------------------
        self.progress("Stage 1/5: Running application and authentication flow discovery...")
        target_inventory = discover_application_and_auth_flow(
            target_url=self.target_url,
            login_path_hint=self.login_path_hint,
            additional_in_scope_origins=self.additional_in_scope_origins,
            verify_tls=self.verify_tls,
            use_browser=self.use_browser_discovery,
        )

        all_results: list[ScanResult] = []

        # -------------------------------------------------------------
        # Stage 2: Pre-Login Blackbox Tests (30 testcases)
        # -------------------------------------------------------------
        self.progress(f"Stage 2/5: Executing Pre-Login Blackbox suite ({len(PRE_LOGIN_TESTS)} testcases)...")
        app_origin_in_scope = self.scope_validator.is_in_scope(target_inventory.application_origin)

        if not app_origin_in_scope:
            self.progress(f"Application origin '{target_inventory.application_origin}' is OUT OF SCOPE. Skipping pre-login tests.")
            for key, name, _ in PRE_LOGIN_TESTS:
                all_results.append(
                    ScanResult(
                        key=key,
                        name=name,
                        status=ResultStatus.SKIPPED.value,
                        summary=f"Skipped: application origin '{target_inventory.application_origin}' is out of scope.",
                        evidence=["Scope policy prohibited active scanning against unauthorized origin."],
                        details={"scope_status": "OUT_OF_SCOPE"},
                        execution_status="SKIPPED",
                        assessment_status=ResultStatus.SKIPPED.value,
                        target_resolution_status="OUT_OF_SCOPE",
                        resolved_target=target_inventory.original_url,
                    )
                )
        else:
            raw_pre_results = run_pre_login_suite(
                target=target_inventory.original_url,
                verify_tls=self.verify_tls,
                progress=self.progress,
            )
            for item in raw_pre_results:
                res = _as_scan_result(item)
                res.resolved_target = target_inventory.original_url
                res.target_resolution_status = "RESOLVED"
                all_results.append(res)

        # -------------------------------------------------------------
        # Stage 3: Login-Page Blackbox Tests (17 testcases)
        # -------------------------------------------------------------
        self.progress(f"Stage 3/5: Executing Login-Page Blackbox suite ({len(LOGIN_PAGE_TESTS)} testcases)...")
        if target_inventory.login_url:
            login_target = target_inventory.login_url
        elif self.login_path_hint.lower().startswith(("http://", "https://")):
            login_target = self.login_path_hint
        else:
            login_target = urljoin(self.target_url.rstrip("/") + "/", self.login_path_hint.lstrip("/"))
        login_origin = target_inventory.login_origin or normalize_origin(login_target)

        login_in_scope = self.scope_validator.is_in_scope(login_origin)

        if not login_in_scope:
            self.progress(
                f"Discovered login origin '{login_origin}' is outside authorized scope. "
                "Skipping active login-page tests against unauthorized origin."
            )
            for item in LOGIN_PAGE_TESTS:
                key, name = item[0], item[1]
                all_results.append(
                    ScanResult(
                        key=key,
                        name=name,
                        status=ResultStatus.SKIPPED.value,
                        summary=(
                            f"Skipped: discovered login origin '{login_origin}' is outside "
                            "the authorized assessment scope. External Identity Providers and unauthorized "
                            "hosts must not be tested actively without written authorization."
                        ),
                        evidence=[
                            f"Discovered Login Target: {login_target}",
                            f"Resolved Login Origin: {login_origin}",
                            f"Scope Map: {target_inventory.scope_map}",
                        ],
                        details={
                            "scope_status": "OUT_OF_SCOPE",
                            "origin": login_origin,
                            "idp_origin": target_inventory.identity_provider_origin,
                        },
                        execution_status="SKIPPED",
                        assessment_status=ResultStatus.SKIPPED.value,
                        target_resolution_status="OUT_OF_SCOPE",
                        resolved_target=login_target,
                    )
                )
        elif not target_inventory.login_controls.has_form and not target_inventory.login_url:
            self.progress("No login page or authentication controls were resolved. Recording login testcases as INCOMPLETE/SKIPPED.")
            for item in LOGIN_PAGE_TESTS:
                key, name = item[0], item[1]
                all_results.append(
                    ScanResult(
                        key=key,
                        name=name,
                        status=ResultStatus.SKIPPED.value,
                        summary="Skipped: no login page or authentication form could be resolved from dynamic discovery.",
                        evidence=["Dynamic discovery found no password input, form, or login control."],
                        details={"target_resolution_status": "UNRESOLVED"},
                        execution_status="SKIPPED",
                        assessment_status=ResultStatus.SKIPPED.value,
                        target_resolution_status="UNRESOLVED",
                        resolved_target=login_target,
                    )
                )
        else:
            raw_login_results = run_login_page_suite(
                target_url=self.target_url,
                login_path=self.login_path_hint,
                login_url=target_inventory.login_url,
                verify_tls=self.verify_tls,
                credentials=self.credentials,
                candidate_usernames=self.candidate_usernames,
                authorized_username=self.authorized_username,
                authorized_password=self.authorized_password,
                protected_url=self.protected_url,
                progress=self.progress,
                target_inventory=target_inventory,
                scope_validator=self.scope_validator,
            )
            for item in raw_login_results:
                res = _as_scan_result(item)
                all_results.append(res)

        # -------------------------------------------------------------
        # Stage 4: Cross-Flow Validation
        # -------------------------------------------------------------
        self.progress("Stage 4/5: Running cross-flow validation and evidence reconciliation...")
        # Attach discovery metadata and redirect chain observations to results where relevant
        for r in all_results:
            if target_inventory.redirect_chain:
                r.details.setdefault("redirect_chain", target_inventory.redirect_chain)
            r.details.setdefault("auth_protocol_hint", target_inventory.auth_flow.protocol_hint)
            # Annotate confirmed UNSAFE findings with CVSS v4.0Base score/vector
            annotate_result(r)

        # -------------------------------------------------------------
        # Stage 5: Validation, Overall Status and Unified Reporting
        # -------------------------------------------------------------
        self.progress("Stage 5/5: Validating verdicts and compiling unified assessment report...")
        overall = calculate_overall_status(all_results)

        # Persist unified report
        run_folder = None
        try:
            run_folder = save_run_output(
                target=target_inventory.original_url,
                results=all_results,
                overall=overall,
                timestamp=start_time,
                target_discovery=target_inventory.as_dict(),
            )
            self.progress(f"Unified Blackbox Assessment completed. Report saved to: {run_folder}")
        except Exception as report_exc:
            logger.warning("Error saving unified report: %s", report_exc)

        return target_inventory, all_results, overall, run_folder


def run_unified_blackbox_suite(
    target_url: str,
    login_path: str = "/login",
    additional_in_scope_origins: list[str] | None = None,
    verify_tls: bool = True,
    use_browser_discovery: bool = True,
    credentials: list[dict] | None = None,
    candidate_usernames: list[str] | None = None,
    authorized_username: str | None = None,
    authorized_password: str | None = None,
    protected_url: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[DiscoveredTargetModel, list[ScanResult], str, Any]:
    """Execute the Unified Blackbox Assessment combining pre-login and login-page testcases."""
    executor = UnifiedBlackboxExecutor(
        target_url=target_url,
        login_path_hint=login_path,
        additional_in_scope_origins=additional_in_scope_origins,
        verify_tls=verify_tls,
        use_browser_discovery=use_browser_discovery,
        credentials=credentials,
        candidate_usernames=candidate_usernames,
        authorized_username=authorized_username,
        authorized_password=authorized_password,
        protected_url=protected_url,
        progress_callback=progress,
    )
    return executor.execute()
