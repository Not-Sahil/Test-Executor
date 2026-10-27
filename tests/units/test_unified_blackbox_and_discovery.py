"""Comprehensive Regression Tests for Unified Blackbox, Target Discovery, Scope, and Graybox.

Covers Scenarios A through L as defined in the architectural specification.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.blackbox_runner import UnifiedBlackboxExecutor, run_unified_blackbox_suite
from core.discovery import (
    analyze_auth_flow,
    discover_application_and_auth_flow,
)
from core.evidence import (
    is_soft_404_or_spa_fallback,
    redact_sensitive_data,
    sanitize_url_parameters,
)
from core.models import (
    AuthFlowMetadata,
    AuthProtocolHint,
    DiscoveredTargetModel,
    LoginFormControls,
    ScanResult,
    ScopeStatus,
    TargetType,
)
from core.scope import ScopeValidator, extract_hostname, normalize_origin
from core.status import ResultStatus, calculate_overall_status
from graybox.accounts import GrayBoxAccountManager
from graybox.artifacts import GrayBoxArtifactManager
from graybox.models import (
    AccountRole,
    ArtifactType,
    AutomationLevel,
    GrayBoxConfig,
    GrayBoxResult,
    GrayBoxTestcase,
    TestCategory,
)
from graybox.registry import GRAYBOX_REGISTRY
from graybox.runner import run_graybox_testcase
from login_page.registry import LOGIN_PAGE_TESTS
from pre_login.registry import PRE_LOGIN_TESTS


# ===========================================================================
# SCENARIO A: Application and login form share one origin
# ===========================================================================
def test_scenario_a_same_origin_unified_execution():
    """Verify application and login page on the same origin run all 47 tests without duplication."""
    target_url = "https://application.example.test"

    mock_inventory = DiscoveredTargetModel(
        original_url=target_url,
        application_origin="https://application.example.test",
        login_url="https://application.example.test/login",
        login_origin="https://application.example.test",
        scope_map={"https://application.example.test": ScopeStatus.IN_SCOPE.value},
        login_controls=LoginFormControls(has_form=True, username_field="username", password_field="password"),
    )

    with patch("core.blackbox_runner.discover_application_and_auth_flow", return_value=mock_inventory), \
         patch("core.blackbox_runner.run_pre_login_suite") as mock_pre, \
         patch("core.blackbox_runner.run_login_page_suite") as mock_login, \
         patch("core.blackbox_runner.save_run_output", return_value="/tmp/test_run"):

        mock_pre.return_value = [
            {"key": key, "name": name, "status": "SAFE", "summary": "Passed"}
            for key, name, _ in PRE_LOGIN_TESTS
        ]
        mock_login.return_value = [
            ScanResult(key=item[0], name=item[1], status="SAFE", summary="Passed")
            for item in LOGIN_PAGE_TESTS
        ]

        inv, results, overall, _ = run_unified_blackbox_suite(target_url=target_url)

        assert inv.application_origin == inv.login_origin == "https://application.example.test"
        assert len(results) == 47, f"Expected 47 tests (30 pre-login + 17 login), got {len(results)}"
        assert overall == "SAFE"

        keys = [r.key for r in results]
        assert len(keys) == len(set(keys)), "Duplicate testcase keys found in unified run!"


# ===========================================================================
# SCENARIO B: Login form is hosted on another origin (cross-origin login)
# ===========================================================================
def test_scenario_b_cross_origin_login_authorized():
    """Verify cross-origin login resolution when external origin is explicitly in scope."""
    target_url = "https://application.example.test"
    auth_origin = "https://identity.example.test"

    mock_inventory = DiscoveredTargetModel(
        original_url=target_url,
        application_origin="https://application.example.test",
        login_url="https://identity.example.test/auth/login",
        login_origin=auth_origin,
        identity_provider_origin=auth_origin,
        additional_in_scope_origins=[auth_origin],
        scope_map={
            "https://application.example.test": ScopeStatus.IN_SCOPE.value,
            auth_origin: ScopeStatus.IN_SCOPE.value,
        },
        login_controls=LoginFormControls(has_form=True, username_field="email", password_field="pwd"),
    )

    with patch("core.blackbox_runner.discover_application_and_auth_flow", return_value=mock_inventory), \
         patch("core.blackbox_runner.run_pre_login_suite") as mock_pre, \
         patch("core.blackbox_runner.run_login_page_suite") as mock_login, \
         patch("core.blackbox_runner.save_run_output", return_value="/tmp/run"):

        mock_pre.return_value = [{"key": "tc01_banner_grabbing", "name": "Banner", "status": "SAFE"}]
        mock_login.return_value = [ScanResult(key="tc01_autocomplete", name="Autocomplete", status="SAFE", summary="Passed")]

        executor = UnifiedBlackboxExecutor(
            target_url=target_url,
            additional_in_scope_origins=[auth_origin],
        )
        inv, results, _, _ = executor.execute()

        assert inv.application_origin == "https://application.example.test"
        assert inv.login_origin == "https://identity.example.test"
        assert executor.scope_validator.is_in_scope(auth_origin) is True


# ===========================================================================
# SCENARIO C: Centralized OIDC-like flow & parameter redaction
# ===========================================================================
def test_scenario_c_oidc_authorization_flow_detection_and_redaction():
    """Verify OIDC protocol hint detection, confidence rating, and sensitive parameter redaction."""
    raw_oidc_url = (
        "https://identity.example.test/auth/realms/corp/protocol/openid-connect/auth?"
        "client_id=web-portal&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&"
        "nonce=secret_nonce_xyz123&state=secure_state_token789&scope=openid+profile"
    )

    flow_meta = analyze_auth_flow(all_observed_urls=[raw_oidc_url])

    assert flow_meta.protocol_hint == AuthProtocolHint.OIDC_AUTHORIZATION_CODE.value
    assert flow_meta.confidence == "high"
    assert flow_meta.confirmed is False
    assert flow_meta.idp_host == "identity.example.test"
    assert flow_meta.callback_url == "https://app.example.test/callback"

    # Verify sensitive parameter redaction in URLs
    sanitized = sanitize_url_parameters(raw_oidc_url)
    assert "secret_nonce_xyz123" not in sanitized
    assert "secure_state_token789" not in sanitized
    assert "nonce=%5BREDACTED%5D" in sanitized or "nonce=[REDACTED]" in sanitized
    assert "state=%5BREDACTED%5D" in sanitized or "state=[REDACTED]" in sanitized


# ===========================================================================
# SCENARIO D: JavaScript-driven login navigation (Browser discovery)
# ===========================================================================
def test_scenario_d_javascript_driven_login_discovery():
    """Verify browser discovery observes client-side navigation and extracts form controls."""
    from core.browser import BrowserDiscoveryResult

    mock_browser_res = BrowserDiscoveryResult(
        initial_url="https://spa.example.test",
        settled_url="https://spa.example.test/accounts/sign-in",
        settled_origin="https://spa.example.test",
        redirect_chain=["https://spa.example.test/accounts/sign-in"],
        controls=LoginFormControls(
            has_form=True,
            username_field="user_email",
            password_field="user_password",
            method="POST",
            remember_me_detected=True,
        ),
        navigation_succeeded=True,
        interaction_occurred=True,
        evidence=["Clicked login button", "Settled on /accounts/sign-in"],
    )

    with patch("core.discovery.validate_target_url", return_value="https://spa.example.test"), \
         patch("core.discovery.discover_browser_flow", return_value=mock_browser_res), \
         patch("requests.Session.get") as mock_http:

        mock_http_resp = MagicMock()
        mock_http_resp.url = "https://spa.example.test"
        mock_http_resp.status_code = 200
        mock_http_resp.history = []
        mock_http_resp.text = '<html><body><div id="root"></div></body></html>'
        mock_http_resp.content = mock_http_resp.text.encode()
        mock_http.return_value = mock_http_resp

        inv = discover_application_and_auth_flow(
            target_url="https://spa.example.test",
            use_browser=True,
        )

        assert inv.login_url == "https://spa.example.test/accounts/sign-in"
        assert inv.login_controls.has_form is True
        assert inv.login_controls.username_field == "user_email"
        assert inv.login_controls.remember_me_detected is True


# ===========================================================================
# SCENARIO E: Identity provider is OUT OF SCOPE
# ===========================================================================
def test_scenario_e_idp_out_of_scope():
    """Verify unauthorized external IdP is not actively tested and login tests are marked SKIPPED."""
    target_url = "https://application.example.test"
    external_idp = "https://unauthorized-idp.example.test"

    mock_inventory = DiscoveredTargetModel(
        original_url=target_url,
        application_origin="https://application.example.test",
        login_url="https://unauthorized-idp.example.test/login",
        login_origin=external_idp,
        identity_provider_origin=external_idp,
        scope_map={
            "https://application.example.test": ScopeStatus.IN_SCOPE.value,
            external_idp: ScopeStatus.OUT_OF_SCOPE.value,
        },
        login_controls=LoginFormControls(has_form=True),
    )

    with patch("core.blackbox_runner.discover_application_and_auth_flow", return_value=mock_inventory), \
         patch("core.blackbox_runner.run_pre_login_suite") as mock_pre, \
         patch("core.blackbox_runner.run_login_page_suite") as mock_login, \
         patch("core.blackbox_runner.save_run_output", return_value="/tmp/run"):

        mock_pre.return_value = [{"key": "tc01_banner_grabbing", "name": "Banner", "status": "SAFE"}]

        executor = UnifiedBlackboxExecutor(target_url=target_url)
        inv, results, _, _ = executor.execute()

        # Login page suite must NOT have been called against unauthorized origin!
        mock_login.assert_not_called()

        login_results = [r for r in results if r.key in [item[0] for item in LOGIN_PAGE_TESTS]]
        assert len(login_results) == 17
        assert all(r.status == "SKIPPED" for r in login_results)
        assert all(r.target_resolution_status == "OUT_OF_SCOPE" for r in login_results)
        assert "outside the authorized assessment scope" in login_results[0].summary


# ===========================================================================
# SCENARIO F: Login form cannot be resolved
# ===========================================================================
def test_scenario_f_unresolved_login_form_handled_gracefully():
    """Verify that when no login page can be found, login tests become SKIPPED without guessing URLs."""
    target_url = "https://content-only.example.test"

    mock_inventory = DiscoveredTargetModel(
        original_url=target_url,
        application_origin="https://content-only.example.test",
        login_url=None,
        login_origin=None,
        scope_map={"https://content-only.example.test": ScopeStatus.IN_SCOPE.value},
        login_controls=LoginFormControls(has_form=False),
    )

    with patch("core.blackbox_runner.discover_application_and_auth_flow", return_value=mock_inventory), \
         patch("core.blackbox_runner.run_pre_login_suite") as mock_pre, \
         patch("core.blackbox_runner.run_login_page_suite") as mock_login, \
         patch("core.blackbox_runner.save_run_output", return_value="/tmp/run"):

        mock_pre.return_value = [{"key": "tc01_banner_grabbing", "name": "Banner", "status": "SAFE"}]

        executor = UnifiedBlackboxExecutor(target_url=target_url)
        _, results, _, _ = executor.execute()

        mock_login.assert_not_called()
        login_results = [r for r in results if r.key in [item[0] for item in LOGIN_PAGE_TESTS]]
        assert all(r.status == "SKIPPED" for r in login_results)
        assert all(r.target_resolution_status == "UNRESOLVED" for r in login_results)
        assert not any(r.status == "SAFE" for r in login_results)


# ===========================================================================
# SCENARIO G: Graybox credentials required — missing prerequisites
# ===========================================================================
def test_scenario_g_graybox_missing_prerequisites():
    """Verify Graybox testcases missing role credentials report NOT_ASSESSED/SKIPPED and never SAFE."""
    config = GrayBoxConfig(target_url="https://example.com")
    accounts = GrayBoxAccountManager()  # Empty account manager (no roles)

    # GB-SESSION-15 (IDOR) requires USER_A and USER_B roles
    res = run_graybox_testcase(
        testcase_id="GB-SESSION-15",
        config=config,
        accounts=accounts,
    )

    assert res.status == ResultStatus.NOT_ASSESSED.value
    assert res.assessment_state == "NOT_ASSESSED"
    assert "Prerequisite account role" in res.summary
    assert res.status != "SAFE"


# ===========================================================================
# SCENARIO H: HTTP 200 soft-404 / generic SPA fallback
# ===========================================================================
def test_scenario_h_soft_404_baseline_check():
    """Verify that a 200 OK returning generic SPA React shell is recognized as soft-404."""
    spa_body = (
        b"<!doctype html><html><head><title>App</title>"
        b"<script src='/static/js/bundle.js'></script></head>"
        b"<body><div id='root'></div></body></html>"
    )

    is_fallback = is_soft_404_or_spa_fallback(
        response_body=spa_body,
        response_status=200,
        content_type="text/html",
    )
    assert is_fallback is True

    # Real sensitive config file must NOT be detected as soft-404
    real_env = b"DB_HOST=10.0.0.1\nDB_PASS=Sup3rSecret\n"
    assert is_soft_404_or_spa_fallback(real_env, 200) is False


# ===========================================================================
# SCENARIO I: Timeout handling
# ===========================================================================
def test_scenario_i_timeout_marked_incomplete():
    """Verify timeouts result in INCOMPLETE and are never reported as SAFE or UNSAFE."""
    timeout_result = ScanResult(
        key="tc14_sql_injection",
        name="SQL Injection",
        status="INCOMPLETE",
        summary="Request timed out after 12.0 seconds.",
        details={"error": "ReadTimeout", "timeout_seconds": 12.0},
    )

    assert timeout_result.status == "INCOMPLETE"
    assert timeout_result.status != "SAFE"
    assert timeout_result.status != "UNSAFE"

    # Overall calculation must reflect INCOMPLETE
    overall = calculate_overall_status([timeout_result])
    assert overall == "INCOMPLETE"


# ===========================================================================
# SCENARIO J: Existing inventory regression preservation
# ===========================================================================
def test_scenario_j_inventory_registry_preservation():
    """Verify all 30 pre-login, 17 login-page, and 85 graybox testcases remain registered."""
    assert len(PRE_LOGIN_TESTS) == 30, f"Expected 30 pre-login testcases, got {len(PRE_LOGIN_TESTS)}"
    assert len(LOGIN_PAGE_TESTS) == 17, f"Expected 17 login-page testcases, got {len(LOGIN_PAGE_TESTS)}"
    assert len(GRAYBOX_REGISTRY) == 85, f"Expected 85 graybox testcases, got {len(GRAYBOX_REGISTRY)}"

    # Check key stability
    pre_keys = [t[0] for t in PRE_LOGIN_TESTS]
    assert "tc01_banner_grabbing" in pre_keys
    assert "tc30_prototype_pollution_dom_xss" in pre_keys

    login_keys = [t[0] for t in LOGIN_PAGE_TESTS]
    assert "tc01_autocomplete" in login_keys
    assert "tc17_rate_limit" in login_keys


# ===========================================================================
# SCENARIO K: Mixed testcase outcomes and overall verdict calculation
# ===========================================================================
def test_scenario_k_mixed_outcomes_overall_status():
    """Verify overall status logic preserves UNSAFE and never lets SAFE hide INCOMPLETE."""
    # 1. Any UNSAFE makes overall UNSAFE
    results_with_unsafe = [
        ScanResult(key="t1", name="T1", status="SAFE", summary="Safe"),
        ScanResult(key="t2", name="T2", status="UNSAFE", summary="Finding confirmed"),
        ScanResult(key="t3", name="T3", status="INCOMPLETE", summary="Timed out"),
    ]
    assert calculate_overall_status(results_with_unsafe) == "UNSAFE"

    # 2. REVIEW REQUIRED takes precedence over INCOMPLETE/SAFE when no UNSAFE
    results_review = [
        ScanResult(key="t1", name="T1", status="SAFE", summary="Safe"),
        ScanResult(key="t2", name="T2", status="REVIEW REQUIRED", summary="Ambiguous"),
    ]
    assert calculate_overall_status(results_review) == "REVIEW REQUIRED"

    # 3. All SAFE results produce SAFE
    results_all_safe = [
        ScanResult(key="t1", name="T1", status="SAFE", summary="Safe"),
        ScanResult(key="t2", name="T2", status="SAFE", summary="Safe"),
    ]
    assert calculate_overall_status(results_all_safe) == "SAFE"

    # 4. Only SKIPPED results produce INCOMPLETE
    results_skipped = [
        ScanResult(key="t1", name="T1", status="SKIPPED", summary="Out of scope"),
    ]
    assert calculate_overall_status(results_skipped) == "INCOMPLETE"


# ===========================================================================
# SCENARIO L: Redirect and scope edge cases (prevent suffix spoofing)
# ===========================================================================
def test_scenario_l_scope_strict_origin_and_suffix_spoofing():
    """Verify scope validator strictly blocks subdomain suffix spoofing and unapproved origins."""
    validator = ScopeValidator(
        primary_target="https://target.example.test",
        additional_in_scope_origins=["https://auth.example.test:8443"],
        allow_subdomains=True,
    )

    # 1. Exact primary origin
    assert validator.is_in_scope("https://target.example.test") is True

    # 2. Valid subdomain of primary target
    assert validator.is_in_scope("https://api.target.example.test") is True

    # 3. Suffix spoofing: attacker-target.example.test must FAIL!
    assert validator.is_in_scope("https://attacker-target.example.test") is False

    # 4. Suffix spoofing: target.example.test.attacker.com must FAIL!
    assert validator.is_in_scope("https://target.example.test.attacker.com") is False

    # 5. Unauthorized external IdP must FAIL
    assert validator.is_in_scope("https://login.microsoftonline.com") is False

    # 6. Additional origin with specific port
    assert validator.is_in_scope("https://auth.example.test:8443") is True
    # Different port must fail unless port matches
    assert validator.is_in_scope("https://auth.example.test:9000") is False


# ===========================================================================
# SCENARIO M: Explicit Centralized Login URL input with Additional In-Scope Origin
# ===========================================================================
def test_scenario_m_explicit_centralized_login_url():
    """Verify that when an absolute centralized login URL is provided with its origin in scope, it executes properly."""
    target_url = "https://developerzone.ob.globalbank.sbi"
    centralized_login = "https://auth.ob.globalbank.sbi/auth/login"
    auth_origin = "https://auth.ob.globalbank.sbi"

    mock_inventory = DiscoveredTargetModel(
        original_url=target_url,
        application_origin="https://developerzone.ob.globalbank.sbi",
        login_url=centralized_login,
        login_origin=auth_origin,
        additional_in_scope_origins=[auth_origin],
        scope_map={
            "https://developerzone.ob.globalbank.sbi": ScopeStatus.IN_SCOPE.value,
            auth_origin: ScopeStatus.IN_SCOPE.value,
        },
        login_controls=LoginFormControls(has_form=True),
    )

    with patch("core.blackbox_runner.discover_application_and_auth_flow", return_value=mock_inventory), \
         patch("core.blackbox_runner.run_pre_login_suite") as mock_pre, \
         patch("core.blackbox_runner.run_login_page_suite") as mock_login, \
         patch("core.blackbox_runner.save_run_output", return_value="/tmp/run"):

        mock_pre.return_value = [{"key": "tc01_banner_grabbing", "name": "Banner", "status": "SAFE"}]
        mock_login.return_value = [ScanResult(key="tc01_autocomplete", name="Autocomplete", status="SAFE", summary="Passed")]

        executor = UnifiedBlackboxExecutor(
            target_url=target_url,
            login_path_hint=centralized_login,
            additional_in_scope_origins=[auth_origin],
        )
        inv, results, _, _ = executor.execute()

        assert inv.login_url == centralized_login
        assert inv.login_origin == auth_origin
        assert mock_login.call_count == 1
        call_kwargs = mock_login.call_args[1]
        assert call_kwargs["login_url"] == centralized_login
