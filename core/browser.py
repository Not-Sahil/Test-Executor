"""Browser-Based Dynamic Discovery Engine using Playwright.

Handles client-side routing, single-page application hydration, login control
detection, and interaction-triggered authentication redirects without submitting
credentials or performing destructive actions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from core.models import LoginFormControls
from core.scope import normalize_origin

logger = logging.getLogger(__name__)


@dataclass
class BrowserDiscoveryResult:
    """Outcome of browser-based dynamic flow discovery."""
    initial_url: str
    settled_url: str
    settled_origin: str
    redirect_chain: list[str] = field(default_factory=list)
    controls: LoginFormControls = field(default_factory=LoginFormControls)
    navigation_succeeded: bool = False
    interaction_occurred: bool = False
    error_message: str | None = None
    evidence: list[str] = field(default_factory=list)


def discover_browser_flow(
    target_url: str,
    timeout: float = 15.0,
    verify_tls: bool = True,
) -> BrowserDiscoveryResult:
    """Execute dynamic browser discovery to observe client-side redirects and login controls.

    Falls back safely if Playwright is not installed or browser launch fails.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return BrowserDiscoveryResult(
            initial_url=target_url,
            settled_url=target_url,
            settled_origin=normalize_origin(target_url),
            navigation_succeeded=False,
            error_message="Playwright is not available in the runtime environment.",
            evidence=["Browser discovery skipped: Playwright package missing."],
        )

    evidence: list[str] = []
    redirect_chain: list[str] = []
    controls = LoginFormControls()
    settled_url = target_url

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                context = browser.new_context(
                    ignore_https_errors=not verify_tls,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestExecutor-SecurityScanner/2.0",
                    viewport={"width": 1280, "height": 800},
                )
                page = context.new_page()

                # Track network redirects and navigation events
                def on_response(response):
                    if response.status in (301, 302, 303, 307, 308):
                        loc = response.headers.get("location")
                        if loc and loc not in redirect_chain:
                            redirect_chain.append(loc)

                page.on("response", on_response)

                # 1. Open initial application target
                try:
                    resp = page.goto(
                        target_url,
                        timeout=int(timeout * 1000),
                        wait_until="domcontentloaded",
                    )
                    evidence.append(f"Browser navigated to {target_url} (HTTP {resp.status if resp else 'N/A'})")
                except Exception as nav_exc:
                    evidence.append(f"Initial navigation encountered exception: {nav_exc}")
                    return BrowserDiscoveryResult(
                        initial_url=target_url,
                        settled_url=target_url,
                        settled_origin=normalize_origin(target_url),
                        navigation_succeeded=False,
                        error_message=str(nav_exc),
                        evidence=evidence,
                    )

                # Wait shortly for client-side routing to settle
                try:
                    page.wait_for_load_state("networkidle", timeout=min(3000, int(timeout * 500)))
                except Exception:
                    pass

                settled_url = page.url
                interaction_occurred = False

                # 2. Inspect for password input on current page
                pwd_inputs = page.query_selector_all('input[type="password"]')

                # If no password form is present, look for visible login button/link to follow
                if not pwd_inputs:
                    login_selectors = [
                        'a[href*="login" i]',
                        'a[href*="signin" i]',
                        'a[href*="sign-in" i]',
                        'button:has-text("Log In")',
                        'button:has-text("Sign In")',
                        'button:has-text("Login")',
                        'a:has-text("Log In")',
                        'a:has-text("Sign In")',
                        'a:has-text("Login")',
                    ]
                    for sel in login_selectors:
                        try:
                            elem = page.query_selector(sel)
                            if elem and elem.is_visible():
                                evidence.append(f"Discovered visible login control matching selector: {sel}")
                                with page.expect_navigation(timeout=min(5000, int(timeout * 1000))):
                                    elem.click()
                                interaction_occurred = True
                                evidence.append(f"Followed login control to: {page.url}")
                                settled_url = page.url
                                break
                        except Exception:
                            continue

                # 3. Analyze settled page DOM for authentication controls
                pwd_elements = page.query_selector_all('input[type="password"]')
                if pwd_elements:
                    controls.has_form = True
                    # Identify form parent if present
                    try:
                        form_elem = pwd_elements[0].evaluate_handle("el => el.closest('form')").as_element()
                        if form_elem:
                            controls.action_url = form_elem.get_attribute("action") or ""
                            controls.method = (form_elem.get_attribute("method") or "POST").upper()
                    except Exception:
                        pass

                    controls.password_field = pwd_elements[0].get_attribute("name") or pwd_elements[0].get_attribute("id") or "password"

                    # Identify candidate username/email field
                    user_inputs = page.query_selector_all('input[type="text"], input[type="email"], input[name*="user" i], input[name*="login" i], input[name*="email" i]')
                    if user_inputs:
                        controls.username_field = user_inputs[0].get_attribute("name") or user_inputs[0].get_attribute("id") or "username"

                    # Identify submit button
                    submit_elem = page.query_selector('button[type="submit"], input[type="submit"], button:has-text("Sign in"), button:has-text("Log in")')
                    if submit_elem:
                        controls.submit_button = submit_elem.get_attribute("name") or submit_elem.get_attribute("id") or "submit"

                    evidence.append(f"Identified login controls: username='{controls.username_field}', password='{controls.password_field}', method='{controls.method}'")

                # Check for CAPTCHA markers
                captcha_selectors = [
                    '.g-recaptcha',
                    'iframe[src*="recaptcha"]',
                    'iframe[src*="hcaptcha"]',
                    '.h-captcha',
                    '.cf-turnstile',
                    'iframe[src*="cloudflare.com/turnstile"]',
                ]
                for c_sel in captcha_selectors:
                    if page.query_selector(c_sel):
                        controls.captcha_detected = True
                        controls.captcha_indicator = c_sel
                        evidence.append(f"CAPTCHA challenge detected on login page: {c_sel}")
                        break

                # Check for Remember-me checkbox
                remember_me = page.query_selector('input[type="checkbox"][name*="remember" i], input[type="checkbox"][id*="remember" i]')
                if remember_me:
                    controls.remember_me_detected = True
                    evidence.append("Remember-me checkbox detected on login page.")

                # Check for Password reset link
                pwd_reset = page.query_selector('a[href*="reset" i], a[href*="forgot" i], a:has-text("Forgot")')
                if pwd_reset:
                    controls.password_reset_detected = True
                    evidence.append("Password-reset / recovery link detected.")

                return BrowserDiscoveryResult(
                    initial_url=target_url,
                    settled_url=settled_url,
                    settled_origin=normalize_origin(settled_url),
                    redirect_chain=redirect_chain,
                    controls=controls,
                    navigation_succeeded=True,
                    interaction_occurred=interaction_occurred,
                    evidence=evidence,
                )
            finally:
                browser.close()

    except Exception as exc:
        logger.warning("Browser discovery execution failed: %s", exc)
        return BrowserDiscoveryResult(
            initial_url=target_url,
            settled_url=target_url,
            settled_origin=normalize_origin(target_url),
            navigation_succeeded=False,
            error_message=f"Browser automation error: {exc}",
            evidence=[f"Playwright navigation failed: {exc}"],
        )
