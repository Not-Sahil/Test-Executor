from __future__ import annotations

import os
from pathlib import Path

from authentication.evidence import safe_url
from authentication.password_validation_models import PasswordAttemptKind, PasswordAttemptState
from authentication.password_validation_signals import (
    detect_captcha_marker,
    detect_failure_marker,
    detect_mfa_marker,
    detect_password_change_marker,
    detect_success_marker,
    normalize_body,
    redact_password_for_evidence,
)

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover
    sync_playwright = None
    PlaywrightTimeoutError = Exception


_BROWSER_DIR = Path(__file__).resolve().parent / ".playwright-browsers"
if _BROWSER_DIR.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_BROWSER_DIR))


def run_browser_password_attempt(
    login_url: str,
    username: str,
    password: str,
    *,
    timeout_ms: int = 20_000,
) -> dict:
    """Bounded browser fallback for JS-rendered login pages.

    It never bypasses CAPTCHA and uses a fresh browser context per attempt.
    """
    if sync_playwright is None:
        return {
            "state": PasswordAttemptState.ERROR.value,
            "error": "playwright_not_installed",
            "evidence": ["Playwright is unavailable for browser fallback"],
        }

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(250)

            password_locator = page.locator('input[type="password"]').first
            if password_locator.count() == 0:
                return {
                    "state": PasswordAttemptState.ERROR.value,
                    "error": "password_field_not_found",
                    "evidence": ["No password input was found in rendered DOM"],
                }

            user_locator = page.locator(
                'input[name*="user" i], input[name*="email" i], '
                'input[name*="login" i], input[type="email"], input[type="text"]'
            ).first
            if user_locator.count() == 0:
                return {
                    "state": PasswordAttemptState.ERROR.value,
                    "error": "username_field_not_found",
                    "evidence": ["No username-like input was found in rendered DOM"],
                }

            user_locator.fill(username)
            password_locator.fill(password)

            if page.locator('button[type="submit"], input[type="submit"]').count() > 0:
                page.locator('button[type="submit"], input[type="submit"]').first.click()
            else:
                password_locator.press("Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 6000))
            except PlaywrightTimeoutError:
                pass
            page.wait_for_timeout(300)

            final_url = safe_url(page.url)
            body = normalize_body(page.locator("body").inner_text()[:20000])

            captcha = detect_captcha_marker(body)
            if captcha:
                return {
                    "state": PasswordAttemptState.CAPTCHA_BLOCKED.value,
                    "final_url": final_url,
                    "evidence": [f"captcha_marker={captcha}"],
                }

            failure = detect_failure_marker(body)
            if failure:
                return {
                    "state": PasswordAttemptState.REJECTED.value,
                    "final_url": final_url,
                    "evidence": [f"failure_marker={failure}"],
                }

            mfa = detect_mfa_marker(body)
            if mfa:
                return {
                    "state": PasswordAttemptState.MFA_REQUIRED.value,
                    "final_url": final_url,
                    "evidence": [f"mfa_marker={mfa}"],
                }

            password_change = detect_password_change_marker(body)
            if password_change:
                return {
                    "state": PasswordAttemptState.PASSWORD_CHANGE_REQUIRED.value,
                    "final_url": final_url,
                    "evidence": [f"password_change_marker={password_change}"],
                }

            success = detect_success_marker(body)
            if success or not any(token in final_url.lower() for token in ("/login", "/signin", "/sign-in")):
                return {
                    "state": PasswordAttemptState.AUTHENTICATED.value,
                    "final_url": final_url,
                    "candidate_success": True,
                    "evidence": [
                        f"success_marker={success or 'left_login_path'}",
                        f"password={redact_password_for_evidence(password)}",
                    ],
                }

            return {
                "state": PasswordAttemptState.AMBIGUOUS.value,
                "final_url": final_url,
                "evidence": ["browser response did not provide a strong validation signal"],
            }
        finally:
            browser.close()
