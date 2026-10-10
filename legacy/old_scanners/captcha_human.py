"""Human-in-the-loop CAPTCHA login for authorized testing.

Opens a visible browser so a person can complete the CAPTCHA. Does not
auto-click CAPTCHA widgets or call solving services.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

_BROWSER_DIR = Path(__file__).resolve().parent / ".playwright-browsers"
if _BROWSER_DIR.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_BROWSER_DIR))

from default_creds_lane import HttpDefaultCredChecker, _mask_secret
from login_applicability import (
    absolute_login_url,
    captcha_marker_from_html,
    captcha_marker_from_url,
    federated_login_skip,
)

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    sync_playwright = None
    PlaywrightTimeoutError = Exception

HUMAN_CAPTCHA_WAIT_MS = 180_000
_SUCCESS_MARKERS = ("sign off", "signoff", "log off", "logoff", "logout", "log out", "welcome")


def probe_login_captcha(target: str, login_path: str, verify_tls: bool = True) -> dict:
    """Discover the login form and whether a CAPTCHA is present."""
    login_url = absolute_login_url(target, login_path)
    federated = federated_login_skip(target, login_path, probe=True)
    checker = HttpDefaultCredChecker(target, verify_tls=verify_tls)
    mechanism, page_url, form = checker._probe_login_page(login_path)
    html = checker._last_login_html or ""
    page = page_url or login_url
    marker = captcha_marker_from_html(html) or captcha_marker_from_url(page)
    return {
        "federated": federated,
        "captcha_marker": marker,
        "mechanism": mechanism,
        "page_url": page,
        "user_field": form.user_field if form else "username",
        "pass_field": form.pass_field if form else "password",
        "action_url": form.action_url if form else page,
    }


def captcha_blocked(url: str, html: str = "") -> bool:
    return bool(captcha_marker_from_url(url) or captcha_marker_from_html(html))


def looks_authenticated(url: str, html: str) -> bool:
    if captcha_blocked(url, html):
        return False
    body = (html or "").lower()
    if any(marker in body for marker in _SUCCESS_MARKERS):
        return True
    path = (urlparse(url).path or "").lower()
    return "login" not in path and "signin" not in path and "sign-in" not in path


def human_login_with_captcha(
    login_url: str,
    username: str,
    password: str,
    user_field: str = "username",
    pass_field: str = "password",
    wait_ms: int = HUMAN_CAPTCHA_WAIT_MS,
    verify_tls: bool = True,
) -> dict:
    """Fill credentials, wait for a human CAPTCHA token, then submit."""
    if sync_playwright is None:
        return {
            "ok": False,
            "success": False,
            "error": "playwright_not_installed",
            "evidence": (
                f"{username}:{_mask_secret(password)} captcha_window_unavailable: "
                "Playwright is not installed"
            ),
        }

    pair = f"{username}:{_mask_secret(password)}"
    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False)
            context = browser.new_context(ignore_https_errors=not verify_tls)
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded", timeout=30_000)
            _fill_named_or_fallback(page, user_field, username, kind="user")
            if pass_field:
                _fill_named_or_fallback(page, pass_field, password or "", kind="pass")

            page.wait_for_function(
                """() => {
                    const names = [
                        'textarea[name="g-recaptcha-response"]',
                        'textarea[name="h-captcha-response"]',
                        'input[name="cf-turnstile-response"]',
                    ];
                    for (const sel of names) {
                        const el = document.querySelector(sel);
                        if (el && el.value && el.value.length > 20) return true;
                    }
                    return false;
                }""",
                timeout=wait_ms,
            )
            _click_submit(page)
            page.wait_for_timeout(1500)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=15_000)
            except PlaywrightTimeoutError:
                pass
            final_url = str(page.url or "")
            html = page.content() or ""
            blocked = captcha_blocked(final_url, html)
            success = (not blocked) and looks_authenticated(final_url, html)
            browser.close()
            browser = None
            if blocked:
                return {
                    "ok": True,
                    "success": False,
                    "blocked_by_captcha": True,
                    "final_url": final_url,
                    "evidence": (
                        f"{pair} human_captcha_submit still_blocked "
                        f"redirected_to={final_url}"
                    ),
                }
            return {
                "ok": True,
                "success": success,
                "blocked_by_captcha": False,
                "final_url": final_url,
                "evidence": (
                    f"{pair} human_captcha_submit success={success} "
                    f"redirected_to={final_url}"
                ),
            }
    except PlaywrightTimeoutError:
        return {
            "ok": False,
            "success": False,
            "error": "captcha_wait_timeout",
            "evidence": f"{pair} human_captcha_timeout: no token within wait window",
        }
    except Exception as exc:
        return {
            "ok": False,
            "success": False,
            "error": str(exc),
            "evidence": f"{pair} human_captcha_error:{exc}",
        }
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


def _fill_named_or_fallback(page, name: str, value: str, kind: str) -> None:
    named = page.locator(f'input[name="{name}"]')
    if named.count() > 0:
        named.first.fill(value)
        return
    if kind == "pass":
        page.locator('input[type="password"]').first.fill(value)
        return
    fallback = page.locator('input[type="email"], input[type="text"]')
    if fallback.count() > 0:
        fallback.first.fill(value)


def _click_submit(page) -> None:
    for selector in (
        'input[type="submit"]',
        'button[type="submit"]',
        'button:has-text("Submit")',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'input[value="Login"]',
        'input[value="Submit"]',
    ):
        loc = page.locator(selector)
        if loc.count() > 0:
            loc.first.click()
            return
    page.keyboard.press("Enter")
