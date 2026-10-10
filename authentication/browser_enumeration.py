from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:  # pragma: no cover - optional dependency
    sync_playwright = None
    PlaywrightTimeoutError = Exception


@dataclass
class BrowserEnumerationObservation:
    username: str
    final_url: str = ""
    status: int | None = None
    body_text: str = ""
    elapsed: float = 0.0
    password_step: bool = False
    captcha_blocked: bool = False
    error: str = ""


def _has_captcha(page) -> bool:
    try:
        content = (page.content() or "").lower()
    except Exception:
        content = ""
    markers = (
        "g-recaptcha",
        "hcaptcha",
        "cf-turnstile",
        "challenges.cloudflare.com/turnstile",
    )
    return any(marker in content for marker in markers)


def _fill_first(page, selectors: tuple[str, ...], value: str) -> bool:
    for selector in selectors:
        locator = page.locator(selector)
        try:
            if locator.count() > 0:
                locator.first.fill(value)
                return True
        except Exception:
            continue
    return False


def _click_submit(page) -> bool:
    selectors = (
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'button:has-text("Submit")',
        'input[value="Login"]',
        'input[value="Sign in"]',
    )
    for selector in selectors:
        locator = page.locator(selector)
        try:
            if locator.count() > 0:
                locator.first.click()
                return True
        except Exception:
            continue
    try:
        page.keyboard.press("Enter")
        return True
    except Exception:
        return False


def probe_browser_username(
    login_url: str,
    username: str,
    probe_password: str,
    *,
    timeout_ms: int = 20_000,
    verify_tls: bool = True,
) -> BrowserEnumerationObservation:
    if sync_playwright is None:
        return BrowserEnumerationObservation(
            username=username,
            error="playwright_not_installed",
        )

    started = time.perf_counter()
    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=not verify_tls)
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)

            if _has_captcha(page):
                return BrowserEnumerationObservation(
                    username=username,
                    final_url=str(page.url or ""),
                    body_text=(page.locator("body").inner_text() or "")[:12000],
                    elapsed=time.perf_counter() - started,
                    captcha_blocked=True,
                )

            user_ok = _fill_first(
                page,
                (
                    'input[autocomplete="username"]',
                    'input[type="email"]',
                    'input[name*="user" i]',
                    'input[name*="login" i]',
                    'input[type="text"]',
                ),
                username,
            )
            pass_ok = _fill_first(
                page,
                (
                    'input[autocomplete="current-password"]',
                    'input[type="password"]',
                    'input[name*="pass" i]',
                ),
                probe_password,
            )
            if not user_ok or not pass_ok:
                return BrowserEnumerationObservation(
                    username=username,
                    final_url=str(page.url or ""),
                    body_text=(page.locator("body").inner_text() or "")[:12000],
                    elapsed=time.perf_counter() - started,
                    error="browser_login_fields_not_found",
                )

            _click_submit(page)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10_000)
            except PlaywrightTimeoutError:
                pass
            page.wait_for_timeout(400)

            final_url = str(page.url or "")
            body = (page.locator("body").inner_text() or "")[:12000]
            password_step = page.locator('input[type="password"]').count() > 0

            return BrowserEnumerationObservation(
                username=username,
                final_url=final_url,
                body_text=body,
                elapsed=time.perf_counter() - started,
                password_step=password_step,
                captcha_blocked=_has_captcha(page),
            )
    except Exception as exc:
        return BrowserEnumerationObservation(
            username=username,
            elapsed=time.perf_counter() - started,
            error=str(exc),
        )
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
