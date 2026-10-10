from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from .auth_discovery import discover_authentication, normalize_login_url
from .evidence import safe_credential
from .login_applicability import captcha_marker_from_html, captcha_marker_from_url, federated_login_skip

_BROWSER_DIR = Path(__file__).resolve().parent / ".playwright-browsers"
if _BROWSER_DIR.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_BROWSER_DIR))

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:  # pragma: no cover
    sync_playwright = None
    PlaywrightTimeoutError = Exception

HUMAN_CAPTCHA_WAIT_MS = 180_000


def probe_login_captcha(target: str, login_path: str, verify_tls: bool = True) -> dict:
    login_url = normalize_login_url(target, login_path)
    federated = federated_login_skip(target, login_path, probe=True)
    mechanism, metadata = discover_authentication(target, login_path, verify_tls=verify_tls)
    marker = None
    html = ""
    try:
        import requests
        response = requests.get(login_url, timeout=8, verify=verify_tls, allow_redirects=True)
        html = response.text or ""
        marker = captcha_marker_from_html(html) or captcha_marker_from_url(response.url)
        page_url = response.url
    except Exception:
        page_url = login_url

    return {
        "federated": federated,
        "captcha_marker": marker,
        "mechanism": mechanism.as_dict() if mechanism else None,
        "discovery": metadata,
        "page_url": page_url,
    }


def captcha_blocked(url: str, html: str = "") -> bool:
    return bool(captcha_marker_from_url(url) or captcha_marker_from_html(html))


def looks_authenticated(url: str, html: str) -> bool:
    if captcha_blocked(url, html):
        return False
    body = (html or "").lower()
    if any(marker in body for marker in ("logout", "log out", "sign out", "welcome", "dashboard")):
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
    if sync_playwright is None:
        return {
            "ok": False,
            "success": False,
            "error": "playwright_not_installed",
            "evidence": f"{safe_credential(username, password)} CAPTCHA window unavailable",
        }

    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False)
            context = browser.new_context(ignore_https_errors=not verify_tls)
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded", timeout=30_000)

            if page.locator(f'input[name="{user_field}"]').count():
                page.locator(f'input[name="{user_field}"]').first.fill(username)
            else:
                page.locator('input[type="email"], input[type="text"]').first.fill(username)

            if page.locator(f'input[name="{pass_field}"]').count():
                page.locator(f'input[name="{pass_field}"]').first.fill(password)
            else:
                page.locator('input[type="password"]').first.fill(password)

            page.wait_for_function(
                """() => [
                    'textarea[name="g-recaptcha-response"]',
                    'textarea[name="h-captcha-response"]',
                    'input[name="cf-turnstile-response"]'
                ].some(sel => {
                    const el = document.querySelector(sel);
                    return el && el.value && el.value.length > 20;
                })""",
                timeout=wait_ms,
            )

            for selector in (
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
            ):
                loc = page.locator(selector)
                if loc.count():
                    loc.first.click()
                    break
            else:
                page.keyboard.press("Enter")

            page.wait_for_timeout(1200)
            final_url = str(page.url or "")
            html = page.content() or ""
            blocked = captcha_blocked(final_url, html)
            success = not blocked and looks_authenticated(final_url, html)
            return {
                "ok": True,
                "success": success,
                "blocked_by_captcha": blocked,
                "final_url": final_url,
                "evidence": f"{safe_credential(username, password)} human CAPTCHA flow success={success}",
            }
    except PlaywrightTimeoutError:
        return {
            "ok": False,
            "success": False,
            "error": "captcha_wait_timeout",
            "evidence": f"{safe_credential(username, password)} human CAPTCHA wait timed out",
        }
    except Exception as exc:
        return {
            "ok": False,
            "success": False,
            "error": str(exc),
            "evidence": f"{safe_credential(username, password)} human CAPTCHA error",
        }
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
