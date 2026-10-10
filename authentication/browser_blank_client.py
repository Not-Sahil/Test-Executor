from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from .credential_variants import CredentialState, CredentialVariant, state_value

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional dependency
    sync_playwright = None
    PlaywrightTimeoutError = Exception


CAPTCHA_MARKERS = (
    "g-recaptcha",
    "grecaptcha",
    "h-captcha",
    "hcaptcha",
    "cf-turnstile",
    "captcha required",
    "verify you are human",
)
SUCCESS_MARKERS = (
    "logout",
    "log out",
    "sign out",
    "dashboard",
    "my account",
    "welcome",
)


@dataclass(frozen=True)
class BrowserVariantResult:
    available: bool
    state: str
    authenticated_candidate: bool
    captcha_blocked: bool
    final_url: str
    error: str = ""
    evidence: tuple[str, ...] = ()


def _fill_state(locator, state: CredentialState, value: str, *, missing_allowed: bool = True) -> None:
    if state == CredentialState.MISSING and missing_allowed:
        return
    if state == CredentialState.NULL:
        locator.fill("")
        return
    locator.fill(state_value(state, value) or "")


def _pick_submit(page):
    for selector in (
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Sign in")',
        'button:has-text("Login")',
        'button:has-text("Log in")',
        'button:has-text("Continue")',
        'input[value="Login"]',
        'input[value="Sign in"]',
    ):
        loc = page.locator(selector)
        if loc.count() > 0:
            return loc.first
    return None


def _find_user(page):
    for selector in (
        'input[autocomplete="username"]',
        'input[type="email"]',
        'input[name*="user" i]',
        'input[name*="email" i]',
        'input[name*="login" i]',
        'input[type="text"]',
    ):
        loc = page.locator(selector)
        if loc.count() > 0:
            return loc.first
    return None


def _find_password(page):
    loc = page.locator('input[type="password"]')
    return loc.first if loc.count() > 0 else None


def _page_has_captcha(page) -> bool:
    try:
        content = page.content().lower()
        url = str(page.url).lower()
    except Exception:
        return False
    return any(marker in content or marker in url for marker in CAPTCHA_MARKERS)


def run_browser_variant(
    login_url: str,
    variant: CredentialVariant,
    *,
    authorized_username: str = "",
    authorized_password: str = "",
    probe_password: str = "__tc03_blank_probe_password__",
    verify_tls: bool = True,
    timeout_ms: int = 20_000,
    protected_urls: tuple[str, ...] = (),
) -> BrowserVariantResult:
    if sync_playwright is None:
        return BrowserVariantResult(False, "BROWSER_UNAVAILABLE", False, False, login_url, error="playwright_not_installed")

    username_value = authorized_username if variant.username_state == CredentialState.VALUE else ""
    password_value = authorized_password if variant.password_state == CredentialState.VALUE else probe_password

    browser = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=not verify_tls)
            page = context.new_page()
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(300)

            if _page_has_captcha(page):
                return BrowserVariantResult(True, "CAPTCHA_BLOCKED", False, True, str(page.url), evidence=("CAPTCHA/challenge detected before submission",))

            user = _find_user(page)
            password = _find_password(page)

            # Same-page form.
            if user is not None and password is not None:
                _fill_state(user, variant.username_state, username_value)
                _fill_state(password, variant.password_state, password_value)
                submit = _pick_submit(page)
                if submit is not None:
                    submit.click()
                else:
                    page.keyboard.press("Enter")
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=10_000)
                except PlaywrightTimeoutError:
                    pass
                page.wait_for_timeout(500)

            # Username-first / multi-step flow.
            elif user is not None and password is None:
                _fill_state(user, variant.username_state, username_value)
                submit = _pick_submit(page)
                if submit is not None:
                    submit.click()
                else:
                    page.keyboard.press("Enter")
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=10_000)
                except PlaywrightTimeoutError:
                    pass
                page.wait_for_timeout(500)

                if _page_has_captcha(page):
                    return BrowserVariantResult(True, "CAPTCHA_BLOCKED", False, True, str(page.url), evidence=("CAPTCHA/challenge detected during multi-step authentication",))

                password = _find_password(page)
                if password is not None:
                    _fill_state(password, variant.password_state, password_value)
                    submit = _pick_submit(page)
                    if submit is not None:
                        submit.click()
                    else:
                        page.keyboard.press("Enter")
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=10_000)
                    except PlaywrightTimeoutError:
                        pass
                    page.wait_for_timeout(500)
                else:
                    return BrowserVariantResult(True, "AMBIGUOUS", False, False, str(page.url), evidence=("username-first flow advanced but no password field was discovered",))

            else:
                return BrowserVariantResult(True, "UNRESOLVED", False, False, str(page.url), evidence=("no recognizable username/password controls were found in the rendered page",))

            if _page_has_captcha(page):
                return BrowserVariantResult(True, "CAPTCHA_BLOCKED", False, True, str(page.url), evidence=("CAPTCHA/challenge detected after submission",))

            body = page.locator("body").inner_text().lower()
            url = str(page.url)
            login_like = any(token in (url.lower()) for token in ("/login", "/signin", "/sign-in"))
            success_marker = any(marker in body for marker in SUCCESS_MARKERS)
            candidate = (not login_like and success_marker) or (not login_like and url != login_url)
            evidence = [
                f"rendered browser final_url={url}",
                f"success_marker={success_marker}",
                f"login_like_url={login_like}",
            ]
            authenticated = False
            if candidate and protected_urls:
                for path in protected_urls:
                    protected_url = urljoin(login_url.rstrip("/") + "/", path.lstrip("/"))
                    try:
                        protected = context.request.get(protected_url, timeout=10_000, fail_on_status_code=False)
                        protected_body = ""
                        try:
                            protected_body = protected.text()[:20000].lower()
                        except Exception:
                            pass
                        protected_login_redirect = any(token in protected.url.lower() for token in ("/login", "/signin", "/sign-in"))
                        protected_marker = any(marker in protected_body for marker in SUCCESS_MARKERS)
                        evidence.append(
                            f"protected verification {protected_url}: status={protected.status} "
                            f"final={protected.url} login_redirect={protected_login_redirect} "
                            f"success_marker={protected_marker}"
                        )
                        if 200 <= protected.status < 300 and not protected_login_redirect and (protected_marker or protected.url.rstrip("/") != protected_url.rstrip("/")):
                            authenticated = True
                            break
                    except Exception as exc:
                        evidence.append(f"protected verification failed for {protected_url}: {exc}")
            return BrowserVariantResult(
                True,
                "AUTHENTICATED" if authenticated else ("CANDIDATE_SUCCESS" if candidate else "REJECTED"),
                authenticated,
                False,
                url,
                evidence=tuple(evidence),
            )
    except PlaywrightTimeoutError:
        return BrowserVariantResult(True, "ERROR", False, False, login_url, error="browser_timeout")
    except Exception as exc:  # pragma: no cover - runtime-specific
        return BrowserVariantResult(True, "ERROR", False, False, login_url, error=str(exc))
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
