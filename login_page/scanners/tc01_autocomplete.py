"""
TC01 - Autocomplete Security Test

Production-oriented login autocomplete assessment.

Scope
-----
This testcase evaluates credential autofill metadata on actual sign-in forms:
- form-level autocomplete
- username/email field autocomplete
- password field autocomplete
- effective autocomplete inheritance
- multiple login forms
- statically rendered and JavaScript-rendered forms
- iframe/SPA discovery (when Playwright is available)
- login-vs-registration/reset context
- invalid/mismatched autocomplete tokens

This testcase deliberately does NOT duplicate:
- browser memory dump (TC07)
- Remember Me/session persistence (TC10)
- transport security (TC08/TC09)
- password strength/validation (TC05)
- password storage/caching headers as a separate control

Modern-browser note
-------------------
`autocomplete="off"` is not treated as a universal security control for
password-manager autofill. Modern browsers may continue to offer/fill saved
credentials. Correct semantic tokens such as `username` and
`current-password` are preferred. Therefore, this scanner does NOT declare
`autocomplete="on"` or a missing attribute a vulnerability by itself.

The scanner distinguishes:
- NOT_A_FINDING: no security-relevant autocomplete weakness confirmed
- REVIEW_REQUIRED: ambiguous/mismatched configuration that needs context
- CONFIRMED: a concrete credential/autofill exposure condition was established

The scanner is intentionally evidence-driven and avoids arbitrary severity.
Severity should be assigned by the application's separate severity engine
only after a finding is CONFIRMED.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
import re
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import requests

try:  # Optional browser lane for JavaScript-rendered forms.
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover - dependency is optional.
    sync_playwright = None


STATUS_CONFIRMED = "CONFIRMED"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_SAFE = "SAFE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT APPLICABLE"

_ALLOWED_TOKENS = {
    "on",
    "off",
    "username",
    "current-password",
    "new-password",
    "one-time-code",
    "webauthn",
}

# Tokens that are meaningful in other contexts, but suspicious on a login
# credential field because they describe unrelated data categories.
# We record them for review rather than declaring a vulnerability automatically.
_UNRELATED_SENSITIVE_TOKENS = {
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "ssn",
}

_USERNAME_NAME_RE = re.compile(
    r"(?:user|username|login|email|mail|account|identifier|userid|user-id|uid|uname|usr)$",
    re.I,
)
_PASSWORD_NAME_RE = re.compile(r"(?:pass|password|passwd|passw|pwd)$", re.I)
_CONFIRM_RE = re.compile(r"(?:confirm|confirmation|repeat|retype|again)", re.I)
_NEW_PASSWORD_RE = re.compile(r"(?:new|change|reset|set).*password", re.I)
_SIGNIN_RE = re.compile(r"(?:sign[ -]?in|log[ -]?in|login|authenticate)", re.I)
_SIGNUP_RE = re.compile(r"(?:sign[ -]?up|register|create account|registration)", re.I)
_RESET_RE = re.compile(r"(?:forgot|reset|recover|change password)", re.I)


@dataclass
class InputRecord:
    name: str
    input_type: str
    autocomplete_raw: str
    autocomplete_tokens: list[str]
    effective_autocomplete: str
    id_attr: str = ""
    aria_label: str = ""
    placeholder: str = ""
    hidden: bool = False
    disabled: bool = False
    readonly: bool = False
    source: str = "static"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FormRecord:
    index: int
    action: str
    method: str
    form_autocomplete_raw: str
    form_autocomplete_tokens: list[str]
    inputs: list[InputRecord] = field(default_factory=list)
    context: str = "ambiguous"
    source: str = "static"
    page_url: str = ""
    frame_url: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


class _StaticParser(HTMLParser):
    """Extract forms and inputs without executing site JavaScript."""

    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[FormRecord] = []
        self._current: FormRecord | None = None
        self._outside_inputs: list[InputRecord] = []

    @staticmethod
    def _tokens(value: str) -> list[str]:
        return [t.strip().lower() for t in (value or "").split() if t.strip()]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "form":
            action = urljoin(self.page_url, attrs_dict.get("action") or self.page_url)
            form_auto = attrs_dict.get("autocomplete", "")
            self._current = FormRecord(
                index=len(self.forms),
                action=action,
                method=(attrs_dict.get("method") or "get").upper(),
                form_autocomplete_raw=form_auto,
                form_autocomplete_tokens=self._tokens(form_auto),
                page_url=self.page_url,
                source="static",
                frame_url=self.page_url,
            )
            self.forms.append(self._current)
            return

        if tag != "input":
            return

        raw_auto = attrs_dict.get("autocomplete", "")
        tokens = self._tokens(raw_auto)
        input_rec = InputRecord(
            name=attrs_dict.get("name", ""),
            input_type=(attrs_dict.get("type") or "text").lower(),
            autocomplete_raw=raw_auto,
            autocomplete_tokens=tokens,
            effective_autocomplete=raw_auto.lower().strip(),
            id_attr=attrs_dict.get("id", ""),
            aria_label=attrs_dict.get("aria-label", ""),
            placeholder=attrs_dict.get("placeholder", ""),
            hidden=(attrs_dict.get("type", "").lower() == "hidden"),
            disabled="disabled" in attrs_dict,
            readonly="readonly" in attrs_dict,
            source="static",
        )

        if self._current is not None:
            self._current.inputs.append(input_rec)
        else:
            self._outside_inputs.append(input_rec)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None

    @property
    def outside_inputs(self) -> list[InputRecord]:
        return self._outside_inputs


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        raise ValueError("Login URL is empty")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError("Login URL has no hostname")
    return value.rstrip("/")


def _token_list(value: str) -> list[str]:
    return [t.strip().lower() for t in (value or "").split() if t.strip()]


def _effective_autocomplete(form_value: str, field_value: str) -> str:
    """Field-level value overrides form-level value; otherwise inherit form."""
    field = (field_value or "").strip()
    if field:
        return field
    return (form_value or "").strip()


def _text_blob(form: FormRecord) -> str:
    parts = [form.action, form.page_url, form.frame_url]
    for inp in form.inputs:
        parts.extend([inp.name, inp.id_attr, inp.aria_label, inp.placeholder])
    return " ".join(parts)


def _looks_username(inp: InputRecord) -> bool:
    auto = set(inp.autocomplete_tokens)
    if "username" in auto:
        return True
    if inp.input_type in {"email", "text"}:
        text = " ".join([inp.name.strip(), inp.id_attr.strip(), inp.aria_label.strip(), inp.placeholder.strip()])
        return any(bool(_USERNAME_NAME_RE.search(part.lower())) for part in text.split())
    return False


def _looks_password(inp: InputRecord) -> bool:
    auto = set(inp.autocomplete_tokens)
    if {"current-password", "new-password"} & auto:
        return True
    if inp.input_type == "password":
        return True
    text = " ".join([inp.name.strip(), inp.id_attr.strip(), inp.aria_label.strip(), inp.placeholder.strip()])
    return any(bool(_PASSWORD_NAME_RE.search(part.lower())) for part in text.split())


def _classify_context(form: FormRecord) -> str:
    text = _text_blob(form)
    low = text.lower()

    if _SIGNUP_RE.search(low):
        return "registration"
    if _RESET_RE.search(low) and not _SIGNIN_RE.search(low):
        return "password_reset_or_change"

    password_inputs = [i for i in form.inputs if _looks_password(i)]
    confirm_inputs = [
        i for i in password_inputs
        if _CONFIRM_RE.search(" ".join([i.name, i.id_attr, i.aria_label, i.placeholder]))
    ]

    if len(password_inputs) >= 2 and confirm_inputs:
        if _SIGNUP_RE.search(low):
            return "registration"
        return "password_change_or_reset"

    if password_inputs and any(_looks_username(i) for i in form.inputs):
        path_low = urlparse(form.page_url).path.lower()
        if _SIGNIN_RE.search(low) or _SIGNIN_RE.search(path_low) or len(password_inputs) == 1:
            return "login"

    # Short field names such as uid/passw are still a login form when a
    # single password input sits next to a visible text input.
    visible_text = [
        i for i in form.inputs
        if i.input_type in {"text", "email", "username"} and not i.hidden
    ]
    if len(password_inputs) == 1 and visible_text:
        path_low = urlparse(form.page_url).path.lower()
        if _SIGNIN_RE.search(low) or _SIGNIN_RE.search(path_low) or form.method.lower() == "post":
            return "login"

    return "ambiguous"


def _candidate_login_form(form: FormRecord) -> bool:
    if form.context == "login":
        return True
    passwords = [i for i in form.inputs if _looks_password(i) and not i.hidden]
    usernames = [i for i in form.inputs if _looks_username(i) and not i.hidden]
    if passwords and usernames and len(passwords) <= 1:
        return True
    visible_text = [
        i for i in form.inputs
        if i.input_type in {"text", "email", "username"} and not i.hidden
    ]
    return bool(len(passwords) == 1 and visible_text)


def _same_origin(base: str, other: str) -> bool:
    a = urlparse(base)
    b = urlparse(other)
    a_port = a.port or (443 if a.scheme == "https" else 80)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme.lower(), a.hostname.lower() if a.hostname else "", a_port) == (
        b.scheme.lower(), b.hostname.lower() if b.hostname else "", b_port
    )


def _static_discovery(
    login_url: str,
    timeout: float = 12.0,
    verify_tls: bool = True,
) -> tuple[str, list[FormRecord], list[str]]:
    try:
        response = requests.get(
            login_url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
            headers={
                "User-Agent": "SecurityAssessmentScanner/1.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
    except requests.exceptions.SSLError:
        response = requests.get(
            login_url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                "User-Agent": "SecurityAssessmentScanner/1.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type and "xhtml" not in content_type:
        return (
            "NON_HTML",
            [],
            [f"Login endpoint returned non-HTML content type: {content_type or 'unknown'}"],
        )

    parser = _StaticParser(response.url)
    parser.feed(response.text[:750_000])
    parser.close()

    forms = parser.forms
    for form in forms:
        form.context = _classify_context(form)
        for inp in form.inputs:
            inp.effective_autocomplete = _effective_autocomplete(
                form.form_autocomplete_raw,
                inp.autocomplete_raw,
            )
            inp.autocomplete_tokens = _token_list(inp.effective_autocomplete)

    return "OK", forms, [f"Static HTTP response: {response.status_code} {response.url}"]


def _browser_discovery(
    login_url: str,
    timeout: float = 12.0,
    verify_tls: bool = True,
) -> tuple[list[FormRecord], list[str]]:
    if sync_playwright is None:
        return [], ["Browser discovery unavailable: Playwright is not installed."]

    forms: list[FormRecord] = []
    evidence: list[str] = []

    import sys
    if sys.platform == "win32":
        try:
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass

    with sync_playwright() as pw:

        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            try:
                page.wait_for_load_state("networkidle", timeout=min(4000, int(timeout * 1000)))
            except Exception:
                pass
            page.wait_for_timeout(600)

            # Inspect every accessible frame, including dynamically generated forms.
            for frame_index, frame in enumerate(page.frames):
                try:
                    frame_url = frame.url or page.url
                    if not frame_url:
                        continue
                    raw_forms = frame.locator("form").all()
                    if not raw_forms:
                        # SPA fallback: synthesize a form-like record from credential inputs.
                        inputs = frame.locator("input").all()
                        candidate_inputs = []
                        for element in inputs:
                            try:
                                candidate_inputs.append({
                                    "name": element.get_attribute("name") or "",
                                    "type": (element.get_attribute("type") or "text").lower(),
                                    "autocomplete": element.get_attribute("autocomplete") or "",
                                    "id": element.get_attribute("id") or "",
                                    "aria": element.get_attribute("aria-label") or "",
                                    "placeholder": element.get_attribute("placeholder") or "",
                                    "hidden": (element.get_attribute("type") or "").lower() == "hidden",
                                })
                            except Exception:
                                continue
                        if candidate_inputs:
                            recs = [
                                InputRecord(
                                    name=x["name"],
                                    input_type=x["type"],
                                    autocomplete_raw=x["autocomplete"],
                                    autocomplete_tokens=_token_list(x["autocomplete"]),
                                    effective_autocomplete=x["autocomplete"],
                                    id_attr=x["id"],
                                    aria_label=x["aria"],
                                    placeholder=x["placeholder"],
                                    hidden=x["hidden"],
                                    source="browser",
                                )
                                for x in candidate_inputs
                            ]
                            synthetic = FormRecord(
                                index=len(forms),
                                action=frame_url,
                                method="POST",
                                form_autocomplete_raw="",
                                form_autocomplete_tokens=[],
                                inputs=recs,
                                page_url=page.url,
                                frame_url=frame_url,
                                source="browser",
                            )
                            synthetic.context = _classify_context(synthetic)
                            for inp in synthetic.inputs:
                                inp.effective_autocomplete = _effective_autocomplete("", inp.autocomplete_raw)
                                inp.autocomplete_tokens = _token_list(inp.effective_autocomplete)
                            if _candidate_login_form(synthetic):
                                forms.append(synthetic)
                        continue

                    for form_index, locator in enumerate(raw_forms):
                        try:
                            action = locator.get_attribute("action") or frame_url
                            action = urljoin(frame_url, action)
                            method = (locator.get_attribute("method") or "get").upper()
                            form_auto = locator.get_attribute("autocomplete") or ""
                            inputs: list[InputRecord] = []
                            for element in locator.locator("input").all():
                                input_auto = element.get_attribute("autocomplete") or ""
                                effective = _effective_autocomplete(form_auto, input_auto)
                                inputs.append(
                                    InputRecord(
                                        name=element.get_attribute("name") or "",
                                        input_type=(element.get_attribute("type") or "text").lower(),
                                        autocomplete_raw=input_auto,
                                        autocomplete_tokens=_token_list(effective),
                                        effective_autocomplete=effective,
                                        id_attr=element.get_attribute("id") or "",
                                        aria_label=element.get_attribute("aria-label") or "",
                                        placeholder=element.get_attribute("placeholder") or "",
                                        hidden=(element.get_attribute("type") or "").lower() == "hidden",
                                        disabled=element.is_disabled(),
                                        readonly=element.is_editable() is False,
                                        source="browser",
                                    )
                                )
                            rec = FormRecord(
                                index=len(forms),
                                action=action,
                                method=method,
                                form_autocomplete_raw=form_auto,
                                form_autocomplete_tokens=_token_list(form_auto),
                                inputs=inputs,
                                page_url=page.url,
                                frame_url=frame_url,
                                source="browser",
                            )
                            rec.context = _classify_context(rec)
                            forms.append(rec)
                        except Exception as exc:
                            evidence.append(f"Browser form {form_index} could not be inspected: {type(exc).__name__}")

                except Exception as exc:
                    evidence.append(f"Frame {frame_index} could not be inspected: {type(exc).__name__}")
        finally:
            browser.close()

    return forms, evidence


def _merge_forms(static_forms: Iterable[FormRecord], browser_forms: Iterable[FormRecord]) -> list[FormRecord]:
    """Keep browser-rendered forms, augmenting with static forms that are not duplicated."""
    merged: list[FormRecord] = []
    signatures: set[tuple[Any, ...]] = set()

    def add(form: FormRecord) -> None:
        sig = (
            form.context,
            form.action,
            tuple((i.name, i.input_type, i.effective_autocomplete) for i in form.inputs),
            form.frame_url,
        )
        if sig not in signatures:
            form.index = len(merged)
            signatures.add(sig)
            merged.append(form)

    # Browser forms first because they represent the actual rendered DOM.
    for item in browser_forms:
        add(item)
    for item in static_forms:
        add(item)
    return merged


def _field_findings(form: FormRecord) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    evidence: list[str] = []

    if form.context != "login":
        return findings, evidence

    for inp in form.inputs:
        tokens = set(inp.autocomplete_tokens)
        is_user = _looks_username(inp)
        is_pass = _looks_password(inp)
        if not (is_user or is_pass):
            continue

        if not inp.name and not inp.id_attr:
            evidence.append(
                f"Credential-like {'password' if is_pass else 'username'} field has no name/id; "
                "autofill semantics may be heuristic."
            )

        if not inp.autocomplete_raw and not form.form_autocomplete_raw:
            findings.append({
                "type": "missing_explicit_autocomplete_token",
                "field": inp.name or inp.id_attr or inp.input_type,
                "severity_candidate": "INFO",
                "message": (
                    "Credential field has no explicit autocomplete token. "
                    "This is not treated as a vulnerability by itself."
                ),
            })

        if is_user and "username" not in tokens:
            if tokens & _UNRELATED_SENSITIVE_TOKENS:
                findings.append({
                    "type": "unrelated_autocomplete_token_on_username",
                    "field": inp.name or inp.id_attr or "username",
                    "severity_candidate": "REVIEW",
                    "message": "Username-like field uses an autocomplete token for unrelated sensitive data.",
                })
            elif tokens and tokens <= {"on", "off"}:
                findings.append({
                    "type": "generic_username_autocomplete",
                    "field": inp.name or inp.id_attr or "username",
                    "severity_candidate": "INFO",
                    "message": "Username field does not use the semantic `username` token.",
                })

        if is_pass:
            if form.context == "login":
                if "new-password" in tokens:
                    findings.append({
                        "type": "new_password_token_on_login",
                        "field": inp.name or inp.id_attr or "password",
                        "severity_candidate": "REVIEW",
                        "message": (
                            "A login password field is marked as `new-password`; "
                            "this is semantically inconsistent with a current credential."
                        ),
                    })
                elif "current-password" in tokens:
                    evidence.append(
                        f"Password field {inp.name or inp.id_attr or '<unnamed>'} uses current-password."
                    )
                elif tokens & _UNRELATED_SENSITIVE_TOKENS:
                    findings.append({
                        "type": "unrelated_autocomplete_token_on_password",
                        "field": inp.name or inp.id_attr or "password",
                        "severity_candidate": "REVIEW",
                        "message": "Password field uses an unrelated sensitive-data autocomplete token.",
                    })
                elif tokens and not tokens & {"on", "off", "username", "current-password", "one-time-code", "webauthn"}:
                    findings.append({
                        "type": "unknown_autocomplete_token_on_password",
                        "field": inp.name or inp.id_attr or "password",
                        "severity_candidate": "REVIEW",
                        "message": "Password field contains an unrecognized autocomplete token.",
                    })

    # Multiple password controls on a form make context classification less certain.
    visible_passwords = [i for i in form.inputs if _looks_password(i) and not i.hidden]
    if len(visible_passwords) > 1:
        findings.append({
            "type": "multiple_visible_password_fields_on_login_form",
            "severity_candidate": "REVIEW",
            "field": "form",
            "message": "More than one visible password-like field was detected on a form classified as login.",
        })

    return findings, evidence


def _classify(findings: list[dict[str, Any]], forms: list[FormRecord], browser_used: bool) -> tuple[str, str, list[str]]:
    evidence: list[str] = []
    for form in forms:
        evidence.append(
            f"Form {form.index}: context={form.context}; source={form.source}; action={form.action}"
        )

    confirmed = [f for f in findings if f.get("confirmed")]
    review = [f for f in findings if f.get("severity_candidate") == "REVIEW"]

    if confirmed:
        return (
            STATUS_CONFIRMED,
            "A security-relevant autocomplete condition was confirmed.",
            evidence,
        )

    if review:
        return (
            STATUS_REVIEW,
            "The login form contains autocomplete configuration that is semantically inconsistent or requires contextual verification; no direct credential exposure was confirmed.",
            evidence,
        )

    if forms:
        return (
            STATUS_SAFE,
            "No security-relevant autocomplete weakness was confirmed on the discovered login form(s).",
            evidence,
        )

    return (
        STATUS_NOT_APPLICABLE,
        "No usable login form was discovered, including the browser-rendered DOM.",
        evidence,
    )



def _candidate_login_urls(
    initial_url: str,
    timeout: float = 8.0,
    limit: int = 8,
    verify_tls: bool = True,
) -> list[str]:
    """Find same-origin login endpoints when the configured /login path is wrong."""
    candidates: list[str] = [initial_url]
    parsed_initial = urlparse(initial_url)
    origin = f"{parsed_initial.scheme}://{parsed_initial.netloc}"
    root_url = origin + "/"
    try:
        try:
            response = requests.get(
                root_url,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
                headers={"User-Agent": "SecurityAssessmentScanner/1.0", "Accept": "text/html"},
            )
        except requests.exceptions.SSLError:
            response = requests.get(
                root_url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "SecurityAssessmentScanner/1.0", "Accept": "text/html"},
            )
        final = urlparse(response.url)
        if final.netloc.lower() == parsed_initial.netloc.lower():
            candidates.append(response.url)
        # Only follow same-origin links whose visible URL/text indicates sign-in.
        from html.parser import HTMLParser

        class _LoginLinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links: list[tuple[str, str]] = []
                self._href = ""
                self._text: list[str] = []

            def handle_starttag(self, tag, attrs):
                if tag.lower() == "a":
                    d = dict(attrs)
                    self._href = d.get("href") or ""
                    self._text = []

            def handle_data(self, data):
                if self._href:
                    self._text.append(data)

            def handle_endtag(self, tag):
                if tag.lower() == "a" and self._href:
                    self.links.append((self._href, " ".join(self._text)))
                    self._href = ""
                    self._text = []

        parser = _LoginLinkParser()
        parser.feed(response.text[:500_000])
        for href, text in parser.links:
            candidate = urljoin(response.url, href)
            parsed = urlparse(candidate)
            hint = f"{parsed.path} {text}".lower()
            if parsed.netloc.lower() != parsed_initial.netloc.lower():
                continue
            if any(token in hint for token in ("login", "sign in", "signin", "log in", "authenticate")):
                candidates.append(candidate)
    except requests.RequestException:
        pass

    for path in ("/login.jsp", "/login.html", "/signin", "/sign-in", "/account/login", "/auth/login"):
        candidates.append(urljoin(origin + "/", path.lstrip("/")))

    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
        if len(unique) >= limit:
            break
    return unique


def scan_autocomplete(
    login_url: str,
    *,
    timeout: float = 12.0,
    use_browser: bool = True,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Run TC01 against the specified login page."""
    try:
        target = _normalize_url(login_url)
    except Exception as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": f"Login URL could not be normalized: {exc}",
            "details": {"error": str(exc)},
            "evidence": [],
        }

    all_evidence: list[str] = []
    static_forms: list[FormRecord] = []
    browser_forms: list[FormRecord] = []

    attempted_urls: list[str] = []
    for candidate_url in _candidate_login_urls(target, timeout=min(timeout, 8.0), verify_tls=verify_tls):
        attempted_urls.append(candidate_url)
        try:
            static_status, candidate_forms, static_evidence = _static_discovery(
                candidate_url,
                timeout=timeout,
                verify_tls=verify_tls,
            )
            all_evidence.extend(static_evidence)
            if candidate_forms:
                static_forms.extend(candidate_forms)
            if static_status == "NON_HTML":
                all_evidence.append(f"Non-HTML login candidate ignored: {candidate_url}")
        except requests.RequestException as exc:
            all_evidence.append(f"Static discovery failed for {candidate_url}: {type(exc).__name__}: {exc}")

        # Browser-rendered discovery is attempted for each likely login endpoint,
        # but bounded by the candidate URL budget.
        if use_browser and not any(_candidate_login_form(f) for f in static_forms):
            try:
                found, browser_evidence = _browser_discovery(
                    candidate_url,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
                browser_forms.extend(found)
                all_evidence.extend(browser_evidence)
            except Exception as exc:
                all_evidence.append(f"Browser discovery failed for {candidate_url}: {type(exc).__name__}: {exc}")
        if any(_candidate_login_form(f) for f in static_forms + browser_forms):
            break

    forms = _merge_forms(static_forms, browser_forms)
    login_forms = [f for f in forms if _candidate_login_form(f)]
    if not login_forms:
        contexts = sorted({f.context for f in forms}) if forms else []
        summary = (
            "No local sign-in form was identified; discovered forms appear to be registration, reset/change-password, or otherwise ambiguous."
            if forms
            else "No usable login form was discovered, including the browser-rendered DOM."
        )
        return {
            "status": STATUS_NOT_APPLICABLE,
            "assessment_state": "NOT_ASSESSED",
            "severity": None,
            "risk_score": None,
            "summary": summary,
            "details": {
                "target": target,
                "candidate_urls_checked": attempted_urls,
                "forms": [f.as_dict() for f in forms],
                "contexts": contexts,
                "browser_discovery_used": bool(use_browser and sync_playwright is not None),
                "operator_note": "If this application uses a custom login path (e.g. /signin, /portal), configure it in Login Page Path.",
            },
            "evidence": all_evidence,
        }


    findings: list[dict[str, Any]] = []
    field_evidence: list[str] = []
    for form in login_forms:
        form_findings, form_evidence = _field_findings(form)
        findings.extend(form_findings)
        field_evidence.extend(form_evidence)

    all_evidence.extend(field_evidence)

    status, summary, classifier_evidence = _classify(
        findings,
        login_forms,
        bool(use_browser and sync_playwright is not None),
    )
    all_evidence.extend(classifier_evidence)

    # Never claim a confirmed vulnerability from generic `autocomplete=on`,
    # missing attributes, or `autocomplete=off` alone. Those are informational
    # or contextual observations only in modern browser environments.
    severity = None
    risk_score = None
    assessment_state = {
        STATUS_CONFIRMED: "CONFIRMED",
        STATUS_SAFE: "NOT_A_FINDING",
        STATUS_REVIEW: "REVIEW_REQUIRED",
        STATUS_INCOMPLETE: "INCOMPLETE",
        STATUS_NOT_APPLICABLE: "NOT_ASSESSED",
    }.get(status, "REVIEW_REQUIRED")

    return {
        "status": status,
        "assessment_state": assessment_state,
        "severity": severity,
        "risk_score": risk_score,
        "summary": summary,
        "details": {
            "target": target,
            "candidate_urls_checked": attempted_urls,
            "browser_discovery_available": sync_playwright is not None,
            "browser_discovery_used": bool(use_browser and sync_playwright is not None),
            "forms_analyzed": len(forms),
            "login_forms_analyzed": len(login_forms),
            "forms": [f.as_dict() for f in forms],
            "login_form_findings": findings,
            "scope_boundaries": [
                "TC01 evaluates autocomplete metadata and effective credential autofill semantics.",
                "Browser memory persistence belongs to TC07.",
                "Remember-me persistence belongs to TC10.",
                "Transport/cipher security belongs to TC08/TC09.",
                "Password validation belongs to TC05.",
            ],
        },
        "evidence": all_evidence,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TC01 Autocomplete scanner")
    parser.add_argument("url")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    result = scan_autocomplete(args.url, use_browser=not args.no_browser)
    print(json.dumps(result, indent=2, default=str))
