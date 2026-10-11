from __future__ import annotations
"""TC11 - Shoulder Surfing / password visual exposure assessment.

Additive scanner. Uses passive HTTP plus an optional Playwright browser lane.
No real credentials are accepted or submitted. A synthetic marker is used to
exercise password reveal controls safely.
"""
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import urljoin, urlparse
import requests

try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_ASSESSED = "NOT ASSESSED"

PASSWORD_RE = re.compile(r"password|passwd|pwd|passcode|secret", re.I)
OTP_RE = re.compile(r"otp|one.?time|verification.?code|security.?code|auth.?code", re.I)
PIN_RE = re.compile(r"(^|[-_ ]|\b)pin($|[-_ ]|\b)", re.I)
CONFIRM_RE = re.compile(r"confirm|confirmation|repeat|retype|again", re.I)
REVEAL_RE = re.compile(r"show|hide|reveal|view|display|visible|visibility|password", re.I)

@dataclass
class PasswordField:
    selector: str
    name: str
    field_id: str
    input_type: str
    autocomplete: str
    aria_label: str
    placeholder: str
    form_action: str
    source_url: str
    likely_role: str
    def as_dict(self): return asdict(self)

class PasswordFieldParser(HTMLParser):
    def __init__(self, source_url):
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.form_action = source_url
        self.fields = []
    def handle_starttag(self, tag, attrs):
        d = {str(k).lower(): (v or "") for k,v in attrs}
        if tag.lower() == "form":
            self.form_action = urljoin(self.source_url, d.get("action") or self.source_url)
        if tag.lower() != "input": return
        typ = d.get("type", "text").lower()
        name, fid = d.get("name", ""), d.get("id", "")
        ac, aria, ph = d.get("autocomplete", "").lower(), d.get("aria-label", ""), d.get("placeholder", "")
        semantic = " ".join((name,fid,ac,aria,ph))
        if not (typ == "password" or PASSWORD_RE.search(semantic) or OTP_RE.search(semantic) or PIN_RE.search(semantic)): return
        role = classify_secret_field(name,fid,ac,aria,ph)
        selector = f"#{fid}" if fid else (f'input[name="{name}"]' if name else "input[type=password]")
        self.fields.append(PasswordField(selector,name,fid,typ,ac,aria,ph,self.form_action,self.source_url,role))

def classify_secret_field(name="", field_id="", autocomplete="", aria_label="", placeholder=""):
    text = " ".join((name,field_id,autocomplete,aria_label,placeholder))
    if OTP_RE.search(text): return "otp"
    if PIN_RE.search(text): return "pin"
    if CONFIRM_RE.search(text): return "password_confirmation"
    if PASSWORD_RE.search(text) or autocomplete == "current-password": return "password"
    return "secret_like"

def _target(url):
    if not url.strip(): raise ValueError("target URL is empty")
    if "://" not in url: url = "https://" + url
    p = urlparse(url.strip())
    if p.scheme not in ("http","https") or not p.netloc: raise ValueError("invalid HTTP(S) target")
    return p._replace(fragment="").geturl()

def _fetch(target, login_path, timeout, verify_tls):
    from authentication.auth_discovery import login_page_candidates
    base = _target(target)
    last_error = None
    last = None
    for url in login_page_candidates(base, login_path or "/login"):
        try:
            r = requests.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True,
                             headers={"User-Agent":"TestExecutor-TC11/1.0","Accept":"text/html,application/xhtml+xml,*/*;q=0.8"})
            if r.status_code < 500 and ("password" in (r.text or "").lower() or "type=\"password\"" in (r.text or "").lower()):
                return r, [f"status={r.status_code}", f"url={r.url}"]
            last = r
        except requests.RequestException as e:
            last_error = e
            last = None
    if last_error and last is None:
        return None, [f"request_error={type(last_error).__name__}:{last_error}"]
    if last is not None:
        return last, [f"status={last.status_code}", f"url={last.url}"]
    return None, ["login_page_unreached"]

def _auth_block(html, url):
    s = ((html or "") + " " + (url or "")).lower()
    if any(x in s for x in ("recaptcha","hcaptcha","turnstile","captcha")): return "captcha_detected"
    if any(x in s for x in ("oauth","openid","oidc","saml","accounts.google.com","login.microsoftonline.com")): return "federated_or_external_auth_detected"
    return None

def _result(target,status,summary,evidence,details):
    state = {STATUS_UNSAFE:"CONFIRMED",STATUS_SAFE:"NOT_A_FINDING",STATUS_REVIEW:"REVIEW_REQUIRED",STATUS_INCOMPLETE:"INCOMPLETE",STATUS_NOT_ASSESSED:"NOT_ASSESSED"}.get(status,"REVIEW_REQUIRED")
    return {"key":"login.tc11_shoulder_surfing","name":"Shoulder Surfing","status":status,"assessment_state":state,"severity":None,"risk_score":None,"summary":summary,"evidence":evidence,"details":details,"target":target}

def _browser(target, login_path, timeout_ms, verify_tls, marker, screenshot=False):
    if sync_playwright is None:
        return {"status": STATUS_REVIEW, "reason": "playwright_unavailable", "evidence": ["browser_lane_unavailable"]}
    base = _target(target)
    from authentication.auth_discovery import login_page_candidates
    candidates = login_page_candidates(base, login_path or "/login")
    login_url = candidates[0] if candidates else urljoin(base.rstrip("/") + "/", (login_path or "/login").lstrip("/"))
    evidence = []
    findings = []
    fields = []
    shots = []
    import sys
    if sys.platform == "win32":
        try:
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass
    try:
        with sync_playwright() as pw:


            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=not verify_tls, viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            try:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                page.wait_for_timeout(300)
                for fi, frame in enumerate(page.frames):
                    loc = frame.locator("input,textarea")
                    for i in range(min(loc.count(), 100)):
                        el = loc.nth(i)
                        try:
                            typ = (el.get_attribute("type") or "text").lower()
                            name = el.get_attribute("name") or ""
                            fid = el.get_attribute("id") or ""
                            aria = el.get_attribute("aria-label") or ""
                            ph = el.get_attribute("placeholder") or ""
                            ac = (el.get_attribute("autocomplete") or "").lower()
                            semantic = " ".join((name, fid, aria, ph, ac))
                            if not (typ == "password" or PASSWORD_RE.search(semantic) or OTP_RE.search(semantic) or PIN_RE.search(semantic)):
                                continue
                            role = classify_secret_field(name, fid, ac, aria, ph)
                            fields.append({"frame": fi, "name": name, "id": fid, "type": typ, "role": role, "visible": el.is_visible()})
                            if role != "password":
                                continue
                            if typ != "password":
                                findings.append({"code": "PASSWORD_NOT_MASKED", "message": "Password-like field is not masked by default."})
                            try:
                                el.fill(marker)
                            except Exception:
                                continue
                            controls = frame.locator("button,[role=button],input[type=button],label")
                            for j in range(min(controls.count(), 150)):
                                c = controls.nth(j)
                                try:
                                    text = " ".join((c.inner_text(timeout=200), c.get_attribute("aria-label") or "", c.get_attribute("title") or "", c.get_attribute("id") or "", c.get_attribute("name") or ""))
                                    if not REVEAL_RE.search(text):
                                        continue
                                    before = (el.get_attribute("type") or "").lower()
                                    c.click(timeout=700)
                                    frame.wait_for_timeout(80)
                                    after = (el.get_attribute("type") or "").lower()
                                    if after == "text":
                                        evidence.append("password_reveal_control_confirmed")
                                        try:
                                            c.click(timeout=700)
                                            frame.wait_for_timeout(80)
                                        except Exception:
                                            pass
                                        restored = (el.get_attribute("type") or "").lower()
                                        if restored != "password":
                                            findings.append({"code": "PASSWORD_MASK_NOT_RESTORED", "message": "Reveal interaction did not restore password masking."})
                                    elif before != "password":
                                        findings.append({"code": "PASSWORD_NOT_MASKED", "message": "Password was not masked before reveal interaction."})
                                except Exception:
                                    continue
                            if screenshot and el.is_visible():
                                p = f"/tmp/tc11_{fi}_{i}.png"
                                try:
                                    page.screenshot(path=p, full_page=False)
                                    shots.append(p)
                                except Exception:
                                    pass
                        except Exception:
                            continue
                # Test for accidental reflection of only the synthetic marker.
                if marker in page.url:
                    findings.append({"code": "PASSWORD_VALUE_REFLECTED_IN_URL", "message": "Synthetic password marker appeared in URL."})
                try:
                    body = page.locator("body").inner_text(timeout=800)
                except Exception:
                    body = ""
                if marker in body:
                    findings.append({"code": "PASSWORD_VALUE_REFLECTED_IN_VISIBLE_DOM", "message": "Synthetic password marker appeared in visible DOM text."})
                fresh = ctx.new_page()
                fresh.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                fresh.wait_for_timeout(150)
                for i in range(min(fresh.locator("input").count(), 100)):
                    try:
                        e = fresh.locator("input").nth(i)
                        typ = (e.get_attribute("type") or "text").lower()
                        sem = " ".join((e.get_attribute("name") or "", e.get_attribute("id") or "", e.get_attribute("aria-label") or "", e.get_attribute("placeholder") or ""))
                        if PASSWORD_RE.search(sem) and typ != "password":
                            findings.append({"code": "PASSWORD_EXPOSED_BY_DEFAULT", "message": "Fresh page contains an unmasked password-like field."})
                    except Exception:
                        pass
                fresh.close()
                high = {"PASSWORD_NOT_MASKED", "PASSWORD_EXPOSED_BY_DEFAULT", "PASSWORD_VALUE_REFLECTED_IN_URL", "PASSWORD_VALUE_REFLECTED_IN_VISIBLE_DOM"}
                if any(x.get("code") in high for x in findings):
                    status, reason = STATUS_UNSAFE, "A concrete password-visibility exposure condition was confirmed."
                elif any(x.get("code") == "PASSWORD_MASK_NOT_RESTORED" for x in findings):
                    status, reason = STATUS_REVIEW, "Password masking was not reliably restored after reveal."
                elif fields:
                    status, reason = STATUS_SAFE, "Password-like login fields were masked by default; no concrete shoulder-surfing exposure was confirmed."
                else:
                    status, reason = STATUS_NOT_ASSESSED, "No password-like login field was identified."
                return {"status": status, "reason": reason, "evidence": evidence, "fields": fields, "findings": findings, "screenshots": shots}
            except Exception as e:
                return {"status": STATUS_NOT_ASSESSED if not fields else STATUS_REVIEW, "reason": f"browser_exception:{type(e).__name__}", "evidence": [f"browser_error={type(e).__name__}:{e}"], "fields": fields, "findings": findings, "screenshots": shots}
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as exc:
        return {"status": STATUS_NOT_ASSESSED, "reason": f"browser_launch_exception:{type(exc).__name__}", "evidence": [f"browser_error={type(exc).__name__}:{exc}"], "fields": [], "findings": [], "screenshots": []}

def scan_shoulder_surfing(target, *, login_path="/login", timeout=10.0, timeout_ms=15000, verify_tls=True, allow_browser=True, capture_screenshot=False, synthetic_marker="TC11_SYNTHETIC_PASSWORD_7F3A"):
    try:
        normalized = _target(target)
    except Exception as e:
        return _result(target, STATUS_INCOMPLETE, "TC11 could not normalize the target URL.", [f"{type(e).__name__}:{e}"], {})
    r, evidence = _fetch(normalized, login_path, timeout, verify_tls)
    if r is None:
        return _result(normalized, STATUS_NOT_ASSESSED, "TC11 could not reach the login page or no login candidate was found.", evidence, {})
    block = _auth_block(r.text, r.url)
    parser = PasswordFieldParser(r.url)
    try:
        parser.feed(r.text or "")
        parser.close()
    except Exception:
        pass
    static = [f.as_dict() for f in parser.fields]
    if block == "federated_or_external_auth_detected":
        return _result(normalized, STATUS_NOT_ASSESSED, "Federated/external authentication was detected.", evidence + [block], {"static_fields": static})
    if block == "captcha_detected":
        return _result(normalized, STATUS_REVIEW, "CAPTCHA was detected; the scanner does not bypass it.", evidence + [block], {"static_fields": static, "captcha_bypass": False})
    details = {"static_fields": static, "browser_available": sync_playwright is not None, "browser_lane_used": False, "synthetic_marker_used": True, "scope_boundaries": ["TC11 assesses password visual masking/UI exposure.", "TC01 assesses autocomplete.", "TC07 assesses browser memory exposure.", "TC10 assesses Remember Me/session persistence.", "TC11 never accepts or stores real credentials."]}
    if allow_browser and sync_playwright is not None:
        try:
            br = _browser(normalized, login_path, timeout_ms, verify_tls, synthetic_marker, capture_screenshot)
            details["browser_lane_used"] = True
            details["browser_lane"] = {k: v for k, v in br.items()}
            return _result(normalized, br["status"], br["reason"], evidence + br.get("evidence", []), details)
        except Exception as exc:
            evidence.append(f"browser_error={type(exc).__name__}:{exc}")
            details["browser_error"] = str(exc)
    if any(f.input_type != "password" and f.likely_role == "password" for f in parser.fields):
        return _result(normalized, STATUS_UNSAFE, "A password-like field is statically rendered without masking.", evidence + ["static_password_field_not_masked"], details)
    if parser.fields:
        return _result(normalized, STATUS_REVIEW, "Password fields were found, but browser interaction is required for full assessment.", evidence + ["browser_lane_not_used"], details)
    return _result(normalized, STATUS_NOT_ASSESSED, "No password-like login field was identified.", evidence + ["no_password_like_field_detected"], details)


scan=scan_shoulder_surfing
