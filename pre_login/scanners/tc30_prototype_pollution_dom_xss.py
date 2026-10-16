"""TC30 - Prototype Pollution Leading to DOM-Based XSS Scanner.

Investigates whether attacker-controlled input can cause client-side prototype pollution
and whether that pollution reaches a dangerous DOM sink, distinguishing prototype pollution
from demonstrable DOM-based XSS exploit chains.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from core.http_client import effective_verify_tls
from core.sqli_engine import (
    STATUS_ERROR,
    STATUS_INCOMPLETE,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
)
from payloads.manager import load_json_records, is_exhaustive_mode

# Unsafe merge/assignment patterns in JS
UNSAFE_MERGE_PATTERNS = [
    (re.compile(r"(?:target|dest)\[(?:key|prop|attr)\]\s*=\s*(?:source|src)\[(?:key|prop|attr)\]"), "recursive_property_assignment"),
    (re.compile(r"\$\.extend\s*\(\s*true\s*,"), "jquery_deep_extend"),
    (re.compile(r"(?:merge|clone|defaults|deepCopy)\s*\([^)]+\)"), "generic_object_merge"),
    (re.compile(r"(?:Object\.prototype|__proto__|constructor\.prototype)"), "prototype_property_reference"),
]

# Dangerous DOM sinks that can execute script if receiving untrusted properties
DOM_SINKS = [
    (re.compile(r"\.innerHTML\s*="), "innerHTML"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML"),
    (re.compile(r"document\.write(?:ln)?\s*\("), "document.write"),
    (re.compile(r"\beval\s*\("), "eval"),
    (re.compile(r"\bFunction\s*\("), "Function"),
    (re.compile(r"(?:window\.)?setTimeout\s*\(\s*['\"][^'\"]+"), "setTimeout_string"),
    (re.compile(r"\.src\s*=\s*(?:script|iframe)"), "script_or_iframe_src"),
]


def _load_pp_scenarios() -> list[dict[str, Any]]:
    return load_json_records(
        "payloads_all_the_things/prototype_pollution/dom_xss_scenarios.json",
        limit=None,
    )


def scan_prototype_pollution_dom_xss(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 8.0,
    check_browser: bool = True,
) -> dict[str, Any]:
    """Execute Prototype Pollution and DOM-Based XSS assessment."""
    target_url = url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    verify_tls, _ = effective_verify_tls(target_url, verify_tls)
    session = requests.Session()
    headers = {"User-Agent": "SecurityAssessmentTestExecutor-TC30/1.0"}

    try:
        resp = session.get(target_url, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
    except Exception as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": f"Could not connect to {target_url} to assess client-side scripts: {exc}",
            "evidence": [f"Connection error: {exc}"],
            "details": {"url": target_url, "error": str(exc)},
        }

    html_content = resp.text or ""

    # 1. Collect inline and external script contents
    scripts: list[str] = []
    # Inline scripts
    inline_scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html_content, flags=re.DOTALL | re.IGNORECASE)
    scripts.extend(inline_scripts)

    # External scripts (fetch up to 3 first-party / relative scripts)
    ext_srcs = re.findall(r'<script\b[^>]*src=["\']([^"\']+)["\']', html_content, flags=re.IGNORECASE)
    p_orig = urlsplit(target_url)
    for src in ext_srcs[:3]:
        full_src = urljoin(target_url, src)
        p_src = urlsplit(full_src)
        if p_src.netloc == p_orig.netloc:
            try:
                r_js = session.get(full_src, headers=headers, timeout=5.0, verify=verify_tls)
                if r_js.status_code == 200 and r_js.text:
                    scripts.append(r_js.text[:50000])
            except Exception:
                pass

    # 2. Static Analysis: search for unsafe merge patterns and DOM sinks
    found_merge_patterns: list[str] = []
    found_dom_sinks: list[str] = []

    combined_js = "\n".join(scripts)
    for rx, name in UNSAFE_MERGE_PATTERNS:
        if rx.search(combined_js):
            found_merge_patterns.append(name)

    for rx, name in DOM_SINKS:
        if rx.search(combined_js):
            found_dom_sinks.append(name)

    # 3. Dynamic Canary Evaluation with Playwright (if available)
    canary_property = "tc_canary_pp_probe"
    canary_value = "canary_val_active_probe"
    pp_confirmed = False
    xss_confirmed = False
    browser_tested = False
    browser_error = ""

    if check_browser:
        try:
            from playwright.sync_api import sync_playwright
            test_target = (
                f"{target_url}{'&' if '?' in target_url else '?'}__proto__[{canary_property}]={canary_value}"
            )
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(ignore_https_errors=not verify_tls)
                page.goto(test_target, timeout=int(timeout * 1000), wait_until="domcontentloaded")
                # Check if Object.prototype was polluted
                polluted_val = page.evaluate(f"window.Object.prototype['{canary_property}']")
                if polluted_val == canary_value:
                    pp_confirmed = True
                    # Check if polluted value reached DOM (innerHTML or sink)
                    body_html = page.content()
                    if canary_value in body_html:
                        xss_confirmed = True
                browser.close()
                browser_tested = True
        except Exception as exc:
            browser_error = str(exc)

    evidence: list[str] = []
    details = {
        "target": target_url,
        "scripts_analyzed": len(scripts),
        "unsafe_merge_patterns": found_merge_patterns,
        "dom_sinks": found_dom_sinks,
        "browser_tested": browser_tested,
        "browser_error": browser_error,
        "prototype_pollution_confirmed": pp_confirmed,
        "dom_xss_confirmed": xss_confirmed,
    }

    # Classification logic based on requirements
    if xss_confirmed:
        evidence.append(
            f"Prototype pollution verified on window.Object.prototype['{canary_property}']. "
            f"Polluted canary flowed directly into rendered DOM."
        )
        return {
            "status": STATUS_UNSAFE,
            "summary": (
                f"Prototype Pollution Leading to DOM-Based XSS Confirmed on {target_url}: "
                f"attacker-controlled property successfully polluted Object.prototype and reached an active DOM sink."
            ),
            "evidence": evidence,
            "details": details,
        }

    if pp_confirmed:
        evidence.append(
            f"Object.prototype['{canary_property}'] was polluted via URL query parameters, "
            f"but script execution / DOM sink flow was not confirmed."
        )
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Prototype Pollution Detected on {target_url}: attacker-controlled input successfully polluted Object.prototype, "
                f"but an active DOM-based XSS exploit chain was not demonstrated."
            ),
            "evidence": evidence,
            "details": details,
        }

    if found_merge_patterns and found_dom_sinks:
        evidence.append(
            f"Static script analysis identified unsafe object manipulation ({', '.join(found_merge_patterns)}) "
            f"and dangerous DOM sinks ({', '.join(found_dom_sinks)})."
        )
        return {
            "status": STATUS_REVIEW,
            "summary": (
                f"Potential Prototype Pollution and DOM Sink Exploit Chain Identified on {target_url}: "
                f"client-side code contains unsafe property merging alongside dangerous DOM sinks ({', '.join(found_dom_sinks)})."
            ),
            "evidence": evidence,
            "details": details,
        }

    if found_merge_patterns or found_dom_sinks:
        if found_dom_sinks:
            evidence.append(f"DOM sink risk identified ({', '.join(found_dom_sinks)}), but no unsafe prototype pollution merge pattern found.")
        else:
            evidence.append(f"Object merge pattern identified ({', '.join(found_merge_patterns)}), but no dangerous DOM sink identified.")
        return {
            "status": STATUS_REVIEW,
            "summary": f"Client-side inspection identified potential DOM sink or property handling patterns that warrant manual review.",
            "evidence": evidence,
            "details": details,
        }

    return {
        "status": STATUS_SAFE,
        "summary": "No prototype pollution patterns or dangerous DOM sinks were identified in client-side scripts.",
        "evidence": [f"Analyzed {len(scripts)} script block(s); no prototype pollution sources or exploitable DOM sinks detected."],
        "details": details,
    }
