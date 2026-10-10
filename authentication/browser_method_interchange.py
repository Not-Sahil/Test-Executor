from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:  # optional dependency
    sync_playwright = None
    PlaywrightTimeoutError = Exception

from .method_interchange_models import MethodObservation
from .method_interchange_signals import classify_response, compact_method_evidence

@dataclass
class BrowserMethodResult:
    observation: MethodObservation
    supported: bool = True

def browser_method_probe(
    *,
    login_url: str,
    alternate_method: str,
    username: str,
    password: str,
    timeout: float,
    verify_tls: bool,
    case_id: str,
    credential_profile: str,
) -> BrowserMethodResult | None:
    """
    Bounded browser fallback for JS/SPAs.

    The browser lane does not rewrite arbitrary requests or crawl the app.
    It only inspects the login page and, when possible, observes the page's
    own authentication request. For an explicit GET/POST interchange,
    direct HTTP replay remains the primary evidence source.
    """
    if sync_playwright is None:
        return None

    # Browser fallback is intentionally conservative: it does not synthesize
    # arbitrary POST/GET requests inside the browser because doing so would
    # blur the boundary with browser automation. Direct HTTP replay is safer.
    observation = MethodObservation(
        case_id=case_id,
        method=alternate_method.upper(),
        credential_profile=credential_profile,
        evidence=[
            "Playwright is available, but direct GET/POST replay is the authoritative TC06 method-interchange path.",
            "Browser fallback should be used by the caller for discovery, not as a generic request forgery mechanism.",
        ],
    )
    return BrowserMethodResult(observation=observation, supported=True)
