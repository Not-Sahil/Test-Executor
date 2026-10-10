from __future__ import annotations

import re
from urllib.parse import urljoin

import requests


ADMIN_MARKERS = (
    "admin panel",
    "administration",
    "administrator",
    "system settings",
    "user management",
    "manage users",
    "/admin",
)
OPERATOR_MARKERS = (
    "operator",
    "moderator",
    "management",
    "manage",
)
STANDARD_MARKERS = (
    "my account",
    "profile",
    "dashboard",
    "settings",
)


def infer_privilege(response: requests.Response | None) -> str:
    if response is None:
        return "unknown"
    try:
        body = response.text[:20000].lower()
    except Exception:
        body = ""
    path = response.url.lower()
    if any(marker in body or marker in path for marker in ADMIN_MARKERS):
        return "admin"
    if any(marker in body or marker in path for marker in OPERATOR_MARKERS):
        return "operator"
    if any(marker in body or marker in path for marker in STANDARD_MARKERS):
        return "standard"
    return "unknown"


def determine_privilege(
    session: requests.Session,
    base_url: str,
    protected_urls: tuple[str, ...],
    timeout: float = 6.0,
) -> tuple[str, list[str]]:
    """Use only operator-configured protected URLs; never crawl post-auth content."""
    evidence: list[str] = []
    best = "unknown"
    rank = {"unknown": 0, "standard": 1, "operator": 2, "admin": 3}

    for target in protected_urls:
        url = urljoin(base_url.rstrip("/") + "/", target.lstrip("/"))
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            evidence.append(f"privilege probe failed for {url}: {exc}")
            continue

        inferred = infer_privilege(response)
        evidence.append(f"privilege probe {url}: status={response.status_code} inferred={inferred}")
        if rank[inferred] > rank[best]:
            best = inferred

    return best, evidence
