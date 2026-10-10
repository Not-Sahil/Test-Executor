from __future__ import annotations

import time
from dataclasses import dataclass

import requests


RATE_LIMIT_STATUS_CODES = {420, 423, 429}
RATE_LIMIT_MARKERS = (
    "too many requests",
    "rate limit",
    "rate-limit",
    "temporarily blocked",
    "try again later",
    "slow down",
    "request limit",
    "account locked",
    "account lock",
    "locked out",
    "captcha required",
)


def is_rate_limited_response(response: requests.Response | None) -> bool:
    if response is None:
        return False
    if response.status_code in RATE_LIMIT_STATUS_CODES:
        return True
    body = ""
    try:
        body = response.text[:8000].lower()
    except Exception:
        pass
    return any(marker in body for marker in RATE_LIMIT_MARKERS)


@dataclass
class LockoutGuard:
    max_attempts: int = 10
    min_delay_seconds: float = 0.5

    def __post_init__(self) -> None:
        self.max_attempts = max(1, int(self.max_attempts))
        self.min_delay_seconds = max(0.0, float(self.min_delay_seconds))
        self.attempts = 0
        self._last_request_at = 0.0

    def can_attempt(self) -> bool:
        return self.attempts < self.max_attempts

    def before_attempt(self) -> bool:
        if not self.can_attempt():
            return False
        now = time.monotonic()
        wait = self.min_delay_seconds - (now - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        self.attempts += 1
        self._last_request_at = time.monotonic()
        return True
