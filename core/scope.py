"""Centralized Scope Enforcement Module.

Ensures that active security testing is strictly confined to explicitly authorized
origins and hosts. Discovered origins (such as external Identity Providers,
third-party CDNs, and redirect targets) are tracked as discovery evidence but
remain untested unless explicitly in-scope.
"""
from __future__ import annotations

from typing import Iterable, Set
from urllib.parse import urlparse

from core.models import ScopeStatus
from core.target_policy import TargetPolicy, validate_target_url


def normalize_origin(url_or_origin: str) -> str:
    """Extract and normalize scheme://hostname[:port] from any URL or origin string.

    Canonicalizes default ports (80 for http, 443 for https) and lowercases hostname.
    """
    raw = (url_or_origin or "").strip()
    if not raw:
        raise ValueError("Cannot normalize an empty URL or origin.")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError(f"URL '{url_or_origin}' has no valid hostname.")

    port = parsed.port
    is_default_port = (scheme == "http" and port in (None, 80)) or (scheme == "https" and port in (None, 443))
    
    if is_default_port or port is None:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def extract_hostname(url_or_origin: str) -> str:
    """Extract normalized hostname from URL or origin."""
    raw = (url_or_origin or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return (urlparse(raw).hostname or "").lower().rstrip(".")


class ScopeValidator:
    """Validates whether candidate targets, URLs, and origins are permitted for active testing."""

    def __init__(
        self,
        primary_target: str,
        additional_in_scope_origins: Iterable[str] | None = None,
        allow_subdomains: bool = False,
        policy: TargetPolicy | None = None,
    ) -> None:
        self.policy = policy or TargetPolicy.from_environment()
        self.primary_origin = normalize_origin(primary_target)
        self.primary_host = extract_hostname(self.primary_origin)
        self.allow_subdomains = allow_subdomains

        self.allowed_origins: Set[str] = {self.primary_origin}

        if additional_in_scope_origins:
            for extra in additional_in_scope_origins:
                extra_clean = (extra or "").strip()
                if not extra_clean:
                    continue
                try:
                    norm = normalize_origin(extra_clean)
                    self.allowed_origins.add(norm)
                except Exception:
                    continue

    def is_in_scope(self, url_or_origin: str) -> bool:
        """Return True if the target URL or origin is authorized for active testing."""
        status, _ = self.validate_scope(url_or_origin)
        return status == ScopeStatus.IN_SCOPE

    def validate_scope(self, url_or_origin: str) -> tuple[ScopeStatus, str]:
        """Perform strict scope validation.

        Returns (ScopeStatus, reason_message).
        """
        raw = (url_or_origin or "").strip()
        if not raw:
            return ScopeStatus.OUT_OF_SCOPE, "Target is empty."

        try:
            target_norm = normalize_origin(raw)
            target_host = extract_hostname(target_norm)
        except Exception as exc:
            return ScopeStatus.OUT_OF_SCOPE, f"Target could not be parsed: {exc}"

        # 1. Exact origin match (scheme, host, port must match)
        if target_norm in self.allowed_origins:
            return ScopeStatus.IN_SCOPE, "Target origin is explicitly authorized."

        # 2. Strict subdomain check if explicitly allowed
        if self.allow_subdomains:
            target_parsed = urlparse(target_norm)
            target_port = target_parsed.port or (443 if target_parsed.scheme == "https" else 80)
            primary_parsed = urlparse(self.primary_origin)
            primary_port = primary_parsed.port or (443 if primary_parsed.scheme == "https" else 80)

            # Subdomain must be a strict sub-domain of primary_host with dot separator
            # (Prevents attacker-example.com or example.com.attacker.com)
            if target_host != self.primary_host and target_host.endswith("." + self.primary_host):
                if target_parsed.scheme == primary_parsed.scheme and target_port == primary_port:
                    return ScopeStatus.IN_SCOPE, f"Subdomain '{target_host}' is permitted under base domain '{self.primary_host}'."

        return ScopeStatus.OUT_OF_SCOPE, (
            f"Origin '{target_norm}' is not authorized. Scans must not test "
            "unauthorized origins, external identity providers, or third parties."
        )

    def assert_in_scope(self, url_or_origin: str) -> None:
        """Raise ValueError if the target is not in authorized scope."""
        status, reason = self.validate_scope(url_or_origin)
        if status != ScopeStatus.IN_SCOPE:
            raise ValueError(f"Scope Violation: {reason}")
