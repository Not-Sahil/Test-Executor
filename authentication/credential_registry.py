from __future__ import annotations

import json
from pathlib import Path

from .models import CredentialCandidate


SUPPORTED_SOURCES = {
    "operator_supplied",
    "product_default",
    "application_default",
    "organization_default",
    "blank_password",
    "lab_profile",
}


def load_authorized_credentials(
    path: str | Path,
    *,
    allow_lab_profile: bool = False,
) -> list[CredentialCandidate]:
    """Load only explicitly authorized credentials. The registry is canonical; no defaults are injected silently."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("credentials.json must contain a top-level array")

    output: list[CredentialCandidate] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"credential entry {index} must be an object")
        username = str(item.get("username", "")).strip()
        if not username:
            continue
        password = str(item.get("password", ""))
        source = str(item.get("credential_source") or item.get("credential_type") or "operator_supplied").strip().lower()
        product_hint = str(item.get("product_hint")).strip().lower() if item.get("product_hint") else None
        account_hint = str(item.get("account_hint")).strip() if item.get("account_hint") else None

        if source not in SUPPORTED_SOURCES:
            raise ValueError(
                f"credential entry {index}: unsupported credential_source={source!r}; "
                f"expected one of {sorted(SUPPORTED_SOURCES)}"
            )
        if source == "lab_profile" and not allow_lab_profile:
            continue
        if password == "" and source == "operator_supplied":
            # Make blank-password origin explicit so downstream reporting is unambiguous.
            source = "blank_password"

        key = (username, password, source, product_hint)
        if key in seen:
            continue
        seen.add(key)
        output.append(CredentialCandidate(username, password, source, product_hint, account_hint))

    return output


def filter_credentials_by_product(
    candidates: list[CredentialCandidate],
    product_hint: str | None,
) -> list[CredentialCandidate]:
    if not product_hint:
        return list(candidates)
    hint = product_hint.strip().lower()
    narrowed = [
        candidate
        for candidate in candidates
        if candidate.product_hint in {None, "", hint}
    ]
    return narrowed
