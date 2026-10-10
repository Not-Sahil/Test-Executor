from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from .evidence import safe_url
from .models import AuthMechanism, CredentialCandidate


@dataclass(frozen=True)
class AuthResponse:
    response: requests.Response | None
    final_url: str = ""
    error: str = ""


def create_session(verify_tls: bool = True) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({
        "User-Agent": "CareerSecurityScanner/AuthClient/2.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
    })
    return session


def submit_credentials(
    session: requests.Session,
    mechanism: AuthMechanism,
    credential: CredentialCandidate,
    timeout: float = 8.0,
    allow_redirects: bool = True,
) -> AuthResponse:
    try:
        if mechanism.type == "http_basic":
            response = session.get(
                mechanism.endpoint,
                auth=(credential.username, credential.password),
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
        elif mechanism.type == "json_api":
            payload: dict[str, Any] = dict(mechanism.extra_fields)
            payload[mechanism.username_field or "email"] = credential.username
            payload[mechanism.password_field or "password"] = credential.password
            response = session.request(
                mechanism.method,
                mechanism.endpoint,
                json=payload,
                timeout=timeout,
                allow_redirects=allow_redirects,
                headers={"Content-Type": "application/json"},
            )
        elif mechanism.type == "html_form":
            payload = dict(mechanism.extra_fields)
            payload[mechanism.username_field or "username"] = credential.username
            payload[mechanism.password_field or "password"] = credential.password
            response = session.request(
                mechanism.method,
                mechanism.endpoint,
                data=payload,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )
        else:
            return AuthResponse(None, error=f"unsupported_auth_mechanism:{mechanism.type}")

        return AuthResponse(response=response, final_url=safe_url(response.url))
    except requests.RequestException as exc:
        return AuthResponse(None, error=str(exc))
