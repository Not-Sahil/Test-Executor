from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin

import requests

from .method_interchange_models import MethodObservation
from .method_interchange_signals import (
    compact_method_evidence,
    classify_response,
    infer_auth_cookies,
)

@dataclass(frozen=True)
class DiscoveredLogin:
    page_url: str
    action_url: str
    method: str
    username_field: str
    password_field: str
    hidden_fields: dict[str, str]
    mechanism: str
    content_type: str = "application/x-www-form-urlencoded"

class MethodInterchangeClient:
    def __init__(
        self,
        *,
        timeout: float = 8.0,
        verify_tls: bool = True,
        auth_cookie_hints: tuple[str, ...] = ("session", "auth", "token", "sid"),
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.auth_cookie_hints = auth_cookie_hints

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Authorized-Security-Assessment/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        })
        return session

    def submit_form(
        self,
        discovered: DiscoveredLogin,
        *,
        method: str,
        username: str,
        password: str,
        preserve_hidden_fields: bool = True,
        case_id: str,
        credential_profile: str,
    ) -> MethodObservation:
        session = self._new_session()

        try:
            # Warm the session. This captures cookies and the initial CSRF state.
            warm = session.get(
                discovered.page_url,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=True,
            )

            fields: dict[str, Any] = {}
            if preserve_hidden_fields:
                fields.update(discovered.hidden_fields)

            fields[discovered.username_field] = username
            fields[discovered.password_field] = password

            url = discovered.action_url
            started = time.perf_counter()

            method_upper = method.upper()
            if method_upper == "GET":
                response = session.get(
                    url,
                    params=fields,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=True,
                )
            elif method_upper == "POST":
                response = session.post(
                    url,
                    data=fields,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=True,
                )
            else:
                raise ValueError(f"Unsupported safe method: {method}")

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            signals = classify_response(
                status_code=response.status_code,
                final_url=response.url,
                body=response.text,
                expected_login_url=discovered.page_url,
                response_headers=response.headers,
            )

            auth_cookies = infer_auth_cookies(
                session.cookies.get_dict(),
                self.auth_cookie_hints,
            )

            evidence = [
                compact_method_evidence(
                    method_upper,
                    response.status_code,
                    response.url,
                    signals,
                ),
                f"response_length={len(response.text)}",
                f"normalized_response_length={signals['normalized_length']}",
                f"body_fingerprint={signals['body_fingerprint']}",
                f"auth_cookie_names={auth_cookies}",
            ]

            return MethodObservation(
                case_id=case_id,
                method=method_upper,
                credential_profile=credential_profile,
                status_code=response.status_code,
                final_url=response.url,
                response_length=len(response.text),
                elapsed_ms=round(elapsed_ms, 2),
                redirected=bool(response.history),
                authenticated_signal=bool(signals["authenticated_signal"]),
                rejected_signal=bool(signals["rejected_signal"]),
                rate_limited=bool(signals["rate_limited"]),
                csrf_rejected=bool(signals["csrf_rejected"]),
                auth_cookie_names=auth_cookies,
                evidence=evidence,
            )
        except requests.RequestException as exc:
            return MethodObservation(
                case_id=case_id,
                method=method.upper(),
                credential_profile=credential_profile,
                evidence=[f"HTTP request error: {exc}"],
                error=str(exc),
            )
        except Exception as exc:
            return MethodObservation(
                case_id=case_id,
                method=method.upper(),
                credential_profile=credential_profile,
                evidence=[f"Method interchange client error: {exc}"],
                error=str(exc),
            )

    def submit_json(
        self,
        *,
        endpoint: str,
        expected_method: str,
        alternate_method: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        case_id: str,
        credential_profile: str,
        content_type: str = "application/json",
    ) -> tuple[MethodObservation, MethodObservation]:
        session = self._new_session()
        payload = {
            username_field: username,
            password_field: password,
        }

        results: list[MethodObservation] = []
        for method in (expected_method.upper(), alternate_method.upper()):
            try:
                started = time.perf_counter()
                if method == "GET":
                    response = session.get(
                        endpoint,
                        params=payload,
                        timeout=self.timeout,
                        verify=self.verify_tls,
                        allow_redirects=True,
                    )
                elif method == "POST":
                    response = session.post(
                        endpoint,
                        json=payload,
                        timeout=self.timeout,
                        verify=self.verify_tls,
                        allow_redirects=True,
                        headers={"Content-Type": content_type},
                    )
                else:
                    raise ValueError("Only GET/POST are supported by TC06.")

                elapsed_ms = (time.perf_counter() - started) * 1000.0
                signals = classify_response(
                    status_code=response.status_code,
                    final_url=response.url,
                    body=response.text,
                    expected_login_url=endpoint,
                    response_headers=response.headers,
                )
                results.append(
                    MethodObservation(
                        case_id=case_id,
                        method=method,
                        credential_profile=credential_profile,
                        status_code=response.status_code,
                        final_url=response.url,
                        response_length=len(response.text),
                        elapsed_ms=round(elapsed_ms, 2),
                        redirected=bool(response.history),
                        authenticated_signal=bool(signals["authenticated_signal"]),
                        rejected_signal=bool(signals["rejected_signal"]),
                        rate_limited=bool(signals["rate_limited"]),
                        csrf_rejected=bool(signals["csrf_rejected"]),
                        evidence=[
                            compact_method_evidence(
                                method,
                                response.status_code,
                                response.url,
                                signals,
                            ),
                            f"response_length={len(response.text)}",
                            f"body_fingerprint={signals['body_fingerprint']}",
                        ],
                    )
                )
            except Exception as exc:
                results.append(
                    MethodObservation(
                        case_id=case_id,
                        method=method,
                        credential_profile=credential_profile,
                        evidence=[f"JSON method error: {exc}"],
                        error=str(exc),
                    )
                )

        return results[0], results[1]
