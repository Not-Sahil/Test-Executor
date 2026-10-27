"""
Assessment orchestrator.

This module coordinates the pre-login/integrated assessment flow.

The orchestrator is responsible for:
    - running scanners in-process where appropriate
    - running authentication checks through the existing auth lane
    - determining HTTPS applicability for TLS-specific testcases
    - automatically using the HTTPS counterpart when the user entered HTTP
    - preserving NOT APPLICABLE separately from SAFE/UNSAFE
    - returning structured ScanResult objects

Use only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile

from contextlib import redirect_stdout
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Optional, Any

from pre_login.scanners import (
    tc01_banner_grabbing as banner_grabbing,
)
from pre_login.scanners import (
    tc07_weak_cipher as weak_cipher_scanner,
)
from pre_login.scanners import (
    tc08_wildcard_certificate as wildcard_certificate_scanner,
)
from pre_login.scanners import (
    tc09_certificate_expiry as certificate_expiry_scanner,
)
from pre_login.scanners import (
    tc12_host_header_injection as host_header_inj,
)
from pre_login.scanners import (
    tc17_website_accessible_over_ip as ip_access_scanner,
)
from pre_login.scanners import (
    tc18_missing_security_headers as security_header_scanner,
)

from authentication.login_applicability import (
    federated_login_skip,
    format_not_applicable_summary,
    skip_evidence,
)

from core.http_client import (
    build_https_url,
    probe_https_endpoint,
)


# ============================================================
# PATHS / CONFIGURATION
# ============================================================

BASE_DIR = Path(
    __file__
).resolve().parent.parent


SCANNERS = {
    "default_runner_module": (
        "authentication.auth_test_runner"
    ),
}


# ============================================================
# RESULT MODEL
# ============================================================

@dataclass
class ScanResult:
    key: str
    name: str
    status: str
    summary: str
    raw_output: str = ""
    evidence: list[str] | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================
# STATUS CONSTANTS
# ============================================================

_INCOMPLETE_STATUSES = {
    "ERROR",
    "UNKNOWN",
    "INCOMPLETE",
}

_NON_EXECUTED_STATUSES = {
    "SKIPPED",
    "NOT APPLICABLE",
    "NOT ASSESSED",
}

_LOGIN_MISSING_STATUSES = {
    "unresolved",
}

_RESOLVED_AUTH_MECHANISMS = {
    "form",
    "browser_form",
    "http_basic",
}


# ============================================================
# GENERIC HELPERS
# ============================================================

def _incomplete_summary(
    output: str,
) -> str:

    if "CONNECTION ERROR" in output:
        return (
            "The scanner did not complete because the "
            "target request failed. This is not a SAFE "
            "or UNSAFE security finding."
        )

    if (
        "ERROR:" in output
        or "CURL ERROR:" in output
    ):
        return (
            "The scanner did not complete due to an error. "
            "See scanner output for details. This is not "
            "a SAFE finding."
        )

    return (
        "The scanner finished without a structured "
        "SAFE/UNSAFE result. See scanner output for details."
    )


def _coerce_list(
    value: Any,
) -> list:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


# ============================================================
# GENERIC IN-PROCESS SCANNER EXECUTOR
# ============================================================

def _run_inprocess_scanner(
    key: str,
    name: str,
    scan_fn: Callable[..., dict | None],
    target: str,
    progress: Optional[
        Callable[[str], None]
    ] = None,
    scanner_kwargs: Optional[
        dict[str, Any]
    ] = None,
) -> ScanResult:

    """
    Call a scanner directly instead of scraping CLI stdout.

    scanner_kwargs allows TLS-specific scanners to receive
    verify_tls/timeout without changing the existing generic
    scanner execution interface.
    """

    if progress:
        progress(
            f"Starting {name}"
        )

    buf = io.StringIO()

    kwargs = (
        dict(scanner_kwargs)
        if scanner_kwargs
        else {}
    )

    try:

        with redirect_stdout(buf):

            payload = (
                scan_fn(
                    target,
                    **kwargs,
                )
                or {}
            )

    except Exception as exc:

        return ScanResult(
            key=key,
            name=name,
            status="ERROR",
            summary=(
                f"Scanner error: {exc}"
            ),
            raw_output=buf.getvalue(),
            details={
                "error": str(exc),
                "exception_type": (
                    type(exc).__name__
                ),
                "target": target,
            },
        )

    raw = buf.getvalue()

    if (
        not isinstance(
            payload,
            dict,
        )
        or not payload
    ):

        return ScanResult(
            key=key,
            name=name,
            status="INCOMPLETE",
            summary=_incomplete_summary(
                raw
            ),
            raw_output=raw,
            details={
                "target": target,
            },
        )

    status = str(
        payload.get(
            "status"
        )
        or "INCOMPLETE"
    )

    summary = str(
        payload.get(
            "summary"
        )
        or ""
    ).strip()

    if not summary:

        summary = (
            _incomplete_summary(
                raw
            )
            if status
            in _INCOMPLETE_STATUSES
            else "Scanner completed."
        )

    return ScanResult(
        key=key,
        name=name,
        status=status,
        summary=summary,
        raw_output=raw,
        evidence=(
            _coerce_list(
                payload.get(
                    "evidence"
                )
            )
            or None
        ),
        details=(
            payload.get(
                "details"
            )
            or None
        ),
    )


# ============================================================
# TLS APPLICABILITY
# ============================================================

def _check_https_applicability(
    target: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> dict[str, Any]:

    """
    Determine whether TC07/TC08/TC09 can be executed.

    Important:
    An HTTPS endpoint with an expired/untrusted certificate is
    STILL HTTPS and must not become NOT APPLICABLE.

    Therefore probe_https_endpoint() retries diagnostically
    without certificate verification when the verified request
    fails.
    """

    try:

        https_url = build_https_url(
            target
        )

    except Exception as exc:

        return {
            "applicable": False,
            "https_url": None,
            "probe": None,
            "error": str(exc),
        }

    probe = probe_https_endpoint(
        https_url,
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=False,
    )

    return {
        "applicable": probe.reachable,
        "https_url": https_url,
        "probe": probe.as_dict(),
        "error": probe.error,
    }


def _tls_not_applicable_result(
    key: str,
    name: str,
    *,
    target: str,
    https_url: str | None,
    probe: dict[str, Any] | None,
    reason: str | None = None,
) -> ScanResult:

    summary = (
        f"{name} requires an HTTPS endpoint because "
        "this testcase evaluates TLS protocol, cipher, "
        "or certificate configuration."
    )

    if reason:
        summary += (
            f" {reason}"
        )

    return ScanResult(
        key=key,
        name=name,
        status="NOT APPLICABLE",
        summary=summary,
        evidence=[
            (
                "No reachable HTTPS/TLS endpoint was "
                "detected for the supplied target."
            )
        ],
        details={
            "not_applicable": True,
            "target": target,
            "https_url": https_url,
            "https_probe": probe,
        },
    )


# ============================================================
# TLS TEST RUNNER
# ============================================================

def run_tls_tests(
    target: str,
    *,
    timeout: float = 12.0,
    verify_tls: bool = True,
    progress: Optional[
        Callable[[str], None]
    ] = None,
) -> list[ScanResult]:

    """
    Execute TC07, TC08 and TC09 when an HTTPS endpoint exists.

    If the user supplies:
        http://example.com

    and:
        https://example.com

    is reachable, all three TLS tests execute against HTTPS.

    If HTTPS is genuinely unavailable, all three become
    NOT APPLICABLE.

    A certificate verification failure does NOT cause
    NOT APPLICABLE; the endpoint is still TLS-enabled.
    """

    applicability = (
        _check_https_applicability(
            target,
            timeout=timeout,
            verify_tls=verify_tls,
        )
    )

    https_url = applicability.get(
        "https_url"
    )

    probe = applicability.get(
        "probe"
    )

    if not applicability.get(
        "applicable"
    ):

        reason = applicability.get(
            "error"
        )

        return [

            _tls_not_applicable_result(
                "weak_cipher",
                "Weak Cipher",
                target=target,
                https_url=https_url,
                probe=probe,
                reason=reason,
            ),

            _tls_not_applicable_result(
                "wildcard_certificate",
                "Wildcard Certificate",
                target=target,
                https_url=https_url,
                probe=probe,
                reason=reason,
            ),

            _tls_not_applicable_result(
                "certificate_expiry",
                "Certificate Expiry",
                target=target,
                https_url=https_url,
                probe=probe,
                reason=reason,
            ),
        ]

    if progress:
        progress(
            "HTTPS detected: running TLS-specific checks"
        )

    # Use HTTPS explicitly.
    tls_target = (
        https_url
        or target
    )

    scanner_kwargs = {
        "timeout": timeout,
        "verify_tls": verify_tls,
    }

    results: list[
        ScanResult
    ] = []

    # --------------------------------------------------------
    # TC07
    # --------------------------------------------------------

    results.append(
        _run_inprocess_scanner(
            key="weak_cipher",
            name="Weak Cipher",
            scan_fn=(
                weak_cipher_scanner.scan_weak_cipher
            ),
            target=tls_target,
            progress=progress,
            scanner_kwargs=scanner_kwargs,
        )
    )

    # --------------------------------------------------------
    # TC08
    # --------------------------------------------------------

    results.append(
        _run_inprocess_scanner(
            key="wildcard_certificate",
            name="Wildcard Certificate",
            scan_fn=(
                wildcard_certificate_scanner
                .scan_wildcard_certificate
            ),
            target=tls_target,
            progress=progress,
            scanner_kwargs=scanner_kwargs,
        )
    )

    # --------------------------------------------------------
    # TC09
    # --------------------------------------------------------

    results.append(
        _run_inprocess_scanner(
            key="certificate_expiry",
            name="Certificate Expiry",
            scan_fn=(
                certificate_expiry_scanner
                .scan_certificate_expiry
            ),
            target=tls_target,
            progress=progress,
            scanner_kwargs=scanner_kwargs,
        )
    )

    return results


# ============================================================
# LOGIN DISCOVERY HELPERS
# ============================================================

def _login_discovery_summary(
    test_name: str,
    login_path: str,
    evidence: list | None,
) -> str:

    path = (
        login_path
        or "/login"
    )

    extra = ""

    joined = " ".join(
        str(item)
        for item in (
            evidence
            or []
        )
        if item
    )

    if joined:
        extra = (
            f" Discovery detail: {joined}"
        )

    return (
        f"{test_name} did not find a usable login form "
        f"at '{path}'. This is not a SAFE or UNSAFE finding. "
        "Enter the real login page path and rerun."
        f"{extra}"
    )


def _lane_is_not_applicable(
    payload: dict,
) -> bool:

    mechanism = str(
        payload.get(
            "auth_mechanism"
        )
        or ""
    ).lower()

    summary = str(
        payload.get(
            "summary"
        )
        or ""
    )

    joined = " ".join(
        str(item)
        for item in (
            payload.get(
                "evidence"
            )
            or []
        )
        if item
    )

    if summary.startswith(
        "Not applicable"
    ):
        return True

    if mechanism in {
        "federated_idp",
        "hosted_identity_provider",
        "oauth_oidc_authorize",
    }:
        return True

    return (
        "not_applicable"
        in joined.lower()
    )


def _auth_mechanism_resolved(
    payload: dict,
) -> bool:

    mechanism = str(
        payload.get(
            "auth_mechanism"
        )
        or ""
    ).lower()

    if mechanism in (
        _RESOLVED_AUTH_MECHANISMS
    ):
        return True

    joined = " ".join(
        str(item)
        for item in (
            payload.get(
                "evidence"
            )
            or []
        )
        if item
    ).lower()

    return any(
        marker in joined
        for marker in (
            "discovered form",
            "mechanism=form",
            "mechanism=http_basic",
            "mechanism=browser_form",
        )
    )


def _not_applicable_auth_result(
    key: str,
    name: str,
    skip: dict,
) -> ScanResult:

    reason = (
        skip.get(
            "reason"
        )
        or "federated authentication is in use"
    )

    final_url = (
        skip.get("final_url")
        or skip.get("matched_url")
        or skip.get("login_url")
    )

    hops = (
        skip.get(
            "redirect_hops"
        )
        or []
    )

    return ScanResult(
        key=key,
        name=name,
        status="SKIPPED",
        summary=format_not_applicable_summary(
            name,
            skip,
        ),
        evidence=skip_evidence(
            skip
        ),
        details={
            "not_applicable": True,
            "classification": (
                skip.get(
                    "classification"
                )
            ),
            "login_url": (
                skip.get(
                    "login_url"
                )
            ),
            "identity_provider_url": final_url,
            "target_host": (
                skip.get(
                    "target_host"
                )
            ),
            "login_host": (
                skip.get(
                    "login_host"
                )
            ),
            "redirect_hops": hops,
            "reason": reason,
        },
    )


# ============================================================
# JSON HELPERS
# ============================================================

def _load_json_result(
    path: Path,
) -> list[dict]:

    try:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        return (
            data
            if isinstance(
                data,
                list,
            )
            else []
        )

    except Exception:
        return []


def _write_json(
    path: Path,
    data,
) -> None:

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


# ============================================================
# DEFAULT CREDENTIALS
# ============================================================

def run_default_credentials(
    target: str,
    login_path: str,
    credential_pairs: list[dict],
    max_attempts: int = 5,
    verify_tls: bool = True,
    progress: Optional[
        Callable[[str], None]
    ] = None,
) -> ScanResult:

    """
    Run the existing WSTG-ATHN-02 lane with a caller-supplied
    credential list.

    This intentionally avoids silently using a large wordlist.
    """

    if not credential_pairs:

        return ScanResult(
            key="default_credentials",
            name="Default Credentials",
            status="SKIPPED",
            summary=(
                "No authorized credential pairs were supplied."
            ),
        )

    if progress:
        progress(
            "Running default-credential check"
        )

    with tempfile.TemporaryDirectory(
        prefix="sixscan_"
    ) as td:

        td = Path(td)

        cases = [
            {
                "test_case_id": (
                    "TC-INTEGRATED-DEFCRED"
                ),
                "target": target,
                "is_http": (
                    target.lower()
                    .startswith("http://")
                ),
                "service_or_path": (
                    login_path
                    or "/login"
                ),
                "max_attempts": min(
                    max_attempts,
                    len(
                        credential_pairs
                    ),
                ),
                "verify_tls": bool(
                    verify_tls
                ),
                "enabled": True,
            }
        ]

        cases_path = td / "cases.json"
        creds_path = td / "creds.json"
        out_path = td / "results.json"

        _write_json(
            cases_path,
            cases,
        )

        _write_json(
            creds_path,
            credential_pairs,
        )

        _write_json(
            out_path,
            [],
        )

        try:

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    SCANNERS[
                        "default_runner_module"
                    ],
                    "--input",
                    str(cases_path),
                    "--creds",
                    str(creds_path),
                    "--output",
                    str(out_path),
                    "--max-attempts",
                    str(
                        min(
                            max_attempts,
                            len(
                                credential_pairs
                            ),
                        )
                    ),
                ],
                text=True,
                capture_output=True,
                cwd=str(BASE_DIR),
                timeout=300,
            )

            raw = (
                proc.stdout or ""
            )

            if proc.stderr:
                raw += (
                    "\n"
                    + proc.stderr
                )

            results = _load_json_result(
                out_path
            )

            if not results:

                return ScanResult(
                    key="default_credentials",
                    name="Default Credentials",
                    status="ERROR",
                    summary=(
                        "No structured result was produced."
                    ),
                    raw_output=raw,
                )

            r = results[0]

            lane_status = str(
                r.get(
                    "result",
                    "unresolved",
                )
            ).lower()

            successful_pairs = (
                r.get(
                    "successful_pairs"
                )
                or []
            )

            if (
                successful_pairs
                or lane_status == "vulnerable"
            ):

                status = "UNSAFE"

                summary = (
                    "A supplied credential pair "
                    "successfully authenticated."
                )

            elif lane_status == (
                "not_vulnerable"
            ):

                status = "SAFE"

                summary = (
                    "None of the supplied credential "
                    "pairs authenticated."
                )

            elif lane_status == (
                "lockout_aborted"
            ):

                status = (
                    "REVIEW REQUIRED"
                )

                summary = (
                    "The lockout/attempt guard stopped "
                    "the credential test."
                )

            elif (
                lane_status == "skipped"
                or _lane_is_not_applicable(r)
            ):

                status = "SKIPPED"

                summary = str(
                    r.get(
                        "summary"
                    )
                    or ""
                ).strip()

                if not summary.startswith(
                    "Not applicable"
                ):

                    summary = (
                        "Not applicable: this login is "
                        "federated SSO / identity-provider "
                        "sign-in, not a local username/password "
                        "form. Default Credentials was skipped."
                    )

            elif (
                lane_status
                in _LOGIN_MISSING_STATUSES
                and not _auth_mechanism_resolved(r)
            ):

                status = "INCOMPLETE"

                summary = (
                    _login_discovery_summary(
                        "Default Credentials",
                        login_path,
                        r.get(
                            "evidence"
                        ),
                    )
                )

            else:

                status = (
                    "ERROR"
                    if lane_status == "error"
                    else "INCOMPLETE"
                )

                summary = (
                    "The authentication check could not "
                    "be completed. "
                    f"Lane result: {lane_status}. "
                    "This is not a SAFE finding."
                )

            return ScanResult(
                key="default_credentials",
                name="Default Credentials",
                status=status,
                summary=summary,
                raw_output=raw,
                evidence=(
                    r.get(
                        "evidence",
                        [],
                    )
                    or []
                ),
                details={
                    "auth_mechanism": (
                        r.get(
                            "auth_mechanism"
                        )
                    ),
                    "attempts_made": (
                        r.get(
                            "attempts_made"
                        )
                    ),
                    "successful_pairs": (
                        r.get(
                            "successful_pairs",
                            [],
                        )
                    ),
                    "target": (
                        r.get(
                            "target"
                        )
                    ),
                },
            )

        except subprocess.TimeoutExpired:

            return ScanResult(
                key="default_credentials",
                name="Default Credentials",
                status="ERROR",
                summary=(
                    "The default-credential check timed out."
                ),
            )


# ============================================================
# USER ENUMERATION
# ============================================================

def run_user_enumeration(
    target: str,
    login_path: str,
    candidate_usernames: list[str],
    probe_password: str = (
        "__wrong_password_idnt04__"
    ),
    max_attempts: int | None = None,
    known_valid_username: str | None = None,
    verify_tls: bool = True,
    progress: Optional[
        Callable[[str], None]
    ] = None,
) -> ScanResult:

    """
    Run the existing WSTG-IDNT-04 implementation.
    """

    if not candidate_usernames:

        return ScanResult(
            key="user_enumeration",
            name="User Enumeration",
            status="SKIPPED",
            summary=(
                "No authorized candidate usernames "
                "were supplied."
            ),
        )

    if progress:
        progress(
            "Running user-enumeration check"
        )

    with tempfile.TemporaryDirectory(
        prefix="sixscan_enum_"
    ) as td:

        td = Path(td)

        cases = [
            {
                "test_case_id": (
                    "TC-INTEGRATED-IDNT04"
                ),
                "target": target,
                "is_http": (
                    target.lower()
                    .startswith("http://")
                ),
                "service_or_path": (
                    login_path
                    or "/login"
                ),
                "test_type": "enumeration",
                "candidate_usernames": (
                    candidate_usernames
                ),
                "probe_password": (
                    probe_password
                ),
                "known_valid_username": (
                    known_valid_username
                ),
                "verify_tls": bool(
                    verify_tls
                ),
                "enabled": True,
            }
        ]

        cases_path = td / "cases.json"
        creds_path = td / "creds.json"
        out_path = td / "results.json"

        _write_json(
            cases_path,
            cases,
        )

        # Runner requires --creds even for enumeration.
        _write_json(
            creds_path,
            [],
        )

        _write_json(
            out_path,
            [],
        )

        try:

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    SCANNERS[
                        "default_runner_module"
                    ],
                    "--input",
                    str(cases_path),
                    "--creds",
                    str(creds_path),
                    "--output",
                    str(out_path),
                ],
                text=True,
                capture_output=True,
                cwd=str(BASE_DIR),
                timeout=240,
            )

            raw = (
                proc.stdout or ""
            )

            if proc.stderr:
                raw += (
                    "\n"
                    + proc.stderr
                )

            results = _load_json_result(
                out_path
            )

            if not results:

                return ScanResult(
                    key="user_enumeration",
                    name="User Enumeration",
                    status="ERROR",
                    summary=(
                        "No structured enumeration "
                        "result was produced."
                    ),
                    raw_output=raw,
                )

            r = results[0]

            lane_status = str(
                r.get(
                    "result",
                    "",
                )
            ).lower()

            candidates = (
                r.get(
                    "candidates",
                    [],
                )
                or []
            )

            site_behavior = (
                r.get(
                    "signal_used"
                )
                or r.get(
                    "site_behavior",
                    "",
                )
            )

            likely_valid = [
                c.get(
                    "username"
                )
                for c in candidates
                if c.get(
                    "classification"
                )
                == "likely_valid"
            ]

            inconclusive = [
                c.get(
                    "username"
                )
                for c in candidates
                if c.get(
                    "classification"
                )
                == "inconclusive"
            ]

            if likely_valid:

                status = "UNSAFE"

                disclosed = [
                    c.get(
                        "username"
                    )
                    for c in candidates
                    if (
                        c.get(
                            "signals"
                        )
                        or {}
                    ).get(
                        "page_disclosure"
                    )
                ]

                if disclosed:

                    summary = (
                        "The login page disclosed account "
                        "identifier(s), which is username "
                        "enumeration / information disclosure."
                    )

                else:

                    summary = (
                        "The login flow exposed response "
                        "differences consistent with account "
                        "enumeration."
                    )

            elif (
                lane_status == "skipped"
                or _lane_is_not_applicable(r)
            ):

                status = "SKIPPED"

                summary = str(
                    r.get(
                        "summary"
                    )
                    or ""
                ).strip()

                if not summary.startswith(
                    "Not applicable"
                ):

                    summary = (
                        "Not applicable: this login is "
                        "federated SSO / identity-provider "
                        "sign-in, not a local username/password "
                        "form. User Enumeration was skipped."
                    )

            elif (
                "login_form_not_found"
                in str(
                    site_behavior
                )
                or (
                    lane_status
                    in _LOGIN_MISSING_STATUSES
                    and not candidates
                    and not _auth_mechanism_resolved(r)
                )
            ):

                status = "INCOMPLETE"

                summary = (
                    _login_discovery_summary(
                        "User Enumeration",
                        login_path,
                        [site_behavior]
                        if site_behavior
                        else None,
                    )
                )

            elif inconclusive:

                status = (
                    "REVIEW REQUIRED"
                )

                summary = (
                    "Some username probes produced "
                    "inconclusive response differences."
                )

            elif lane_status == (
                "not_vulnerable"
            ):

                status = "SAFE"

                summary = (
                    "No username was classified as "
                    "likely valid by the configured signals."
                )

            elif lane_status == (
                "lockout_aborted"
            ):

                status = (
                    "REVIEW REQUIRED"
                )

                summary = (
                    "The lockout/attempt guard stopped "
                    "the enumeration test."
                )

            elif lane_status == "error":

                status = "ERROR"

                summary = (
                    "The user-enumeration check could "
                    "not be completed. This is not a "
                    "SAFE finding."
                )

            else:

                status = "SAFE"

                summary = (
                    "No username was classified as "
                    "likely valid by the configured signals."
                )

            return ScanResult(
                key="user_enumeration",
                name="User Enumeration",
                status=status,
                summary=summary,
                raw_output=raw,
                evidence=[
                    c.get(
                        "evidence",
                        "",
                    )
                    for c in candidates
                ],
                details={
                    "site_behavior": (
                        site_behavior
                    ),
                    "candidates": candidates,
                    "likely_valid_usernames": (
                        likely_valid
                    ),
                    "inconclusive_usernames": (
                        inconclusive
                    ),
                },
            )

        except subprocess.TimeoutExpired:

            return ScanResult(
                key="user_enumeration",
                name="User Enumeration",
                status="ERROR",
                summary=(
                    "The user-enumeration check timed out."
                ),
            )

# ============================================================
# CAPTCHA / AUTH RESULT HELPER
# ============================================================

def captcha_auth_result(
    key: str,
    name: str,
    status: str,
    summary: str,
    evidence: list[str] | None = None,
    details: dict | None = None,
) -> ScanResult:
    """
    Create a standardized ScanResult for authentication/
    CAPTCHA-related checks used by the Streamlit layer.
    """

    return ScanResult(
        key=key,
        name=name,
        status=status,
        summary=summary,
        evidence=evidence or [],
        details=details or {},
    )
# ============================================================
# FIRST FOUR EXISTING CHECKS
# ============================================================

def run_first_four_tests(
    target: str,
    progress: Optional[
        Callable[[str], None]
    ] = None,
) -> list[ScanResult]:

    """
    Existing:
        TC01 Banner
        TC12 Host Header
        TC17 Website IP Access
        TC18 Security Headers

    TLS checks are intentionally kept separate because they
    require HTTPS applicability detection.
    """

    results: list[
        ScanResult
    ] = []

    ordered = [
        (
            "banner_grabbing",
            "Banner Disclosure",
            banner_grabbing.scan_banner,
        ),
        (
            "security_header_scanner",
            "Security Headers",
            security_header_scanner
            .scan_security_headers,
        ),
        (
            "ip_access_scanner",
            "Website IP Access",
            ip_access_scanner.scan_ip_access,
        ),
        (
            "host_header_inj",
            "Host Header Injection",
            host_header_inj.scan_host_header,
        ),
    ]

    for (
        key,
        name,
        scan_fn,
    ) in ordered:

        results.append(
            _run_inprocess_scanner(
                key,
                name,
                scan_fn,
                target,
                progress=progress,
            )
        )

    return results


# ============================================================
# COMBINED RUNNER
# ============================================================

def run_all(
    target: str,
    login_path: str = "/login",
    credential_pairs: Optional[
        list[dict]
    ] = None,
    candidate_usernames: Optional[
        list[str]
    ] = None,
    max_credential_attempts: int = 5,
    probe_password: str = (
        "__wrong_password_idnt04__"
    ),
    verify_tls: bool = True,
    timeout: float = 12.0,
    progress: Optional[
        Callable[[str], None]
    ] = None,
) -> list[ScanResult]:

    """
    Execute the integrated assessment.

    Execution order:

        Existing four scanners
                +
        HTTPS applicability check
                +
        TC07 Weak Cipher
        TC08 Wildcard Certificate
        TC09 Certificate Expiry
                +
        authentication lane
    """

    results = run_first_four_tests(
        target,
        progress=progress,
    )

    # ========================================================
    # TLS-SPECIFIC TESTS
    # ========================================================

    results.extend(
        run_tls_tests(
            target,
            timeout=timeout,
            verify_tls=verify_tls,
            progress=progress,
        )
    )

    # ========================================================
    # AUTHENTICATION LANE
    # ========================================================

    auth_skip = federated_login_skip(
        target,
        login_path,
    )

    if auth_skip:

        if progress:
            progress(
                "Skipping Default Credentials and "
                "User Enumeration: login is federated "
                "SSO / identity-provider (not applicable)"
            )

        results.append(
            _not_applicable_auth_result(
                "default_credentials",
                "Default Credentials",
                auth_skip,
            )
        )

        results.append(
            _not_applicable_auth_result(
                "user_enumeration",
                "User Enumeration",
                auth_skip,
            )
        )

        return results

    # --------------------------------------------------------
    # Default Credentials
    # --------------------------------------------------------

    results.append(
        run_default_credentials(
            target=target,
            login_path=login_path,
            credential_pairs=(
                credential_pairs
                or []
            ),
            max_attempts=(
                max_credential_attempts
            ),
            verify_tls=verify_tls,
            progress=progress,
        )
    )

    # --------------------------------------------------------
    # User Enumeration
    # --------------------------------------------------------

    results.append(
        run_user_enumeration(
            target=target,
            login_path=login_path,
            candidate_usernames=(
                candidate_usernames
                or []
            ),
            probe_password=probe_password,
            known_valid_username=(
                None
            ),
            verify_tls=verify_tls,
            progress=progress,
        )
    )

    return results


# ============================================================
# OVERALL STATUS
# ============================================================

def overall_status(
    results: list[ScanResult],
) -> str:

    statuses = {
        r.status
        for r in results
        if r.status
        not in _NON_EXECUTED_STATUSES
    }

    if "UNSAFE" in statuses:
        return "UNSAFE"

    if "REVIEW REQUIRED" in statuses:
        return "REVIEW REQUIRED"

    if statuses & _INCOMPLETE_STATUSES:
        return "INCOMPLETE"

    if statuses and statuses <= {
        "SAFE"
    }:
        return "SAFE"

    # If everything was NOT APPLICABLE/SKIPPED,
    # the assessment did not produce a meaningful
    # overall security conclusion.
    if not statuses:
        return "INCOMPLETE"

    return "INCOMPLETE"


# ============================================================
# UNIFIED BLACKBOX EXECUTOR EXPORTS
# ============================================================
from core.blackbox_runner import (
    UnifiedBlackboxExecutor,
    run_unified_blackbox_suite,
)