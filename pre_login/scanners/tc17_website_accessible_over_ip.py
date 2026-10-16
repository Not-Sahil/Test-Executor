from __future__ import annotations

import hashlib
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


CURL = "curl.exe" if os.name == "nt" else "curl"

MAX_ADDRESSES = 12
MAX_BODY_CHARS = 150_000
REQUEST_TIMEOUT = 15


@dataclass
class ResponseSnapshot:
    url: str
    address: str
    scheme: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    title: str
    fingerprint: str
    location: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "address": self.address,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "headers": self.headers,
            "title": self.title,
            "body_length": len(self.body),
            "fingerprint": self.fingerprint,
            "location": self.location,
            "error": self.error,
        }


def _result(
    status: str,
    summary: str,
    details: dict[str, Any] | None = None,
    evidence: list[str] | None = None,
) -> dict:
    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


def _ensure_url(value: str) -> str:
    value = value.strip()

    if not value.startswith(
        ("http://", "https://")
    ):
        value = "https://" + value

    return value


def _resolve_all(hostname: str) -> dict[str, list[str]]:
    """
    Resolve both IPv4 and IPv6 addresses with a bounded result count.
    """

    ipv4: list[str] = []
    ipv6: list[str] = []

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return {
            "ipv4": [],
            "ipv6": [],
        }

    for family, _, _, _, sockaddr in results:

        address = sockaddr[0]

        if family == socket.AF_INET:

            if address not in ipv4:
                ipv4.append(
                    address
                )

        elif family == socket.AF_INET6:

            if address not in ipv6:
                ipv6.append(
                    address
                )

    return {
        "ipv4": ipv4[:MAX_ADDRESSES],
        "ipv6": ipv6[:MAX_ADDRESSES],
    }


def _parse_header_blocks(
    raw: str,
) -> list[dict[str, Any]]:
    """
    Parse curl's response header blocks.

    Redirects can produce several HTTP header blocks.
    """

    blocks: list[
        dict[str, Any]
    ] = []

    current: dict[str, Any] | None = None

    for line in raw.splitlines():

        status_match = re.match(
            r"^HTTP/\d(?:\.\d)?\s+(\d{3})",
            line.strip(),
            flags=re.IGNORECASE,
        )

        if status_match:

            current = {
                "status_code": int(
                    status_match.group(1)
                ),
                "headers": {},
            }

            blocks.append(
                current
            )

            continue

        if current is None:
            continue

        if ":" not in line:
            continue

        name, value = line.split(
            ":",
            1,
        )

        current["headers"][
            name.strip()
        ] = value.strip()

    return blocks


def _extract_title(
    body: str,
) -> str:

    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return ""

    title = re.sub(
        r"<[^>]+>",
        " ",
        match.group(1),
    )

    return re.sub(
        r"\s+",
        " ",
        title,
    ).strip()[:300]


def _normalise_body(
    body: str,
) -> str:

    body = body[:MAX_BODY_CHARS]

    # Remove common dynamic values that can make otherwise identical pages
    # look different.
    body = re.sub(
        r"\bcsrf(?:token)?\b.{0,200}",
        "csrf-token",
        body,
        flags=re.IGNORECASE,
    )

    body = re.sub(
        r"\bnonce[-_=:\s]+[A-Za-z0-9+/=_-]+",
        "nonce",
        body,
        flags=re.IGNORECASE,
    )

    body = re.sub(
        r"\s+",
        " ",
        body,
    )

    return body.lower().strip()


def _fingerprint(
    body: str,
) -> str:

    normalized = _normalise_body(
        body
    )

    return hashlib.sha256(
        normalized.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def _similarity(
    left: str,
    right: str,
) -> float:

    from difflib import SequenceMatcher

    left_normalized = _normalise_body(
        left
    )

    right_normalized = _normalise_body(
        right
    )

    if not left_normalized or not right_normalized:
        return 0.0

    if left_normalized == right_normalized:
        return 100.0

    return round(
        SequenceMatcher(
            None,
            left_normalized,
            right_normalized,
        ).ratio()
        * 100,
        2,
    )


def _requests_request(
    url: str,
    *,
    connect_ip: str | None = None,
    hostname: str | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> tuple[str | None, str | None]:
    """HTTP fallback used when curl is not installed."""
    try:
        import requests
    except Exception as exc:
        return None, f"curl executable was not found and requests fallback failed: {exc}"

    parsed = urlparse(url)
    headers = {"User-Agent": "SecurityAssessmentTestExecutor-TC17/1.0"}
    target = url
    effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if connect_ip and hostname:
        clean_ip = connect_ip.strip("[]")
        netloc = f"[{clean_ip}]:{effective_port}" if ":" in clean_ip else f"{clean_ip}:{effective_port}"
        target = parsed._replace(netloc=netloc).geturl()
        headers["Host"] = hostname if not parsed.port else f"{hostname}:{parsed.port}"

    try:
        response = requests.get(
            target,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        header_block = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        raw = f"HTTP/1.1 {response.status_code}\r\n{header_block}\r\n\r\n{response.text or ''}"
        return raw, None
    except Exception as exc:
        return None, f"requests fallback: {type(exc).__name__}: {exc}"


def _curl_request(
    url: str,
    *,
    connect_ip: str | None = None,
    hostname: str | None = None,
    timeout: int = REQUEST_TIMEOUT,
    verify_tls: bool = True,
) -> tuple[
    str | None,
    str | None,
]:
    """
    Execute a bounded curl request.

    When connect_ip is provided, --resolve keeps the original hostname in
    the URL/Host/SNI while forcing the TCP connection to connect_ip.

    This is particularly important for HTTPS virtual hosting.
    """

    command = [
        CURL,
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--connect-timeout",
        str(min(timeout, 10)),
        "--dump-header",
        "-",
        "--no-buffer",
        url,
    ]
    if not verify_tls:
        command.insert(1, "--insecure")

    parsed = urlparse(
        url
    )
    effective_port = parsed.port or (
        443 if parsed.scheme == "https" else 80
    )

    if (
        connect_ip
        and hostname
        and parsed.scheme in {
            "http",
            "https",
        }
    ):
        clean_ip = connect_ip.strip("[]")
        command[1:1] = [
            "--resolve",
            (
                f"{hostname}:"
                f"{effective_port}:"
                f"{clean_ip}"
            ),
        ]

    try:

        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 5,
        )

    except FileNotFoundError:

        return _requests_request(
            url,
            connect_ip=connect_ip,
            hostname=hostname,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:

        return (
            None,
            "curl request timed out",
        )

    except Exception as exc:

        return (
            None,
            str(exc),
        )

    output = completed.stdout.decode(
        "utf-8",
        errors="replace",
    )

    stderr = completed.stderr.decode(
        "utf-8",
        errors="replace",
    )

    if completed.returncode != 0:
        if verify_tls and (
            "CERT" in stderr.upper()
            or "SSL" in stderr.upper()
            or "SCHANNEL" in stderr.upper()
        ):
            return _curl_request(
                url,
                connect_ip=connect_ip,
                hostname=hostname,
                timeout=timeout,
                verify_tls=False,
            )
        return (
            output or None,
            stderr[:1000]
            or f"curl exit code {completed.returncode}",
        )

    return (
        output,
        None,
    )


def _build_snapshot(
    raw: str,
    *,
    url: str,
    address: str,
) -> ResponseSnapshot:

    blocks = _parse_header_blocks(
        raw
    )

    if blocks:

        final_block = blocks[-1]

        status_code = final_block[
            "status_code"
        ]

        headers = final_block[
            "headers"
        ]

        # Everything after the final response-header block is treated as
        # the response body. This works for our bounded comparison purpose.
        # Remove header blocks from the curl response.
        split = re.split(
            r"\r?\n\r?\n",
            raw,
        )

        body = (
            split[-1]
            if split
            else ""
        )

    else:

        status_code = None
        headers = {}
        body = raw

    title = _extract_title(
        body
    )

    return ResponseSnapshot(
        url=url,
        address=address,
        scheme=urlparse(url).scheme,
        status_code=status_code,
        headers=headers,
        body=body[
            :MAX_BODY_CHARS
        ],
        title=title,
        fingerprint=_fingerprint(
            body
        ),
        location=headers.get(
            "Location",
            "",
        ),
    )


def _important_headers(
    snapshot: ResponseSnapshot,
) -> dict[str, str]:

    wanted = {
        "server",
        "location",
        "content-type",
        "content-length",
        "set-cookie",
        "cache-control",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "via",
        "x-cache",
        "cf-cache-status",
        "x-served-by",
    }

    return {
        key: value[:2000]
        for key, value
        in snapshot.headers.items()
        if key.lower() in wanted
    }


def _snapshot_comparison(
    domain: ResponseSnapshot,
    ip_direct: ResponseSnapshot,
) -> dict[str, Any]:

    body_similarity = _similarity(
        domain.body,
        ip_direct.body,
    )

    title_same = (
        domain.title
        and ip_direct.title
        and domain.title.lower()
        == ip_direct.title.lower()
    )

    content_type_same = (
        domain.headers.get(
            "Content-Type",
            ""
        ).split(";")[0].lower()
        ==
        ip_direct.headers.get(
            "Content-Type",
            ""
        ).split(";")[0].lower()
    )

    same_status = (
        domain.status_code
        == ip_direct.status_code
    )

    same_application_signals = (
        sum(
            [
                same_status,
                bool(title_same),
                content_type_same,
                (
                    domain.fingerprint
                    == ip_direct.fingerprint
                ),
            ]
        )
    )

    return {
        "body_similarity_percent": body_similarity,
        "same_status": same_status,
        "same_title": bool(
            title_same
        ),
        "same_content_type": (
            content_type_same
        ),
        "same_body_fingerprint": (
            domain.fingerprint
            == ip_direct.fingerprint
        ),
        "matching_application_signals": (
            same_application_signals
        ),
        "domain_headers": _important_headers(
            domain
        ),
        "ip_headers": _important_headers(
            ip_direct
        ),
    }


def _evaluate_direct_access(
    *,
    domain_response: ResponseSnapshot,
    ip_response: ResponseSnapshot | None,
    comparison: dict[str, Any] | None,
) -> tuple[str, str, list[str]]:

    if ip_response is None:

        return (
            "SAFE",
            "The application was not directly reachable through the tested IP address.",
            [],
        )

    ip_status = (
        ip_response.status_code
    )

    if ip_status is None:

        return (
            "REVIEW REQUIRED",
            "The direct-IP response could not be classified reliably.",
            [],
        )

    # Redirect to canonical hostname is normally desirable.
    location = (
        ip_response.location
        or ""
    ).lower()

    original_host = (
        urlparse(
            domain_response.url
        ).hostname
        or ""
    ).lower()

    if (
        300 <= ip_status < 400
        and original_host
        and original_host in location
    ):

        return (
            "SAFE",
            "The direct IP endpoint redirects clients back to the intended hostname.",
            [
                (
                    "IP redirect target: "
                    + ip_response.location
                )
            ],
        )

    if comparison is None:

        return (
            "REVIEW REQUIRED",
            "The direct IP endpoint responded, but response comparison could not be completed.",
            [
                f"IP returned HTTP {ip_status}",
            ],
        )

    similarity = comparison[
        "body_similarity_percent"
    ]

    signals = comparison[
        "matching_application_signals"
    ]

    # Stronger evidence of direct application access.
    if (
        200 <= ip_status < 300
        and similarity >= 85
        and signals >= 3
    ):

        return (
            "REVIEW REQUIRED",
            "The application appears to be directly reachable through the resolved IP address using response characteristics similar to the hostname-based application. Review whether direct IP access bypasses an intended CDN, WAF, reverse proxy, access policy, or virtual-host boundary.",
            [
                (
                    f"Direct IP returned HTTP {ip_status}"
                ),
                (
                    f"Content similarity: "
                    f"{similarity}%"
                ),
                (
                    f"Matching application signals: "
                    f"{signals}/4"
                ),
            ],
        )

    # Some meaningful response, but insufficient evidence.
    if 200 <= ip_status < 300:

        return (
            "REVIEW REQUIRED",
            "The resolved IP address returned a successful response, but the scanner could not establish with high confidence that it represents the same application or a security-boundary bypass.",
            [
                (
                    f"Direct IP returned HTTP "
                    f"{ip_status}"
                ),
                (
                    f"Content similarity: "
                    f"{similarity}%"
                ),
            ],
        )

    if ip_status in {
        401,
        403,
        404,
        410,
    }:

        return (
            "SAFE",
            "The resolved IP did not provide unrestricted successful access to the application.",
            [
                f"Direct IP returned HTTP {ip_status}",
            ],
        )

    if 300 <= ip_status < 400:

        return (
            "REVIEW REQUIRED",
            "The resolved IP redirects, but not directly to the expected canonical hostname. Review the redirect configuration.",
            [
                (
                    f"Direct IP returned HTTP "
                    f"{ip_status}"
                ),
                (
                    f"Location: "
                    f"{ip_response.location}"
                ),
            ],
        )

    if ip_status >= 500:

        return (
            "REVIEW REQUIRED",
            "The resolved IP returned a server error. Direct-IP behavior could not be classified confidently.",
            [
                (
                    f"Direct IP returned HTTP "
                    f"{ip_status}"
                )
            ],
        )

    return (
        "SAFE",
        "No direct-IP application exposure was confirmed.",
        [],
    )


def scan_ip_access(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = REQUEST_TIMEOUT,
) -> dict:

    target = _ensure_url(
        url
    )

    parsed = urlparse(
        target
    )

    if not parsed.hostname:

        return _result(
            "INCOMPLETE",
            "The target URL does not contain a valid hostname.",
            {
                "target": target,
            },
        )

    hostname = parsed.hostname
    scheme = parsed.scheme
    port = parsed.port or (
        443
        if scheme == "https"
        else 80
    )

    # ========================================================================
    # 1. Resolve ALL available addresses
    # ========================================================================

    resolved = _resolve_all(
        hostname
    )

    addresses = (
        resolved["ipv4"]
        + resolved["ipv6"]
    )

    if not addresses:

        return _result(
            "INCOMPLETE",
            "The target hostname could not be resolved to an IP address.",
            {
                "target": target,
                "hostname": hostname,
                "resolved": resolved,
            },
        )

    details: dict[str, Any] = {
        "target": target,
        "hostname": hostname,
        "scheme": scheme,
        "port": port,
        "resolved_addresses": resolved,
        "verification": verify_tls,
        "tests": [],
    }

    # ========================================================================
    # 2. Establish normal hostname baseline
    # ========================================================================

    normal_raw, normal_error = _curl_request(
        target,
        timeout=int(timeout),
        verify_tls=verify_tls,
    )

    if not normal_raw:

        return _result(
            "INCOMPLETE",
            "The normal hostname request could not be completed, so IP-access comparison could not be performed reliably.",
            {
                **details,
                "normal_request_error": (
                    normal_error
                    or "unknown error"
                ),
            },
        )

    domain_snapshot = _build_snapshot(
        normal_raw,
        url=target,
        address=hostname,
    )

    details[
        "hostname_baseline"
    ] = domain_snapshot.as_dict()

    # ========================================================================
    # 3. Test each resolved IP
    # ========================================================================

    address_results: list[dict[str, Any]] = []
    direct_application_exposures: list[dict[str, Any]] = []
    forced_candidates: list[dict[str, Any]] = []
    canonical_redirects: list[dict[str, Any]] = []
    default_vhosts: list[dict[str, Any]] = []
    sensitive_exposures: list[dict[str, Any]] = []
    restricted_ips: list[dict[str, Any]] = []

    completed = 0

    for address in addresses:
        clean_ip = address.strip("[]")
        formatted_address = f"[{clean_ip}]" if ":" in clean_ip else clean_ip
        port_suffix = f":{port}" if parsed.port or (port != (443 if scheme == "https" else 80)) else ""
        raw_ip_url = f"{scheme}://{formatted_address}{port_suffix}{parsed.path or '/'}"

        raw_ip_result: dict[str, Any] = {
            "address": address,
            "raw_ip_url": raw_ip_url,
        }

        # --------------------------------------------------------------
        # A. Raw direct-IP URL
        # --------------------------------------------------------------
        raw_ip, raw_ip_error = _curl_request(
            raw_ip_url,
            timeout=int(timeout),
            verify_tls=verify_tls,
        )

        if raw_ip:
            try:
                raw_snapshot = _build_snapshot(
                    raw_ip,
                    url=raw_ip_url,
                    address=address,
                )
                raw_ip_result["response"] = raw_snapshot.as_dict()
                raw_comparison = _snapshot_comparison(domain_snapshot, raw_snapshot)
                raw_ip_result["comparison"] = raw_comparison
                completed += 1

                raw_status = raw_snapshot.status_code or 0
                similarity = raw_comparison.get("body_similarity_percent", 0.0)
                signals = raw_comparison.get("matching_application_signals", 0)

                # 1. Canonical redirect
                if 300 <= raw_status < 400 and (raw_snapshot.location or ""):
                    loc = raw_snapshot.location.lower()
                    if hostname.lower() in loc:
                        canonical_redirects.append({
                            "address": address,
                            "status_code": raw_status,
                            "location": raw_snapshot.location,
                        })

                # 2. Direct raw IP serves target application
                elif 200 <= raw_status < 300 and similarity >= 80 and signals >= 3:
                    direct_application_exposures.append({
                        "address": address,
                        "url": raw_ip_url,
                        "status_code": raw_status,
                        "similarity": similarity,
                        "signals": signals,
                        "title": raw_snapshot.title,
                    })

                # 3. Direct raw IP exposes sensitive/admin interface
                elif 200 <= raw_status < 300 and any(
                    ind in (raw_snapshot.title or "").lower() or ind in (raw_snapshot.body or "")[:5000].lower()
                    for ind in ("phpmyadmin", "admin panel", "cpanel", "webmin", "dashboard", "index of /")
                ) and similarity < 50:
                    sensitive_exposures.append({
                        "address": address,
                        "url": raw_ip_url,
                        "status_code": raw_status,
                        "title": raw_snapshot.title,
                    })

                # 4. Default virtual host page
                elif 200 <= raw_status < 300 and (
                    any(ind in (raw_snapshot.title or "").lower() for ind in ("welcome to", "apache2 default", "iis windows", "nginx default"))
                    or (similarity < 25 and any(ind in raw_snapshot.body.lower() for ind in ("default page", "welcome to", "it works!")))
                ):
                    default_vhosts.append({
                        "address": address,
                        "url": raw_ip_url,
                        "status_code": raw_status,
                        "title": raw_snapshot.title,
                    })

                # 5. Explicitly restricted status
                elif raw_status in {401, 403, 404, 410}:
                    restricted_ips.append({
                        "address": address,
                        "status_code": raw_status,
                    })

            except Exception as exc:
                raw_ip_result["parse_error"] = str(exc)
        else:
            raw_ip_result["error"] = raw_ip_error
            if raw_ip_error and any(token in raw_ip_error.lower() for token in ("refused", "timeout", "timed out", "unreachable", "reset")):
                restricted_ips.append({
                    "address": address,
                    "error": raw_ip_error,
                })

        # --------------------------------------------------------------
        # B. Hostname-preserving forced-IP request
        # --------------------------------------------------------------
        forced_raw, forced_error = _curl_request(
            target,
            connect_ip=address,
            hostname=hostname,
            timeout=int(timeout),
            verify_tls=verify_tls,
        )

        if forced_raw:
            try:
                forced_snapshot = _build_snapshot(
                    forced_raw,
                    url=target,
                    address=address,
                )
                raw_ip_result["forced_hostname_response"] = forced_snapshot.as_dict()
                forced_comparison = _snapshot_comparison(domain_snapshot, forced_snapshot)
                raw_ip_result["forced_hostname_comparison"] = forced_comparison
                completed += 1

                forced_status = forced_snapshot.status_code or 0
                forced_sim = forced_comparison.get("body_similarity_percent", 0.0)
                forced_sig = forced_comparison.get("matching_application_signals", 0)

                if 200 <= forced_status < 300 and forced_sim >= 80 and forced_sig >= 3:
                    forced_candidates.append({
                        "address": address,
                        "similarity": forced_sim,
                        "signals": forced_sig,
                        "status_code": forced_status,
                        "response": forced_snapshot.as_dict(),
                    })
            except Exception as exc:
                raw_ip_result["forced_parse_error"] = str(exc)
        else:
            raw_ip_result["forced_hostname_error"] = forced_error

        address_results.append(raw_ip_result)

    details["ip_tests"] = address_results
    details["successful_ip_tests"] = completed
    details["direct_application_exposures"] = direct_application_exposures
    details["forced_candidates"] = forced_candidates
    details["canonical_redirects"] = canonical_redirects
    details["default_vhosts"] = default_vhosts
    details["sensitive_exposures"] = sensitive_exposures
    details["restricted_ips"] = restricted_ips

    # ========================================================================
    # 4. Final classification
    # ========================================================================

    # A. Direct application exposure over raw IP (without Host header)
    if direct_application_exposures:
        details["security_bypass_confirmed"] = True
        details["direct_application_reachability_confirmed"] = True
        evidence = [
            f"Direct IP {item['address']} served the intended application directly ({item['similarity']}% similarity, {item['signals']}/4 signals)."
            for item in direct_application_exposures
        ]
        return _result(
            "UNSAFE",
            "The web application is directly accessible via its public IP address without virtual-host or domain routing. This confirms origin exposure and potential bypass of fronting CDN, WAF, or access controls.",
            details,
            evidence,
        )

    # B. Direct IP exposes sensitive secondary application / interface
    if sensitive_exposures:
        details["sensitive_exposure_confirmed"] = True
        evidence = [
            f"Direct IP {item['address']} exposed secondary interface: {item['title']} (HTTP {item['status_code']})."
            for item in sensitive_exposures
        ]
        return _result(
            "UNSAFE",
            "Direct IP access exposes an administrative or secondary application interface on the server.",
            details,
            evidence,
        )

    # C. Hostname-preserving forced IP access
    if forced_candidates:
        details["security_bypass_confirmed"] = False
        details["direct_application_reachability_confirmed"] = True
        evidence = [
            f"IP {candidate['address']} served the application when Host header {hostname!r} was provided ({candidate['similarity']}% similarity)."
            for candidate in forced_candidates
        ]
        return _result(
            "REVIEW REQUIRED",
            "A resolved IP address serves the application when the original hostname is preserved. Direct origin reachability is confirmed; review whether this IP allows bypassing CDN, WAF, or network restrictions.",
            details,
            evidence,
        )

    # D. Canonical redirect
    if canonical_redirects and not direct_application_exposures and not forced_candidates:
        evidence = [
            f"IP {item['address']} redirects (HTTP {item['status_code']}) to {item['location']}."
            for item in canonical_redirects
        ]
        return _result(
            "SAFE",
            "Direct IP access safely redirects clients back to the intended canonical hostname.",
            details,
            evidence,
        )

    # E. Default virtual host
    if default_vhosts and not direct_application_exposures and not forced_candidates:
        evidence = [
            f"IP {item['address']} served default virtual host page: {item['title']!r}."
            for item in default_vhosts
        ]
        return _result(
            "SAFE",
            "Direct IP access serves a default server or virtual-host page rather than the application.",
            details,
            evidence,
        )

    # F. Correctly restricted access
    if restricted_ips or completed > 0:
        return _result(
            "SAFE",
            "Direct IP access to the application is restricted, blocked, or not exposed across the resolved addresses.",
            details,
        )

    return _result(
        "INCOMPLETE",
        "None of the resolved IP addresses could be assessed reliably due to network or connection errors.",
        details,
    )


if __name__ == "__main__":

    target = input(
        "Enter target URL: "
    ).strip()

    if not target:

        print(
            "ERROR: URL cannot be empty."
        )

    else:

        result = scan_ip_access(
            target
        )

        print(
            result
        )