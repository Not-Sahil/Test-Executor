from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urljoin, urlparse

from defusedxml import ElementTree as SafeET

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
    same_origin,
)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 10.0

MAX_POLICY_FILES = 20
MAX_BODY_BYTES = 1_000_000
MAX_DISCOVERED_PATHS = 50
MAX_FINDINGS = 100
MAX_SWF_REFERENCES = 20

STANDARD_POLICY_NAMES = (
    "crossdomain.xml",
    "clientaccesspolicy.xml",
)

SUSPICIOUS_DIRECTORY_HINTS = (
    "api",
    "service",
    "services",
    "media",
    "assets",
    "static",
    "upload",
    "uploads",
    "download",
    "downloads",
    "files",
    "flash",
    "silverlight",
    "swf",
    "app",
)


# ============================================================
# RESULT HELPERS
# ============================================================

def _finding(
    finding_type: str,
    severity: str,
    confidence: str,
    message: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "evidence": evidence or {},
    }


# ============================================================
# XML HELPERS
# ============================================================

def _local_name(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""

    if "}" in tag:
        tag = tag.rsplit("}", 1)[-1]

    return tag.lower().strip()


def _children(element, name: str):
    wanted = name.lower()

    for child in list(element):
        if _local_name(child.tag) == wanted:
            yield child


def _attribute_map(element) -> dict[str, str]:
    output: dict[str, str] = {}

    for key, value in element.attrib.items():
        output[str(key).lower()] = str(value).strip()

    return output


def _safe_xml_parse(body: str):
    try:
        return SafeET.fromstring(
            body.encode("utf-8", errors="replace")
        )
    except Exception:
        return None


# ============================================================
# DOMAIN VALIDATION
# ============================================================

def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _domain_is_wildcard(value: str) -> bool:
    return _normalize_domain(value) == "*"


def _domain_is_subdomain_wildcard(value: str) -> bool:
    value = _normalize_domain(value)

    return (
        value.startswith("*.")
        and len(value) > 2
    )


def _domain_is_broad(value: str) -> bool:
    value = _normalize_domain(value)

    if value == "*":
        return True

    # Very broad public suffix-like entries should receive
    # additional scrutiny.
    if value.startswith("*."):
        suffix = value[2:]

        # Examples:
        # *.com
        # *.net
        # *.org
        # *.co.uk
        if suffix.count(".") <= 1:
            return True

    return False


def _domain_is_plausible(value: str) -> bool:
    value = _normalize_domain(value)

    if not value:
        return False

    if value == "*":
        return True

    # IP address
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        value,
    ):
        return True

    if value.startswith("*."):
        value = value[2:]

    # Basic hostname/domain validation.
    return bool(
        re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}",
            value,
            re.I,
        )
    )


# ============================================================
# SECURE ATTRIBUTE
# ============================================================

def _parse_boolean_attribute(
    attrs: dict[str, str],
    name: str = "secure",
) -> tuple[bool | None, str]:

    raw = attrs.get(name)

    if raw is None:
        return True, "default"

    value = raw.strip().lower()

    if value == "true":
        return True, "explicit_true"

    if value == "false":
        return False, "explicit_false"

    return None, "invalid"


# ============================================================
# PORT PARSING
# ============================================================

@dataclass
class PortRange:
    start: int
    end: int


def _parse_ports(
    value: str | None,
) -> tuple[list[PortRange], list[str], bool]:

    if value is None:
        return [], [], False

    value = value.strip()

    if not value:
        return [], ["empty to-ports"], False

    if value == "*":
        return [
            PortRange(1, 65535)
        ], [], True

    ranges: list[PortRange] = []
    errors: list[str] = []

    for token in value.split(","):

        token = token.strip()

        if not token:
            errors.append(
                "empty port token"
            )
            continue

        if "-" in token:

            pieces = token.split("-", 1)

            if len(pieces) != 2:
                errors.append(
                    f"invalid range: {token}"
                )
                continue

            try:
                start = int(pieces[0])
                end = int(pieces[1])
            except ValueError:
                errors.append(
                    f"non-numeric range: {token}"
                )
                continue

            if not (
                1 <= start <= 65535
                and
                1 <= end <= 65535
            ):
                errors.append(
                    f"port outside valid range: {token}"
                )
                continue

            if start > end:
                errors.append(
                    f"reversed range: {token}"
                )
                continue

            ranges.append(
                PortRange(start, end)
            )

        else:

            try:
                port = int(token)
            except ValueError:
                errors.append(
                    f"non-numeric port: {token}"
                )
                continue

            if not 1 <= port <= 65535:
                errors.append(
                    f"port outside valid range: {port}"
                )
                continue

            ranges.append(
                PortRange(port, port)
            )

    return ranges, errors, False


def _ports_are_broad(
    ranges: list[PortRange],
    wildcard: bool,
) -> bool:

    if wildcard:
        return True

    total = sum(
        r.end - r.start + 1
        for r in ranges
    )

    # More than 1000 explicitly permitted ports is
    # considered broad enough to warrant review.
    if total >= 1000:
        return True

    # Entire common-port span such as 1-1024.
    return any(
        r.start <= 1 and r.end >= 1024
        for r in ranges
    )


# ============================================================
# HEADER PERMISSION ANALYSIS
# ============================================================

def _split_header_list(
    value: str | None,
) -> list[str]:

    if not value:
        return []

    return [
        part.strip()
        for part in value.split(",")
        if part.strip()
    ]


def _headers_are_broad(
    headers: list[str],
) -> bool:

    for header in headers:

        if header == "*":
            return True

        if "*" in header:
            # Header-prefix wildcards such as X-Foo*
            # are narrower than a global wildcard, but still
            # deserve review.
            return True

    return False


# ============================================================
# RIA POLICY ANALYSIS — CROSSDOMAIN.XML
# ============================================================

def _analyze_crossdomain_policy(
    root,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:

    findings: list[dict[str, Any]] = []

    policy: dict[str, Any] = {
        "type": "crossdomain.xml",
        "site_control": [],
        "allow_access_from": [],
        "allow_http_request_headers_from": [],
        "unknown_elements": [],
    }

    root_name = _local_name(root.tag)

    if root_name != "cross-domain-policy":

        findings.append(
            _finding(
                "invalid_root_element",
                "REVIEW REQUIRED",
                "HIGH",
                (
                    "The document is XML but does not use "
                    "<cross-domain-policy> as its root element."
                ),
                {
                    "root_element": root_name,
                },
            )
        )

        return policy, findings

    # --------------------------------------------------------
    # Elements
    # --------------------------------------------------------

    for node in root.iter():

        if node is root:
            continue

        tag = _local_name(node.tag)
        attrs = _attribute_map(node)

        # ====================================================
        # SITE CONTROL
        # ====================================================

        if tag == "site-control":

            value = attrs.get(
                "permitted-cross-domain-policies"
            )

            policy["site_control"].append(
                {
                    "attributes": attrs,
                    "permitted_cross_domain_policies": value,
                }
            )

            if value is None:

                findings.append(
                    _finding(
                        "invalid_site_control",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "site-control is present but "
                            "permitted-cross-domain-policies "
                            "is missing."
                        ),
                        {
                            "attributes": attrs
                        },
                    )
                )

            elif value not in {
                "none",
                "master-only",
                "by-content-type",
                "all",
            }:

                findings.append(
                    _finding(
                        "invalid_site_control_value",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "site-control contains an "
                            "unrecognized permitted-cross-domain-"
                            "policies value."
                        ),
                        {
                            "value": value,
                        },
                    )
                )

            elif value == "all":

                findings.append(
                    _finding(
                        "permissive_policy_meta_control",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "The policy permits all policy files "
                            "on the target domain to participate "
                            "in cross-domain authorization."
                        ),
                        {
                            "value": value,
                        },
                    )
                )

            continue

        # ====================================================
        # ALLOW ACCESS FROM
        # ====================================================

        if tag == "allow-access-from":

            domain = attrs.get("domain")
            secure, secure_state = (
                _parse_boolean_attribute(attrs)
            )

            to_ports = attrs.get(
                "to-ports"
            )

            ranges, port_errors, port_wildcard = (
                _parse_ports(to_ports)
            )

            entry = {
                "attributes": attrs,
                "domain": domain,
                "secure": secure,
                "secure_state": secure_state,
                "to_ports": to_ports,
                "parsed_ports": [
                    {
                        "start": item.start,
                        "end": item.end,
                    }
                    for item in ranges
                ],
                "port_errors": port_errors,
                "port_wildcard": port_wildcard,
            }

            policy[
                "allow_access_from"
            ].append(entry)

            # --------------------------------------------
            # Domain
            # --------------------------------------------

            if not domain:

                findings.append(
                    _finding(
                        "missing_policy_domain",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-access-from is missing "
                            "its domain attribute."
                        ),
                        {
                            "attributes": attrs
                        },
                    )
                )

            else:

                if not _domain_is_plausible(
                    domain
                ):

                    findings.append(
                        _finding(
                            "invalid_policy_domain",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "allow-access-from contains "
                                "a domain value that does not "
                                "appear syntactically valid."
                            ),
                            {
                                "domain": domain
                            },
                        )
                    )

                if _domain_is_wildcard(
                    domain
                ):

                    findings.append(
                        _finding(
                            "global_wildcard_access",
                            "UNSAFE",
                            "HIGH",
                            (
                                "allow-access-from grants "
                                "cross-domain access to any "
                                "requesting domain."
                            ),
                            {
                                "domain": domain
                            },
                        )
                    )

                elif _domain_is_broad(
                    domain
                ):

                    findings.append(
                        _finding(
                            "broad_wildcard_domain",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "allow-access-from uses a "
                                "very broad wildcard domain."
                            ),
                            {
                                "domain": domain
                            },
                        )
                    )

            # --------------------------------------------
            # Secure
            # --------------------------------------------

            if secure_state == "invalid":

                findings.append(
                    _finding(
                        "invalid_secure_attribute",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-access-from contains "
                            "an invalid secure attribute."
                        ),
                        {
                            "secure": attrs.get(
                                "secure"
                            )
                        },
                    )
                )

            elif secure is False:

                severity = (
                    "UNSAFE"
                    if (
                        domain == "*"
                        or _domain_is_broad(
                            domain or ""
                        )
                    )
                    else "REVIEW REQUIRED"
                )

                findings.append(
                    _finding(
                        "insecure_cross_domain_transport",
                        severity,
                        "HIGH",
                        (
                            "allow-access-from explicitly "
                            "allows insecure HTTP-origin "
                            "cross-domain access."
                        ),
                        {
                            "domain": domain,
                            "secure": False,
                        },
                    )
                )

            # --------------------------------------------
            # Ports
            # --------------------------------------------

            if port_errors:

                findings.append(
                    _finding(
                        "invalid_port_specification",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-access-from contains "
                            "an invalid to-ports specification."
                        ),
                        {
                            "to_ports": to_ports,
                            "errors": port_errors,
                        },
                    )
                )

            if port_wildcard:

                findings.append(
                    _finding(
                        "wildcard_socket_ports",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-access-from grants "
                            "socket access across all ports."
                        ),
                        {
                            "to_ports": to_ports,
                        },
                    )
                )

            elif _ports_are_broad(
                ranges,
                port_wildcard,
            ):

                findings.append(
                    _finding(
                        "broad_socket_port_range",
                        "REVIEW REQUIRED",
                        "MEDIUM",
                        (
                            "allow-access-from specifies "
                            "a broad socket port range."
                        ),
                        {
                            "to_ports": to_ports
                        },
                    )
                )

            continue

        # ====================================================
        # ALLOW HTTP REQUEST HEADERS FROM
        # ====================================================

        if tag == "allow-http-request-headers-from":

            domain = attrs.get(
                "domain"
            )

            headers = _split_header_list(
                attrs.get("headers")
            )

            secure, secure_state = (
                _parse_boolean_attribute(attrs)
            )

            entry = {
                "attributes": attrs,
                "domain": domain,
                "headers": headers,
                "secure": secure,
                "secure_state": secure_state,
            }

            policy[
                "allow_http_request_headers_from"
            ].append(entry)

            if not domain:

                findings.append(
                    _finding(
                        "missing_header_policy_domain",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-http-request-headers-from "
                            "is missing its domain attribute."
                        ),
                        {
                            "attributes": attrs
                        },
                    )
                )

            elif _domain_is_wildcard(
                domain
            ):

                severity = (
                    "UNSAFE"
                    if _headers_are_broad(headers)
                    else "REVIEW REQUIRED"
                )

                findings.append(
                    _finding(
                        "wildcard_header_origin",
                        severity,
                        "HIGH",
                        (
                            "Custom request headers may be "
                            "submitted from any requesting domain."
                        ),
                        {
                            "domain": domain,
                            "headers": headers,
                        },
                    )
                )

            elif _domain_is_broad(
                domain
            ):

                findings.append(
                    _finding(
                        "broad_header_origin",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "Header permission applies to a "
                            "broad wildcard domain."
                        ),
                        {
                            "domain": domain,
                            "headers": headers,
                        },
                    )
                )

            if not headers:

                findings.append(
                    _finding(
                        "missing_header_list",
                        "REVIEW REQUIRED",
                        "MEDIUM",
                        (
                            "Header permission element does not "
                            "specify a header list."
                        ),
                        {
                            "domain": domain
                        },
                    )
                )

            elif _headers_are_broad(
                headers
            ):

                severity = (
                    "UNSAFE"
                    if _domain_is_wildcard(
                        domain or ""
                    )
                    else "REVIEW REQUIRED"
                )

                findings.append(
                    _finding(
                        "wildcard_header_permission",
                        severity,
                        "HIGH",
                        (
                            "The policy allows a broad set "
                            "of HTTP request headers."
                        ),
                        {
                            "domain": domain,
                            "headers": headers,
                        },
                    )
                )

            if secure_state == "invalid":

                findings.append(
                    _finding(
                        "invalid_header_secure_attribute",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "allow-http-request-headers-from "
                            "contains an invalid secure attribute."
                        ),
                        {
                            "secure": attrs.get(
                                "secure"
                            )
                        },
                    )
                )

            elif secure is False:

                findings.append(
                    _finding(
                        "insecure_header_transport",
                        (
                            "UNSAFE"
                            if _domain_is_wildcard(
                                domain or ""
                            )
                            and _headers_are_broad(
                                headers
                            )
                            else "REVIEW REQUIRED"
                        ),
                        "HIGH",
                        (
                            "The policy permits custom "
                            "request headers from an insecure "
                            "HTTP-origin context."
                        ),
                        {
                            "domain": domain,
                            "headers": headers,
                            "secure": False,
                        },
                    )
                )

            continue

        # Unknown policy element
        findings.append(
            _finding(
                "unknown_policy_element",
                "REVIEW REQUIRED",
                "MEDIUM",
                (
                    "The cross-domain policy contains an "
                    "unrecognized element that should be manually "
                    "validated."
                ),
                {
                    "element": tag,
                    "attributes": attrs,
                },
            )
        )

    # --------------------------------------------------------
    # Cross-element combinations
    # --------------------------------------------------------

    global_access = [
        item
        for item in policy["allow_access_from"]
        if item.get("domain") == "*"
    ]

    global_headers = [
        item
        for item in policy[
            "allow_http_request_headers_from"
        ]
        if item.get("domain") == "*"
    ]

    if global_access and global_headers:

        headers_are_wildcard = any(
            "*" in item.get("headers", [])
            for item in global_headers
        )

        if headers_are_wildcard:

            findings.append(
                _finding(
                    "maximally_permissive_policy",
                    "UNSAFE",
                    "HIGH",
                    (
                        "The policy combines unrestricted "
                        "cross-domain data access with unrestricted "
                        "custom-header permissions."
                    ),
                    {
                        "global_access_rules": len(
                            global_access
                        ),
                        "global_header_rules": len(
                            global_headers
                        ),
                    },
                )
            )

    return policy, findings


# ============================================================
# RIA POLICY ANALYSIS — CLIENTACCESSPOLICY.XML
# ============================================================

def _analyze_clientaccess_policy(
    root,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:

    findings: list[dict[str, Any]] = []

    policy: dict[str, Any] = {
        "type": "clientaccesspolicy.xml",
        "allow_from": [],
        "grant_to": [],
        "unknown_elements": [],
    }

    root_name = _local_name(
        root.tag
    )

    if root_name != "access-policy":

        findings.append(
            _finding(
                "invalid_clientaccess_root",
                "REVIEW REQUIRED",
                "HIGH",
                (
                    "The document does not use "
                    "<access-policy> as the root element."
                ),
                {
                    "root_element": root_name
                },
            )
        )

        return policy, findings

    for node in root.iter():

        if node is root:
            continue

        tag = _local_name(node.tag)
        attrs = _attribute_map(node)

        # ====================================================
        # ALLOW FROM
        # ====================================================

        if tag == "allow-from":

            headers = _split_header_list(
                attrs.get(
                    "http-request-headers"
                )
            )

            entry = {
                "attributes": attrs,
                "headers": headers,
                "domains": [],
            }

            policy[
                "allow_from"
            ].append(entry)

            if _headers_are_broad(
                headers
            ):

                findings.append(
                    _finding(
                        "clientaccess_wildcard_headers",
                        "REVIEW REQUIRED",
                        "HIGH",
                        (
                            "Silverlight clientaccess policy "
                            "allows a broad set of HTTP request "
                            "headers."
                        ),
                        {
                            "headers": headers
                        },
                    )
                )

            for child in list(node):

                if _local_name(
                    child.tag
                ) != "domain":
                    continue

                child_attrs = (
                    _attribute_map(child)
                )

                uri = child_attrs.get(
                    "uri"
                )

                entry[
                    "domains"
                ].append(uri)

                if not uri:
                    findings.append(
                        _finding(
                            "missing_clientaccess_domain",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "A Silverlight policy domain "
                                "element is missing its URI."
                            ),
                            {
                                "attributes": child_attrs
                            },
                        )
                    )
                    continue

                if uri == "*":

                    findings.append(
                        _finding(
                            "clientaccess_global_wildcard",
                            "UNSAFE",
                            "HIGH",
                            (
                                "clientaccesspolicy.xml allows "
                                "access from any origin."
                            ),
                            {
                                "uri": uri
                            },
                        )
                    )

                elif not uri.startswith(
                    ("http://", "https://")
                ):

                    findings.append(
                        _finding(
                            "invalid_clientaccess_domain",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "The Silverlight policy domain "
                                "URI is not an HTTP(S) origin."
                            ),
                            {
                                "uri": uri
                            },
                        )
                    )

            continue

        # ====================================================
        # GRANT TO
        # ====================================================

        if tag == "grant-to":

            policy[
                "grant_to"
            ].append(
                {
                    "attributes": attrs,
                    "resources": [],
                }
            )

            for child in list(node):

                if _local_name(
                    child.tag
                ) != "resource":
                    continue

                child_attrs = (
                    _attribute_map(child)
                )

                path = child_attrs.get(
                    "path",
                    "",
                )

                include_subpaths = (
                    child_attrs.get(
                        "include-subpaths",
                        "false",
                    )
                    .lower()
                    == "true"
                )

                resource = {
                    "path": path,
                    "include_subpaths": (
                        include_subpaths
                    ),
                    "attributes": child_attrs,
                }

                policy[
                    "grant_to"
                ][-1][
                    "resources"
                ].append(resource)

                if (
                    path == "/"
                    and include_subpaths
                ):

                    findings.append(
                        _finding(
                            "clientaccess_entire_site",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "The Silverlight policy grants "
                                "cross-domain access across the "
                                "entire site."
                            ),
                            {
                                "path": path,
                                "include_subpaths": (
                                    include_subpaths
                                ),
                            },
                        )
                    )

            continue

        findings.append(
            _finding(
                "unknown_clientaccess_element",
                "REVIEW REQUIRED",
                "MEDIUM",
                (
                    "The clientaccess policy contains an "
                    "unrecognized element requiring review."
                ),
                {
                    "element": tag,
                    "attributes": attrs,
                },
            )
        )

    # Broad origin + broad resource combination.
    for allow in policy["allow_from"]:

        domains = allow.get(
            "domains",
            [],
        )

        if "*" not in domains:
            continue

        for grant in policy["grant_to"]:

            for resource in grant.get(
                "resources",
                [],
            ):

                if (
                    resource["path"] == "/"
                    and resource["include_subpaths"]
                ):

                    findings.append(
                        _finding(
                            "clientaccess_maximally_broad",
                            "UNSAFE",
                            "HIGH",
                            (
                                "clientaccesspolicy.xml combines "
                                "a wildcard origin with permission "
                                "covering the entire target site."
                            ),
                            {
                                "domains": domains,
                                "resource": resource,
                            },
                        )
                    )

    return policy, findings


# ============================================================
# POLICY TYPE DETECTION
# ============================================================

def _detect_policy_type(
    root,
) -> str | None:

    name = _local_name(
        root.tag
    )

    if name == "cross-domain-policy":
        return "crossdomain.xml"

    if name == "access-policy":
        return "clientaccesspolicy.xml"

    return None


# ============================================================
# DISCOVER SWF / SILVERLIGHT RESOURCE DIRECTORIES
# ============================================================

_SWF_PATTERN = re.compile(
    r"""
    (?:
        ["']
    )
    (
        [^"']+\.swf(?:\?[^"']*)?
    )
    (?:
        ["']
    )
    """,
    re.I | re.X,
)

_POLICY_PATH_PATTERN = re.compile(
    r"""
    (?:
        ["']
    )
    (
        [^"']*(?:crossdomain|clientaccesspolicy)\.xml
    )
    (?:
        ["']
    )
    """,
    re.I | re.X,
)


def _discover_policy_paths(
    base: str,
    html: str,
) -> list[str]:

    candidates: list[str] = []

    # Root policy files
    for filename in STANDARD_POLICY_NAMES:
        candidates.append(
            urljoin(
                base + "/",
                filename,
            )
        )

    # Explicit policy references.
    for match in _POLICY_PATH_PATTERN.finditer(
        html or ""
    ):

        raw = match.group(1)

        absolute = urljoin(
            base,
            raw,
        )

        if same_origin(
            base,
            absolute,
        ):
            candidates.append(
                absolute
            )

    # SWF-relative policy locations.
    swf_urls: list[str] = []

    for match in _SWF_PATTERN.finditer(
        html or ""
    ):

        absolute = urljoin(
            base,
            match.group(1),
        )

        if same_origin(
            base,
            absolute,
        ):
            swf_urls.append(
                absolute
            )

    for swf_url in swf_urls[
        :MAX_SWF_REFERENCES
    ]:

        parsed = urlparse(
            swf_url
        )

        directory = (
            parsed.path.rsplit(
                "/",
                1,
            )[0]
            + "/"
        )

        directory_url = (
            f"{parsed.scheme}://"
            f"{parsed.netloc}"
            f"{directory}"
        )

        for filename in STANDARD_POLICY_NAMES:

            candidates.append(
                urljoin(
                    directory_url,
                    filename,
                )
            )

    # Also inspect a bounded number of likely directories
    # visible in HTML links.
    href_pattern = re.compile(
        r'href\s*=\s*["\']([^"\']+)["\']',
        re.I,
    )

    for match in href_pattern.finditer(
        html or ""
    ):

        absolute = urljoin(
            base,
            match.group(1),
        )

        if not same_origin(
            base,
            absolute,
        ):
            continue

        parsed = urlparse(
            absolute
        )

        path = parsed.path.lower()

        if not any(
            f"/{hint}/" in (
                path + "/"
            )
            for hint in SUSPICIOUS_DIRECTORY_HINTS
        ):
            continue

        directory = (
            path.rsplit(
                "/",
                1,
            )[0]
            + "/"
        )

        directory_url = (
            f"{parsed.scheme}://"
            f"{parsed.netloc}"
            f"{directory}"
        )

        for filename in STANDARD_POLICY_NAMES:
            candidates.append(
                urljoin(
                    directory_url,
                    filename,
                )
            )

    # Deduplicate and bound.
    output: list[str] = []
    seen: set[str] = set()

    for candidate in candidates:

        parsed = urlparse(
            candidate
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            continue

        if candidate in seen:
            continue

        seen.add(candidate)
        output.append(candidate)

        if len(output) >= MAX_DISCOVERED_PATHS:
            break

    return output


# ============================================================
# FETCH POLICY DOCUMENT
# ============================================================

def _fetch_policy(
    url: str,
    verify_tls: bool,
    timeout: float,
):

    try:
        return request(
            url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            max_body=MAX_BODY_BYTES,
        )

    except Exception:
        return None


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_crossdomain_xml(
    url: str,
    verify_tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:

    base = normalize_url(
        url
    )

    # --------------------------------------------------------
    # Fetch root document for discovery
    # --------------------------------------------------------

    try:
        root_response = request(
            base,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            max_body=750_000,
        )

        root_html = (
            root_response.text or ""
            if root_response.status_code == 200
            else ""
        )

    except Exception:
        root_html = ""

    # --------------------------------------------------------
    # Discover policy files
    # --------------------------------------------------------

    candidate_policies = _discover_policy_paths(
        base,
        root_html,
    )

    checked: list[dict[str, Any]] = []

    global_findings: list[dict[str, Any]] = []

    policy_types = Counter()

    connection_failures = 0

    unexpected_responses = 0

    accessible_policy_count = 0

    # --------------------------------------------------------
    # Bounded fetch
    # --------------------------------------------------------

    for policy_url in candidate_policies:

        if len(checked) >= MAX_POLICY_FILES:
            break

        response = _fetch_policy(
            policy_url,
            verify_tls=verify_tls,
            timeout=timeout,
        )

        if response is None:

            connection_failures += 1

            checked.append(
                {
                    "url": policy_url,
                    "state": "connection_failed",
                }
            )

            continue

        status_code = (
            response.status_code
        )

        content_type = (
            response.headers.get(
                "Content-Type",
                "",
            )
        )

        entry: dict[str, Any] = {
            "url": policy_url,
            "status_code": status_code,
            "content_type": content_type,
        }

        # ====================================================
        # REDIRECT
        # ====================================================

        if status_code in {
            301,
            302,
            303,
            307,
            308,
        }:

            location = (
                response.headers.get(
                    "Location"
                )
            )

            entry["state"] = "redirect"
            entry["location"] = location

            if location:

                redirected = urljoin(
                    policy_url,
                    location,
                )

                entry[
                    "redirect_same_origin"
                ] = same_origin(
                    base,
                    redirected,
                )

                if not same_origin(
                    base,
                    redirected,
                ):

                    global_findings.append(
                        _finding(
                            "cross_origin_policy_redirect",
                            "REVIEW REQUIRED",
                            "HIGH",
                            (
                                "A cross-domain policy request "
                                "redirects to another origin."
                            ),
                            {
                                "policy_url": policy_url,
                                "location": redirected,
                            },
                        )
                    )

            checked.append(entry)
            continue

        # ====================================================
        # NOT FOUND
        # ====================================================

        if status_code in {
            404,
            410,
        }:

            entry["state"] = "not_found"

            checked.append(entry)
            continue

        # ====================================================
        # ACCESS FORBIDDEN
        # ====================================================

        if status_code in {
            401,
            403,
        }:

            entry["state"] = (
                "access_denied"
            )

            checked.append(entry)
            continue

        # ====================================================
        # OTHER STATUS
        # ====================================================

        if status_code != 200:

            unexpected_responses += 1

            entry["state"] = (
                "unexpected_status"
            )

            global_findings.append(
                _finding(
                    "unexpected_policy_response",
                    "REVIEW REQUIRED",
                    "MEDIUM",
                    (
                        "A candidate cross-domain policy "
                        "resource returned an unexpected "
                        f"HTTP status: {status_code}."
                    ),
                    {
                        "url": policy_url,
                        "status_code": status_code,
                    },
                )
            )

            checked.append(entry)
            continue

        accessible_policy_count += 1

        body = response.text or ""

        # ====================================================
        # XML PARSE
        # ====================================================

        root = _safe_xml_parse(
            body
        )

        if root is None:

            entry["state"] = (
                "invalid_xml"
            )

            global_findings.append(
                _finding(
                    "invalid_policy_xml",
                    "REVIEW REQUIRED",
                    "HIGH",
                    (
                        "The policy file is publicly reachable "
                        "but is not valid XML."
                    ),
                    {
                        "url": policy_url,
                        "content_type": content_type,
                    },
                )
            )

            checked.append(entry)
            continue

        policy_type = _detect_policy_type(
            root
        )

        entry["policy_type"] = (
            policy_type
        )

        entry["root_element"] = _local_name(
            root.tag
        )

        # ====================================================
        # CONTENT-TYPE
        # ====================================================

        content_type_lower = (
            content_type.lower()
        )

        if content_type and not any(
            token in content_type_lower
            for token in (
                "xml",
                "text/plain",
                "application/octet-stream",
            )
        ):

            global_findings.append(
                _finding(
                    "unexpected_policy_content_type",
                    "REVIEW REQUIRED",
                    "MEDIUM",
                    (
                        "A cross-domain policy resource is "
                        "reachable with an unexpected "
                        "Content-Type."
                    ),
                    {
                        "url": policy_url,
                        "content_type": content_type,
                    },
                )
            )

        # ====================================================
        # UNKNOWN DOCUMENT TYPE
        # ====================================================

        if policy_type is None:

            entry["state"] = (
                "unknown_policy_type"
            )

            global_findings.append(
                _finding(
                    "unknown_policy_document",
                    "REVIEW REQUIRED",
                    "HIGH",
                    (
                        "A publicly reachable policy-looking "
                        "XML document does not match either "
                        "crossdomain.xml or clientaccesspolicy.xml "
                        "schema family."
                    ),
                    {
                        "url": policy_url,
                        "root_element": _local_name(
                            root.tag
                        ),
                    },
                )
            )

            checked.append(entry)
            continue

        policy_types[
            policy_type
        ] += 1

        # ====================================================
        # POLICY-SPECIFIC ANALYSIS
        # ====================================================

        if policy_type == (
            "crossdomain.xml"
        ):

            policy, findings = (
                _analyze_crossdomain_policy(
                    root
                )
            )

        else:

            policy, findings = (
                _analyze_clientaccess_policy(
                    root
                )
            )

        entry[
            "state"
        ] = "parsed"

        entry[
            "policy"
        ] = policy

        entry[
            "findings"
        ] = findings

        global_findings.extend(
            findings
        )

        checked.append(
            entry
        )

        if len(global_findings) >= (
            MAX_FINDINGS
        ):
            global_findings = (
                global_findings[
                    :MAX_FINDINGS
                ]
            )
            break

    # --------------------------------------------------------
    # Overall finding counts
    # --------------------------------------------------------

    unsafe = [
        item
        for item in global_findings
        if item.get("severity")
        == "UNSAFE"
    ]

    review = [
        item
        for item in global_findings
        if item.get("severity")
        == "REVIEW REQUIRED"
    ]

    high_confidence = [
        item
        for item in global_findings
        if item.get("confidence")
        == "HIGH"
    ]

    # --------------------------------------------------------
    # Overall status
    # --------------------------------------------------------

    if unsafe:

        overall_status = (
            "UNSAFE"
        )

        summary = (
            "The target exposes a cross-domain policy "
            "containing strongly over-permissive permissions. "
            "The configuration should be reviewed and "
            "restricted according to least privilege."
        )

    elif review:

        overall_status = (
            "REVIEW REQUIRED"
        )

        summary = (
            "One or more cross-domain policy files were "
            "found with legacy, broad, malformed, or "
            "context-dependent permissions requiring review."
        )

    elif accessible_policy_count > 0:

        overall_status = (
            "SAFE"
        )

        summary = (
            "Cross-domain policy files were found and "
            "parsed successfully. No clearly over-permissive "
            "policy condition was detected by the bounded "
            "assessment."
        )

    elif unexpected_responses:

        overall_status = (
            "REVIEW REQUIRED"
        )

        summary = (
            "Candidate cross-domain policy locations "
            "returned unexpected responses."
        )

    elif connection_failures and not checked:

        overall_status = (
            "INCOMPLETE"
        )

        summary = (
            "The scanner could not reliably determine "
            "whether cross-domain policy files are present."
        )

    else:

        overall_status = (
            "SAFE"
        )

        summary = (
            "No accessible cross-domain policy file was "
            "identified at the tested locations."
        )

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence: list[str] = []

    for item in unsafe[:25]:

        evidence.append(
            (
                f"{item['type']}: "
                f"{item['message']}"
            )
        )

    for item in review[:25]:

        evidence.append(
            (
                f"{item['type']}: "
                f"{item['message']}"
            )
        )

    # --------------------------------------------------------
    # Return structured result
    # --------------------------------------------------------

    details: dict[str, Any] = {

        "target": base,

        "candidate_policy_urls": (
            candidate_policies
        ),

        "policy_files_checked": checked,

        "accessible_policy_count": (
            accessible_policy_count
        ),

        "policy_types": dict(
            policy_types
        ),

        "finding_counts": {
            "total": len(
                global_findings
            ),
            "unsafe": len(
                unsafe
            ),
            "review_required": len(
                review
            ),
            "high_confidence": len(
                high_confidence
            ),
        },

        "limits": {
            "max_policy_files": (
                MAX_POLICY_FILES
            ),
            "max_body_bytes": (
                MAX_BODY_BYTES
            ),
            "max_discovered_paths": (
                MAX_DISCOVERED_PATHS
            ),
            "max_swf_references": (
                MAX_SWF_REFERENCES
            ),
            "max_findings": (
                MAX_FINDINGS
            ),
        },

        "connection_failures": (
            connection_failures
        ),

        "unexpected_responses": (
            unexpected_responses
        ),

        "findings": global_findings[
            :MAX_FINDINGS
        ],
    }

    return result(
        overall_status,
        summary,
        details,
        evidence,
    )