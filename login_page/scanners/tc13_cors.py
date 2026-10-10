"""TC13 - Cross-Origin Resource Sharing (CORS) security assessment.

Additive scanner: this module does not import or modify other testcase modules.
It performs bounded, non-destructive CORS preflight/simple-request probes and
reports observable policy behavior without attempting credential theft or
state-changing actions.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse
import re
import secrets

import requests

from payloads.manager import load_lines


STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_ASSESSED = "NOT ASSESSED"
STATUS_ERROR = "ERROR"

DEFAULT_TIMEOUT = 8.0
MAX_PROBES = 12


@dataclass(frozen=True)
class CORSProbe:
    name: str
    origin: str
    method: str = "GET"
    access_control_request_method: str | None = None
    access_control_request_headers: str | None = None
    credentials: bool = False


@dataclass
class CORSConfig:
    timeout: float = DEFAULT_TIMEOUT
    verify_tls: bool = True
    max_probes: int = MAX_PROBES
    include_preflight: bool = True
    include_credentials_probe: bool = True
    allow_redirects: bool = False
    user_agent: str = "SecurityAssessmentTestExecutor-TC13/1.0"


def _normalise_target(target: str) -> str:
    value = (target or "").strip()
    if not value:
        raise ValueError("target URL is empty")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError("target URL has no hostname")
    return value.rstrip("/") + (parsed.path or "")


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.hostname:
        return ""
    host = p.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{p.scheme}://{host}" + (f":{p.port}" if p.port else "")


def _cross_origin_candidates(target: str, marker: str) -> list[str]:
    own = _origin(target)
    p = urlparse(target)
    host = p.hostname or "example.invalid"
    templates = load_lines(
        "payloads_all_the_things/cors/origin_probe_templates.txt",
        limit=4,
    )
    candidates = [template.format(marker=marker, hostname=host) for template in templates]
    # Use reserved .invalid origins and null; never contact third-party sites.
    return list(dict.fromkeys(x for x in candidates if x.lower() != own.lower()))


def _headers(response: requests.Response) -> dict[str, str]:
    return {k.lower(): v for k, v in response.headers.items()}


def _cors_fields(response: requests.Response) -> dict[str, Any]:
    h = _headers(response)
    return {
        "access_control_allow_origin": h.get("access-control-allow-origin"),
        "access_control_allow_credentials": h.get("access-control-allow-credentials"),
        "access_control_allow_methods": h.get("access-control-allow-methods"),
        "access_control_allow_headers": h.get("access-control-allow-headers"),
        "access_control_expose_headers": h.get("access-control-expose-headers"),
        "vary": h.get("vary"),
        "status_code": response.status_code,
    }


def _acao_matches_origin(acao: str | None, origin: str) -> bool:
    if not acao:
        return False
    return acao.strip() == origin


def _acao_wildcard(acao: str | None) -> bool:
    return bool(acao and acao.strip() == "*")


def _truthy_credentials(value: str | None) -> bool:
    return bool(value and value.strip().lower() == "true")


def _classify_probe(probe: CORSProbe, cors: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    acao = cors.get("access_control_allow_origin")
    acac = cors.get("access_control_allow_credentials")

    if not acao:
        return STATUS_SAFE, ["No Access-Control-Allow-Origin header was returned for this origin probe."]

    if probe.credentials and _acao_wildcard(acao) and _truthy_credentials(acac):
        return STATUS_UNSAFE, [
            "Wildcard ACAO (*) was combined with Access-Control-Allow-Credentials: true."
        ]

    if probe.credentials and _acao_matches_origin(acao, probe.origin) and _truthy_credentials(acac):
        return STATUS_UNSAFE, [
            "A cross-origin credentialed request was explicitly allowed for the attacker-controlled origin."
        ]

    if _acao_wildcard(acao):
        if probe.credentials:
            return STATUS_REVIEW, [
                "Wildcard ACAO is present on a credentialed probe, but credentials were not simultaneously allowed."
            ]
        return STATUS_REVIEW, [
            "Wildcard ACAO permits cross-origin reads for non-credentialed requests; impact depends on resource sensitivity."
        ]

    if _acao_matches_origin(acao, probe.origin):
        if probe.credentials:
            if _truthy_credentials(acac):
                return STATUS_UNSAFE, [
                    "Arbitrary cross-origin credentialed access appears permitted for the supplied origin."
                ]
            return STATUS_REVIEW, [
                "The supplied cross-origin origin is reflected/allowed, but credentialed access was not enabled."
            ]
        return STATUS_REVIEW, [
            "The supplied cross-origin origin is allowed; resource sensitivity and origin trust model require review."
        ]

    return STATUS_SAFE, [f"CORS policy did not grant the tested origin (ACAO={acao!r})."]


def _severity_rank(status: str) -> int:
    return {
        STATUS_UNSAFE: 5,
        STATUS_REVIEW: 4,
        STATUS_INCOMPLETE: 3,
        STATUS_ERROR: 2,
        STATUS_NOT_ASSESSED: 1,
        STATUS_SAFE: 0,
    }.get(status, 2)


def _rollup(statuses: Iterable[str]) -> str:
    values = list(statuses)
    if not values:
        return STATUS_INCOMPLETE
    return max(values, key=_severity_rank)


def _request(
    session: requests.Session,
    target: str,
    probe: CORSProbe,
    config: CORSConfig,
) -> dict[str, Any]:
    headers = {
        "User-Agent": config.user_agent,
        "Origin": probe.origin,
        "Accept": "*/*",
        "Cache-Control": "no-cache",
    }
    if probe.access_control_request_method:
        headers["Access-Control-Request-Method"] = probe.access_control_request_method
    if probe.access_control_request_headers:
        headers["Access-Control-Request-Headers"] = probe.access_control_request_headers

    method = "OPTIONS" if probe.name.startswith("preflight_") else probe.method
    try:
        response = session.request(
            method,
            target,
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_tls,
            allow_redirects=config.allow_redirects,
        )
        cors = _cors_fields(response)
        status, reasons = _classify_probe(probe, cors)
        return {
            "name": probe.name,
            "request_method": method,
            "origin": probe.origin,
            "credentials_probe": probe.credentials,
            "status": status,
            "reason": reasons,
            "response": cors,
            "final_url": response.url,
        }
    except requests.exceptions.SSLError as exc:
        return {"name": probe.name, "origin": probe.origin, "status": STATUS_INCOMPLETE,
                "reason": [f"TLS verification failed: {type(exc).__name__}"], "error": "tls_error"}
    except requests.RequestException as exc:
        return {"name": probe.name, "origin": probe.origin, "status": STATUS_INCOMPLETE,
                "reason": [f"Request failed: {type(exc).__name__}"], "error": "request_error"}


def _build_probes(target: str, config: CORSConfig) -> list[CORSProbe]:
    marker = "tc13-" + secrets.token_hex(4)
    origins = _cross_origin_candidates(target, marker)
    probes: list[CORSProbe] = []

    for idx, origin in enumerate(origins[:4]):
        probes.append(CORSProbe(name=f"simple_cross_origin_{idx+1}", origin=origin))

    if config.include_preflight:
        for idx, origin in enumerate(origins[:2]):
            probes.append(CORSProbe(
                name=f"preflight_{idx+1}",
                origin=origin,
                access_control_request_method="GET",
                access_control_request_headers="X-TC13-Probe",
            ))

    if config.include_credentials_probe:
        for idx, origin in enumerate(origins[:2]):
            probes.append(CORSProbe(
                name=f"credentialed_origin_{idx+1}",
                origin=origin,
                credentials=True,
            ))

    return probes[: config.max_probes]


def scan_cors(
    target: str,
    *,
    config: CORSConfig | None = None,
    timeout: float | None = None,
    verify_tls: bool = True,
    **_: Any,
) -> dict[str, Any]:
    """Run TC13 CORS checks with a bounded, non-destructive request budget."""
    try:
        normalized = _normalise_target(target)
    except ValueError as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "The target URL could not be normalized.",
            "details": {"error": str(exc)},
            "evidence": [],
        }

    cfg = config or CORSConfig(verify_tls=verify_tls)
    if timeout is not None:
        cfg.timeout = timeout
    cfg.verify_tls = verify_tls if config is None else cfg.verify_tls
    cfg.max_probes = max(1, min(int(cfg.max_probes), MAX_PROBES))

    target_origin = _origin(normalized)
    if not target_origin:
        return {"status": STATUS_INCOMPLETE, "summary": "No valid target origin was found.", "details": {}, "evidence": []}

    session = requests.Session()
    probes = _build_probes(normalized, cfg)
    results: list[dict[str, Any]] = []
    try:
        for probe in probes:
            results.append(_request(session, normalized, probe, cfg))
    finally:
        session.close()

    statuses = [r["status"] for r in results]
    final_status = _rollup(statuses)

    confirmed = [r for r in results if r["status"] == STATUS_UNSAFE]
    review = [r for r in results if r["status"] == STATUS_REVIEW]
    triggering_source = confirmed[0] if confirmed else (review[0] if review else None)
    triggering = None
    if triggering_source:
        triggering = {
            "name": triggering_source.get("name"),
            "payload": triggering_source.get("origin"),
            "reason": " ".join(triggering_source.get("reason") or []),
            "verdict": triggering_source.get("status"),
        }

    if confirmed:
        summary = (
            f"CORS policy testing observed cross-origin credentialed access. "
            f"Origin probe {triggering['payload']!r} ({triggering['name']}) produced UNSAFE behavior: "
            f"{triggering['reason']}"
        )
    elif review:
        summary = (
            "CORS probing observed a reflected or wildcard origin policy that a pentester would "
            f"flag for review. Origin {triggering['payload']!r}: {triggering['reason']}"
        )
    else:
        summary = "CORS probing completed with no unsafe cross-origin credentialed access observed."

    evidence = []
    for r in results:
        if r["status"] in (STATUS_UNSAFE, STATUS_REVIEW):
            evidence.append(
                f"{r['name']}: origin {r.get('origin')!r} → {r['status']} — {' '.join(r['reason'])}"
            )

    return {
        "status": final_status,
        "summary": summary,
        "details": {
            "target": normalized,
            "target_origin": target_origin,
            "probe_count": len(results),
            "payloads_used": [{"name": r.get("name"), "payload": r.get("origin"), "kind": "origin"} for r in results],
            "triggering_payload": triggering,
            "payload_library": {
                "source": "PayloadsAllTheThings CORS-origin testing approach; reserved-origin templates",
                "file": "payloads/payloads_all_the_things/cors/origin_probe_templates.txt",
                "items_used": len({probe.origin for probe in probes}),
            },
            "max_probe_budget": cfg.max_probes,
            "probes": results,
            "unsafe_probe_count": len(confirmed),
            "review_probe_count": len(review),
            "limitations": [
                "The scanner does not attempt to steal or replay authenticated data.",
                "Wildcard ACAO without credentials is reported for review rather than automatically treated as a vulnerability.",
                "Application sensitivity and intended trusted origins determine real-world impact.",
                "Only the supplied target URL is probed; no unrestricted crawling is performed.",
            ],
        },
        "evidence": evidence,
        "raw_output": "",
    }


# Runner compatibility alias.
def scan(target: str, **kwargs: Any) -> dict[str, Any]:
    return scan_cors(target, **kwargs)
