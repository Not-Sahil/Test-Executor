"""Common SQL Injection testing engine for test executor.

Provides shared target discovery, baseline collection, parameter injection,
dynamic content normalization, and evidence generation across all SQLi variants.
"""
from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from core.http_client import effective_verify_tls

STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_ERROR = "ERROR"

SQL_ERROR_PATTERNS = {
    "mysql": re.compile(r"mysql|mysqli|you have an error in your sql syntax|warning.*mysql", re.I),
    "postgresql": re.compile(r"postgresql|postgres|pg_query|unterminated quoted string", re.I),
    "mssql": re.compile(r"microsoft sql server|\bsql server\b|odbc sql server|unclosed quotation mark", re.I),
    "oracle": re.compile(r"ora-\d{4,5}|oracle.*error|quoted string not properly terminated", re.I),
    "sqlite": re.compile(r"sqlite|sqlite3|near \".*\": syntax error", re.I),
    "generic": re.compile(r"sql syntax|sqlstate|database error|db error|query failed|syntax error.*sql", re.I),
}

DYNAMIC_REDACTIONS = [
    (re.compile(r"csrf[_\-a-z0-9]*[=:]\s*['\"]?[a-zA-Z0-9\-_+/=]+['\"]?", re.I), "csrf=<redacted>"),
    (re.compile(r"token[_\-a-z0-9]*[=:]\s*['\"]?[a-zA-Z0-9\-_+/=]+['\"]?", re.I), "token=<redacted>"),
    (re.compile(r"nonce[_\-a-z0-9]*[=:]\s*['\"]?[a-zA-Z0-9\-_+/=]+['\"]?", re.I), "nonce=<redacted>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<timestamp>"),
    (re.compile(r"__VIEWSTATE(?:GENERATOR)?[=:][a-zA-Z0-9\-_+/=]+", re.I), "__VIEWSTATE=<redacted>"),
]


@dataclass
class TargetParam:
    param_type: str  # "query" or "form"
    name: str
    original_value: str
    url: str
    method: str = "get"
    form_data: dict[str, str] | None = None


def normalize_body(text: str) -> str:
    """Normalize HTML/dynamic text for reliable differential comparisons."""
    t = html.unescape(text or "")
    for pattern, repl in DYNAMIC_REDACTIONS:
        t = pattern.sub(repl, t)
    t = re.sub(r"\s+", " ", t)
    return t.strip().lower()


def detect_sql_errors(text: str, baseline_errors: set[str] | None = None) -> list[str]:
    """Detect disclosed SQL/database errors excluding any seen in baseline."""
    base = baseline_errors or set()
    found = []
    for name, rx in SQL_ERROR_PATTERNS.items():
        if rx.search(text or "") and name not in base:
            found.append(name)
    return sorted(found)


def discover_targets(base_url: str, response: requests.Response) -> list[TargetParam]:
    """Extract query parameters and form fields from page."""
    targets: list[TargetParam] = []

    # 1. Query parameters
    p = urlsplit(response.url or base_url)
    if p.query:
        for name, value in parse_qsl(p.query, keep_blank_values=True):
            if name.lower() not in {"csrf", "token", "nonce", "_csrf", "authenticity_token"}:
                targets.append(TargetParam(
                    param_type="query",
                    name=name,
                    original_value=value or "1",
                    url=response.url or base_url,
                    method="get",
                ))

    # 2. Forms on page
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text or "", "html.parser")
        for form in soup.find_all("form")[:10]:
            action = urljoin(response.url or base_url, form.get("action") or response.url or base_url)
            method = str(form.get("method") or "get").lower()
            fields: dict[str, str] = {}
            injectable_fields: list[str] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                fname = inp.get("name")
                if not fname:
                    continue
                ftype = str(inp.get("type") or "text").lower()
                fval = inp.get("value") or ""
                fields[fname] = fval
                if ftype not in {"hidden", "submit", "button", "reset", "image", "file"}:
                    if fname.lower() not in {"csrf", "token", "nonce"}:
                        injectable_fields.append(fname)

            for ifield in injectable_fields:
                targets.append(TargetParam(
                    param_type="form",
                    name=ifield,
                    original_value=fields.get(ifield, "test"),
                    url=action,
                    method=method,
                    form_data=dict(fields),
                ))
    except Exception:
        pass

    # If no parameters discovered, add common URL query candidates
    if not targets:
        targets.append(TargetParam(
            param_type="query",
            name="id",
            original_value="1",
            url=urlunsplit((p.scheme or "http", p.netloc, p.path or "/", "id=1", "")),
            method="get",
        ))

    return targets[:8]


def execute_probe(
    session: requests.Session,
    target: TargetParam,
    payload_value: str,
    *,
    timeout: float = 8.0,
    verify_tls: bool = True,
    verify: bool | None = None,
) -> tuple[requests.Response | None, float, str | None]:
    """Execute a single probe against a target parameter and measure response time."""
    if verify is not None:
        verify_tls = verify
    headers = {
        "User-Agent": "SecurityAssessmentTestExecutor-SQLi/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    start = time.perf_counter()
    try:
        if target.param_type == "query":
            p = urlsplit(target.url)
            query_pairs = parse_qsl(p.query, keep_blank_values=True)
            new_pairs = []
            found = False
            for k, v in query_pairs:
                if k == target.name and not found:
                    new_pairs.append((k, payload_value))
                    found = True
                else:
                    new_pairs.append((k, v))
            if not found:
                new_pairs.append((target.name, payload_value))
            new_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(new_pairs), p.fragment))
            resp = session.get(new_url, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
        else:
            data = dict(target.form_data or {})
            data[target.name] = payload_value
            if target.method == "post":
                resp = session.post(target.url, data=data, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
            else:
                resp = session.get(target.url, params=data, headers=headers, timeout=timeout, verify=verify_tls, allow_redirects=True)
        elapsed = time.perf_counter() - start
        return resp, elapsed, None
    except requests.exceptions.Timeout:
        elapsed = time.perf_counter() - start
        return None, elapsed, "Request timed out"
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return None, elapsed, str(exc)


def calculate_similarity(sig_a: str, sig_b: str) -> float:
    """Calculate SequenceMatcher similarity between two normalized signatures."""
    if not sig_a and not sig_b:
        return 1.0
    if not sig_a or not sig_b:
        return 0.0
    if sig_a == sig_b:
        return 1.0
    return round(SequenceMatcher(None, sig_a, sig_b, autojunk=False).ratio(), 4)
