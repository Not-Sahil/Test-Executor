import json
import os
from html import escape
from pathlib import Path

_BROWSER_DIR = Path(__file__).resolve().parent / ".playwright-browsers"
if _BROWSER_DIR.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_BROWSER_DIR))

import streamlit as st

from core.assessment_orchestrator import (
    captcha_auth_result,
    overall_status,
    ScanResult,
)
from pre_login.runner import run_pre_login_suite
from login_page.registry import LOGIN_PAGE_TESTS as LOGIN_PAGE_REGISTRY

from authentication.captcha_human import (
    human_login_with_captcha,
    probe_login_captcha,
)

from core.reporting import save_run_output
from core.cvss_scoring import annotate_result
from payloads.manager import payload_library_summary, source_catalog_summary
from core.target_policy import TargetPolicy, validate_target_url, same_origin


# ==============================================================
# CONFIGURATION
# ==============================================================

CREDENTIAL_FILE = (
    Path(__file__).resolve().parent
    / "authentication"
    / "credentials.json"
)

# Bounded common-default list used when credentials.json is not supplied.
# Intended for Default Credentials and User Enumeration on authorized targets.
COMMON_CREDENTIAL_FILE = (
    Path(__file__).resolve().parent
    / "authentication"
    / "common_default_credentials.json"
)

# Keep this conservative for authorized live testing.
# Set to None only when testing a controlled lab environment.
MAX_CREDENTIAL_ATTEMPTS = 100

# Deliberately invalid password used for user-enumeration comparison.
ENUMERATION_PROBE_PASSWORD = "__wrong_password_idnt04__"

# TLS policy for authorized assessments. Keep enabled for normal production use.
# Disable only when the target intentionally uses an expired/self-signed certificate.
VERIFY_TLS = True


# ==============================================================
# LOAD AUTHENTICATION DATABASE
# ==============================================================

def load_authentication_database():
    """
    Load the shared credential database.

    Prefer an operator-supplied authentication/credentials.json. When that
    file is absent, fall back to the bounded common-default list used to
    prove Default Credentials and User Enumeration findings.
    """

    source_path = CREDENTIAL_FILE if CREDENTIAL_FILE.exists() else COMMON_CREDENTIAL_FILE
    if not source_path.exists():
        return [], []

    with open(source_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            f"{source_path.name} must contain a JSON list of credential objects."
        )

    credentials = []
    seen_pairs = set()

    for item in data:
        if not isinstance(item, dict):
            continue

        username = str(item.get("username", "")).strip()
        password = str(item.get("password", ""))

        if not username:
            continue

        pair = (username, password)

        # Avoid testing exactly the same username/password pair twice.
        if pair in seen_pairs:
            continue

        seen_pairs.add(pair)

        credentials.append({
            "username": username,
            "password": password,
            "credential_source": str(
                item.get("credential_source")
                or item.get("credential_type")
                or "application_default"
            ).strip().lower(),
            "product_hint": str(
                item.get("product_hint", "generic")
            ).strip().lower() or "generic",
            "credential_type": str(
                item.get(
                    "credential_type",
                    "blank_password" if password == "" else "default"
                )
            ).strip().lower(),
            "known_valid_username": bool(item.get("known_valid_username", False)),
            "account_hint": str(item.get("account_hint") or "").strip(),
            "source_file": source_path.name,
        })

    # An empty list is valid for URL-only, unauthenticated assessment runs.
    # Tests requiring valid/default credentials must remain unassessed until
    # an explicitly authorized credential source is supplied.

    # Same database -> usernames for enumeration.
    candidate_usernames = list(dict.fromkeys(
        item["username"] for item in credentials
    ))

    return credentials, candidate_usernames


def _normalize_status(status: str) -> str:
    raw = str(status or "INCOMPLETE").strip()
    compact = raw.upper().replace("_", " ").replace("-", " ")
    aliases = {
        "REVIEW": "REVIEW REQUIRED",
        "REVIEW REQUIRED": "REVIEW REQUIRED",
        "NOT ASSESSED": "NOT ASSESSED",
        "NOT APPLICABLE": "NOT APPLICABLE",
        "NOT APPLICABLE.": "NOT APPLICABLE",
        "NA": "NOT APPLICABLE",
        "N.A.": "NOT APPLICABLE",
        "SKIPPED": "SKIPPED",
        "SAFE": "SAFE",
        "UNSAFE": "UNSAFE",
        "INCOMPLETE": "INCOMPLETE",
        "ERROR": "ERROR",
        "UNKNOWN": "UNKNOWN",
    }
    return aliases.get(compact, raw or "INCOMPLETE")


def _status_icon(status: str) -> str:
    status = _normalize_status(status)
    return {
        "SAFE": "🟢",
        "UNSAFE": "🔴",
        "REVIEW REQUIRED": "🟠",
        "SKIPPED": "⚪",
        "NOT APPLICABLE": "⚪",
        "NOT ASSESSED": "⚪",
        "ERROR": "⚠️",
        "INCOMPLETE": "⚠️",
        "UNKNOWN": "⚠️",
    }.get(status, "⚪")


def _status_label(status: str) -> str:
    status = _normalize_status(status)
    return {
        "SAFE": "Safe",
        "UNSAFE": "Unsafe",
        "REVIEW REQUIRED": "Requires Review",
        "SKIPPED": "Skipped",
        "NOT APPLICABLE": "Not Applicable",
        "NOT ASSESSED": "Not Assessed",
        "ERROR": "Error",
        "INCOMPLETE": "Incomplete",
        "UNKNOWN": "Unknown",
    }.get(status, status.title())


def _status_class(status: str) -> str:
    status = _normalize_status(status)
    return {
        "SAFE": "safe",
        "UNSAFE": "unsafe",
        "REVIEW REQUIRED": "review",
        "SKIPPED": "skipped",
        "NOT APPLICABLE": "skipped",
        "NOT ASSESSED": "skipped",
        "ERROR": "incomplete",
        "INCOMPLETE": "incomplete",
        "UNKNOWN": "incomplete",
    }.get(status, "neutral")


def _as_scan_result(result, key: str, name: str) -> ScanResult:
    """Normalize scanner dataclasses/dicts into the shared ScanResult shape."""
    if isinstance(result, ScanResult):
        result.status = _normalize_status(result.status)
        return result

    if hasattr(result, "as_dict"):
        payload = result.as_dict()
    elif isinstance(result, dict):
        payload = result
    else:
        payload = {}

    return ScanResult(
        key=key,
        name=name,
        status=_normalize_status(str(payload.get("status") or "INCOMPLETE")),
        summary=str(
            payload.get("summary")
            or "The scanner did not produce a structured result."
        ),
        raw_output=str(payload.get("raw_output") or ""),
        evidence=payload.get("evidence") or None,
        details=payload.get("details") or None,
    )


def _extract_known_valid_username(default_result, credentials) -> str | None:
    """Use a previously confirmed account as the invalid-password control for IDNT-04."""
    if default_result is not None:
        details = getattr(default_result, "details", None) or {}
        for item in details.get("successful_pairs", []) or []:
            text = str(item)
            if ":" in text:
                username = text.split(":", 1)[0].strip()
                if username:
                    return username

    for item in credentials or []:
        if bool(item.get("known_valid_username", False)):
            username = str(item.get("username", "")).strip()
            if username:
                return username
    return None


def _inject_professional_ui() -> None:
    """Global visual styling only; scanner/workflow behavior is unchanged."""
    st.markdown(
        """
        <style>
        /* ---------- App shell ---------- */
        .block-container {
            padding-top: 1.6rem;
            padding-bottom: 2rem;
            max-width: 1500px;
        }

        /* ---------- Typography ---------- */
        h1, h2, h3, h4 {
            letter-spacing: -0.02em;
        }

        /* ---------- Result cards ---------- */
        .result-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(215px, 1fr));
            gap: 12px;
            margin: 0.8rem 0 1.5rem 0;
        }

        .result-card {
            border: 1px solid rgba(128, 128, 128, 0.20);
            border-radius: 14px;
            padding: 15px 16px 14px 16px;
            background: rgba(128, 128, 128, 0.045);
            min-height: 104px;
        }

        .result-card:hover {
            border-color: rgba(128, 128, 128, 0.38);
        }

        .result-card-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            margin-bottom: 12px;
        }

        .result-card-name {
            font-size: 0.92rem;
            font-weight: 650;
            line-height: 1.25;
            color: inherit;
        }

        .result-status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 8px;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 700;
            white-space: nowrap;
        }

        .pill-safe {
            background: rgba(34, 197, 94, 0.12);
            color: #16a34a;
        }

        .pill-unsafe {
            background: rgba(239, 68, 68, 0.12);
            color: #dc2626;
        }

        .pill-review {
            background: rgba(245, 158, 11, 0.14);
            color: #d97706;
        }

        .pill-skipped {
            background: rgba(107, 114, 128, 0.12);
            color: #6b7280;
        }

        .pill-incomplete {
            background: rgba(234, 88, 12, 0.12);
            color: #c2410c;
        }

        .result-card-summary {
            font-size: 0.77rem;
            line-height: 1.35;
            opacity: 0.72;
        }

        /* ---------- Summary stats ---------- */
        .overview-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
            gap: 10px;
            margin: 0.7rem 0 1.35rem 0;
        }

        .overview-card {
            border: 1px solid rgba(128, 128, 128, 0.18);
            border-radius: 13px;
            padding: 13px 15px;
            background: rgba(128, 128, 128, 0.04);
        }

        .overview-label {
            font-size: 0.74rem;
            opacity: 0.68;
            margin-bottom: 5px;
        }

        .overview-value {
            font-size: 1.35rem;
            font-weight: 750;
            line-height: 1;
        }

        /* ---------- Category blocks ---------- */
        .category-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 11px 14px;
            border-radius: 11px;
            margin: 1rem 0 0.6rem 0;
            border: 1px solid rgba(128, 128, 128, 0.15);
            background: rgba(128, 128, 128, 0.035);
        }

        .category-title {
            font-weight: 720;
            font-size: 1rem;
        }

        .category-count {
            font-size: 0.78rem;
            opacity: 0.65;
        }

        /* ---------- Target/run metadata ---------- */
        .assessment-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 0.65rem 0 1.1rem 0;
        }

        .meta-chip {
            border: 1px solid rgba(128, 128, 128, 0.18);
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.75rem;
            background: rgba(128, 128, 128, 0.04);
        }

        /* ---------- Expander polish ---------- */
        div[data-testid="stExpander"] {
            border-radius: 12px;
            border: 1px solid rgba(128, 128, 128, 0.18);
            margin-bottom: 8px;
        }

        /* ---------- Tables ---------- */
        div[data-testid="stDataFrame"] {
            border-radius: 12px;
            overflow: hidden;
        }

        /* ---------- Small screens ---------- */
        @media (max-width: 700px) {
            .result-grid {
                grid-template-columns: 1fr;
            }
            .overview-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_result_cards(results: list) -> None:
    """Render all testcase status cards without changing the result data."""
    cards = []

    for result in results:
        css = _status_class(result.status)
        label = _status_label(result.status)
        icon = _status_icon(result.status)

        cards.append(
            f"""
            <div class="result-card">
                <div class="result-card-top">
                    <div class="result-card-name">{escape(str(result.name))}</div>
                    <span class="result-status-pill pill-{css}">
                        {icon} {escape(label)}
                    </span>
                </div>
                <div class="result-card-summary">
                    {escape(str(result.summary or ""))}
                </div>
            </div>
            """
        )

    if cards:
        st.markdown(
            '<div class="result-grid">' + "".join(cards) + "</div>",
            unsafe_allow_html=True,
        )


def _payload_rows_from_details(details: dict) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple] = set()

    def add(name, payload, kind=""):
        text = str(payload or "").strip()
        if not text:
            return
        key = (str(name or ""), text, str(kind or ""))
        if key in seen:
            return
        seen.add(key)
        rows.append({"Name": name or "", "Payload": text, "Kind": kind or ""})

    library = details.get("payload_library") if isinstance(details.get("payload_library"), dict) else {}
    for item in details.get("payloads_used") or library.get("payloads") or library.get("payloads_used") or []:
        if isinstance(item, dict):
            add(item.get("name") or item.get("probe"), item.get("payload") or item.get("value") or item.get("origin"), item.get("kind"))
        else:
            add("", item, "")
    for item in library.get("payloads") or []:
        if isinstance(item, dict):
            add(item.get("name"), item.get("payload") or item.get("value"), item.get("kind"))
    for assessment in details.get("assessments") or []:
        nested = assessment.get("details") if isinstance(assessment, dict) else None
        if isinstance(nested, dict):
            rows.extend(_payload_rows_from_details(nested))
    return rows


def _triggering_payload_from_details(details: dict) -> dict | None:
    triggering = details.get("triggering_payload")
    if isinstance(triggering, dict) and triggering.get("payload"):
        return triggering
    for assessment in details.get("assessments") or []:
        nested = (assessment.get("details") if isinstance(assessment, dict) else None) or {}
        payload = nested.get("triggering_payload") if isinstance(nested, dict) else None
        if isinstance(payload, dict) and payload.get("payload"):
            return payload
    return None


def _render_payload_evidence(result) -> None:
    details = result.details if isinstance(result.details, dict) else {}
    rows = _payload_rows_from_details(details)
    triggering = _triggering_payload_from_details(details)
    if not rows and not triggering:
        return
    st.markdown("**Payloads used**")
    if rows:
        unique = []
        seen = set()
        for row in rows:
            key = (row.get("Name"), row.get("Payload"), row.get("Kind"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(row)
        st.dataframe(unique, use_container_width=True, hide_index=True)
    if triggering:
        verdict = _normalize_status(str(triggering.get("verdict") or result.status))
        reason = str(triggering.get("reason") or "").strip()
        st.markdown("**Triggering payload**")
        st.warning(
            f"`{triggering.get('payload')}` "
            f"({triggering.get('name') or 'payload'}) produced **{_status_label(verdict)}**. "
            f"{reason}".strip()
        )


def _render_category(
    title: str,
    status: str,
    category_results: list,
) -> None:
    """Render one status category and its testcases."""
    if not category_results:
        return

    icon = _status_icon(status)
    label = _status_label(status)

    st.markdown(
        f"""
        <div class="category-header">
            <div class="category-title">{icon} {escape(title)}</div>
            <div class="category-count">
                {len(category_results)} testcase{"s" if len(category_results) != 1 else ""}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    for result in category_results:
        st.markdown(
            f"""
            <div style="
                border:1px solid rgba(128,128,128,0.14);
                border-radius:10px;
                padding:11px 13px;
                margin:0 0 7px 0;
                background:rgba(128,128,128,0.025);
            ">
                <div style="font-weight:650;">
                    {escape(str(result.name))}
                </div>
                <div style="font-size:0.82rem;opacity:0.72;margin-top:3px;">
                    {escape(str(result.summary or ""))}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_combined_report(
    results: list,
    target_url: str,
    run_dir=None,
) -> None:
    """
    Professional presentation layer for the combined results.

    IMPORTANT:
    - No scanner logic is changed.
    - No result values are changed.
    - No workflow is changed.
    - Test Summary remains a table.
    - Detailed Results remains an expander/dropdown section.
    - Client-friendly findings are grouped by category.
    """

    _inject_professional_ui()

    # ----------------------------------------------------------
    # Combined Assessment Header
    # ----------------------------------------------------------

    st.header("3. Combined Assessment Result")

    overall = overall_status(results)

    if overall == "SAFE":
        st.success("OVERALL STATUS: SAFE")
    elif overall == "UNSAFE":
        st.error("OVERALL STATUS: UNSAFE")
    elif overall == "REVIEW REQUIRED":
        st.warning("OVERALL STATUS: REVIEW REQUIRED")
    elif overall == "INCOMPLETE":
        st.warning("OVERALL STATUS: INCOMPLETE")
    else:
        st.warning(f"OVERALL STATUS: {overall}")

    escaped_target = escape(str(target_url))

    st.markdown(
        f"""
        <div class="assessment-meta">
            <div class="meta-chip"><strong>Target</strong>&nbsp; {escaped_target}</div>
            <div class="meta-chip"><strong>Tests</strong>&nbsp; {len(results)}</div>
            <div class="meta-chip"><strong>Overall</strong>&nbsp; {escape(_status_label(overall))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if run_dir:
        st.info(
            f"Run output saved to `{run_dir}`"
        )

    # Curated, file-backed payload transparency for reviewers and clients.
    with st.expander("Payload Library & CVSS v4.0", expanded=False):
        try:
            library = payload_library_summary()
            st.caption(
                "Payload sources are curated subsets with provenance recorded in payloads/SOURCES_AND_LICENSES.md. "
                "Header, TLS, certificate and browser-observation tests correctly use protocol/browser evidence instead of payload lists."
            )
            source_cols = st.columns(max(1, len(library.get("sources", []))))
            for col, source in zip(source_cols, library.get("sources", [])):
                col.write(source)
            try:
                catalog = source_catalog_summary()
                cached = sum(1 for item in catalog.get("sources", []) if item.get("cached"))
                st.caption(f"Upstream source cache: {cached}/{len(catalog.get('sources', []))} catalogued sources available locally. Runtime uses only testcase-mapped, safety-filtered inputs.")
            except Exception as source_exc:
                st.caption(f"Upstream source catalog unavailable: {source_exc}")
            st.metric("Payload-backed testcase groups", library.get("active_testcase_count", 0))
            st.metric("Active payload files", library.get("active_file_count", 0))
            payload_rows = []
            for item in library.get("testcases", []):
                payload_rows.append({
                    "Testcase": item.get("label", item.get("testcase")),
                    "Payload inputs": item.get("item_count", 0),
                    "Probe cap": item.get("max_items", 0),
                    "Execution mode": item.get("execution", "bounded"),
                    "Files": ", ".join(item.get("files", [])),
                })
            if payload_rows:
                st.dataframe(payload_rows, use_container_width=True, hide_index=True)
            st.caption("CVSS v4.0 Base scores appear on confirmed UNSAFE findings only. Scores are provisional until an analyst verifies the impact metrics.")
        except Exception as exc:
            st.warning(f"Payload library metadata could not be loaded: {exc}")

    # ----------------------------------------------------------
    # Status overview
    # ----------------------------------------------------------

    safe = [
        r for r in results
        if r.status == "SAFE"
    ]

    unsafe = [
        r for r in results
        if r.status == "UNSAFE"
    ]

    review = [
        r for r in results
        if r.status == "REVIEW REQUIRED"
    ]

    incomplete = [
        r for r in results
        if r.status in {
            "ERROR",
            "UNKNOWN",
            "INCOMPLETE",
        }
    ]

    skipped = [
        r for r in results
        if r.status in {
            "SKIPPED",
            "NOT APPLICABLE",
            "NOT ASSESSED",
        }
    ]

    st.markdown(
        f"""
        <div class="overview-grid">
            <div class="overview-card">
                <div class="overview-label">Total Tests</div>
                <div class="overview-value">{len(results)}</div>
            </div>
            <div class="overview-card">
                <div class="overview-label">Unsafe</div>
                <div class="overview-value">🔴 {len(unsafe)}</div>
            </div>
            <div class="overview-card">
                <div class="overview-label">Requires Review</div>
                <div class="overview-value">🟠 {len(review)}</div>
            </div>
            <div class="overview-card">
                <div class="overview-label">Safe</div>
                <div class="overview-value">🟢 {len(safe)}</div>
            </div>
            <div class="overview-card">
                <div class="overview-label">Incomplete</div>
                <div class="overview-value">⚠️ {len(incomplete)}</div>
            </div>
            <div class="overview-card">
                <div class="overview-label">Skipped / N.A.</div>
                <div class="overview-value">⚪ {len(skipped)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ----------------------------------------------------------
    # Test Summary — intentionally retained as a table
    # ----------------------------------------------------------

    st.subheader("Test Summary")

    st.dataframe(
        [
            {
                "Security Test": result.name,
                "Status": result.status,
                "Summary": result.summary,
            }
            for result in results
        ],
        use_container_width=True,
        hide_index=True,
        column_config={
            "Security Test": st.column_config.TextColumn(
                "Security Test",
                width="medium",
            ),
            "Status": st.column_config.TextColumn(
                "Status",
                width="small",
            ),
            "Summary": st.column_config.TextColumn(
                "Summary",
                width="large",
            ),
        },
    )

    # ----------------------------------------------------------
    # Detailed Results — intentionally retained as dropdowns
    # ----------------------------------------------------------

    st.subheader("Detailed Results")

    for number, result in enumerate(
        results,
        start=1,
    ):
        css = _status_class(
            result.status
        )

        with st.expander(
            f"{number}. {_status_icon(result.status)} "
            f"{result.name} — {_status_label(result.status)}",
            expanded=(
                result.status == "UNSAFE"
            ),
        ):
            st.markdown(
                f"""
                <div class="result-status-pill pill-{css}" style="margin-bottom:10px;">
                    {_status_icon(result.status)}
                    {escape(_status_label(result.status))}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.write(
                result.summary
            )

            _render_payload_evidence(result)

            operator_note = None
            if isinstance(result.details, dict):
                operator_note = result.details.get("operator_action") or result.details.get("operator_note")
            if isinstance(operator_note, str) and operator_note.strip():
                st.info(f"Operator action: {operator_note}")

            cvss = (result.details or {}).get("cvss") if isinstance(result.details, dict) else None
            if isinstance(cvss, dict):
                st.markdown("**CVSS v4.0 Base Score (provisional)**")
                metric_col, severity_col = st.columns(2)
                with metric_col:
                    score = cvss.get("base_score")
                    st.metric("CVSS-B", f"{score:.1f}" if isinstance(score, (int, float)) else "Pending calculation")
                with severity_col:
                    st.metric("Severity", str(cvss.get("severity", "Pending calculation")))
                st.code(str(cvss.get("vector", "")), language="text")
                st.caption(str(cvss.get("method", "")))
                st.markdown(f"[Open the NIST CVSS v4.0 calculator]({cvss.get('calculator_url', 'https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator')})")

            if result.details:
                st.markdown(
                    "**Structured evidence**"
                )
                st.json(
                    result.details
                )

            if result.evidence:
                st.markdown(
                    "**Evidence**"
                )
                for item in result.evidence:
                    st.code(
                        str(item),
                        language="text",
                    )

            if result.raw_output:
                st.markdown(
                    "**Scanner output**"
                )
                st.code(
                    result.raw_output,
                    language="text",
                )

    # ----------------------------------------------------------
    # Category-based Client-Friendly Findings
    # ----------------------------------------------------------

    st.subheader("Client-Friendly Findings")

    _render_category(
        "Issues Detected",
        "UNSAFE",
        unsafe,
    )

    _render_category(
        "Requires Review",
        "REVIEW REQUIRED",
        review,
    )

    _render_category(
        "Checks That Did Not Complete",
        "INCOMPLETE",
        incomplete,
    )

    _render_category(
        "Skipped / Not Applicable",
        "SKIPPED",
        skipped,
    )

    _render_category(
        "Safe Checks",
        "SAFE",
        safe,
    )

    # ----------------------------------------------------------
    # Empty/positive state
    # ----------------------------------------------------------

    if (
        not unsafe
        and not review
        and not incomplete
    ):
        if skipped:
            st.success(
                "No issues were identified by the checks that ran. "
                "Some checks were skipped or not applicable to the target."
            )
        else:
            st.success(
                "No issues were identified by the configured security checks."
            )

    # ----------------------------------------------------------
    # Footer note
    # ----------------------------------------------------------

    st.divider()

    st.caption(
        "Detection results are based on the logic in the configured scanners. "
        "A SAFE result means no issue was identified by that scanner's configured "
        "detection criteria; it does not mean the entire website is secure."
    )

def _init_captcha_session(
    target_url: str,
    login_input: str,
    first_four: list,
    meta: dict,
    credential_pairs: list,
    usernames: list,
    verify_tls: bool = True,
) -> None:
    st.session_state.scan_phase = "captcha"
    st.session_state.scan_target = target_url
    st.session_state.scan_login = login_input
    st.session_state.verify_tls = bool(verify_tls)
    st.session_state.scan_results = first_four
    st.session_state.captcha_test = "dc"
    st.session_state.dc_queue = list(credential_pairs)
    st.session_state.enum_queue = list(usernames)
    st.session_state.dc_evidence = []
    st.session_state.dc_successes = []
    st.session_state.dc_attempts = 0
    st.session_state.dc_pair_skips = 0
    st.session_state.dc_rest_stopped = False
    st.session_state.enum_evidence = []
    st.session_state.enum_attempts = 0
    st.session_state.enum_skips = 0
    st.session_state.enum_rest_stopped = False
    st.session_state.captcha_meta = meta
    st.session_state.scan_run_dir = None
    st.session_state.captcha_notice = ""
    st.session_state.known_valid_username = None


def _finish_scan() -> None:
    st.session_state.scan_phase = "done"
    results = st.session_state.scan_results
    # CVSS v4.0 is attached only to UNSAFE/confirmed outcomes; REVIEW REQUIRED
    # remains unscored to avoid implying a confirmed vulnerability.
    for item in results:
        try:
            annotate_result(item)
        except Exception:
            # Scoring failure must not overwrite or block the underlying scan verdict.
            pass
    target_url = st.session_state.scan_target
    try:
        st.session_state.scan_run_dir = str(
            save_run_output(target_url, results, overall_status(results))
        )
    except Exception as exc:
        st.session_state.scan_run_dir = None
        st.session_state.captcha_notice = f"Could not save run output: {exc}"


def _append_auth_result(result) -> None:
    st.session_state.scan_results = list(st.session_state.scan_results) + [result]


def _build_dc_captcha_result():
    evidence = list(st.session_state.dc_evidence)
    successes = list(st.session_state.dc_successes)
    attempts = int(st.session_state.dc_attempts)
    skips = int(st.session_state.dc_pair_skips)
    rest_stopped = bool(st.session_state.get("dc_rest_stopped"))
    details = {
        "captcha": True,
        "attempts_made": attempts,
        "pairs_skipped": skips,
        "remaining_not_tested": rest_stopped,
        "successful_pairs": successes,
        "captcha_marker": (st.session_state.captcha_meta or {}).get("captcha_marker"),
    }
    if successes:
        summary = (
            "A supplied credential pair successfully authenticated after a human CAPTCHA solve."
        )
        if rest_stopped:
            summary += " Remaining pairs were not tested."
        return captcha_auth_result(
            "default_credentials",
            "Default Credentials",
            "UNSAFE",
            summary,
            evidence,
            details,
        )
    if attempts == 0:
        return captcha_auth_result(
            "default_credentials",
            "Default Credentials",
            "SKIPPED",
            "Not applicable: a CAPTCHA blocked automated login. Default Credentials was skipped.",
            evidence,
            details,
        )
    if rest_stopped:
        return captcha_auth_result(
            "default_credentials",
            "Default Credentials",
            "SAFE",
            (
                f"None of the {attempts} human-solved CAPTCHA attempt(s) authenticated. "
                "Remaining pairs were not tested."
            ),
            evidence,
            details,
        )
    if skips:
        return captcha_auth_result(
            "default_credentials",
            "Default Credentials",
            "INCOMPLETE",
            (
                f"CAPTCHA limited this check. {attempts} pair(s) were tested after a "
                f"human solve and {skips} were skipped. This is not a SAFE finding."
            ),
            evidence,
            details,
        )
    return captcha_auth_result(
        "default_credentials",
        "Default Credentials",
        "SAFE",
        "None of the human-solved CAPTCHA attempts authenticated.",
        evidence,
        details,
    )


def _build_enum_captcha_result():
    evidence = list(st.session_state.enum_evidence)
    attempts = int(st.session_state.enum_attempts)
    skips = int(st.session_state.enum_skips)
    rest_stopped = bool(st.session_state.get("enum_rest_stopped"))
    details = {
        "captcha": True,
        "attempts_made": attempts,
        "usernames_skipped": skips,
        "remaining_not_tested": rest_stopped,
        "captcha_marker": (st.session_state.captcha_meta or {}).get("captcha_marker"),
    }
    logged_in = [item for item in evidence if "success=True" in str(item)]
    if logged_in:
        summary = (
            "A username authenticated during a human CAPTCHA solve, "
            "which is an account-existence signal."
        )
        if rest_stopped:
            summary += " Remaining usernames were not tested."
        return captcha_auth_result(
            "user_enumeration",
            "User Enumeration",
            "UNSAFE",
            summary,
            evidence,
            details,
        )
    if attempts == 0:
        return captcha_auth_result(
            "user_enumeration",
            "User Enumeration",
            "SKIPPED",
            "Not applicable: a CAPTCHA blocked automated login. User Enumeration was skipped.",
            evidence,
            details,
        )
    if rest_stopped:
        return captcha_auth_result(
            "user_enumeration",
            "User Enumeration",
            "SAFE",
            (
                f"No username authenticated during {attempts} human-solved CAPTCHA probe(s). "
                "Remaining usernames were not tested."
            ),
            evidence,
            details,
        )
    if skips:
        return captcha_auth_result(
            "user_enumeration",
            "User Enumeration",
            "INCOMPLETE",
            (
                f"CAPTCHA limited this check. {attempts} username(s) were probed after a "
                f"human solve and {skips} were skipped. This is not a SAFE finding."
            ),
            evidence,
            details,
        )
    return captcha_auth_result(
        "user_enumeration",
        "User Enumeration",
        "SAFE",
        "No username authenticated during human-solved CAPTCHA probes.",
        evidence,
        details,
    )


def _complete_current_captcha_test() -> None:
    if st.session_state.captcha_test == "dc":
        _append_auth_result(_build_dc_captcha_result())
        st.session_state.captcha_test = "enum"
        if st.session_state.enum_queue:
            return
        _append_auth_result(_build_enum_captcha_result())
        _finish_scan()
        return
    _append_auth_result(_build_enum_captcha_result())
    _finish_scan()


def _run_human_captcha_attempt(username: str, password: str) -> dict:
    meta = st.session_state.captcha_meta or {}
    login_url = meta.get("page_url") or ""
    if not login_url:
        return {
            "ok": False,
            "success": False,
            "error": "missing_login_url",
            "evidence": f"{username} captcha_window_unavailable: login URL was not discovered",
        }
    return human_login_with_captcha(
        login_url=login_url,
        username=username,
        password=password,
        user_field=meta.get("user_field") or "username",
        pass_field=meta.get("pass_field") or "password",
        verify_tls=bool(st.session_state.get("verify_tls", True)),
    )


def _pop_current_captcha_item() -> None:
    if st.session_state.captcha_test == "dc":
        st.session_state.dc_queue = list(st.session_state.dc_queue[1:])
        if not st.session_state.dc_queue:
            _complete_current_captcha_test()
        return
    st.session_state.enum_queue = list(st.session_state.enum_queue[1:])
    if not st.session_state.enum_queue:
        _complete_current_captcha_test()


def _skip_remaining_captcha_test() -> None:
    if st.session_state.captcha_test == "dc":
        remaining = len(st.session_state.dc_queue)
        st.session_state.dc_pair_skips = int(st.session_state.dc_pair_skips) + remaining
        st.session_state.dc_queue = []
        _complete_current_captcha_test()
        return
    remaining = len(st.session_state.enum_queue)
    st.session_state.enum_skips = int(st.session_state.enum_skips) + remaining
    st.session_state.enum_queue = []
    _complete_current_captcha_test()


def _skip_rest_after_tested() -> None:
    """Keep tested-item verdicts; do not test the rest of this check."""
    if st.session_state.captcha_test == "dc":
        remaining = len(st.session_state.dc_queue)
        st.session_state.dc_rest_stopped = True
        st.session_state.dc_evidence = list(st.session_state.dc_evidence) + [
            f"{remaining} remaining pair(s) not tested (operator skipped the rest)"
        ]
        st.session_state.dc_queue = []
        _complete_current_captcha_test()
        return
    remaining = len(st.session_state.enum_queue)
    st.session_state.enum_rest_stopped = True
    st.session_state.enum_evidence = list(st.session_state.enum_evidence) + [
        f"{remaining} remaining username(s) not tested (operator skipped the rest)"
    ]
    st.session_state.enum_queue = []
    _complete_current_captcha_test()




# ==============================================================
# LOGIN-PAGE SUITE — 17 TESTCASES
# ==============================================================

LOGIN_PAGE_TESTS = tuple((key, name) for key, name, _module in LOGIN_PAGE_REGISTRY)


def _effective_verify_tls(target_url: str, verify_tls: bool) -> tuple[bool, str | None]:
    """Keep application tests running when an authorized target uses an expired lab certificate."""
    from core.http_client import effective_verify_tls
    return effective_verify_tls(target_url, verify_tls)


def _login_url_from_target(target_url: str, login_path: str) -> str:
    # Share the same normalizer as the authentication scanners so a target
    # already ending in /login.jsp is not transformed into /login.jsp/login.
    from authentication.auth_discovery import normalize_login_url
    return normalize_login_url(target_url, login_path or "/login")


def _login_config_common(login_path, verify_tls, username, password, protected_url):
    values = {
        "login_path": login_path or "/login",
        "verify_tls": bool(verify_tls),
        "authorized_username": username,
        "authorized_password": password,
        "protected_urls": (protected_url,) if protected_url else (),
        "protected_url": protected_url or None,
    }
    return values


def _build_dataclass_config(config_cls, values: dict):
    """Instantiate a testcase config using only fields supported by that config."""
    try:
        from dataclasses import fields
        names = {f.name for f in fields(config_cls)}
        return config_cls(**{k: v for k, v in values.items() if k in names})
    except Exception:
        return config_cls()


def _coerce_login_result(payload, key: str, name: str):
    """Normalize scanner dicts/dataclasses into the Streamlit ScanResult model."""
    if hasattr(payload, "as_dict"):
        payload = payload.as_dict()
    elif isinstance(payload, dict):
        payload = dict(payload)
    else:
        payload = {
            "status": str(getattr(payload, "status", "INCOMPLETE")),
            "summary": str(getattr(payload, "summary", "Scanner did not return a structured result.")),
            "raw_output": str(getattr(payload, "raw_output", "") or ""),
            "evidence": getattr(payload, "evidence", None),
            "details": getattr(payload, "details", None),
        }

    payload.setdefault("key", key)
    payload.setdefault("name", name)
    payload.setdefault("status", "INCOMPLETE")
    payload.setdefault("summary", f"{name} did not produce a structured result.")
    payload.setdefault("raw_output", "")
    payload.setdefault("evidence", [])
    payload.setdefault("details", {})
    payload["status"] = _normalize_status(payload.get("status"))
    return _as_scan_result(payload, key, name)


def _as_credential_candidates(credentials: list[dict]):
    from authentication.models import CredentialCandidate

    supported = {
        "operator_supplied",
        "product_default",
        "application_default",
        "organization_default",
        "blank_password",
        "lab_profile",
    }
    output = []
    for item in credentials or []:
        username = str(item.get("username") or "").strip()
        if not username:
            continue
        source = str(item.get("credential_source") or item.get("credential_type") or "application_default").strip().lower()
        if source not in supported:
            source = "application_default"
        output.append(
            CredentialCandidate(
                username=username,
                password=str(item.get("password") or ""),
                credential_source=source,
                product_hint=str(item.get("product_hint") or "") or None,
                account_hint=str(item.get("account_hint") or "") or None,
            )
        )
    return output


def _confirmed_pair_from_result(payload, credentials: list[dict]) -> tuple[str, str] | None:
    if hasattr(payload, "as_dict"):
        payload = payload.as_dict()
    if not isinstance(payload, dict):
        return None
    details = payload.get("details") or {}
    usernames: list[str] = []
    confirmed = details.get("confirmed") or {}
    cred = confirmed.get("credential") if isinstance(confirmed, dict) else {}
    if isinstance(cred, dict) and cred.get("username"):
        usernames.append(str(cred.get("username")).strip())
    for attempt in details.get("attempts") or []:
        if not isinstance(attempt, dict):
            continue
        if attempt.get("authentication_confirmed"):
            name = str((attempt.get("credential") or {}).get("username") or "").strip()
            if name:
                usernames.append(name)
    for item in details.get("successful_pairs") or []:
        text = str(item)
        if ":" in text:
            usernames.append(text.split(":", 1)[0].strip())
    for username in usernames:
        if not username:
            continue
        for item in credentials or []:
            if str(item.get("username") or "").strip() == username and str(item.get("password") or ""):
                return username, str(item.get("password"))
    return None


def run_login_page_suite(
    target_url: str,
    *,
    login_path: str = "/login",
    verify_tls: bool = True,
    credentials: list[dict] | None = None,
    candidate_usernames: list[str] | None = None,
    authorized_username: str | None = None,
    authorized_password: str | None = None,
    protected_url: str | None = None,
    progress=None,
) -> list:
    """Run all 17 Login Page testcases in deterministic TC01→TC17 order."""
    import importlib

    credentials = credentials or []
    candidate_usernames = candidate_usernames or list(dict.fromkeys(
        str(item.get("username") or "").strip() for item in credentials if str(item.get("username") or "").strip()
    ))
    verify_tls, tls_note = _effective_verify_tls(target_url, verify_tls)
    if tls_note and progress:
        progress(tls_note)
    results = []

    for key, name in LOGIN_PAGE_TESTS:
        common = _login_config_common(
            login_path,
            verify_tls,
            authorized_username,
            authorized_password,
            protected_url,
        )
        if progress:
            progress(f"Running {name} ({key.upper()})")

        try:
            module_name = f"login_page.scanners.{key}"
            module = importlib.import_module(module_name)

            if key == "tc02_default_credentials":
                cfg = _build_dataclass_config(
                    module.TC02Config,
                    {
                        **common,
                        "max_attempts": min(MAX_CREDENTIAL_ATTEMPTS, max(1, len(credentials) or 10)),
                        "stop_on_first_confirmed": True,
                    },
                )
                payload = module.scan_default_credentials(
                    target_url,
                    _as_credential_candidates(credentials),
                    config=cfg,
                )

            elif key == "tc03_blank_credentials":
                cfg = _build_dataclass_config(
                    module.TC03Config,
                    {
                        **common,
                        "max_attempts": 10,
                        "include_optional_variants": True,
                        "stop_on_confirmed": True,
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_blank_credentials(target_url, cfg)

            elif key == "tc04_user_enumeration":
                from authentication.enumeration_models import EnumerationConfig
                cfg = _build_dataclass_config(
                    EnumerationConfig,
                    {
                        **common,
                        "candidate_usernames": tuple(candidate_usernames),
                        "known_valid_username": authorized_username,
                        "probe_password": ENUMERATION_PROBE_PASSWORD,
                        "max_candidates": min(25, max(1, len(candidate_usernames) or 10)),
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_user_enumeration(target_url, config=cfg, progress=progress)

            elif key == "tc05_password_validation":
                cfg = _build_dataclass_config(
                    module.PasswordValidationConfig,
                    {
                        **common,
                        "max_wrong_attempts": 5,
                        "min_delay_seconds": 0.75,
                        "protected_urls": (protected_url,) if protected_url else ("/account", "/dashboard"),
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_password_validation(target_url, cfg, progress=progress)

            elif key == "tc06_method_interchange":
                from authentication.method_interchange_models import MethodInterchangeConfig
                cfg = _build_dataclass_config(
                    MethodInterchangeConfig,
                    {
                        **common,
                        "max_attempts": 6,
                        "min_delay_seconds": 0.75,
                        "use_browser_fallback": True,
                    },
                )
                payload = module.scan_method_interchange(target_url, config=cfg, progress=progress)

            elif key == "tc07_browser_memory_dump":
                from authentication.browser_memory_models import BrowserMemoryConfig
                cfg = _build_dataclass_config(
                    BrowserMemoryConfig,
                    {
                        **common,
                        "perform_authenticated_lane": bool(authorized_username and authorized_password),
                    },
                )
                payload = module.scan_browser_memory_dump(target_url, config=cfg, progress=progress)

            elif key == "tc08_login_over_http":
                payload = module.scan_login_over_http(
                    target_url,
                    login_path=login_path,
                    verify_tls=verify_tls,
                )

            elif key == "tc09_cleartext_traffic":
                payload = module.scan_cleartext_traffic(
                    target_url,
                    login_path=login_path,
                    verify_tls=verify_tls,
                    progress=progress,
                )

            elif key == "tc10_remember_me":
                payload = module.scan_remember_me(
                    target_url,
                    login_path=login_path,
                    authorized_username=authorized_username,
                    authorized_password=authorized_password,
                    protected_urls=(protected_url,) if protected_url else (),
                    verify_tls=verify_tls,
                )

            elif key == "tc11_shoulder_surfing":
                payload = module.scan_shoulder_surfing(
                    target_url,
                    login_path=login_path,
                    verify_tls=verify_tls,
                    allow_browser=True,
                )

            elif key == "tc12_captcha_missing":
                cfg = _build_dataclass_config(
                    module.TC12Config,
                    {
                        **common,
                        "max_failed_probes": 3,
                        "allow_browser_fallback": True,
                    },
                )
                payload = module.scan_captcha_missing(target_url, config=cfg, progress=progress)

            elif key == "tc13_cors":
                cfg = _build_dataclass_config(
                    module.CORSConfig,
                    {"verify_tls": verify_tls},
                )
                payload = module.scan_cors(target_url, config=cfg, verify_tls=verify_tls)

            elif key == "tc14_sql_injection":
                cfg = _build_dataclass_config(
                    module.SQLiConfig,
                    {"verify_tls": verify_tls, "login_path": login_path},
                )
                payload = module.scan_sql_injection(target_url, config=cfg, verify_tls=verify_tls)

            elif key == "tc15_ldap_ad":
                cfg = _build_dataclass_config(
                    module.LDAPConfig,
                    {
                        **common,
                        "login_path": login_path,
                        "allow_active_probes": True,
                    },
                )
                payload = module.scan_ldap_ad(target_url, config=cfg)

            elif key == "tc16_weak_password_encoding":
                cfg = _build_dataclass_config(
                    module.WeakPasswordConfig,
                    {"verify_tls": verify_tls, "login_path": login_path},
                )
                payload = module.scan_weak_password_encoding(target_url, config=cfg)

            elif key == "tc17_rate_limit":
                cfg = _build_dataclass_config(
                    module.RateLimitConfig,
                    {
                        **common,
                        "max_wrong_attempts": 6,
                        "min_interval_seconds": 0.75,
                        "allow_browser_fallback": False,
                    },
                )
                payload = module.scan_rate_limit(target_url, config=cfg, progress=progress)

            elif key == "tc01_autocomplete":
                payload = module.scan_autocomplete(
                    _login_url_from_target(target_url, login_path),
                    timeout=12.0,
                    use_browser=True,
                )

            else:
                raise RuntimeError(f"No integration handler exists for {key}")

            result = _coerce_login_result(payload, key, name)
            if key == "tc02_default_credentials" and not (authorized_username and authorized_password):
                recovered = _confirmed_pair_from_result(payload, credentials)
                if recovered:
                    authorized_username, authorized_password = recovered
                    if progress:
                        progress(
                            "Reusing a confirmed default-credential pair as the authorized "
                            "control for later authentication tests."
                        )
            results.append(result)

        except Exception as exc:
            results.append(
                _coerce_login_result(
                    {
                        "key": key,
                        "name": name,
                        "status": "ERROR",
                        "summary": f"{name} failed to execute: {exc}",
                        "details": {
                            "module": f"login_page.scanners.{key}",
                            "exception_type": type(exc).__name__,
                            "error": str(exc),
                        },
                        "evidence": [str(exc)],
                        "raw_output": "",
                    },
                    key,
                    name,
                )
            )

    return results


# ==============================================================
# PAGE CONFIGURATION
# ==============================================================

st.set_page_config(
    page_title="Test Executor",
    page_icon=None,
    layout="wide",
)

st.title("Security Assessment Test Executor")
st.caption(
    "Runs the configured security checks sequentially. Choose the 23-test pre-login suite "
    "or the integrated 17-test login-page suite. Login-page checks use the configured "
    "login path and authorized credential controls where a testcase requires them."
)


# ==============================================================
# TARGET CONFIGURATION
# ==============================================================

st.header("0. Assessment Suite")
assessment_suite = st.radio(
    "Choose assessment suite",
    ("Pre-Login Tests (23)", "Login Page Tests (17)"),
    index=0,
    horizontal=True,
    help="Run the 23 pre-login scanners or the integrated 17-test login-page suite.",
)

st.header("1. Target")

target = st.text_input(
    "Target URL",
    placeholder="https://example.com",
    help="Enter the live website you are authorized to assess.",
)

authorized_assessment = st.checkbox(
    "I confirm that I have written authorization to assess this target.",
    value=False,
    help="The executor is intended only for authorized security assessments.",
)

login_path = st.text_input(
    "Login Page Path",
    value="/login",
    help="Path used by login-page authentication tests. Example: /login or /signin.",
)

protected_url = st.text_input(
    "Optional Protected URL",
    value="",
    placeholder="/dashboard",
    help="Optional protected resource used by authentication/session testcases when available.",
)

# ==============================================================
# TLS / TRANSPORT CONFIGURATION
# ==============================================================

verify_tls = st.checkbox(
    "Verify TLS certificate",
    value=VERIFY_TLS,
    help=(
        "Keep enabled for normal testing. Disable only for an authorized target "
        "whose HTTPS certificate is expired, self-signed, or otherwise invalid."
    ),
)

if not verify_tls:
    st.warning(
        "TLS certificate verification is disabled for this assessment. "
        "The report should record this test condition."
    )


# ==============================================================
# AUTHORIZED CREDENTIAL INPUTS
# ==============================================================
# Shared credential candidates for TC02/TC04 remain file-backed. The four
# authenticated checks below additionally accept one operator-supplied test
# account directly in the UI; values stay in Streamlit session state and are
# not written to credentials.json or reports.
try:
    credentials, candidate_usernames = load_authentication_database()
except Exception:
    credentials, candidate_usernames = [], []

ui_auth_username = ""
ui_auth_password = ""
ui_auth_confirmed = False
if assessment_suite.startswith("Login Page"):
    with st.expander("Authorized test account — TC05, TC06, TC10 & TC17", expanded=False):
        st.caption(
            "Optional. Supply a test account you are explicitly authorized to use. "
            "These credentials support Password Validation, Method Interchange, "
            "Remember Me, and Rate Limit checks. They are not used as a default-credential list."
        )
        ui_auth_username = st.text_input(
            "Authorized test-account username",
            key="ui_auth_test_username",
            placeholder="test-account username",
            help="Use a dedicated test account for this assessment."
        ).strip()
        ui_auth_password = st.text_input(
            "Authorized test-account password",
            key="ui_auth_test_password",
            type="password",
            placeholder="Enter password for the test account",
            help="Password is kept in the current Streamlit session and is not saved to credentials.json."
        )
        ui_auth_confirmed = st.checkbox(
            "I am authorized to use this account for the selected target.",
            key="ui_auth_test_confirmed",
            value=False,
        )
        st.caption(
            "If no account is supplied, the suite still runs checks that do not need a successful login. "
            "Authentication-dependent subchecks will report their missing prerequisite rather than SAFE."
        )
        if (ui_auth_username or ui_auth_password) and not ui_auth_confirmed:
            st.warning("The supplied account will not be used until you confirm its authorization.")


# ==============================================================
# RUN ASSESSMENT
# ==============================================================

if "scan_phase" not in st.session_state:
    st.session_state.scan_phase = "idle"
    st.session_state.scan_results = []
    st.session_state.scan_target = ""
    st.session_state.scan_run_dir = None
    st.session_state.captcha_notice = ""

st.header("2. Run Assessment")

if st.button(
    "🚀 Start Security Assessment",
    type="primary",
    use_container_width=True,
    key="start_assessment",
):
    if not target.strip():
        st.error("Enter a target URL.")
        st.stop()

    if not authorized_assessment:
        st.error("Written authorization is required before an assessment can start.")
        st.stop()

    target_url = target.strip()
    try:
        target_url = validate_target_url(target_url, TargetPolicy.from_environment())
    except ValueError as exc:
        st.error(f"Target validation failed: {exc}")
        st.stop()

    normalized_login_path = (login_path or "/login").strip()
    if normalized_login_path.lower().startswith(("http://", "https://", "//")):
        st.error("Login Page Path must be a same-origin path such as /login or /signin.")
        st.stop()

    if protected_url.strip():
        protected_candidate = protected_url.strip()
        if protected_candidate.lower().startswith(("http://", "https://")):
            if not same_origin(target_url, protected_candidate):
                st.error("Protected URL must remain on the target origin.")
                st.stop()

    st.session_state.verify_tls = bool(verify_tls)
    st.session_state.known_valid_username = None

    progress_box = st.empty()
    status_box = st.status(
        "Running security assessment...",
        expanded=True,
    )
    completed = []

    def progress(message):
        display_message = message
        if isinstance(message, str) and message.startswith("Starting "):
            display_message = "Running " + message[len("Starting "):]
        completed.append(display_message)
        progress_box.info(display_message)
        status_box.write("▶ " + display_message)

    try:
        # --------------------------------------------------------------
        # PRE-LOGIN SUITE — existing 23-test workflow
        # --------------------------------------------------------------
        if assessment_suite.startswith("Pre-Login"):
            progress("Running Pre-Login Assessment (23 test cases)")

            pre_login_payloads = run_pre_login_suite(
                target_url,
                verify_tls=verify_tls,
                progress=progress,
            )

            results = []
            for payload in pre_login_payloads:
                results.append(
                    _as_scan_result(
                        payload,
                        str(payload.get("key") or "pre_login_test"),
                        str(payload.get("name") or "Pre-Login Test"),
                    )
                )

            st.session_state.scan_target = target_url
            st.session_state.scan_results = results
            _finish_scan()

            status_box.update(
                label="All 23 pre-login security tests completed.",
                state="complete",
                expanded=False,
            )
            progress_box.empty()
            st.rerun()

        # --------------------------------------------------------------
        # LOGIN-PAGE SUITE — all 17 testcases
        # --------------------------------------------------------------
        progress("Running Login Page Assessment (17 test cases)")

        authorized_username = None
        authorized_password = None

        # Prefer the explicit UI account only when the operator has confirmed
        # authorization. Otherwise retain the existing known-valid file-backed
        # account behavior. Never infer that an arbitrary credential pair is valid.
        if ui_auth_confirmed and ui_auth_username and ui_auth_password:
            authorized_username = ui_auth_username
            authorized_password = ui_auth_password
        else:
            for item in credentials:
                if item.get("known_valid_username"):
                    candidate_username = str(item.get("username") or "").strip() or None
                    candidate_password = str(item.get("password") or "")
                    if candidate_username and candidate_password:
                        authorized_username = candidate_username
                        authorized_password = candidate_password
                        break

        if not authorized_username or not authorized_password:
            # Do not guess which credential is valid. The login-page suite will
            # still execute passive/non-authentication tests; credential-dependent
            # tests will return INCOMPLETE/NOT ASSESSED as appropriate.
            progress("No explicitly marked known-valid credential was available; credential-dependent tests will report this condition.")

        results = run_login_page_suite(
            target_url,
            login_path=normalized_login_path,
            verify_tls=verify_tls,
            credentials=credentials,
            candidate_usernames=candidate_usernames,
            authorized_username=authorized_username,
            authorized_password=authorized_password,
            protected_url=protected_url.strip() or None,
            progress=progress,
        )

        st.session_state.scan_target = target_url
        st.session_state.scan_results = results
        _finish_scan()

        status_box.update(
            label="All 17 login-page security tests completed.",
            state="complete",
            expanded=False,
        )
        progress_box.empty()
        st.rerun()

    except Exception as exc:
        status_box.update(
            label="Assessment failed.",
            state="error",
            expanded=True,
        )
        st.exception(exc)
        st.stop()



if st.session_state.scan_phase == "captcha":
    test_key = st.session_state.captcha_test
    is_dc = test_key == "dc"
    queue = (
        st.session_state.dc_queue if is_dc else st.session_state.enum_queue
    )
    if not queue:
        _complete_current_captcha_test()
        st.rerun()

    test_name = "Default Credentials" if is_dc else "User Enumeration"
    marker = (st.session_state.captcha_meta or {}).get("captcha_marker") or "CAPTCHA"
    current = queue[0]
    current_username = current["username"] if is_dc else current

    st.warning(
        f"**{test_name} is paused.** A {marker} was detected on the login page. "
        "A browser window will open if you choose Solve. Complete the CAPTCHA "
        "there yourself — this tool does not click it or call a solving service."
    )
    if st.session_state.captcha_notice:
        st.error(st.session_state.captcha_notice)

    st.markdown(
        f"Remaining in this check: **{len(queue)}**. "
        f"Next username: `{current_username}`"
    )

    tested_count = (
        int(st.session_state.dc_attempts)
        if is_dc
        else int(st.session_state.enum_attempts)
    )
    show_skip_rest = tested_count >= 1

    if show_skip_rest:
        col_solve, col_skip_item, col_skip_rest, col_skip_test = st.columns(4)
    else:
        col_solve, col_skip_item, col_skip_test = st.columns(3)
        col_skip_rest = None

    with col_solve:
        solve_clicked = st.button(
            "Solve CAPTCHA for this item",
            type="primary",
            use_container_width=True,
            key="captcha_solve",
        )
    with col_skip_item:
        skip_item_clicked = st.button(
            "Skip this pair" if is_dc else "Skip this username",
            use_container_width=True,
            key="captcha_skip_item",
        )
    skip_rest_clicked = False
    if col_skip_rest is not None:
        with col_skip_rest:
            skip_rest_clicked = st.button(
                "Skip the rest pairs" if is_dc else "Skip the rest usernames",
                use_container_width=True,
                key="captcha_skip_rest",
            )
    with col_skip_test:
        skip_test_clicked = st.button(
            f"Skip {test_name}",
            use_container_width=True,
            key="captcha_skip_test",
        )

    if solve_clicked:
        password = (
            current.get("password", "")
            if is_dc
            else ENUMERATION_PROBE_PASSWORD
        )
        with st.spinner(
            "Waiting for you to complete the CAPTCHA in the browser window "
            "(up to 3 minutes)..."
        ):
            outcome = _run_human_captcha_attempt(current_username, password)

        if outcome.get("error") == "playwright_not_installed":
            st.session_state.captcha_notice = (
                "Playwright is not installed, so a browser window cannot open. "
                "Install it with `pip install playwright` and "
                "`playwright install chromium`, or skip this item / test."
            )
            st.rerun()

        st.session_state.captcha_notice = ""
        evidence_line = outcome.get("evidence") or (
            f"{current_username} human_captcha_submit success="
            f"{outcome.get('success')}"
        )
        if is_dc:
            st.session_state.dc_attempts = int(st.session_state.dc_attempts) + 1
            st.session_state.dc_evidence = list(st.session_state.dc_evidence) + [
                evidence_line
            ]
            if outcome.get("success"):
                st.session_state.dc_successes = list(
                    st.session_state.dc_successes
                ) + [current_username]
        else:
            st.session_state.enum_attempts = int(st.session_state.enum_attempts) + 1
            st.session_state.enum_evidence = list(st.session_state.enum_evidence) + [
                evidence_line
            ]
        _pop_current_captcha_item()
        st.rerun()

    if skip_item_clicked:
        st.session_state.captcha_notice = ""
        if is_dc:
            st.session_state.dc_pair_skips = int(st.session_state.dc_pair_skips) + 1
            st.session_state.dc_evidence = list(st.session_state.dc_evidence) + [
                f"{current_username} skipped_by_operator"
            ]
        else:
            st.session_state.enum_skips = int(st.session_state.enum_skips) + 1
            st.session_state.enum_evidence = list(st.session_state.enum_evidence) + [
                f"{current_username} skipped_by_operator"
            ]
        _pop_current_captcha_item()
        st.rerun()

    if skip_rest_clicked:
        st.session_state.captcha_notice = ""
        _skip_rest_after_tested()
        st.rerun()

    if skip_test_clicked:
        st.session_state.captcha_notice = ""
        _skip_remaining_captcha_test()
        st.rerun()

    st.caption(
        "Passwords are not shown. After this check finishes, the other "
        "authentication check is offered the same choices if it still "
        "has items left. After the first item is tested, Skip the rest "
        "pairs keeps those results and stops the remaining list."
    )

    if st.session_state.scan_results:
        st.info("Results so far (authentication checks are not finished):")
        render_combined_report(
            st.session_state.scan_results,
            st.session_state.scan_target,
            st.session_state.scan_run_dir,
        )

elif st.session_state.scan_phase == "done" and st.session_state.scan_results:
    render_combined_report(
        st.session_state.scan_results,
        st.session_state.scan_target,
        st.session_state.scan_run_dir,
    )
    if st.session_state.captcha_notice:
        st.warning(st.session_state.captcha_notice)
