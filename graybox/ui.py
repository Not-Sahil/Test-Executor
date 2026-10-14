"""Gray-Box Security Assessment Frontend UI for Streamlit.

Provides an isolated, dedicated UI for Gray-Box testing including:
- 85-testcase inventory browser
- Gray-Box Knowledge and Artifact Manager
- Multi-identity Account and Role Manager
- Category selection & safety budget configuration
- Live progress orchestration
- Evidence-driven findings, payload coverage breakdown, and NIST CVSS adjuster
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

from graybox.accounts import GrayBoxAccountManager, TestAccount
from graybox.artifacts import GrayBoxArtifactManager, redact_text_secrets
from graybox.models import (
    AccountRole,
    ArtifactType,
    AutomationLevel,
    GrayBoxConfig,
    GrayBoxResult,
    ResultStatus,
    TestCategory,
)
from graybox.payload_manager import GrayBoxPayloadManager
from graybox.registry import GRAYBOX_REGISTRY, get_graybox_registry
from graybox.reporting import (
    render_graybox_html,
    save_graybox_run_output,
)
from graybox.runner import calculate_suite_metrics, run_graybox_suite


def _init_graybox_session_state() -> None:
    """Initialize Streamlit session state for Gray-Box testing with complete isolation."""
    if "gb_scan_phase" not in st.session_state:
        st.session_state.gb_scan_phase = "idle"
        st.session_state.gb_results = []
        st.session_state.gb_target = ""
        st.session_state.gb_run_dir = None
        st.session_state.gb_artifacts = GrayBoxArtifactManager()
        st.session_state.gb_accounts = GrayBoxAccountManager()


def render_graybox_ui() -> None:
    """Render the complete Gray-Box Security Testing interface."""
    _init_graybox_session_state()

    # Stylized banner
    st.markdown(
        """
        <div style="background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
                    padding: 20px 24px; border-radius: 10px; margin-bottom: 20px;
                    border-left: 6px solid #6366f1; color: #f8fafc;">
            <div style="font-size: 1.4rem; font-weight: 700; display:flex; align-items:center; gap:10px;">
                <span>🛡️ Gray-Box Security Testing Platform</span>
                <span style="font-size: 0.75rem; background: #6366f1; color: white; padding: 2px 8px; border-radius: 12px; font-weight: 600;">OWASP WSTG & ASVS</span>
            </div>
            <div style="font-size: 0.88rem; color: #94a3b8; margin-top: 6px;">
                Authorized client-side security assessment subsystem with <strong>85 dedicated testcases</strong>,
                typed payload libraries, multi-role credential orchestration, and artifact ingestion.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Target & Environment Controls
    st.subheader("1. Target & Environment Configuration")
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        gb_target = st.text_input(
            "Target Base URL",
            value=st.session_state.get("gb_target", ""),
            placeholder="https://app.example.com or http://localhost:8000",
            key="gb_target_input",
            help="Authorized target domain or IP. Supports HTTP and HTTPS.",
        )
    with col_t2:
        gb_login_path = st.text_input(
            "Login Path",
            value="/login",
            key="gb_login_path_input",
            help="Relative endpoint for authentication forms.",
        )

    col_c1, col_c2, col_c3 = st.columns(3)
    with col_c1:
        gb_verify_tls = st.checkbox("Verify TLS Certificates", value=True, key="gb_verify_tls_cb")
    with col_c2:
        gb_allow_private = st.checkbox("Allow Private / Local Targets", value=True, key="gb_allow_private_cb")
    with col_c3:
        gb_auth_confirmed = st.checkbox(
            "I have explicit authorization to assess this target",
            value=False,
            key="gb_auth_cb",
        )

    with st.expander("⚙️ Execution Safeguards & Safety Budget", expanded=False):
        col_b1, col_b2, col_b3 = st.columns(3)
        with col_b1:
            gb_budget = st.number_input("Request Budget per Testcase", min_value=5, max_value=200, value=50, key="gb_budget_num")
        with col_b2:
            gb_timeout = st.number_input("Request Timeout (seconds)", min_value=1.0, max_value=60.0, value=10.0, key="gb_timeout_num")
        with col_b3:
            gb_delay = st.number_input("Delay Between Requests (seconds)", min_value=0.0, max_value=2.0, value=0.05, step=0.05, key="gb_delay_num")

    # 2. Knowledge & Artifact Manager
    st.subheader("2. Gray-Box Knowledge & Artifact Manager")
    with st.expander("📂 Ingest Assessment Artifacts (OpenAPI, SBOM, Source, Schema, Roles)", expanded=False):
        st.caption("Supply white-box/gray-box artifacts to unlock assisted and architecture-dependent security checks.")
        art_tab1, art_tab2, art_tab3, art_tab4 = st.tabs(["OpenAPI / Swagger", "SBOM & Dependencies", "Source Code & Schemas", "Role & Permission Matrix"])

        with art_tab1:
            st.markdown("**Upload OpenAPI / Swagger Specification** (JSON or YAML)")
            openapi_file = st.file_uploader("Upload OpenAPI Spec", type=["json", "yaml", "yml"], key="gb_openapi_upload")
            openapi_text = st.text_area("Or paste OpenAPI JSON content directly:", height=100, key="gb_openapi_paste")
            if st.button("Ingest OpenAPI Artifact", key="btn_ingest_openapi"):
                content = ""
                name = "openapi_spec"
                if openapi_file:
                    content = openapi_file.read().decode("utf-8", errors="replace")
                    name = openapi_file.name
                elif openapi_text.strip():
                    content = openapi_text.strip()
                if content:
                    st.session_state.gb_artifacts.add_artifact(
                        artifact_type=ArtifactType.OPENAPI_SPEC,
                        name=name,
                        content=content,
                    )
                    st.success("✅ OpenAPI artifact registered successfully.")

        with art_tab2:
            st.markdown("**Upload SBOM or Dependency Manifests** (package.json, requirements.txt, CycloneDX)")
            sbom_file = st.file_uploader("Upload SBOM file", type=["json", "txt", "xml"], key="gb_sbom_upload")
            sbom_text = st.text_area("Or paste SBOM / requirements.txt text:", height=100, key="gb_sbom_paste")
            if st.button("Ingest SBOM Artifact", key="btn_ingest_sbom"):
                content = ""
                name = "sbom_manifest"
                if sbom_file:
                    content = sbom_file.read().decode("utf-8", errors="replace")
                    name = sbom_file.name
                elif sbom_text.strip():
                    content = sbom_text.strip()
                if content:
                    st.session_state.gb_artifacts.add_artifact(
                        artifact_type=ArtifactType.SBOM,
                        name=name,
                        content=content,
                    )
                    st.success("✅ SBOM artifact registered successfully.")

        with art_tab3:
            st.markdown("**Ingest Source Code Snippets or Database Schemas**")
            source_text = st.text_area("Paste critical endpoint source code or database schema (SQL DDL):", height=100, key="gb_source_paste")
            if st.button("Ingest Source/Schema Artifact", key="btn_ingest_source"):
                if source_text.strip():
                    st.session_state.gb_artifacts.add_artifact(
                        artifact_type=ArtifactType.SOURCE_CODE,
                        name="source_snippet.py",
                        content=source_text.strip(),
                    )
                    st.success("✅ Source artifact registered.")

        with art_tab4:
            st.markdown("**Ingest Role & Permission Matrix**")
            matrix_text = st.text_area("Paste documented permission matrix (JSON or Markdown table):", height=100, key="gb_matrix_paste")
            if st.button("Ingest Permission Matrix", key="btn_ingest_matrix"):
                if matrix_text.strip():
                    st.session_state.gb_artifacts.add_artifact(
                        artifact_type=ArtifactType.ROLE_MATRIX,
                        name="role_matrix.json",
                        content=matrix_text.strip(),
                    )
                    st.success("✅ Role matrix registered.")

        # Show currently loaded artifacts
        loaded_arts = st.session_state.gb_artifacts.artifacts
        if loaded_arts:
            st.markdown(f"**Currently Active Artifacts ({len(loaded_arts)}):**")
            for art in loaded_arts:
                st.info(f"📄 **[{art.artifact_type.value}]** {art.name} ({len(art.content)} bytes)")

    # 3. Account and Role Manager
    st.subheader("3. Account & Role Manager")
    with st.expander("👥 Configure Test Identities (User A, User B, Admin)", expanded=False):
        st.caption("IDOR, Privilege Escalation, and Session Management testcases use these identities safely.")
        acc_tab1, acc_tab2, acc_tab3 = st.tabs(["Standard User A", "Standard User B (IDOR Isolation)", "Administrator / Privileged"])

        with acc_tab1:
            ua_user = st.text_input("User A Username / ID", key="gb_ua_user", placeholder="testuser_a")
            ua_pass = st.text_input("User A Password", key="gb_ua_pass", type="password")
            ua_token = st.text_input("User A Bearer Token / Session Cookie (Optional)", key="gb_ua_token")
            if st.button("Save User A Account", key="btn_save_ua"):
                st.session_state.gb_accounts.add_account(
                    TestAccount(
                        role=AccountRole.USER_A,
                        username=ua_user.strip(),
                        password=ua_pass,
                        bearer_token=ua_token.strip(),
                    )
                )
                st.success("✅ User A identity configured.")

        with acc_tab2:
            ub_user = st.text_input("User B Username / ID", key="gb_ub_user", placeholder="testuser_b")
            ub_pass = st.text_input("User B Password", key="gb_ub_pass", type="password")
            ub_token = st.text_input("User B Bearer Token / Session Cookie (Optional)", key="gb_ub_token")
            if st.button("Save User B Account", key="btn_save_ub"):
                st.session_state.gb_accounts.add_account(
                    TestAccount(
                        role=AccountRole.USER_B,
                        username=ub_user.strip(),
                        password=ub_pass,
                        bearer_token=ub_token.strip(),
                    )
                )
                st.success("✅ User B identity configured.")

        with acc_tab3:
            adm_user = st.text_input("Admin Username / ID", key="gb_adm_user", placeholder="admin_user")
            adm_pass = st.text_input("Admin Password", key="gb_adm_pass", type="password")
            adm_token = st.text_input("Admin Bearer Token (Optional)", key="gb_adm_token")
            if st.button("Save Admin Account", key="btn_save_adm"):
                st.session_state.gb_accounts.add_account(
                    TestAccount(
                        role=AccountRole.ADMINISTRATOR,
                        username=adm_user.strip(),
                        password=adm_pass,
                        bearer_token=adm_token.strip(),
                    )
                )
                st.success("✅ Administrator identity configured.")

    # 4. Category & Testcase Scope Selection
    st.subheader("4. Testcase Scope Selection")
    all_categories = [
        TestCategory.BASIC.value,
        TestCategory.ENCRYPTION.value,
        TestCategory.FORM_AUTHENTICATION.value,
        TestCategory.SESSION_MANAGEMENT.value,
        TestCategory.INJECTION.value,
        TestCategory.SSRF.value,
    ]
    selected_categories = st.multiselect(
        "Select Categories to Assess",
        options=all_categories,
        default=all_categories,
        key="gb_selected_categories",
    )

    with st.expander(f"📋 View Registered Inventory ({len(GRAYBOX_REGISTRY)} Testcases)", expanded=False):
        table_rows = []
        for tc in GRAYBOX_REGISTRY.values():
            cat_name = tc.category.value if hasattr(tc.category, "value") else str(tc.category)
            if not selected_categories or cat_name in selected_categories:
                table_rows.append({
                    "ID": tc.id,
                    "Name": tc.name,
                    "Category": cat_name,
                    "Automation": tc.automation_level.value if hasattr(tc.automation_level, "value") else str(tc.automation_level),
                    "Payload Library": tc.payload_file,
                })
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

    # 5. Execution Button
    st.subheader("5. Run Gray-Box Security Assessment")
    run_btn = st.button("🚀 Start Gray-Box Security Assessment", type="primary", use_container_width=True, key="gb_start_btn")

    if run_btn:
        if not gb_target.strip():
            st.error("Please provide a valid Target Base URL.")
            return
        if not gb_auth_confirmed:
            st.error("Written authorization confirmation is required before launching the assessment.")
            return

        config = GrayBoxConfig(
            target_url=gb_target.strip(),
            login_path=gb_login_path.strip() or "/login",
            verify_tls=gb_verify_tls,
            allow_private_targets=gb_allow_private,
            request_budget_per_testcase=int(gb_budget),
            timeout_seconds=float(gb_timeout),
            delay_between_requests=float(gb_delay),
            active_categories=[TestCategory(c) for c in selected_categories],
            operator_authorized=True,
        )

        progress_bar = st.progress(0, text="Initializing Gray-Box assessment...")
        status_box = st.status("Executing Gray-Box security test suite...", expanded=True)

        def on_progress(current: int, total: int, res: GrayBoxResult) -> None:
            pct = int((current / total) * 100)
            progress_bar.progress(pct, text=f"[{current}/{total}] Executed {res.testcase_id}: {res.name} ({res.status})")
            status_box.write(f"`{res.testcase_id}`: **{res.name}** -> `{res.status}`")

        with st.spinner("Running Gray-Box security testcases..."):
            results = run_graybox_suite(
                config=config,
                artifacts=st.session_state.gb_artifacts,
                accounts=st.session_state.gb_accounts,
                progress_callback=on_progress,
            )

        run_dir = save_graybox_run_output(
            target=config.target_url,
            results=results,
            config=config,
        )

        st.session_state.gb_scan_phase = "done"
        st.session_state.gb_results = results
        st.session_state.gb_target = config.target_url
        st.session_state.gb_run_dir = run_dir

        status_box.update(label=f"Completed {len(results)} Gray-Box testcases.", state="complete", expanded=False)
        progress_bar.empty()
        st.rerun()

    # 6. Render Results if Available
    if st.session_state.gb_scan_phase == "done" and st.session_state.gb_results:
        _render_graybox_results(
            results=st.session_state.gb_results,
            target=st.session_state.gb_target,
            run_dir=st.session_state.gb_run_dir,
        )


def _render_graybox_results(
    results: list[GrayBoxResult],
    target: str,
    run_dir: Path | None,
) -> None:
    """Render comprehensive Gray-Box assessment findings, metrics, and payload coverage."""
    st.markdown("---")
    st.subheader(f"📊 Assessment Results: {target}")

    metrics = calculate_suite_metrics(results)
    status_counts = metrics.get("status_counts", {})
    payload_cov = metrics.get("payload_coverage", {})
    coverage_pct = payload_cov.get("coverage_percentage", 100.0)

    # Executive Metric Cards
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Total Tests", metrics["total_testcases"])
    with c2:
        st.metric("Confirmed (UNSAFE)", status_counts.get("UNSAFE", 0), delta=None)
    with c3:
        st.metric("Review Required", status_counts.get("REVIEW REQUIRED", 0))
    with c4:
        st.metric("Verified Safe", status_counts.get("SAFE", 0))
    with c5:
        st.metric("Payload Coverage", f"{coverage_pct}%", help=f"{payload_cov.get('executed', 0)} of {payload_cov.get('total_required', 0)} required payloads executed")

    st.caption(f"**Payload Execution Details:** {payload_cov.get('executed', 0)} executed, {payload_cov.get('skipped', 0)} skipped, {payload_cov.get('failed', 0)} failed.")

    # Report Download Actions
    if run_dir and Path(run_dir).exists():
        html_file = Path(run_dir) / "compiled_graybox.html"
        json_file = Path(run_dir) / "compiled_graybox.json"
        md_file = Path(run_dir) / "report.md"

        d_col1, d_col2, d_col3 = st.columns(3)
        if html_file.exists():
            with d_col1:
                st.download_button(
                    "📄 Download HTML Report",
                    data=html_file.read_bytes(),
                    file_name="graybox_assessment_report.html",
                    mime="text/html",
                    use_container_width=True,
                )
        if json_file.exists():
            with d_col2:
                st.download_button(
                    "📦 Download JSON Report",
                    data=json_file.read_bytes(),
                    file_name="graybox_assessment_report.json",
                    mime="application/json",
                    use_container_width=True,
                )
        if md_file.exists():
            with d_col3:
                st.download_button(
                    "📝 Download Markdown Report",
                    data=md_file.read_bytes(),
                    file_name="graybox_assessment_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                )

    # Category and Status Filter Controls
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        status_filter = st.multiselect(
            "Filter by Result Status",
            options=list(status_counts.keys()),
            default=[s for s in status_counts.keys() if status_counts[s] > 0],
            key="gb_status_filter",
        )
    with filter_col2:
        search_query = st.text_input("Search testcases by keyword / ID", "", key="gb_search_query")

    filtered_results = [
        r for r in results
        if (not status_filter or r.status in status_filter)
        and (not search_query or search_query.lower() in r.name.lower() or search_query.lower() in r.testcase_id.lower())
    ]

    st.markdown(f"**Showing {len(filtered_results)} of {len(results)} testcases:**")

    for r in filtered_results:
        status_color = {
            ResultStatus.UNSAFE.value: "red",
            ResultStatus.SAFE.value: "green",
            ResultStatus.REVIEW_REQUIRED.value: "orange",
            ResultStatus.NOT_ASSESSED.value: "gray",
            ResultStatus.INCOMPLETE.value: "gray",
            ResultStatus.SKIPPED.value: "gray",
            ResultStatus.ERROR.value: "red",
        }.get(r.status, "gray")

        with st.expander(f"**[{r.testcase_id}] {r.name}** — :{status_color}[{r.status}]", expanded=(r.status == ResultStatus.UNSAFE.value)):
            st.markdown(f"**Category:** {r.category} | **Automation Level:** `{r.automation_level}` | **Assessment State:** `{r.assessment_state}`")
            st.markdown(f"**Summary:** {r.summary}")

            cov = r.payload_coverage
            st.markdown(f"**Payloads Executed:** {cov.executed}/{cov.total_required} required (Skipped: {cov.skipped})")

            if r.evidence:
                st.markdown("**Evidence Collected:**")
                for e in r.evidence:
                    st.code(redact_text_secrets(e), language="text")

            if r.details:
                st.markdown("**Technical Findings:**")
                st.json(r.details)
