import json
import os
from pathlib import Path

_BROWSER_DIR = Path(__file__).resolve().parent / ".playwright-browsers"
if _BROWSER_DIR.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_BROWSER_DIR))

import streamlit as st

from known_components_scanner import scan_known_components
from helpful_error_scanner import scan_helpful_error_messages

from integrated_scanner import (
    captcha_auth_result,
    overall_status,
    run_default_credentials,
    run_first_four_tests,
    run_user_enumeration,
    _not_applicable_auth_result,
    ScanResult,
)
from captcha_human import human_login_with_captcha, probe_login_captcha
from run_output import save_run_output


# ==============================================================
# CONFIGURATION
# ==============================================================

CREDENTIAL_FILE = Path(__file__).with_name("credentials.json")

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
    Load the shared credentials.json database.

    The same JSON file is used for:
      - Default Credentials: username + password
      - User Enumeration: username only
    """

    if not CREDENTIAL_FILE.exists():
        raise FileNotFoundError(
            f"credentials.json was not found beside app.py:\n{CREDENTIAL_FILE}"
        )

    with open(CREDENTIAL_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(
            "credentials.json must contain a JSON list of credential objects."
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
        })

    if not credentials:
        raise ValueError(
            "credentials.json contains no usable credential entries."
        )

    # Same database -> usernames for enumeration.
    candidate_usernames = list(dict.fromkeys(
        item["username"] for item in credentials
    ))

    return credentials, candidate_usernames


def _status_icon(status: str) -> str:
    return {
        "SAFE": "🟢",
        "UNSAFE": "🔴",
        "REVIEW REQUIRED": "🟠",
        "SKIPPED": "⚪",
        "ERROR": "⚠️",
        "INCOMPLETE": "⚠️",
        "UNKNOWN": "⚠️",
    }.get(status, "⚪")


def _as_scan_result(result, key: str, name: str) -> ScanResult:
    """Normalize scanner dataclasses/dicts into the shared ScanResult shape."""
    if isinstance(result, ScanResult):
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
        status=str(payload.get("status") or "INCOMPLETE"),
        summary=str(payload.get("summary") or "The scanner did not produce a structured result."),
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

def render_combined_report(results: list, target_url: str, run_dir=None) -> None:
    st.header("4. Combined Assessment Result — 8 Checks")
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

    st.caption(f"Target: {target_url}")
    if run_dir:
        st.info(f"Run output saved to `{run_dir}`")

    # Render summary cards in rows of up to six so all configured tests remain visible.
    for start in range(0, len(results), 6):
        row = results[start:start + 6]
        cols = st.columns(len(row))
        for col, result in zip(cols, row):
            with col:
                st.metric(
                    label=result.name,
                    value=f"{_status_icon(result.status)} {result.status}",
                )

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
    )

    st.subheader("Detailed Results")
    for number, result in enumerate(results, start=1):
        with st.expander(
            f"{number}. {_status_icon(result.status)} {result.name} — {result.status}",
            expanded=(result.status == "UNSAFE"),
        ):
            st.write(result.summary)
            if result.details:
                st.markdown("**Structured evidence**")
                st.json(result.details)
            if result.evidence:
                st.markdown("**Evidence**")
                for item in result.evidence:
                    st.code(str(item), language="text")
            if result.raw_output:
                st.markdown("**Scanner output**")
                st.code(result.raw_output, language="text")

    unsafe = [r for r in results if r.status == "UNSAFE"]
    review = [r for r in results if r.status == "REVIEW REQUIRED"]
    incomplete = [r for r in results if r.status in {"ERROR", "UNKNOWN", "INCOMPLETE"}]
    skipped = [r for r in results if r.status == "SKIPPED"]

    st.subheader("Client-Friendly Findings")
    if unsafe:
        st.markdown("### 🔴 Issues detected")
        for r in unsafe:
            st.write(f"• **{r.name}:** {r.summary}")
    if review:
        st.markdown("### 🟠 Requires review")
        for r in review:
            st.write(f"• **{r.name}:** {r.summary}")
    if incomplete:
        st.markdown("### Checks that did not complete")
        for r in incomplete:
            st.write(f"• **{r.name}:** {r.summary}")
    if skipped:
        st.markdown("### Not applicable")
        for r in skipped:
            st.write(f"• **{r.name}:** {r.summary}")
    if not unsafe and not review and not incomplete:
        if skipped:
            st.success(
                "No issues were identified by the checks that ran. "
                "Some checks were not applicable to this login page."
            )
        else:
            st.success(
                "No issues were identified by the configured security checks."
            )

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
# PAGE CONFIGURATION
# ==============================================================

st.set_page_config(
    page_title="Test Executor",
    page_icon="🛡️",
    layout="wide",
)

st.title("Security Assessment Test Executor")
st.caption(
    "Runs the configured security checks sequentially and presents one combined report (8 checks). "
    "Federated SSO / identity-provider login pages skip default-credential and "
    "user-enumeration checks as not applicable. If a CAPTCHA is detected, those two "
    "checks pause so you can solve it, skip one pair, or skip the test."
)


# ==============================================================
# TARGET CONFIGURATION
# ==============================================================

st.header("1. Target")

target = st.text_input(
    "Target URL",
    placeholder="https://example.com",
    help="Enter the live website you are authorized to assess.",
)

login_path = st.text_input(
    "Login page URL or path",
    value="/login",
    help=(
        "Paste the full login URL (https://example.com/login) or only the path "
        "(/login, /login.jsp). Used by default-credentials and user-enumeration. "
        "Hosted SSO pages (OAuth / OpenID Connect identity providers) are skipped "
        "as not applicable."
    ),
    placeholder="https://example.com/login",
)

known_valid_username_input = st.text_input(
    "Known Valid Username (User Enumeration control)",
    value="",
    placeholder="e.g. demo-user",
    help=(
        "Optional but recommended for User Enumeration. Enter a username you know "
        "exists on the authorized target. The scanner tests it with the deliberately "
        "wrong password as the known-valid control, then compares candidate usernames "
        "against both known-invalid and known-valid responses. The control username "
        "itself is never counted as an enumeration finding."
    ),
)

if known_valid_username_input.strip():
    st.info(
        f"User Enumeration control: `{known_valid_username_input.strip()}` "
        "(password is not requested or displayed)."
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
# AUTHENTICATION DATABASE STATUS
# ==============================================================

st.header("2. Authentication Database")

try:
    credentials, candidate_usernames = load_authentication_database()

    st.success(
        "Authentication credentials loaded automatically from credentials.json."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Credential Pairs",
            len(credentials),
        )

    with col2:
        st.metric(
            "Unique Usernames",
            len(candidate_usernames),
        )

    st.caption(
        "The credential pairs are used for the Default Credentials test. "
        "The usernames from the same file are used for User Enumeration. "
        "Credentials are not displayed in the UI."
    )

except Exception as exc:
    credentials = []
    candidate_usernames = []

    st.error(
        f"Could not load the authentication database: {exc}"
    )


# ==============================================================
# RUN ASSESSMENT
# ==============================================================

if "scan_phase" not in st.session_state:
    st.session_state.scan_phase = "idle"
    st.session_state.scan_results = []
    st.session_state.scan_target = ""
    st.session_state.scan_run_dir = None
    st.session_state.captcha_notice = ""

st.header("3. Run Assessment")

if st.button(
    "🚀 Start Security Assessment",
    type="primary",
    use_container_width=True,
    key="start_assessment",
):

    if not target.strip():
        st.error("Enter a target URL.")
        st.stop()

    if not credentials:
        st.error(
            "No authentication credentials were loaded from credentials.json."
        )
        st.stop()

    target_url = target.strip()
    if not target_url.lower().startswith(("http://", "https://")):
        target_url = "https://" + target_url

    login_input = login_path.strip() or "/login"
    manual_known_valid_username = known_valid_username_input.strip() or None
    st.session_state.verify_tls = bool(verify_tls)
    st.session_state.known_valid_username = manual_known_valid_username
    pair_limit = MAX_CREDENTIAL_ATTEMPTS
    credential_pairs = (
        credentials[:pair_limit] if pair_limit else list(credentials)
    )
    usernames = (
        candidate_usernames[:pair_limit]
        if pair_limit
        else list(candidate_usernames)
    )

    progress_box = st.empty()
    status_box = st.status(
        "Starting security assessment...",
        expanded=True,
    )
    completed = []

    def progress(message):
        completed.append(message)
        progress_box.info(message)
        status_box.write("▶ " + message)

    try:
        first_four = run_first_four_tests(target_url, progress=progress)

        # Test Case 5: Known Components
        progress("Running Known Components check")
        known_components_raw = scan_known_components(
            target_url,
            timeout=8.0,
            use_browser_runtime=True,
        )
        known_components_result = _as_scan_result(
            known_components_raw,
            "known_components",
            "Known Components",
        )

        # Test Case 8: Helpful Error Messages (WSTG-ERRH-01 oriented)
        progress("Running Helpful Error Messages check")
        helpful_error_raw = scan_helpful_error_messages(
            target_url,
            timeout=8.0,
            verify_tls=True,
        )
        helpful_error_result = _as_scan_result(
            helpful_error_raw,
            "helpful_error_messages",
            "Helpful Error Messages",
        )

        base_results = list(first_four) + [
            known_components_result,
            helpful_error_result,
        ]

        progress("Checking whether the login page uses federated SSO or a CAPTCHA")
        meta = probe_login_captcha(target_url, login_input, verify_tls=verify_tls)

        if meta.get("federated"):
            progress(
                "Skipping Default Credentials and User Enumeration: "
                "login is federated SSO / identity-provider (not applicable)"
            )
            results = list(base_results)
            results.append(
                _not_applicable_auth_result(
                    "default_credentials",
                    "Default Credentials",
                    meta["federated"],
                )
            )
            results.append(
                _not_applicable_auth_result(
                    "user_enumeration",
                    "User Enumeration",
                    meta["federated"],
                )
            )
            st.session_state.scan_target = target_url
            st.session_state.scan_results = results
            _finish_scan()
            status_box.update(
                label="Assessment completed.",
                state="complete",
                expanded=False,
            )
            progress_box.empty()
            st.rerun()

        if not meta.get("captcha_marker"):
            results = list(base_results)
            default_credentials_result = run_default_credentials(
                target=target_url,
                login_path=login_input,
                credential_pairs=credential_pairs,
                max_attempts=MAX_CREDENTIAL_ATTEMPTS,
                verify_tls=verify_tls,
                progress=progress,
            )
            results.append(default_credentials_result)

            auto_known_valid_username = _extract_known_valid_username(
                default_credentials_result, credentials
            )
            known_valid_username = manual_known_valid_username or auto_known_valid_username
            if manual_known_valid_username:
                progress(
                    f"Using the operator-supplied known-valid username as the User Enumeration control: {manual_known_valid_username}"
                )
            elif auto_known_valid_username:
                progress(
                    f"Using a confirmed/declared valid username as the User Enumeration control: {auto_known_valid_username}"
                )
            else:
                progress(
                    "No known-valid username is available; User Enumeration will use the synthetic invalid-user baseline only"
                )

            results.append(
                run_user_enumeration(
                    target=target_url,
                    login_path=login_input,
                    candidate_usernames=usernames,
                    probe_password=ENUMERATION_PROBE_PASSWORD,
                    known_valid_username=known_valid_username,
                    verify_tls=verify_tls,
                    progress=progress,
                )
            )
            st.session_state.scan_target = target_url
            st.session_state.scan_results = results
            _finish_scan()
            status_box.update(
                label="All configured security checks completed.",
                state="complete",
                expanded=False,
            )
            progress_box.empty()
            st.rerun()

        _init_captcha_session(
            target_url,
            login_input,
            base_results,
            meta,
            credential_pairs,
            usernames,
            verify_tls=verify_tls,
        )
        status_box.update(
            label="Non-authentication checks finished. CAPTCHA paused authentication checks.",
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
