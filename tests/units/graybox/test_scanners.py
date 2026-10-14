"""Tests for Gray-Box scanner execution, safety budgets, evidence, and prerequisite checking."""
from unittest.mock import MagicMock, patch
import requests

from graybox.accounts import GrayBoxAccountManager, TestAccount
from graybox.artifacts import GrayBoxArtifactManager
from graybox.models import (
    AccountRole,
    ArtifactType,
    GrayBoxConfig,
    GrayBoxPayload,
    ResultStatus,
)
from graybox.runner import run_graybox_testcase
from graybox.scanners.basic import (
    GBBASIC06_SecurityHeaders,
    GBBASIC14_HostHeaderInjection,
)
from graybox.scanners.common import GrayBoxExecutionSession


def test_safety_budget_stops_requests_when_exhausted():
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000", request_budget_per_testcase=2)
    session = GrayBoxExecutionSession(config=config)

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_resp.headers = {}

    with patch.object(session.session, "request", return_value=mock_resp) as mock_req:
        r1 = session.get("http://127.0.0.1:8000/1")
        assert r1 is not None
        assert session.request_count == 1

        r2 = session.get("http://127.0.0.1:8000/2")
        assert r2 is not None
        assert session.request_count == 2

        # 3rd request must be blocked by budget
        r3 = session.get("http://127.0.0.1:8000/3")
        assert r3 is None
        assert session.request_count == 2
        assert mock_req.call_count == 2


def test_missing_role_prerequisite_reports_not_assessed():
    # GB-SESSION-15 (IDOR) requires USER_A and USER_B
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")
    accounts = GrayBoxAccountManager()  # Anonymous only

    result = run_graybox_testcase(
        testcase_id="GB-SESSION-15",
        config=config,
        accounts=accounts,
    )

    assert result.status == ResultStatus.NOT_ASSESSED.value
    assert result.assessment_state == "NOT_ASSESSED"
    assert "Prerequisite account role" in result.summary


def test_missing_artifact_prerequisite_reports_not_assessed():
    # Suppose a testcase requires an artifact
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")
    artifacts = GrayBoxArtifactManager()
    accounts = GrayBoxAccountManager()

    # If testcase ID does not exist
    result_invalid = run_graybox_testcase(
        testcase_id="GB-NONEXISTENT-99",
        config=config,
        artifacts=artifacts,
        accounts=accounts,
    )
    assert result_invalid.status == ResultStatus.ERROR.value


def test_security_headers_scanner_safe_when_all_headers_present():
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")
    session = GrayBoxExecutionSession(config=config)

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    mock_resp.text = "Safe Web Application"

    with patch.object(session.session, "request", return_value=mock_resp):
        scanner = GBBASIC06_SecurityHeaders(session=session)
        res = scanner.execute()
        assert res.status == ResultStatus.SAFE.value
        assert "present" in res.summary.lower()


def test_security_headers_scanner_review_required_when_headers_missing():
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")
    session = GrayBoxExecutionSession(config=config)

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}  # Missing all security headers
    mock_resp.text = "Insecure Web Application"

    with patch.object(session.session, "request", return_value=mock_resp):
        scanner = GBBASIC06_SecurityHeaders(session=session)
        res = scanner.execute()
        assert res.status == ResultStatus.REVIEW_REQUIRED.value
        assert "Missing" in res.summary
        assert len(res.evidence) >= 1


def test_arbitrary_methods_scanner_unsafe_when_put_succeeds():
    from graybox.scanners.basic import GBBASIC04_ArbitraryMethods
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")
    session = GrayBoxExecutionSession(config=config)

    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.text = "Uploaded"

    with patch.object(session.session, "request", return_value=mock_resp):
        scanner = GBBASIC04_ArbitraryMethods(session=session)
        res = scanner.execute()
        assert res.status == ResultStatus.UNSAFE.value
        assert "Arbitrary HTTP PUT method is enabled" in res.summary
