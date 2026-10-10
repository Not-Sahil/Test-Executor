from authentication.method_interchange_analyzer import assess_method_interchange
from authentication.method_interchange_models import MethodObservation

def obs(
    case_id: str,
    method: str,
    *,
    auth: bool,
    rejected: bool,
    rate_limited: bool = False,
) -> MethodObservation:
    return MethodObservation(
        case_id=case_id,
        method=method,
        credential_profile=case_id,
        status_code=302 if auth else 401,
        final_url="/dashboard" if auth else "/login",
        response_length=100,
        authenticated_signal=auth,
        rejected_signal=rejected,
        rate_limited=rate_limited,
    )

def test_alternate_wrong_password_acceptance_is_confirmed():
    decision = assess_method_interchange(
        expected_valid=obs("EV", "POST", auth=True, rejected=False),
        expected_wrong=obs("EW", "POST", auth=False, rejected=True),
        alternate_valid=obs("AV", "GET", auth=True, rejected=False),
        alternate_wrong=obs("AW", "GET", auth=True, rejected=False),
    )
    assert decision["status"] == "UNSAFE"
    assert decision["assessment_state"] == "CONFIRMED"

def test_valid_alternate_method_alone_is_not_a_finding():
    decision = assess_method_interchange(
        expected_valid=obs("EV", "POST", auth=True, rejected=False),
        expected_wrong=obs("EW", "POST", auth=False, rejected=True),
        alternate_valid=obs("AV", "GET", auth=True, rejected=False),
        alternate_wrong=obs("AW", "GET", auth=False, rejected=True),
    )
    assert decision["status"] == "SAFE"
    assert decision["assessment_state"] == "NOT_A_FINDING"

def test_baseline_valid_authentication_failure_is_incomplete():
    decision = assess_method_interchange(
        expected_valid=obs("EV", "POST", auth=False, rejected=True),
        expected_wrong=obs("EW", "POST", auth=False, rejected=True),
        alternate_valid=obs("AV", "GET", auth=True, rejected=False),
        alternate_wrong=obs("AW", "GET", auth=True, rejected=False),
    )
    assert decision["status"] == "INCOMPLETE"

def test_rate_limit_causes_review():
    decision = assess_method_interchange(
        expected_valid=obs("EV", "POST", auth=True, rejected=False),
        expected_wrong=obs("EW", "POST", auth=False, rejected=True, rate_limited=True),
        alternate_valid=obs("AV", "GET", auth=False, rejected=True),
        alternate_wrong=obs("AW", "GET", auth=False, rejected=True),
    )
    assert decision["status"] == "REVIEW REQUIRED"

def test_observation_serializes():
    item = obs("EV", "POST", auth=True, rejected=False)
    payload = item.as_dict()
    assert payload["method"] == "POST"
    assert payload["authenticated_signal"] is True
