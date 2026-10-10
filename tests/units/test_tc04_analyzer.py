from dataclasses import dataclass

from authentication.enumeration_analyzer import AnalysisThresholds, classify_candidate
from authentication.enumeration_models import EnumerationClassification, ResponseFingerprint


@dataclass
class FakeResponse:
    status_code: int
    url: str
    headers: dict
    text_value: str

    @property
    def text(self):
        return self.text_value


@dataclass
class FakeProbe:
    response: FakeResponse
    fingerprint: ResponseFingerprint
    elapsed: float = 0.1
    rate_limited: bool = False
    error: str = ""


def fp(status, path, message, digest, length, password_step=False):
    return ResponseFingerprint(
        status=status,
        final_path=path,
        location_path="",
        content_type="text/html",
        body_length=length,
        normalized_digest=digest,
        message_class=message,
        password_step=password_step,
    )


def probe(username, fingerprint, body, status=200):
    return FakeProbe(
        response=FakeResponse(status, fingerprint.final_path, {}, body),
        fingerprint=fingerprint,
    )


def test_single_length_difference_is_inconclusive():
    baseline = probe("bad", fp(200, "/login", "invalid_username", "a", 100), "Invalid username")
    candidate = probe("alice", fp(200, "/login", "invalid_username", "b", 130), "Invalid username plus text")
    obs = classify_candidate(
        username="alice",
        candidate=candidate,
        invalid_control=baseline,
        thresholds=AnalysisThresholds(length_delta=20),
    )
    assert obs.classification == EnumerationClassification.INCONCLUSIVE.value


def test_invalid_password_message_plus_routing_difference_is_likely_valid():
    baseline = probe("bad", fp(401, "/login", "invalid_username", "a", 100), "Invalid username")
    candidate = probe("alice", fp(200, "/login", "invalid_password", "b", 140), "Incorrect password")
    obs = classify_candidate(
        username="alice",
        candidate=candidate,
        invalid_control=baseline,
        thresholds=AnalysisThresholds(length_delta=20),
    )
    assert obs.classification == EnumerationClassification.LIKELY_VALID.value
    assert "message" in obs.signals["signals_fired"] or "body" in obs.signals["signals_fired"]


def test_timing_only_never_confirms():
    baseline = probe("bad", fp(200, "/login", "generic_failure", "a", 100), "Invalid credentials")
    candidate = probe("alice", fp(200, "/login", "generic_failure", "a", 100), "Invalid credentials")
    obs = classify_candidate(
        username="alice",
        candidate=candidate,
        invalid_control=baseline,
        candidate_samples=[0.50, 0.51, 0.49],
        invalid_samples=[0.10, 0.11, 0.09],
        thresholds=AnalysisThresholds(length_delta=20, timing_ratio=1.8),
    )
    assert obs.classification == EnumerationClassification.INCONCLUSIVE.value
