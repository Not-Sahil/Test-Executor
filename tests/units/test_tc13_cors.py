from __future__ import annotations

from types import SimpleNamespace

from login_page.scanners.tc13_cors import (
    CORSProbe,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
    _classify_probe,
    _cors_fields,
    _build_probes,
    CORSConfig,
)


def response(headers=None, status_code=200):
    return SimpleNamespace(headers=headers or {}, status_code=status_code)


def test_no_acao_is_safe():
    probe = CORSProbe("simple", "https://evil.invalid")
    status, _ = _classify_probe(probe, {})
    assert status == STATUS_SAFE


def test_wildcard_noncredentialed_requires_review():
    probe = CORSProbe("simple", "https://evil.invalid")
    status, _ = _classify_probe(probe, {"access_control_allow_origin": "*"})
    assert status == STATUS_REVIEW


def test_wildcard_with_credentials_is_unsafe():
    probe = CORSProbe("credentialed", "https://evil.invalid", credentials=True)
    status, _ = _classify_probe(probe, {
        "access_control_allow_origin": "*",
        "access_control_allow_credentials": "true",
    })
    assert status == STATUS_UNSAFE


def test_reflected_credentialed_origin_is_unsafe():
    origin = "https://evil.invalid"
    probe = CORSProbe("credentialed", origin, credentials=True)
    status, _ = _classify_probe(probe, {
        "access_control_allow_origin": origin,
        "access_control_allow_credentials": "true",
    })
    assert status == STATUS_UNSAFE


def test_reflected_origin_without_credentials_is_review():
    origin = "https://evil.invalid"
    probe = CORSProbe("simple", origin)
    status, _ = _classify_probe(probe, {
        "access_control_allow_origin": origin,
    })
    assert status == STATUS_REVIEW


def test_different_explicit_origin_is_safe():
    probe = CORSProbe("simple", "https://evil.invalid")
    status, _ = _classify_probe(probe, {
        "access_control_allow_origin": "https://trusted.example"
    })
    assert status == STATUS_SAFE


def test_header_extraction_is_case_insensitive():
    r = response({
        "Access-Control-Allow-Origin": "*",
        "Vary": "Origin",
    })
    fields = _cors_fields(r)
    assert fields["access_control_allow_origin"] == "*"
    assert fields["vary"] == "Origin"


def test_probe_budget_is_bounded():
    probes = _build_probes("https://example.test/login", CORSConfig(max_probes=3))
    assert len(probes) <= 3


def test_scanner_exposes_scan_alias():
    from login_page.scanners import tc13_cors
    assert callable(tc13_cors.scan)
    assert callable(tc13_cors.scan_cors)


def test_scan_cors_reports_probe_origin_count_without_name_error(monkeypatch):
    from login_page.scanners import tc13_cors

    class FakeSession:
        def request(self, method, target, **kwargs):
            return SimpleNamespace(
                headers={},
                status_code=200,
                url=target,
            )
        def close(self):
            pass

    monkeypatch.setattr(tc13_cors.requests, "Session", FakeSession)
    result = tc13_cors.scan_cors("https://example.test")
    assert result["status"] == STATUS_SAFE
    assert result["details"]["payload_library"]["items_used"] >= 1
