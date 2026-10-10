from __future__ import annotations

from authentication.browser_memory_analyzer import analyze_browser_memory
from authentication.browser_memory_models import MemoryObservation


def test_direct_page_memory_retention_confirms():
    observations = [
        MemoryObservation(
            phase="after_clear",
            source="js_reachable",
            inspected=True,
            matched=True,
            confidence="high",
            matched_type="password",
            location="window.passwordCache",
        )
    ]
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=observations,
        authenticated_completed=True,
        heap_supported=True,
        heap_examined=True,
        direct_issue=True,
        heap_only_issue=False,
        storage_issue=False,
        require_authenticated_lane=True,
    )
    assert result.status == "CONFIRMED"
    assert result.assessment_state == "CONFIRMED"


def test_username_only_retention_does_not_confirm_credential_exposure():
    observations = [
        MemoryObservation(
            phase="after_clear",
            source="js_reachable",
            inspected=True,
            matched=True,
            confidence="medium",
            matched_type="username",
            location="window.currentUser",
        )
    ]
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=observations,
        authenticated_completed=True,
        heap_supported=True,
        heap_examined=True,
        direct_issue=False,
        heap_only_issue=False,
        storage_issue=False,
        require_authenticated_lane=True,
    )
    assert result.status == "SAFE"


def test_exact_storage_retention_confirms():
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=[],
        authenticated_completed=True,
        heap_supported=True,
        heap_examined=True,
        direct_issue=False,
        heap_only_issue=False,
        storage_issue=True,
        require_authenticated_lane=True,
    )
    assert result.status == "CONFIRMED"


def test_heap_only_signal_requires_manual_review():
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=[],
        authenticated_completed=True,
        heap_supported=True,
        heap_examined=True,
        direct_issue=False,
        heap_only_issue=True,
        storage_issue=False,
        require_authenticated_lane=True,
    )
    assert result.status == "REVIEW REQUIRED"
    assert result.assessment_state == "REVIEW_REQUIRED"


def test_missing_authenticated_lane_is_incomplete():
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=[],
        authenticated_completed=False,
        heap_supported=True,
        heap_examined=True,
        direct_issue=False,
        heap_only_issue=False,
        storage_issue=False,
        require_authenticated_lane=True,
    )
    assert result.status == "INCOMPLETE"


def test_clean_full_run_is_safe():
    result = analyze_browser_memory(
        target="https://example.test",
        login_url="https://example.test/login",
        observations=[
            MemoryObservation(
                phase="after_clear",
                source="dom_js",
                inspected=True,
                matched=False,
            )
        ],
        authenticated_completed=True,
        heap_supported=True,
        heap_examined=True,
        direct_issue=False,
        heap_only_issue=False,
        storage_issue=False,
        require_authenticated_lane=True,
    )
    assert result.status == "SAFE"
    assert result.assessment_state == "NOT_A_FINDING"


def test_browser_memory_config_normalization_disallows_unbounded_values():
    from authentication.browser_memory_models import BrowserMemoryConfig

    cfg = BrowserMemoryConfig(
        heap_snapshot_max_bytes=1,
        indexeddb_max_databases=0,
        indexeddb_max_records_per_store=0,
        max_global_objects=1,
    ).normalized()
    assert cfg.heap_snapshot_max_bytes >= 1024 * 1024
    assert cfg.indexeddb_max_databases >= 1
    assert cfg.indexeddb_max_records_per_store >= 1
    assert cfg.max_global_objects >= 50
