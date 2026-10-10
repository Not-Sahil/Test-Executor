from __future__ import annotations

from typing import Iterable

from authentication.browser_memory_models import BrowserMemoryResult, MemoryObservation


def _status_payload(status: str, state: str, summary: str, **kwargs):
    return BrowserMemoryResult(
        status=status,
        assessment_state=state,
        summary=summary,
        **kwargs,
    )


def analyze_browser_memory(
    *,
    target: str,
    login_url: str,
    observations: Iterable[MemoryObservation],
    authenticated_completed: bool,
    heap_supported: bool,
    heap_examined: bool,
    direct_issue: bool,
    heap_only_issue: bool,
    storage_issue: bool,
    errors: list[str] | None = None,
    require_authenticated_lane: bool = True,
) -> BrowserMemoryResult:
    observations = list(observations)
    errors = list(errors or [])

    if direct_issue or storage_issue:
        return _status_payload(
            "CONFIRMED",
            "CONFIRMED",
            "The browser retained an exact supplied credential probe after the test flow explicitly cleared the credential field. The evidence indicates page-owned client memory or client-side storage retention.",
            target=target,
            login_url=login_url,
            authenticated_lane_completed=authenticated_completed,
            heap_snapshot_supported=heap_supported,
            heap_snapshot_examined=heap_examined,
            direct_client_memory_issue=direct_issue,
            heap_only_memory_signal=heap_only_issue,
            storage_credential_exposure=storage_issue,
            observations=observations,
            evidence=[
                "Finding requires exact-match evidence for the supplied probe; generic token/session presence is not sufficient.",
                "The actual supplied password is never included in report evidence.",
            ],
            details={
                "finding_confirmed": True,
                "confirmation_basis": [
                    "page-owned DOM/JavaScript retention" if direct_issue else None,
                    "exact credential probe present in browser storage" if storage_issue else None,
                ],
            },
        )

    if heap_only_issue:
        return _status_payload(
            "REVIEW REQUIRED",
            "REVIEW_REQUIRED",
            "The credential probe appeared in the Chromium heap snapshot after clearing the field, but no page-owned DOM/JavaScript/storage reference was independently confirmed. Browser/renderer implementation details can retain values temporarily, so manual forensic review is required before treating this as a confirmed application issue.",
            target=target,
            login_url=login_url,
            authenticated_lane_completed=authenticated_completed,
            heap_snapshot_supported=heap_supported,
            heap_snapshot_examined=heap_examined,
            direct_client_memory_issue=False,
            heap_only_memory_signal=True,
            storage_credential_exposure=False,
            observations=observations,
            evidence=[
                "Heap-only signal is deliberately not auto-confirmed to avoid false positives from browser internals or transient allocations.",
            ],
        )

    if require_authenticated_lane and not authenticated_completed:
        return _status_payload(
            "INCOMPLETE",
            "INCOMPLETE",
            "The transient browser-memory lane completed without a confirmed retention issue, but the authenticated memory-retention lane could not be completed with a verified operator-authorized credential pair.",
            target=target,
            login_url=login_url,
            authenticated_lane_completed=False,
            heap_snapshot_supported=heap_supported,
            heap_snapshot_examined=heap_examined,
            observations=observations,
            evidence=["No confirmed credential-memory retention was observed in the completed lanes.", *errors],
        )

    if errors and not heap_examined and not observations:
        return _status_payload(
            "INCOMPLETE",
            "INCOMPLETE",
            "TC07 could not obtain the required browser-memory evidence because the browser execution lane failed.",
            target=target,
            login_url=login_url,
            authenticated_lane_completed=authenticated_completed,
            heap_snapshot_supported=heap_supported,
            heap_snapshot_examined=heap_examined,
            observations=observations,
            evidence=errors,
        )

    if not heap_supported and not direct_issue:
        return _status_payload(
            "REVIEW REQUIRED",
            "REVIEW_REQUIRED",
            "No confirmed credential retention was observed through direct browser inspection, but the Chromium heap-snapshot portion of TC07 was unavailable. Manual browser-memory verification is recommended to cover renderer-process memory outside page-reachable state.",
            target=target,
            login_url=login_url,
            authenticated_lane_completed=authenticated_completed,
            heap_snapshot_supported=False,
            heap_snapshot_examined=False,
            observations=observations,
            evidence=["Heap snapshot unavailable; direct DOM/JS/storage checks are not a complete substitute for process-level memory forensics."],
        )

    return _status_payload(
        "SAFE",
        "NOT_A_FINDING",
        "No exact supplied credential probe was retained in page-owned DOM/JavaScript or bounded browser storage after the field was cleared and the available memory checks completed.",
        target=target,
        login_url=login_url,
        authenticated_lane_completed=authenticated_completed,
        heap_snapshot_supported=heap_supported,
        heap_snapshot_examined=heap_examined,
        direct_client_memory_issue=False,
        heap_only_memory_signal=False,
        storage_credential_exposure=False,
        observations=observations,
        evidence=[
            "The supplied password value was never emitted into report output.",
            "Heap and storage scans were bounded to avoid unrestricted memory/data extraction.",
        ],
    )
