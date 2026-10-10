from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class HeapScanResult:
    supported: bool
    examined: bool
    matched_password: bool = False
    matched_username: bool = False
    bytes_observed: int = 0
    truncated: bool = False
    error: str = ""


def scan_heap_snapshot_for_markers(
    cdp_session,
    *,
    username: str,
    password: str,
    max_bytes: int,
    overlap_bytes: int = 256,
    on_progress: Callable[[int], None] | None = None,
) -> HeapScanResult:
    """
    Capture a Chromium JS heap snapshot and search only for the two operator
    supplied probe values. The raw heap snapshot is never returned or persisted.

    Heap snapshots are supported through Chrome DevTools Protocol's
    HeapProfiler domain. This module intentionally does not dump or expose
    arbitrary heap contents to the report.
    """
    if cdp_session is None:
        return HeapScanResult(supported=False, examined=False, error="cdp_session_unavailable")

    username_bytes = username.encode("utf-8", errors="ignore")
    password_bytes = password.encode("utf-8", errors="ignore")
    if not username_bytes or not password_bytes:
        return HeapScanResult(supported=False, examined=False, error="probe_values_empty")

    overlap_bytes = max(overlap_bytes, max(len(username_bytes), len(password_bytes)) + 32)
    total = 0
    prior_tail = b""
    matched_username = False
    matched_password = False

    try:
        cdp_session.send("HeapProfiler.enable")

        def on_chunk(params):
            nonlocal total, prior_tail, matched_username, matched_password
            chunk = (params or {}).get("chunk", "")
            data = chunk.encode("utf-8", errors="ignore")
            if not data:
                return

            total += len(data)
            search_blob = prior_tail + data
            matched_username = matched_username or username_bytes in search_blob
            matched_password = matched_password or password_bytes in search_blob
            prior_tail = search_blob[-overlap_bytes:]
            if on_progress:
                on_progress(total)

        cdp_session.on("HeapProfiler.addHeapSnapshotChunk", on_chunk)
        cdp_session.send("HeapProfiler.takeHeapSnapshot", {"reportProgress": False})

        truncated = total > max_bytes
        return HeapScanResult(
            supported=True,
            examined=True,
            matched_password=matched_password,
            matched_username=matched_username,
            bytes_observed=total,
            truncated=truncated,
        )
    except Exception as exc:
        return HeapScanResult(
            supported=True,
            examined=False,
            bytes_observed=total,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        try:
            cdp_session.send("HeapProfiler.disable")
        except Exception:
            pass
