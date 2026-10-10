from __future__ import annotations

from authentication.browser_memory_heap import scan_heap_snapshot_for_markers


class FakeCDP:
    def __init__(self, chunks):
        self.chunks = chunks
        self.handlers = {}
        self.sent = []

    def on(self, name, callback):
        self.handlers[name] = callback

    def send(self, method, params=None):
        self.sent.append((method, params))
        if method == "HeapProfiler.takeHeapSnapshot":
            callback = self.handlers["HeapProfiler.addHeapSnapshotChunk"]
            for chunk in self.chunks:
                callback({"chunk": chunk})
        return {}


def test_heap_scanner_detects_marker_without_returning_snapshot():
    cdp = FakeCDP(['{"x":"nothing"}', '{"x":"__TC07_SECRET__"}'])
    result = scan_heap_snapshot_for_markers(
        cdp,
        username="__TC07_USER__",
        password="__TC07_SECRET__",
        max_bytes=1024 * 1024,
    )
    assert result.supported is True
    assert result.examined is True
    assert result.matched_password is True
    assert not hasattr(result, "snapshot")


def test_heap_scanner_handles_marker_across_chunks():
    cdp = FakeCDP(['{"x":"__TC07_', 'SECRET__"}'])
    result = scan_heap_snapshot_for_markers(
        cdp,
        username="__TC07_USER__",
        password="__TC07_SECRET__",
        max_bytes=1024 * 1024,
        overlap_bytes=8,
    )
    assert result.matched_password is True
