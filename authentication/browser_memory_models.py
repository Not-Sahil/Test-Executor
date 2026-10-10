from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

AssessmentState = Literal[
    "CONFIRMED",
    "NOT_A_FINDING",
    "REVIEW_REQUIRED",
    "NOT_ASSESSED",
    "INCOMPLETE",
]


@dataclass(frozen=True)
class MemoryProbe:
    """Ephemeral, unique values used to trace authorized test input in memory."""

    username: str
    password: str

    @property
    def masked_password(self) -> str:
        return "<redacted>"


@dataclass
class MemoryObservation:
    phase: str
    source: str
    inspected: bool = False
    matched: bool = False
    confidence: str = "none"
    matched_type: str = ""
    location: str = ""
    evidence: list[str] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserMemoryConfig:
    login_path: str = "/login"
    authorized_username: str | None = None
    authorized_password: str | None = None

    timeout_ms: int = 12_000
    page_settle_ms: int = 750
    post_submit_settle_ms: int = 750
    post_clear_settle_ms: int = 250

    use_heap_snapshot: bool = True
    heap_snapshot_max_bytes: int = 40 * 1024 * 1024
    heap_scan_overlap_bytes: int = 256

    inspect_js_reachability: bool = True
    inspect_local_storage: bool = True
    inspect_session_storage: bool = True
    inspect_cookies: bool = True
    inspect_indexeddb: bool = True

    indexeddb_max_databases: int = 8
    indexeddb_max_object_stores: int = 12
    indexeddb_max_records_per_store: int = 100

    max_global_objects: int = 600
    max_global_depth: int = 2
    max_string_length: int = 16_384

    perform_authenticated_lane: bool = True
    logout_after_authenticated_lane: bool = True
    logout_paths: tuple[str, ...] = ("/logout", "/signout", "/sign-out")
    protected_urls: tuple[str, ...] = ("/account", "/dashboard", "/profile")

    verify_tls: bool = True

    def normalized(self) -> "BrowserMemoryConfig":
        return BrowserMemoryConfig(
            login_path=self.login_path.strip() or "/login",
            authorized_username=self.authorized_username,
            authorized_password=self.authorized_password,
            timeout_ms=max(3000, int(self.timeout_ms)),
            page_settle_ms=max(0, int(self.page_settle_ms)),
            post_submit_settle_ms=max(0, int(self.post_submit_settle_ms)),
            post_clear_settle_ms=max(0, int(self.post_clear_settle_ms)),
            use_heap_snapshot=bool(self.use_heap_snapshot),
            heap_snapshot_max_bytes=max(1_024 * 1024, int(self.heap_snapshot_max_bytes)),
            heap_scan_overlap_bytes=max(32, int(self.heap_scan_overlap_bytes)),
            inspect_js_reachability=bool(self.inspect_js_reachability),
            inspect_local_storage=bool(self.inspect_local_storage),
            inspect_session_storage=bool(self.inspect_session_storage),
            inspect_cookies=bool(self.inspect_cookies),
            inspect_indexeddb=bool(self.inspect_indexeddb),
            indexeddb_max_databases=max(1, int(self.indexeddb_max_databases)),
            indexeddb_max_object_stores=max(1, int(self.indexeddb_max_object_stores)),
            indexeddb_max_records_per_store=max(1, int(self.indexeddb_max_records_per_store)),
            max_global_objects=max(50, int(self.max_global_objects)),
            max_global_depth=max(1, int(self.max_global_depth)),
            max_string_length=max(256, int(self.max_string_length)),
            perform_authenticated_lane=bool(self.perform_authenticated_lane),
            logout_after_authenticated_lane=bool(self.logout_after_authenticated_lane),
            logout_paths=tuple(self.logout_paths or ("/logout",)),
            protected_urls=tuple(self.protected_urls or ()),
            verify_tls=bool(self.verify_tls),
        )


@dataclass
class BrowserMemoryResult:
    status: str
    assessment_state: AssessmentState
    summary: str
    target: str = ""
    login_url: str = ""
    authenticated_lane_completed: bool = False
    heap_snapshot_supported: bool = False
    heap_snapshot_examined: bool = False
    direct_client_memory_issue: bool = False
    heap_only_memory_signal: bool = False
    storage_credential_exposure: bool = False
    observations: list[MemoryObservation] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observations"] = [item.as_dict() for item in self.observations]
        return payload
