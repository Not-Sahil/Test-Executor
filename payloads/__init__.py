"""Curated, file-backed payload sets used by Test Executor scanners."""
from .manager import (
    get_testcase_spec, load_lines, load_optional_lines, load_json_records,
    payload_library_summary, testcase_payloads,
)

__all__ = [
    "get_testcase_spec", "load_lines", "load_optional_lines",
    "load_json_records", "payload_library_summary", "testcase_payloads",
]
