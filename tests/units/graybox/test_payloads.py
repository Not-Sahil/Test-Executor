"""Tests verifying Gray-Box payload library schemas, manifest mapping, and completeness."""
import json
from pathlib import Path

from graybox.payload_manager import GrayBoxPayloadManager
from graybox.registry import GRAYBOX_REGISTRY

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
PAYLOAD_DIR = BASE_DIR / "payloads" / "graybox"


def test_manifest_file_exists_and_maps_all_85_testcases():
    manifest_path = PAYLOAD_DIR / "manifest.json"
    assert manifest_path.is_file(), "payloads/graybox/manifest.json does not exist"

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data.get("schema_version") == 1
    testcases = data.get("testcases", {})
    assert len(testcases) == 85, f"Expected 85 testcase libraries in manifest, got {len(testcases)}"

    for tc_id in GRAYBOX_REGISTRY.keys():
        assert tc_id in testcases, f"Testcase {tc_id} missing from manifest.json"


def test_every_payload_file_exists_on_disk():
    pm = GrayBoxPayloadManager()
    for tc_id, tc in GRAYBOX_REGISTRY.items():
        file_path = PAYLOAD_DIR / tc.payload_file
        assert file_path.is_file(), f"Payload file {tc.payload_file} for {tc_id} does not exist on disk"

        payloads = pm.get_payloads_for_testcase(tc_id)
        assert len(payloads) >= 1, f"Testcase {tc_id} has zero payloads in {tc.payload_file}"

        for p in payloads:
            assert p.id.strip(), f"Payload in {tc_id} missing ID"
            assert p.testcase_id == tc_id, f"Payload {p.id} testcase_id '{p.testcase_id}' does not match '{tc_id}'"
            assert p.name.strip(), f"Payload {p.id} missing name"
            assert p.purpose.strip(), f"Payload {p.id} missing purpose"
            assert p.expected_secure_behavior.strip(), f"Payload {p.id} missing expected_secure_behavior"


def test_payload_schema_validation_has_zero_errors():
    pm = GrayBoxPayloadManager()
    report = pm.validate_all_libraries()
    assert report["valid"] is True
    assert report["testcases_validated"] == 85
    assert len(report["issues"]) == 0, f"Schema validation failed with issues: {report['issues']}"
