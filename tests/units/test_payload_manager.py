from __future__ import annotations

import pytest

from payloads.manager import (
    get_testcase_spec,
    load_json_records,
    load_lines,
    payload_library_summary,
    bounded_sample,
    source_catalog_summary,
)


def test_manifest_has_curated_payload_backed_cases():
    summary = payload_library_summary()
    keys = {item["testcase"] for item in summary["testcases"]}
    assert {
        "tc03_helpful_error_message",
        "tc10_directory_listing",
        "tc13_sensitive_file_exposure",
        "tc23_internal_path_disclosure",
        "tc13_cors",
        "tc14_sql_injection",
        "tc15_ldap_ad",
    }.issubset(keys)
    assert summary["active_file_count"] >= 9


def test_sqli_probes_are_curated_and_non_destructive():
    records = load_json_records(
        "payloads_all_the_things/sql_injection/safe_differential_probes.json"
    )
    assert len(records) >= 8
    assert all(record.get("destructive") is False for record in records)
    assert {record["kind"] for record in records} == {"syntax", "differential"}


def test_ldap_markers_substitute_nonce_and_are_external():
    records = load_lines(
        "payloads_all_the_things/ldap_injection/safe_syntax_markers.txt",
        substitutions={"nonce": "UNIT42"},
    )
    assert len(records) == 5
    assert all("{{nonce}}" not in item for item in records)
    assert all("UNIT42" in item for item in records)


def test_manifest_spec_has_probe_budget():
    spec = get_testcase_spec("tc14_sql_injection")
    assert spec["max_items"] == 8
    assert spec["execution"] == "no_auth_bypass_no_data_extraction_no_writes_no_time_delays"


def test_loader_rejects_paths_outside_payload_directory():
    with pytest.raises(ValueError):
        load_lines("../README.md")


def test_loader_deduplicates_and_ignores_comments():
    entries = load_lines("seclists/discovery/backup_suffixes.txt")
    assert len(entries) == len(set(entries))
    assert all(entry and not entry.startswith("#") for entry in entries)


def test_source_catalog_is_explicit_and_reproducible():
    catalog = source_catalog_summary()
    assert len(catalog["sources"]) >= 10
    assert {item["repository"] for item in catalog["sources"]} == {"SecLists", "FuzzDB", "PayloadsAllTheThings"}
    values = [f"entry-{i}" for i in range(100)]
    assert bounded_sample(values, 12, seed="target-a") == bounded_sample(values, 12, seed="target-a")
    assert bounded_sample(values, 12, seed="target-a") != bounded_sample(values, 12, seed="target-b")


def test_fuzzdb_response_error_dictionary_is_vendored_and_loaded():
    entries = load_lines("upstream/FuzzDB/regex/errors.txt", limit=100)
    assert len(entries) >= 90
    assert "MySQL Error" in entries
    assert "ORA-0" in entries
    assert "PostgreSQL query failed: ERROR: parser: parse error" in entries


def test_exhaustive_mode_sets_maximum_caps():
    summary_bounded = payload_library_summary(exhaustive=False)
    summary_max = payload_library_summary(exhaustive=True)

    bounded_map = {item["testcase"]: item["max_items"] for item in summary_bounded["testcases"]}
    max_map = {item["testcase"]: item["max_items"] for item in summary_max["testcases"]}
    count_map = {item["testcase"]: item["item_count"] for item in summary_max["testcases"]}

    # In exhaustive mode, every testcase probe cap equals its total payload input count
    for tc_key in max_map:
        assert max_map[tc_key] == count_map[tc_key]

    assert max_map["tc03_helpful_error_message"] == count_map["tc03_helpful_error_message"] == 112
    assert max_map["tc10_directory_listing"] == count_map["tc10_directory_listing"] == 27569
    assert max_map["tc13_sensitive_file_exposure"] == count_map["tc13_sensitive_file_exposure"] == 16274
    assert max_map["tc23_internal_path_disclosure"] == count_map["tc23_internal_path_disclosure"] == 112
    assert max_map["tc14_sql_injection"] == count_map["tc14_sql_injection"] == 16

    # In bounded mode, bounded limits from manifest are preserved
    assert bounded_map["tc03_helpful_error_message"] == 10
    assert bounded_map["tc10_directory_listing"] == 120
    assert bounded_map["tc13_sensitive_file_exposure"] == 100
    assert bounded_map["tc23_internal_path_disclosure"] == 16
    assert bounded_map["tc14_sql_injection"] == 8
