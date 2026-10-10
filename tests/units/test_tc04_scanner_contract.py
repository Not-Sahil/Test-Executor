from authentication.enumeration_models import EnumerationConfig


def test_config_deduplicates_and_bounds_candidates():
    cfg = EnumerationConfig(
        candidate_usernames=("alice", "", "alice", "bob", " carol "),
        max_candidates=2,
    )
    assert cfg.normalized_candidates() == ["alice", "bob"]


def test_timing_defaults_to_single_sample():
    cfg = EnumerationConfig()
    assert cfg.samples_per_probe == 1
    assert cfg.include_timing is False
