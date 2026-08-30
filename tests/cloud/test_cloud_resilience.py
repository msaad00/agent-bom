from __future__ import annotations

from click.testing import CliRunner


def test_provider_resilience_covers_registered_cloud_providers() -> None:
    from agent_bom.cloud import _PROVIDERS
    from agent_bom.cloud.resilience import provider_resilience_summary

    summary = provider_resilience_summary()
    providers = {profile["provider"] for profile in summary["providers"]}

    assert set(_PROVIDERS) <= providers
    assert summary["target_resource_count"] == 10_000
    assert summary["default_ci_mode"] == "synthetic_no_credentials"


def test_provider_resilience_profiles_have_operator_evidence() -> None:
    from agent_bom.cloud.resilience import provider_resilience_profiles

    for profile in provider_resilience_profiles():
        assert profile.pagination
        assert profile.retry_backoff
        assert profile.partial_failure
        assert profile.max_page_safety
        assert profile.evidence


def test_provider_resilience_gaps_are_explicit() -> None:
    from agent_bom.cloud.resilience import provider_resilience_gaps

    gaps = provider_resilience_gaps()
    assert gaps
    assert all(gap["status"] == "partial" for gap in gaps)
    assert {gap["provider"] for gap in gaps} >= {"azure", "gcp", "databricks"}


def test_synthetic_scale_target_is_not_self_reported_as_verified_without_a_load_proof() -> None:
    from agent_bom.cloud.resilience import provider_resilience_profiles

    unsupported_claims = [
        profile.provider
        for profile in provider_resilience_profiles()
        if profile.synthetic_scale_target is not None and profile.status == "verified"
    ]

    assert unsupported_claims == []


def test_openai_resilience_surface_matches_exercised_inventory_calls() -> None:
    from agent_bom.cloud.resilience import provider_resilience_profiles

    profile = next(profile for profile in provider_resilience_profiles() if profile.provider == "openai")

    assert profile.surface == "OpenAI assistants and completed fine-tuning jobs with referenced training-file IDs"
    assert profile.status == "partial"


def test_cloud_resilience_json_command() -> None:
    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["cloud", "resilience", "--format", "json"])

    assert result.exit_code == 0
    assert '"schema_version": 1' in result.output
    assert '"provider": "aws"' in result.output
    assert '"provider": "openai"' in result.output
