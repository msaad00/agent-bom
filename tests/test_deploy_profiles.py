"""Tests for canonical Helm deployment validation profiles."""

from __future__ import annotations

from pathlib import Path

from agent_bom.deploy_profiles import helm_chart_dir, helm_validation_profiles


def test_helm_validation_profiles_reference_existing_chart_assets():
    repo_root = Path(__file__).resolve().parent.parent
    chart_dir = helm_chart_dir(repo_root)
    assert chart_dir.exists()
    profiles = helm_validation_profiles(repo_root)
    assert [profile.name for profile in profiles] == [
        "sqlite-pilot",
        "focused-pilot",
        "production",
        "mesh-hardening",
        "snowflake-backend",
        "gateway-runtime",
    ]
    for profile in profiles:
        for values_file in profile.values_files:
            assert values_file.exists(), f"{profile.name} missing values file {values_file}"
        for _key, file_path in profile.set_file_arguments:
            assert file_path.exists(), f"{profile.name} missing set-file input {file_path}"


def test_gateway_runtime_profile_uses_shipped_upstreams_example():
    repo_root = Path(__file__).resolve().parent.parent
    profiles = {profile.name: profile for profile in helm_validation_profiles(repo_root)}
    gateway = profiles["gateway-runtime"]
    assert gateway.set_arguments == ("gateway.enabled=true",)
    assert gateway.set_file_arguments == (
        ("gateway.upstreamsYaml", repo_root / "deploy" / "helm" / "agent-bom" / "examples" / "gateway-upstreams.example.yaml"),
    )
