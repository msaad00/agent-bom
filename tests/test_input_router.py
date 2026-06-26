"""Tests for the input → scanner-driver router."""

from __future__ import annotations

import pytest

from agent_bom.routing import (
    InputDescriptor,
    can_route,
    known_input_types,
    resolve_input,
    resolve_scanners,
    route_table,
)


@pytest.fixture(autouse=True)
def reset_scanner_registry(monkeypatch):
    import agent_bom.scanners.registry as scanner_registry
    from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    scanner_registry._reset_scanner_registry_for_tests()
    yield
    scanner_registry._reset_scanner_registry_for_tests()
    scanner_registry.list_registered_scanners()


def test_resolve_known_input_types_map_to_expected_drivers() -> None:
    cases = {
        "image_ref": "container-image",
        "cyclonedx": "sbom-ingest",
        "terraform_dir": "iac-terraform",
        "github_actions_path": "cicd-github-actions",
        "prompt_file": "prompt-injection",
        "code_path": "sast-semgrep",
    }
    for input_type, expected_driver in cases.items():
        names = {registration.name for registration in resolve_scanners(input_type)}
        assert expected_driver in names, f"{input_type} should route to {expected_driver}"


def test_resolution_is_case_insensitive_and_descriptor_aware() -> None:
    direct = {r.name for r in resolve_scanners("IMAGE_REF")}
    via_descriptor = {r.name for r in resolve_input(InputDescriptor(input_type="image_ref", source="docker.io/lib/x"))}
    assert direct == via_descriptor
    assert "container-image" in direct


def test_unknown_input_type_resolves_to_nothing() -> None:
    assert resolve_scanners("not_a_real_input_type") == []
    assert resolve_scanners("") == []
    assert can_route("not_a_real_input_type") is False
    assert can_route("image_ref") is True


def test_planned_drivers_excluded_by_default() -> None:
    # yara-signature (planned) declares 'model_file'; excluded unless requested.
    default_names = {r.name for r in resolve_scanners("model_file")}
    planned_names = {r.name for r in resolve_scanners("model_file", include_planned=True)}
    assert "yara-signature" not in default_names
    assert "yara-signature" in planned_names


def test_route_table_and_known_input_types_are_consistent() -> None:
    table = route_table(include_planned=True)
    types = known_input_types(include_planned=True)
    assert set(table) == types
    assert "image_ref" in table
    assert "container-image" in table["image_ref"]
    # An input shared by multiple drivers lists them sorted and deduped.
    assert table["packages"] == sorted(set(table["packages"]))
