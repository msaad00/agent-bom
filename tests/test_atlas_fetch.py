"""Tests for MITRE ATLAS catalog fetch + bundled-fallback flow."""

from __future__ import annotations

import json

import pytest

_FIXTURE_YAML = """\
---
id: ATLAS
name: Adversarial Threat Landscape for AI Systems
version: 9.9.0
matrices:
- id: ATLAS
  name: ATLAS Matrix
  tactics:
  - id: AML.TA0002
    name: Reconnaissance
    description: Gather info about target AI system.
    object-type: tactic
  - id: AML.TA0004
    name: Initial Access
    description: Gain access to AI system.
    object-type: tactic
  techniques:
  - id: AML.T0010
    name: AI Supply Chain Compromise
    description: Compromise the AI supply chain.
    object-type: technique
    tactics:
      - AML.TA0004
    ATT&CK-reference:
      id: T1195
      url: https://attack.mitre.org/techniques/T1195/
  - id: AML.T0010.001
    name: AI Software
    description: AI software sub-technique.
    object-type: technique
    tactics:
      - AML.TA0004
  - id: AML.T0007
    name: Discover AI Artifacts
    description: Discover AI artifacts.
    object-type: technique
    tactics:
      - AML.TA0002
"""


def test_parse_atlas_yaml_extracts_techniques_and_tactics() -> None:
    from agent_bom.atlas_fetch import _parse_atlas_yaml

    version, techniques, tactics = _parse_atlas_yaml(_FIXTURE_YAML)
    assert version == "9.9.0"
    assert set(techniques) == {"AML.T0010", "AML.T0010.001", "AML.T0007"}
    assert techniques["AML.T0010"]["name"] == "AI Supply Chain Compromise"
    assert techniques["AML.T0010"]["tactics"] == ["AML.TA0004"]
    assert techniques["AML.T0010"]["attck_reference"] == "T1195"
    assert techniques["AML.T0010.001"]["is_subtechnique"] is True
    assert techniques["AML.T0010"]["is_subtechnique"] is False
    assert set(tactics) == {"AML.TA0002", "AML.TA0004"}
    assert tactics["AML.TA0002"]["name"] == "Reconnaissance"


def test_parse_atlas_yaml_skips_non_aml_ids() -> None:
    from agent_bom.atlas_fetch import _parse_atlas_yaml

    bogus = (
        _FIXTURE_YAML
        + """\
  - id: T1234
    name: Bogus Non-AML technique
    object-type: technique
"""
    )
    _, techniques, _ = _parse_atlas_yaml(bogus)
    assert "T1234" not in techniques


def test_load_catalog_from_bundled_json_file() -> None:
    """The committed bundled catalog ships in the wheel and is loadable."""
    from agent_bom.atlas_fetch import _BUNDLED_CATALOG_PATH, load_catalog

    assert _BUNDLED_CATALOG_PATH.exists(), (
        "Bundled MITRE ATLAS catalog must be committed at "
        f"{_BUNDLED_CATALOG_PATH}. Refresh via 'agent-bom db update-frameworks --framework atlas'."
    )
    catalog = load_catalog()
    techniques = catalog.get("techniques", {})
    assert techniques, "Bundled ATLAS catalog must contain techniques"
    assert all(t.startswith("AML.T") for t in techniques)
    assert catalog.get("atlas_version", "unknown") not in ("unknown", "unavailable")


def test_load_catalog_falls_back_to_bundled_when_no_synced_catalog(monkeypatch, tmp_path) -> None:
    """If no synced catalog is present, build_catalog returns the bundled one."""
    from agent_bom import atlas_fetch

    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_PATH", str(tmp_path / "missing.json"))
    monkeypatch.delenv("AGENT_BOM_ATLAS_CATALOG_MODE", raising=False)
    catalog = atlas_fetch.build_catalog()
    assert catalog["source"] in ("bundled", "synced")
    assert len(catalog.get("techniques", {})) > 0


def test_sync_catalog_writes_normalized_json(tmp_path, monkeypatch) -> None:
    from agent_bom import atlas_fetch

    monkeypatch.setattr(atlas_fetch, "_fetch_text", lambda url: _FIXTURE_YAML)
    out = tmp_path / "atlas.json"
    catalog = atlas_fetch.sync_catalog(output_path=out)
    assert out.exists()
    on_disk = json.loads(out.read_text())
    assert on_disk["atlas_version"] == "9.9.0"
    assert "AML.T0010" in on_disk["techniques"]
    assert catalog["normalized_sha256"] == on_disk["normalized_sha256"]


def test_sync_catalog_falls_back_when_fetch_fails(monkeypatch, tmp_path) -> None:
    from agent_bom import atlas_fetch

    monkeypatch.setattr(atlas_fetch, "_fetch_text", lambda url: None)
    monkeypatch.setenv("AGENT_BOM_ATLAS_CATALOG_PATH", str(tmp_path / "absent.json"))
    catalog = atlas_fetch.sync_catalog()
    # Should fall back to bundled (which has techniques)
    assert catalog.get("techniques"), "fallback must surface bundled catalog"


def test_get_catalog_metadata_returns_summary_fields() -> None:
    from agent_bom.atlas_fetch import get_catalog_metadata

    meta = get_catalog_metadata()
    assert "technique_count" in meta
    assert "tactic_count" in meta
    assert meta["technique_count"] > 0


def test_atlas_curated_subset_stays_in_upstream_catalog() -> None:
    """Every curated tag-surface technique must exist upstream — no fabrications."""
    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.atlas_fetch import load_catalog

    upstream = load_catalog().get("techniques", {})
    missing = [tid for tid in ATLAS_TECHNIQUES if tid not in upstream]
    assert not missing, (
        f"Curated ATLAS techniques not found upstream: {missing}. Either fix the curated catalog or refresh the bundled catalog."
    )


def test_atlas_curated_count_is_load_bearing() -> None:
    """Curated tag surface stays at 65 per the curation rationale doc."""
    from agent_bom.atlas import curated_total

    assert curated_total() == 65, (
        "Curated ATLAS tag surface drifted from 65. Update atlas.py docstring + "
        "docs/ATLAS_COVERAGE.md if the curated set legitimately changed."
    )


def test_release_freshness_gate_passes_for_bundled_catalog() -> None:
    """The bundled ATLAS catalog must satisfy the release freshness gate."""
    from click.testing import CliRunner

    from agent_bom.cli._db import db_framework_status

    runner = CliRunner()
    result = runner.invoke(
        db_framework_status,
        [
            "--framework",
            "atlas",
            "--stale-after-days",
            "365",
            "--fail-on-stale",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    [atlas] = [f for f in payload["frameworks"] if f["framework"] == "mitre_atlas"]
    assert atlas["status"] == "fresh"
    assert atlas["techniques"] > 0


def test_release_freshness_gate_fails_for_empty_catalog(monkeypatch) -> None:
    from click.testing import CliRunner

    from agent_bom.cli import _db as db_cli

    monkeypatch.setattr(
        db_cli,
        "get_atlas_metadata" if hasattr(db_cli, "get_atlas_metadata") else "get_atlas_metadata",
        lambda: {"atlas_version": "0", "source": "test", "technique_count": 0, "tactic_count": 0, "updated_at": ""},
        raising=False,
    )
    # Patch the imported symbol inside the function
    from agent_bom import atlas_fetch as af

    monkeypatch.setattr(
        af,
        "get_catalog_metadata",
        lambda: {"atlas_version": "0", "source": "test", "technique_count": 0, "tactic_count": 0, "updated_at": ""},
    )
    runner = CliRunner()
    result = runner.invoke(
        db_cli.db_framework_status,
        [
            "--framework",
            "atlas",
            "--stale-after-days",
            "365",
            "--fail-on-stale",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1, result.output


@pytest.fixture
def _restore_env(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_ATLAS_CATALOG_MODE", raising=False)
    monkeypatch.delenv("AGENT_BOM_ATLAS_CATALOG_PATH", raising=False)
    yield
