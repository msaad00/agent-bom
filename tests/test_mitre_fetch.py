"""Tests for mitre_fetch.py — bundled + refreshable MITRE ATT&CK catalogs."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from agent_bom.mitre_fetch import (
    TOP_TACTIC_PHASE_NAMES,
    _parse_attack_stix,
    _parse_capec_stix,
    build_catalog,
    get_catalog_metadata,
    get_cwe_to_attack,
    get_techniques,
    sync_catalog,
)

# ─── Minimal STIX fixtures ────────────────────────────────────────────────────


def _attack_bundle(techniques: list[dict]) -> dict:
    """Build a minimal enterprise-attack STIX 2.0 bundle."""
    objects = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--test",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "16.1",
        }
    ]
    objects.extend(techniques)
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


def _attack_bundle_current_schema(techniques: list[dict]) -> dict:
    """Build a minimal current-style enterprise ATT&CK bundle."""
    objects = [
        {
            "type": "x-mitre-matrix",
            "id": "x-mitre-matrix--test",
            "name": "Enterprise ATT&CK",
            "modified": "2025-04-25T14:41:40.982Z",
            "x_mitre_attack_spec_version": "3.2.0",
        }
    ]
    objects.extend(techniques)
    return {"type": "bundle", "id": "bundle--current", "objects": objects}


def _technique(
    stix_id: str,
    ext_id: str,
    name: str,
    tactics: list[str],
    deprecated: bool = False,
) -> dict:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": f"Description of {name}.",
        "x_mitre_deprecated": deprecated,
        "revoked": False,
        "x_mitre_platforms": ["Linux", "macOS"],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic} for tactic in tactics],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": ext_id, "url": f"https://attack.mitre.org/techniques/{ext_id}"}
        ],
    }


# ─── _parse_attack_stix ───────────────────────────────────────────────────────


def test_parse_extracts_technique_in_scope():
    bundle = _attack_bundle([_technique("attack-pattern--exec", "T1059", "Command and Scripting Interpreter", ["execution"])])
    version, techniques = _parse_attack_stix(bundle)
    assert "T1059" in techniques
    assert techniques["T1059"]["name"] == "Command and Scripting Interpreter"
    assert "execution" in techniques["T1059"]["tactics"]


def test_parse_excludes_out_of_scope_tactic():
    bundle = _attack_bundle([_technique("attack-pattern--recon", "T1595", "Active Scanning", ["reconnaissance"])])
    _, techniques = _parse_attack_stix(bundle)
    assert "T1595" not in techniques  # reconnaissance not in TOP_TACTIC_PHASE_NAMES


def test_parse_excludes_deprecated():
    bundle = _attack_bundle([_technique("attack-pattern--old", "T9999", "Old Technique", ["execution"], deprecated=True)])
    _, techniques = _parse_attack_stix(bundle)
    assert "T9999" not in techniques


def test_parse_extracts_version():
    bundle = _attack_bundle([])
    version, _ = _parse_attack_stix(bundle)
    assert version == "16.1"


def test_parse_extracts_snapshot_version_from_matrix():
    bundle = _attack_bundle_current_schema([])
    version, _ = _parse_attack_stix(bundle)
    assert version == "snapshot 2025-04-25 (spec 3.2.0)"


def test_parse_empty_bundle():
    _, techniques = _parse_attack_stix({"objects": []})
    assert techniques == {}


def test_parse_multiple_techniques():
    bundle = _attack_bundle(
        [
            _technique("attack-pattern--a", "T1059", "Execution Tech", ["execution"]),
            _technique("attack-pattern--b", "T1552", "Cred Tech", ["credential-access"]),
            _technique("attack-pattern--c", "T1595", "Recon Tech", ["reconnaissance"]),  # out of scope
        ]
    )
    _, techniques = _parse_attack_stix(bundle)
    assert "T1059" in techniques
    assert "T1552" in techniques
    assert "T1595" not in techniques


def test_all_parsed_tactics_in_top_scope():
    bundle = _attack_bundle(
        [
            _technique("attack-pattern--a", "T1059", "Cmd Interp", ["execution"]),
            _technique("attack-pattern--b", "T1078", "Valid Accts", ["initial-access", "privilege-escalation"]),
        ]
    )
    _, techniques = _parse_attack_stix(bundle)
    for tid, meta in techniques.items():
        for tactic in meta["tactics"]:
            if tactic in TOP_TACTIC_PHASE_NAMES:
                break
        else:
            pytest.fail(f"{tid} has no tactic in TOP_TACTIC_PHASE_NAMES: {meta['tactics']}")


# ─── _parse_capec_stix ────────────────────────────────────────────────────────


def _capec_bundle_with_mapping(
    cwe_ext_id: str,
    capec_stix_id: str,
    capec_ext_id: str,
    attack_stix_id: str,
    attack_ext_id: str,
    technique_metadata: dict,
) -> dict:
    """Build a minimal CAPEC STIX bundle with one CWE→CAPEC→ATT&CK chain."""
    weakness_stix_id = f"weakness--{cwe_ext_id.lower().replace('-', '')}"
    objects = [
        # Weakness (CWE)
        {
            "type": "weakness",
            "id": weakness_stix_id,
            "name": f"Weakness {cwe_ext_id}",
            "external_references": [{"source_name": "cwe", "external_id": cwe_ext_id}],
        },
        # CAPEC attack pattern
        {
            "type": "attack-pattern",
            "id": capec_stix_id,
            "name": f"CAPEC Pattern {capec_ext_id}",
            "external_references": [{"source_name": "capec", "external_id": capec_ext_id}],
        },
        # ATT&CK technique (also attack-pattern in CAPEC bundle)
        {
            "type": "attack-pattern",
            "id": attack_stix_id,
            "name": technique_metadata["name"],
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_ext_id}],
        },
        # Relationship: CAPEC exploits CWE
        {
            "type": "relationship",
            "id": f"relationship--cwe-{capec_ext_id}",
            "relationship_type": "exploits",
            "source_ref": capec_stix_id,
            "target_ref": weakness_stix_id,
        },
        # Relationship: CAPEC uses ATT&CK technique
        {
            "type": "relationship",
            "id": f"relationship--atk-{capec_ext_id}",
            "relationship_type": "uses",
            "source_ref": capec_stix_id,
            "target_ref": attack_stix_id,
        },
    ]
    return {"type": "bundle", "objects": objects}


def test_capec_parse_derives_cwe_to_attack_mapping():
    attack_techniques = {"T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"]}}
    bundle = _capec_bundle_with_mapping(
        cwe_ext_id="CWE-78",
        capec_stix_id="attack-pattern--capec-88",
        capec_ext_id="CAPEC-88",
        attack_stix_id="attack-pattern--t1059",
        attack_ext_id="T1059",
        technique_metadata=attack_techniques["T1059"],
    )
    mapping = _parse_capec_stix(bundle, attack_techniques)
    assert "CWE-78" in mapping
    assert "T1059" in mapping["CWE-78"]


def test_capec_parse_current_direct_refs_schema():
    attack_techniques = {"T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"], "capec_refs": []}}
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--capec-88",
                "name": "OS Command Injection",
                "external_references": [
                    {"source_name": "capec", "external_id": "CAPEC-88"},
                    {"source_name": "cwe", "external_id": "CWE-78"},
                    {"source_name": "ATTACK", "external_id": "T1059"},
                ],
            }
        ],
    }
    mapping = _parse_capec_stix(bundle, attack_techniques)
    assert mapping == {"CWE-78": ["T1059"]}


def test_capec_parse_excludes_out_of_scope_techniques():
    """ATT&CK technique not in our catalog is excluded from CWE mapping."""
    attack_techniques = {}  # empty — no techniques in scope
    bundle = _capec_bundle_with_mapping(
        cwe_ext_id="CWE-78",
        capec_stix_id="attack-pattern--capec-88",
        capec_ext_id="CAPEC-88",
        attack_stix_id="attack-pattern--t1059",
        attack_ext_id="T1059",
        technique_metadata={"name": "Command and Scripting Interpreter"},
    )
    mapping = _parse_capec_stix(bundle, attack_techniques)
    assert mapping == {}


def test_capec_parse_empty_bundle():
    mapping = _parse_capec_stix({"objects": []}, {})
    assert mapping == {}


def test_capec_cwe_normalised_to_uppercase():
    attack_techniques = {"T1059": {"name": "Cmd", "tactics": ["execution"]}}
    bundle = _capec_bundle_with_mapping(
        cwe_ext_id="CWE-78",
        capec_stix_id="attack-pattern--capec-88",
        capec_ext_id="CAPEC-88",
        attack_stix_id="attack-pattern--t1059",
        attack_ext_id="T1059",
        technique_metadata=attack_techniques["T1059"],
    )
    mapping = _parse_capec_stix(bundle, attack_techniques)
    # Keys must be uppercase CWE-NNN format
    for key in mapping:
        assert key.startswith("CWE-"), f"CWE key not normalised: {key!r}"


# ─── build_catalog / sync_catalog ─────────────────────────────────────────────


def _catalog(version: str, source: str = "bundled") -> dict:
    return {
        "schema_version": 1,
        "catalog_id": "mitre_attack_enterprise_capec",
        "catalog_type": "mitre_attack",
        "source": source,
        "attack_version": version,
        "updated_at": "2026-04-10T00:00:00+00:00",
        "fetched_at": time.time(),
        "normalized_sha256": "sha",
        "sources": {},
        "techniques": {"T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"]}},
        "cwe_to_attack": {"CWE-78": ["T1059"]},
    }


def test_build_catalog_uses_bundled_by_default(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.delenv("AGENT_BOM_MITRE_CATALOG_PATH", raising=False)
    monkeypatch.delenv("AGENT_BOM_MITRE_CATALOG_MODE", raising=False)

    catalog = build_catalog()

    assert catalog["attack_version"] == "bundled-v1"
    assert catalog["source"] == "bundled"


def test_build_catalog_auto_prefers_synced_catalog(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    synced_file = tmp_path / "synced.json"
    synced_file.write_text(json.dumps(_catalog("synced-v2", source="synced")))

    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(synced_file))
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "auto")

    catalog = build_catalog()

    assert catalog["attack_version"] == "synced-v2"
    assert catalog["source"] == "synced"


def test_sync_catalog_writes_normalized_override(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    out_file = tmp_path / "synced.json"
    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(out_file))

    fresh_attack = _attack_bundle([_technique("attack-pattern--exec", "T1059", "Command and Scripting Interpreter", ["execution"])])
    fresh_capec = _capec_bundle_with_mapping(
        cwe_ext_id="CWE-78",
        capec_stix_id="attack-pattern--capec-88",
        capec_ext_id="CAPEC-88",
        attack_stix_id="attack-pattern--t1059",
        attack_ext_id="T1059",
        technique_metadata={"name": "Command and Scripting Interpreter"},
    )

    with patch("agent_bom.mitre_fetch._fetch_text", side_effect=[json.dumps(fresh_attack), json.dumps(fresh_capec)]):
        catalog = sync_catalog()

    assert out_file.exists()
    assert catalog["source"] == "synced"
    assert catalog["attack_version"] == "16.1"
    assert catalog["cwe_to_attack"]["CWE-78"] == ["T1059"]


def test_sync_failure_uses_last_known_good_synced(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    synced_file = tmp_path / "synced.json"
    synced_file.write_text(json.dumps(_catalog("synced-v2", source="synced")))

    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(synced_file))

    with patch("agent_bom.mitre_fetch._fetch_text", return_value=None):
        catalog = sync_catalog()

    assert catalog["attack_version"] == "synced-v2"
    assert catalog["source"] == "synced"


def test_sync_failure_without_synced_uses_bundled(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(tmp_path / "missing.json"))

    with patch("agent_bom.mitre_fetch._fetch_text", return_value=None):
        catalog = sync_catalog()

    assert catalog["attack_version"] == "bundled-v1"
    assert catalog["source"] == "bundled"


def test_get_catalog_metadata_exposes_counts(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.delenv("AGENT_BOM_MITRE_CATALOG_PATH", raising=False)

    metadata = get_catalog_metadata()

    assert metadata["attack_version"] == "bundled-v1"
    assert metadata["technique_count"] == 1
    assert metadata["cwe_mapping_count"] == 1


# ─── TOP_TACTIC_PHASE_NAMES coverage ─────────────────────────────────────────


def test_top_tactics_is_frozenset():
    assert isinstance(TOP_TACTIC_PHASE_NAMES, frozenset)


def test_top_tactics_count():
    """Exactly 10 tactics are in scope."""
    assert len(TOP_TACTIC_PHASE_NAMES) == 10


def test_top_tactics_all_lowercase_hyphenated():
    for name in TOP_TACTIC_PHASE_NAMES:
        assert name == name.lower(), f"Tactic name not lowercase: {name!r}"
        assert " " not in name, f"Tactic name contains space: {name!r}"


def test_key_tactics_included():
    assert "initial-access" in TOP_TACTIC_PHASE_NAMES
    assert "credential-access" in TOP_TACTIC_PHASE_NAMES
    assert "execution" in TOP_TACTIC_PHASE_NAMES
    assert "exfiltration" in TOP_TACTIC_PHASE_NAMES


# ─── get_techniques / get_cwe_to_attack integration ──────────────────────────


def test_get_techniques_returns_dict():
    with patch("agent_bom.mitre_fetch.build_catalog") as mock_build:
        mock_build.return_value = {
            "techniques": {"T1059": {"name": "Cmd", "tactics": ["execution"]}},
            "cwe_to_attack": {},
        }
        result = get_techniques()
    assert "T1059" in result


def test_get_cwe_to_attack_returns_dict():
    with patch("agent_bom.mitre_fetch.build_catalog") as mock_build:
        mock_build.return_value = {
            "techniques": {},
            "cwe_to_attack": {"CWE-78": ["T1059"]},
        }
        result = get_cwe_to_attack()
    assert "CWE-78" in result
    assert "T1059" in result["CWE-78"]


def test_refresh_mode_uses_live_sync(tmp_path, monkeypatch):
    bundled_file = tmp_path / "bundled.json"
    bundled_file.write_text(json.dumps(_catalog("bundled-v1", source="bundled")))
    out_file = tmp_path / "synced.json"
    monkeypatch.setattr("agent_bom.mitre_fetch._BUNDLED_CATALOG_PATH", bundled_file)
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(out_file))
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "refresh")

    fresh_attack = _attack_bundle([_technique("attack-pattern--exec", "T1059", "Command and Scripting Interpreter", ["execution"])])
    fresh_capec = _capec_bundle_with_mapping(
        cwe_ext_id="CWE-78",
        capec_stix_id="attack-pattern--capec-88",
        capec_ext_id="CAPEC-88",
        attack_stix_id="attack-pattern--t1059",
        attack_ext_id="T1059",
        technique_metadata={"name": "Command and Scripting Interpreter"},
    )

    with patch("agent_bom.mitre_fetch._fetch_text", side_effect=[json.dumps(fresh_attack), json.dumps(fresh_capec)]):
        catalog = build_catalog()

    assert catalog["source"] == "synced"
    assert catalog["attack_version"] == "16.1"
