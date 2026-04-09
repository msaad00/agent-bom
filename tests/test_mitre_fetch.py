"""Tests for mitre_fetch.py — MITRE ATT&CK + CAPEC STIX fetching and caching."""

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
    get_cwe_to_attack,
    get_techniques,
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


# ─── build_catalog ────────────────────────────────────────────────────────────


def test_build_catalog_uses_cache(tmp_path):
    cache = {
        "fetched_at": time.time(),
        "attack_version": "cached",
        "techniques": {"T1059": {"name": "Cached Technique", "tactics": ["execution"]}},
        "cwe_to_attack": {},
    }
    cache_file = tmp_path / "mitre-attack-catalog.json"
    cache_file.write_text(json.dumps(cache))

    with patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file):
        catalog = build_catalog()

    assert catalog["attack_version"] == "cached"
    assert "T1059" in catalog["techniques"]


def test_build_catalog_expired_cache_triggers_fetch(tmp_path):
    old_cache = {
        "fetched_at": 0.0,  # expired immediately
        "attack_version": "old",
        "techniques": {},
        "cwe_to_attack": {},
    }
    cache_file = tmp_path / "mitre-attack-catalog.json"
    cache_file.write_text(json.dumps(old_cache))

    fresh_attack = _attack_bundle([_technique("attack-pattern--exec", "T1059", "Command and Scripting Interpreter", ["execution"])])

    with (
        patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file),
        patch("agent_bom.mitre_fetch._fetch_json", side_effect=[fresh_attack, None]),
    ):
        catalog = build_catalog()

    assert "T1059" in catalog["techniques"]
    assert catalog["attack_version"] == "16.1"


def test_build_catalog_network_failure_returns_empty(tmp_path):
    cache_file = tmp_path / "mitre-attack-catalog.json"

    with (
        patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file),
        patch("agent_bom.mitre_fetch._fetch_json", return_value=None),
    ):
        catalog = build_catalog()

    assert catalog["techniques"] == {}
    assert catalog["cwe_to_attack"] == {}


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


# ─── Offline fallback: stale cache on network failure (#409) ──────────────────


def test_network_failure_uses_stale_cache(tmp_path):
    """When the cache is expired AND the network fetch fails, serve stale cache."""
    stale_cache = {
        "fetched_at": 1.0,  # expired long ago
        "attack_version": "stale-v15",
        "techniques": {"T1059": {"name": "Stale Technique", "tactics": ["execution"]}},
        "cwe_to_attack": {"CWE-78": ["T1059"]},
    }
    cache_file = tmp_path / "mitre-attack-catalog.json"
    cache_file.write_text(json.dumps(stale_cache))

    with (
        patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file),
        patch("agent_bom.mitre_fetch._fetch_json", return_value=None),
    ):
        catalog = build_catalog()

    # Should return stale data rather than empty dict
    assert catalog["attack_version"] == "stale-v15"
    assert "T1059" in catalog["techniques"]
    assert "CWE-78" in catalog["cwe_to_attack"]


def test_network_failure_no_cache_returns_empty(tmp_path):
    """When network fails AND no cache exists at all, return empty catalog."""
    cache_file = tmp_path / "mitre-attack-catalog.json"
    # cache_file does NOT exist

    with (
        patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file),
        patch("agent_bom.mitre_fetch._fetch_json", return_value=None),
    ):
        catalog = build_catalog()

    assert catalog["techniques"] == {}
    assert catalog["attack_version"] == "unavailable"


def test_load_cache_ignore_ttl(tmp_path):
    """_load_cache(ignore_ttl=True) returns stale cache even if expired."""
    from agent_bom.mitre_fetch import _load_cache

    stale = {
        "fetched_at": 1.0,
        "attack_version": "old",
        "techniques": {"T9999": {}},
        "cwe_to_attack": {},
    }
    cache_file = tmp_path / "mitre-attack-catalog.json"
    cache_file.write_text(json.dumps(stale))

    with patch("agent_bom.mitre_fetch._CACHE_PATH", cache_file):
        # Normal load: expired → None
        assert _load_cache() is None
        # ignore_ttl: returns data anyway
        result = _load_cache(ignore_ttl=True)
        assert result is not None
        assert result["attack_version"] == "old"
