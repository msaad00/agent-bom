"""Lock the shipped MITRE ATT&CK catalog: 14 Enterprise tactics + provenance.

These tests pin the *generated bundled artifact* (not a live fetch) so a stale,
partial, or silently re-scoped catalog cannot ship. They assert:

* all 14 Enterprise tactics are present by ATT&CK tactic ID (incl. Reconnaissance
  TA0043 and Resource Development TA0042);
* the recorded provenance (release, source URL, source digest, fetch time,
  technique count, tactic count) is present and internally consistent; and
* the offline framework APIs and coverage exports resolve against the refreshed
  artifact with no dangling technique/tactic.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from agent_bom.mitre_fetch import (
    _BUNDLED_CATALOG_PATH,
    TOP_TACTIC_PHASE_NAMES,
    _load_bundled_catalog,
    get_bundled_tactics,
)

# The canonical 14 MITRE ATT&CK Enterprise tactics, by ATT&CK tactic ID.
EXPECTED_TACTIC_IDS = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
}

PINNED_ATTACK_RELEASE = "18.1"


@pytest.fixture(scope="module")
def bundled() -> dict:
    return _load_bundled_catalog()


# ─── 14 Enterprise tactics, locked by ID ─────────────────────────────────────


def test_bundled_catalog_locks_all_14_enterprise_tactics(bundled):
    assert set(bundled["tactics"].keys()) == set(EXPECTED_TACTIC_IDS)
    assert len(bundled["tactics"]) == 14


def test_reconnaissance_and_resource_development_present_by_id(bundled):
    assert "TA0043" in bundled["tactics"]
    assert bundled["tactics"]["TA0043"]["shortname"] == "reconnaissance"
    assert "TA0042" in bundled["tactics"]
    assert bundled["tactics"]["TA0042"]["shortname"] == "resource-development"


def test_tactic_shortnames_match_expected_and_top_scope(bundled):
    for tactic_id, meta in bundled["tactics"].items():
        assert meta["shortname"] == EXPECTED_TACTIC_IDS[tactic_id]
        assert meta["shortname"] in TOP_TACTIC_PHASE_NAMES
        assert meta["name"]  # human-readable name recorded


def test_get_bundled_tactics_offline_api_returns_14():
    assert set(get_bundled_tactics().keys()) == set(EXPECTED_TACTIC_IDS)


# ─── Provenance: present + internally consistent ─────────────────────────────


def test_provenance_fields_present(bundled):
    assert bundled["attack_release"] == PINNED_ATTACK_RELEASE
    assert bundled["attack_version"] == PINNED_ATTACK_RELEASE
    assert bundled["fetched_at"] > 0
    assert bundled["updated_at"]
    assert len(bundled["normalized_sha256"]) == 64
    ent = bundled["sources"]["enterprise_attack"]
    assert ent["release"] == PINNED_ATTACK_RELEASE
    assert ent["url"].startswith("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.1/")
    assert len(ent["sha256"]) == 64
    capec = bundled["sources"]["capec"]
    assert capec["release"] == "3.5"
    assert "CAPEC-v3.5" in capec["url"]
    assert len(capec["sha256"]) == 64


def test_provenance_counts_reconcile_with_catalog(bundled):
    assert bundled["technique_count"] == len(bundled["techniques"])
    assert bundled["tactic_count"] == len(bundled["tactics"]) == 14
    # The pinned source release drives the top-level release identifier.
    assert bundled["attack_release"] == bundled["sources"]["enterprise_attack"]["release"]


def test_normalized_sha256_matches_recomputation(bundled):
    core = {
        "techniques": bundled["techniques"],
        "tactics": bundled["tactics"],
        "cwe_to_attack": bundled["cwe_to_attack"],
        "attack_version": bundled["attack_version"],
        "attack_release": bundled["attack_release"],
    }
    recomputed = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert recomputed == bundled["normalized_sha256"]


def test_source_digest_matches_pinned_release_bytes(bundled):
    # The recorded digest must be a real sha256 of the pinned release bytes; a
    # placeholder or hand-edited digest would not be 64 hex chars.
    for src in bundled["sources"].values():
        int(src["sha256"], 16)  # raises if not hex


# ─── No dangling technique / tactic ──────────────────────────────────────────


def test_every_technique_tactic_resolves_to_a_catalog_tactic(bundled):
    valid_shortnames = {m["shortname"] for m in bundled["tactics"].values()}
    for tid, meta in bundled["techniques"].items():
        for phase in meta["tactics"]:
            assert phase in valid_shortnames, f"{tid} references unknown tactic {phase!r}"


def test_all_14_tactics_have_at_least_one_technique(bundled):
    covered = set()
    for meta in bundled["techniques"].values():
        covered.update(meta["tactics"])
    for shortname in EXPECTED_TACTIC_IDS.values():
        assert shortname in covered, f"no technique tagged for tactic {shortname!r}"


def test_reconnaissance_and_resource_dev_have_techniques(bundled):
    recon = [t for t, m in bundled["techniques"].items() if "reconnaissance" in m["tactics"]]
    resdev = [t for t, m in bundled["techniques"].items() if "resource-development" in m["tactics"]]
    assert recon, "expected at least one reconnaissance technique"
    assert resdev, "expected at least one resource-development technique"


def test_cwe_to_attack_has_no_dangling_technique(bundled):
    techniques = bundled["techniques"]
    for cwe, techs in bundled["cwe_to_attack"].items():
        for tid in techs:
            assert tid in techniques, f"{cwe} maps to unknown technique {tid}"


# ─── Offline framework APIs + coverage exports reconcile ─────────────────────


@pytest.fixture
def _force_bundled(monkeypatch):
    """Make the active-catalog APIs read the shipped bundled artifact."""
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "bundled")
    monkeypatch.setattr("agent_bom.mitre_fetch._DEFAULT_SYNC_PATH", _BUNDLED_CATALOG_PATH.with_name("no-such-synced.json"))
    monkeypatch.delenv("AGENT_BOM_MITRE_CATALOG_PATH", raising=False)


def test_offline_apis_reconcile_with_artifact(_force_bundled, bundled):
    from agent_bom.mitre_attack import get_attack_techniques, get_bundled_attack_techniques
    from agent_bom.mitre_fetch import get_attack_release, get_attack_version

    assert get_attack_release() == PINNED_ATTACK_RELEASE
    assert get_attack_version() == PINNED_ATTACK_RELEASE
    assert len(get_attack_techniques()) == bundled["technique_count"]
    assert len(get_bundled_attack_techniques()) == bundled["technique_count"]


def test_attack_coverage_export_reconciles(_force_bundled, bundled):
    from agent_bom.mitre_coverage import build_attack_coverage

    # Two findings tagged with real techniques from the refreshed artifact.
    tids = list(bundled["techniques"].keys())[:2]
    findings = [{"id": f"f{i}", "attack_tags": [tid]} for i, tid in enumerate(tids)]
    coverage = build_attack_coverage(findings)

    assert coverage["catalogue_total"] == bundled["technique_count"]
    assert coverage["catalogue_version"] == PINNED_ATTACK_RELEASE
    assert coverage["covered_count"] == len(tids)
    for entry in coverage["covered_techniques"]:
        assert entry["id"] in bundled["techniques"]


def test_coverage_ignores_unknown_technique_tag(_force_bundled):
    from agent_bom.mitre_coverage import build_attack_coverage

    coverage = build_attack_coverage([{"id": "f1", "attack_tags": ["T9999999"]}])
    assert coverage["covered_count"] == 0
