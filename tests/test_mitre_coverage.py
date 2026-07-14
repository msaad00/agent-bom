"""Unit tests for the MITRE technique-coverage aggregation (#3892).

Coverage is honest: a technique is "covered" only when at least one finding
carries real mapped evidence for it. Uncovered means "no evidence", never
"safe". These tests pin that contract across ATT&CK, ATLAS, and MAESTRO.
"""

from __future__ import annotations

from agent_bom import atlas
from agent_bom.mitre_attack import get_attack_techniques
from agent_bom.mitre_coverage import (
    COVERED_DEFINITION,
    UNCOVERED_DEFINITION,
    build_atlas_coverage,
    build_attack_coverage,
    build_maestro_coverage,
    build_mitre_coverage,
)


def _valid_attack_id() -> str:
    return next(iter(get_attack_techniques()))


def _valid_atlas_id() -> str:
    return next(iter(atlas.ATLAS_TECHNIQUES))


# ─── Empty estate: honest zeros, never fabricated coverage ───────────────────


def test_empty_estate_is_zero_covered_not_fake() -> None:
    result = build_mitre_coverage([])
    assert result["finding_count"] == 0
    frameworks = {f["framework"]: f for f in result["frameworks"]}
    for fw in frameworks.values():
        assert fw["covered_count"] == 0
        assert fw["coverage_pct"] == 0.0
        assert fw["covered_techniques"] == []
        # Catalogue total is a real, non-zero denominator even with no findings.
        assert fw["catalogue_total"] > 0


def test_definitions_label_uncovered_as_no_evidence() -> None:
    result = build_mitre_coverage([])
    assert result["covered_definition"] == COVERED_DEFINITION
    assert result["uncovered_definition"] == UNCOVERED_DEFINITION
    # Honesty guard: uncovered must not be presented as "safe".
    assert "safe" in UNCOVERED_DEFINITION.lower()
    assert "not" in UNCOVERED_DEFINITION.lower()


# ─── ATT&CK ──────────────────────────────────────────────────────────────────


def test_attack_coverage_reflects_finding_tags() -> None:
    tid = _valid_attack_id()
    findings = [
        {"id": "f1", "attack_tags": [tid]},
        {"id": "f2", "attack_tags": [tid]},
        {"id": "f3", "attack_tags": []},
    ]
    cov = build_attack_coverage(findings)
    assert cov["framework"] == "mitre_attack"
    assert cov["covered_count"] == 1
    assert cov["catalogue_total"] == len(get_attack_techniques())
    covered = {t["id"]: t for t in cov["covered_techniques"]}
    assert tid in covered
    assert covered[tid]["finding_count"] == 2
    assert set(covered[tid]["finding_refs"]) == {"f1", "f2"}
    expected_pct = round(1 / len(get_attack_techniques()) * 100, 2)
    assert cov["coverage_pct"] == expected_pct


def test_attack_coverage_ignores_unknown_technique_ids() -> None:
    findings = [{"id": "f1", "attack_tags": ["T9999999", "not-a-technique", ""]}]
    cov = build_attack_coverage(findings)
    assert cov["covered_count"] == 0
    assert cov["covered_techniques"] == []


def test_attack_coverage_canonicalizes_and_dedupes() -> None:
    tid = _valid_attack_id()
    findings = [
        {"id": "f1", "attack_tags": [f"  {tid.lower()} "]},
        {"id": "f1", "attack_tags": [tid]},  # same finding id -> deduped ref
    ]
    cov = build_attack_coverage(findings)
    assert cov["covered_count"] == 1
    covered = cov["covered_techniques"][0]
    assert covered["id"] == tid
    assert covered["finding_refs"] == ["f1"]
    assert covered["finding_count"] == 1


def test_attack_coverage_accepts_alternate_tag_field() -> None:
    tid = _valid_attack_id()
    cov = build_attack_coverage([{"id": "f1", "attack_techniques": [tid]}])
    assert cov["covered_count"] == 1


# ─── ATLAS ───────────────────────────────────────────────────────────────────


def test_atlas_coverage_reflects_finding_tags() -> None:
    aid = _valid_atlas_id()
    cov = build_atlas_coverage([{"id": "f1", "atlas_tags": [aid]}])
    assert cov["framework"] == "mitre_atlas"
    assert cov["covered_count"] == 1
    assert cov["catalogue_total"] == atlas.curated_total()
    assert cov["catalogue_upstream_total"] == atlas.upstream_total()
    assert cov["covered_techniques"][0]["id"] == aid


def test_atlas_empty_is_zero() -> None:
    cov = build_atlas_coverage([{"id": "f1", "atlas_tags": []}])
    assert cov["covered_count"] == 0
    assert cov["coverage_pct"] == 0.0


# ─── MAESTRO (source -> layer, explicit evidence only) ───────────────────────


def test_maestro_coverage_from_explicit_source() -> None:
    findings = [
        {"id": "f1", "source": "huggingface"},  # KC1
        {"id": "f2", "source": "mcp_server"},  # KC5
    ]
    cov = build_maestro_coverage(findings)
    assert cov["framework"] == "mitre_maestro"
    assert cov["catalogue_total"] == 6
    covered_ids = {t["id"] for t in cov["covered_techniques"]}
    assert "KC1" in covered_ids
    assert "KC5" in covered_ids
    assert cov["covered_count"] == 2


def test_maestro_unknown_source_is_not_credited() -> None:
    # Honesty: an unmapped source must NOT silently count as KC6 coverage.
    cov = build_maestro_coverage([{"id": "f1", "source": "totally-unknown-source"}])
    assert cov["covered_count"] == 0
    assert cov["covered_techniques"] == []


def test_maestro_layer_references_findings() -> None:
    cov = build_maestro_coverage(
        [
            {"id": "f1", "source": "ollama"},
            {"id": "f2", "source": "ollama"},
        ]
    )
    kc1 = next(t for t in cov["covered_techniques"] if t["id"] == "KC1")
    assert kc1["finding_count"] == 2
    assert set(kc1["finding_refs"]) == {"f1", "f2"}


# ─── Unified surface ─────────────────────────────────────────────────────────


def test_build_mitre_coverage_unifies_three_frameworks() -> None:
    tid = _valid_attack_id()
    aid = _valid_atlas_id()
    findings = [
        {"id": "f1", "attack_tags": [tid], "atlas_tags": [aid], "source": "vector_db"},
    ]
    result = build_mitre_coverage(findings)
    assert result["finding_count"] == 1
    ids = {f["framework"] for f in result["frameworks"]}
    assert ids == {"mitre_attack", "mitre_atlas", "mitre_maestro"}
    by_id = {f["framework"]: f for f in result["frameworks"]}
    assert by_id["mitre_attack"]["covered_count"] == 1
    assert by_id["mitre_atlas"]["covered_count"] == 1
    assert by_id["mitre_maestro"]["covered_count"] == 1  # KC4 from vector_db


def test_finding_refs_are_capped_for_scale() -> None:
    tid = _valid_attack_id()
    findings = [{"id": f"f{i}", "attack_tags": [tid]} for i in range(500)]
    cov = build_attack_coverage(findings)
    covered = cov["covered_techniques"][0]
    assert covered["finding_count"] == 500
    assert len(covered["finding_refs"]) <= 25
    assert covered["finding_refs_truncated"] is True
