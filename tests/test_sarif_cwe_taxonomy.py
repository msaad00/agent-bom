"""Structured CWE classification survives prose-free and repeated findings."""

import json
from pathlib import Path

from jsonschema import Draft7Validator

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif import to_sarif


def test_cwe_taxonomy_relationships_union_repeated_rules_and_validate():
    findings = [
        Finding(
            finding_type=FindingType.SAST,
            source=FindingSource.SAST,
            asset=Asset(name=f"file{i}.py", asset_type="code"),
            severity="high",
            title="Unsafe operation",
            description="No weakness identifiers in this text.",
            cwe_ids=cwes,
            evidence={"rule_id": "unsafe-operation"},
        )
        for i, cwes in enumerate((["CWE-79", "CWE-79"], ["CWE-89", "CWE-noinfo", "not-a-cwe"]))
    ]
    sarif = to_sarif(AIBOMReport(findings=findings))
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text())
    Draft7Validator(schema).validate(sarif)
    run = sarif["runs"][0]
    cwe = next(t for t in run["taxonomies"] if t["name"] == "CWE")
    assert [t["id"] for t in cwe["taxa"]] == ["79", "89"]
    assert cwe["isComprehensive"] is False
    assert run["tool"]["driver"]["supportedTaxonomies"] == [{"name": "CWE"}]
    relationships = run["tool"]["driver"]["rules"][0]["relationships"]
    assert [r["target"]["id"] for r in relationships] == ["79", "89"]
    assert all(r["target"]["toolComponent"]["name"] == "CWE" and r["kinds"] == ["superset"] for r in relationships)
    assert [{t["id"] for t in r["taxa"]} for r in run["results"]] == [{"79"}, {"89"}]


def test_no_invented_cwe_when_structured_field_is_empty():
    finding = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(name="code.py", asset_type="code"),
        severity="high",
        title="Mentions CWE-79 in prose",
        cwe_ids=[],
    )
    run = to_sarif(AIBOMReport(findings=[finding]))["runs"][0]
    assert not any(t["name"] == "CWE" for t in run.get("taxonomies", []))
    assert "relationships" not in run["tool"]["driver"]["rules"][0]
