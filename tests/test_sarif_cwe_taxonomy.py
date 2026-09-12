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
    assert run["tool"]["driver"]["supportedTaxonomies"] == [{"name": "CWE", "guid": cwe["guid"]}]
    relationships = run["tool"]["driver"]["rules"][0]["relationships"]
    assert [r["target"]["id"] for r in relationships] == ["79", "89"]
    assert all(r["target"]["toolComponent"]["name"] == "CWE" and r["kinds"] == ["relevant"] for r in relationships)
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


def test_cwe_references_resolve_without_display_names_and_are_stable():
    from agent_bom.output.sarif import _attach_cwe_taxonomy

    def export():
        results = [
            {"ruleId": "shared", "properties": {"cwe_ids": ["CWE-79"]}},
            {"ruleId": "shared", "properties": {"cwe_ids": []}},
        ]
        rules = [{"id": "shared"}]
        taxonomy = _attach_cwe_taxonomy(results, rules)
        assert taxonomy is not None
        return results, rules, taxonomy

    results, rules, taxonomy = export()
    assert export() == (results, rules, taxonomy)
    refs = results[0]["taxa"] + [r["target"] for r in rules[0]["relationships"]]
    for ref in refs:
        # SARIF display names do not participate in descriptor resolution.
        assert ref["toolComponent"]["guid"] == taxonomy["guid"]
        taxon = next(t for t in taxonomy["taxa"] if t["guid"] == ref["guid"])
        assert taxon["id"] == ref["id"] == "79"
    assert "taxa" not in results[1]
    # A shared rule must not automatically apply one result's CWE to another.
    assert all("superset" not in r["kinds"] for r in rules[0]["relationships"])


def test_oversized_cwe_id_does_not_crash_export():
    from agent_bom.output.sarif import _attach_cwe_taxonomy

    results = [{"ruleId": "rule", "properties": {"cwe_ids": ["CWE-" + "9" * 5000, "CWE-79"]}}]
    taxonomy = _attach_cwe_taxonomy(results, [{"id": "rule"}])
    assert taxonomy is not None
    assert [t["id"] for t in taxonomy["taxa"]] == ["79"]
