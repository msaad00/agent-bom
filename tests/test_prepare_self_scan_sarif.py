"""GitHub upload locations must refer to retained, real evidence artifacts."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

SCRIPT = Path(__file__).parents[1] / "scripts/prepare_self_scan_sarif.py"


def prepare(doc, uri):
    spec = importlib.util.spec_from_file_location("prepare_self_scan_sarif", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepare(doc, uri)


def finding():
    return {
        "ruleId": "GHSA-real-advisory",
        "level": "error",
        "message": {"text": "Installed package finding"},
        "locations": [{"logicalLocations": [{"fullyQualifiedName": "self-scan://agent-bom"}]}],
        "relatedLocations": [{"id": 1, "logicalLocations": [{"fullyQualifiedName": "pkg:pypi/tornado@6.5.8"}]}],
        "fingerprints": {"agent-bom/v1": "a" * 64},
        "properties": {"occurrence_id": "finding-one"},
    }


def test_generated_evidence_is_the_location_without_losing_the_finding():
    original = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "agent-bom"}}, "results": [finding()]}]}
    before = copy.deepcopy(original)
    doc, evidence = prepare(original, "self-scan-findings.jsonl")
    result = doc["runs"][0]["results"][0]
    location = result["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "self-scan-findings.jsonl"
    assert json.loads(evidence.splitlines()[location["physicalLocation"]["region"]["startLine"] - 1])["finding"] == finding()
    assert result["relatedLocations"][0]["physicalLocation"] == location["physicalLocation"]
    assert result["relatedLocations"][0]["logicalLocations"] == finding()["relatedLocations"][0]["logicalLocations"]
    assert location["logicalLocations"] == finding()["locations"][0]["logicalLocations"]
    assert result["ruleId"] == finding()["ruleId"] and result["level"] == "error"
    assert result["fingerprints"] == finding()["fingerprints"]
    assert original == before
    assert prepare(doc, "self-scan-findings.jsonl")[0] == doc
    schema = json.loads((Path(__file__).parent / "fixtures/sarif-schema-2.1.0.json").read_text())
    Draft7Validator(schema).validate(doc)


def test_real_source_locations_are_unchanged_and_do_not_create_evidence():
    result = finding()
    result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": "uv.lock"}, "region": {"startLine": 12}}}]
    doc = {"runs": [{"results": [result]}]}
    assert prepare(doc, "evidence.jsonl") == (doc, "")


@pytest.mark.parametrize("uri", ["../outside.jsonl", "/tmp/evidence.jsonl", "self-scan://artifact", ""])
def test_evidence_location_must_be_a_checkout_relative_artifact(uri):
    with pytest.raises(ValueError):
        prepare({"runs": [{"results": [finding()]}]}, uri)
