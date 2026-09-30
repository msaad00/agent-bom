"""Malformed CloudFormation values retain partial coverage and valid findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.iac.cloudformation import scan_cloudformation
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings


@pytest.fixture(autouse=True)
def isolated_coverage():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def scan(tmp_path, template):
    path = tmp_path / "template.json"
    path.write_text(json.dumps(template))
    return scan_cloudformation(path)


def valid_policy():
    return {
        "Type": "AWS::IAM::Policy",
        "Properties": {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        },
    }


def assert_partial():
    warnings = consume_coverage_warnings()
    assert warnings and all(w["ecosystem"] == "cloudformation" for w in warnings)
    assert all(w["reason"] == "unevaluated_template_input" for w in warnings)
    assert "untrusted-value" not in json.dumps(warnings)


@pytest.mark.parametrize(
    "name",
    ["synthetic_list_template.yaml", "synthetic_policy_doc_string.yaml", "synthetic_props_list.yaml", "synthetic_resource_not_dict.yaml"],
)
def test_existing_malformed_corpus_reports_coverage(name):
    path = Path(__file__).parent / "fixtures/iac_golden/cloudformation" / name
    assert scan_cloudformation(path) == []
    assert_partial()


@pytest.mark.parametrize("template", [[], "untrusted-value", 42, None, {"Resources": []}, {"Resources": None}])
def test_invalid_template_shapes_are_not_clean(tmp_path, template):
    assert scan(tmp_path, template) == []
    assert_partial()


@pytest.mark.parametrize(
    "bad",
    ["untrusted-value", {"Type": []}, {}, {"Type": "AWS::S3::Bucket", "Properties": [1]}, {"Type": "AWS::S3::Bucket", "Properties": None}],
)
def test_invalid_resource_keeps_valid_sibling_findings(tmp_path, bad):
    findings = scan(tmp_path, {"Resources": {"Bad": bad, "Valid": valid_policy()}})
    assert {f.rule_id for f in findings} == {"CFN-004", "CFN-014"}
    assert_partial()


@pytest.mark.parametrize(
    "document",
    [
        "untrusted-value",
        [],
        42,
        None,
        {"Statement": None},
        {"Statement": "untrusted-value"},
        {"Statement": [42]},
        {"Ref": "PolicyParameter"},
    ],
)
def test_invalid_policy_document_keeps_other_inline_policy(tmp_path, document):
    policies = [
        {"PolicyName": "Bad", "PolicyDocument": document},
        {"PolicyName": "Valid", "PolicyDocument": valid_policy()["Properties"]["PolicyDocument"]},
    ]
    findings = scan(tmp_path, {"Resources": {"Role": {"Type": "AWS::IAM::Role", "Properties": {"Policies": policies}}}})
    assert {f.rule_id for f in findings} == {"CFN-004", "CFN-014"}
    assert_partial()


def test_single_statement_object_is_evaluated(tmp_path):
    policy = valid_policy()
    policy["Properties"]["PolicyDocument"]["Statement"] = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    findings = scan(tmp_path, {"Resources": {"Policy": policy}})
    assert {f.rule_id for f in findings} == {"CFN-004", "CFN-014"}
    assert consume_coverage_warnings() == []


@pytest.mark.parametrize("props", [{"Policies": None}, {"Policies": "untrusted-value"}, {"Policies": [42]}])
def test_invalid_policy_collection_records_coverage(tmp_path, props):
    assert scan(tmp_path, {"Resources": {"Role": {"Type": "AWS::IAM::Role", "Properties": props}}}) == []
    assert_partial()


@pytest.mark.parametrize(
    "resource",
    [
        {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": None}},
        {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": "untrusted-value"}},
        {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {"configured": True}, "VersioningConfiguration": "untrusted-value"}},
    ],
)
def test_invalid_nested_rule_input_is_not_a_missing_control(tmp_path, resource):
    assert scan(tmp_path, {"Resources": {"Invalid": resource}}) == []
    assert_partial()


@pytest.mark.parametrize("parameters", [[], "untrusted-value", None, {"Secret": "untrusted-value"}])
def test_invalid_parameters_keep_resource_findings(tmp_path, parameters):
    findings = scan(tmp_path, {"Resources": {"Valid": valid_policy()}, "Parameters": parameters})
    assert {f.rule_id for f in findings} == {"CFN-004", "CFN-014"}
    assert_partial()


def test_cli_emits_partial_report_and_retains_valid_findings(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from agent_bom.cli import main

    project = tmp_path / "project"
    project.mkdir()
    (project / "template.json").write_text(
        json.dumps(
            {
                "Resources": {
                    "Invalid": {"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": "untrusted-value"}},
                    "Valid": valid_policy(),
                }
            }
        )
    )
    output = tmp_path / "report.json"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--project",
            str(project),
            "--no-discover",
            "--offline",
            "--no-scan",
            "--no-auto-update-db",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(output),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.output
    report = json.loads(output.read_text())
    assert report["scan_run"]["outcome"] == "partial"
    gaps = [w for w in report["coverage_warnings"] if w["ecosystem"] == "cloudformation"]
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "unevaluated_template_input"
    assert "untrusted-value" not in json.dumps(gaps)
    assert {f["rule_id"] for f in report["iac_findings"]["findings"]} == {"CFN-004", "CFN-014"}
