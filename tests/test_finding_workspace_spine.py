from __future__ import annotations

from pathlib import Path

from agent_bom.compliance_hub_ingest import parse_sarif_document
from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    ast_flow_dict_to_finding,
    iac_finding_to_finding,
    secret_dict_to_finding,
)
from agent_bom.graph.codeowners import apply_codeowners, load_codeowners
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json


def test_source_findings_share_file_asset_but_keep_occurrence_identity() -> None:
    ast_one = ast_flow_dict_to_finding(
        {"category": "command_execution", "file": "src/app.py", "line": 10, "entrypoint": "run", "sink": "exec"}
    )
    ast_two = ast_flow_dict_to_finding(
        {"category": "command_execution", "file": "src/app.py", "line": 20, "entrypoint": "run", "sink": "exec"}
    )
    secret_one = secret_dict_to_finding({"type": "api_key", "category": "credential", "file": "src/app.py", "line": 11, "severity": "high"})
    secret_two = secret_dict_to_finding({"type": "api_key", "category": "credential", "file": "src/app.py", "line": 21, "severity": "high"})
    iac_one = iac_finding_to_finding({"rule_id": "K8S-001", "file_path": "deploy/app.yaml", "line_number": 5, "category": "k8s"})
    iac_two = iac_finding_to_finding({"rule_id": "K8S-001", "file_path": "deploy/app.yaml", "line_number": 15, "category": "k8s"})

    assert ast_one.asset.stable_id == ast_two.asset.stable_id
    assert ast_one.id != ast_two.id
    assert secret_one.asset.stable_id == secret_two.asset.stable_id
    assert secret_one.id != secret_two.id
    assert iac_one.asset.stable_id == iac_two.asset.stable_id
    assert iac_one.id != iac_two.id


def test_sarif_assets_are_files_and_findings_are_rule_occurrences() -> None:
    findings = parse_sarif_document(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "rules": [{"id": "python.lang.security.audit"}]}},
                    "results": [
                        {
                            "ruleId": "python.lang.security.audit",
                            "level": "warning",
                            "message": {"text": "unsafe call"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.py"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "python.lang.security.audit",
                            "level": "warning",
                            "message": {"text": "unsafe call"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/b.py"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ],
        }
    )

    assert [finding.asset.identifier for finding in findings] == ["src/a.py", "src/b.py"]
    assert findings[0].asset.stable_id != findings[1].asset.stable_id
    assert findings[0].id != findings[1].id


def test_generic_control_tags_are_promoted_to_named_frameworks() -> None:
    finding = Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.CLOUD_SECURITY,
        asset=Asset(name="deploy/app.yaml", asset_type="iac_resource", identifier="deploy/app.yaml"),
        severity="high",
        compliance_tags=["NIST-AC-6", "CIS-K8s-5.2.1", "SOC2-CC6.1"],
    )

    controls = {(tag.framework, tag.control) for tag in finding.normalized_controls()}
    assert ("nist_800_53", "AC-6") in controls
    assert ("cis_kubernetes_benchmark", "5.2.1") in controls
    assert ("soc2", "CC6.1") in controls
    assert not any(framework == "generic" for framework, _ in controls)


def test_codeowners_assigns_most_specific_owner_without_overwriting_triage(tmp_path: Path) -> None:
    codeowners_path = tmp_path / ".github" / "CODEOWNERS"
    codeowners_path.parent.mkdir()
    codeowners_path.write_text("* @platform\n/src/payments/ @payments @security\n", encoding="utf-8")
    rules = load_codeowners(tmp_path)
    owned = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(name="src/payments/api.py", asset_type="source_file", identifier="src/payments/api.py", location="src/payments/api.py"),
        severity="high",
    )
    assigned = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(
            name="src/payments/jobs.py", asset_type="source_file", identifier="src/payments/jobs.py", location="src/payments/jobs.py"
        ),
        severity="high",
        owner="incident-commander@example.test",
    )

    apply_codeowners([owned, assigned], rules)

    assert owned.owner == "@payments, @security"
    assert owned.evidence["codeowners_pattern"] == "/src/payments/"
    assert assigned.owner == "incident-commander@example.test"
    assert [rule.to_dict() for rule in rules] == [
        {"pattern": "*", "owners": ["@platform"]},
        {"pattern": "/src/payments/", "owners": ["@payments", "@security"]},
    ]


def test_report_applies_and_exports_codeowners_rules() -> None:
    finding = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(name="src/api.py", asset_type="source_file", identifier="src/api.py", location="src/api.py"),
        severity="high",
    )
    report = AIBOMReport(
        findings=[finding],
        codeowners=[{"pattern": "/src/", "owners": ["@appsec"]}],
    )

    payload = to_json(report)

    assert payload["codeowners"] == [{"pattern": "/src/", "owners": ["@appsec"]}]
    assert payload["findings"][0]["owner"] == "@appsec"
