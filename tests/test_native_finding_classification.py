from __future__ import annotations

from agent_bom.finding import (
    ast_flow_dict_to_finding,
    iac_finding_to_finding,
    secret_dict_to_finding,
)
from agent_bom.parsers.prompt_scanner import prompt_scan_data_to_findings
from agent_bom.parsers.skill_audit import skill_audit_data_to_findings


def test_native_security_adapters_apply_compliance_hub_classification() -> None:
    ast = ast_flow_dict_to_finding(
        {
            "category": "command_execution",
            "file": "src/app.py",
            "line": 7,
            "entrypoint": "run",
            "sink": "subprocess.run",
        }
    )
    secret = secret_dict_to_finding(
        {
            "file": "src/app.py",
            "line": 8,
            "type": "AWS access key",
            "category": "credential",
            "severity": "critical",
            "preview": "***REDACTED***",
        }
    )
    iac = iac_finding_to_finding(
        {
            "rule_id": "TF001",
            "file_path": "main.tf",
            "line_number": 9,
            "category": "terraform",
            "severity": "high",
            "title": "Public storage",
            "compliance": ["NIST-AC-3", "CIS-AWS-2.1.1"],
        }
    )
    skill = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "prompt_injection",
                    "title": "Untrusted prompt reaches tool",
                    "source_file": "SKILL.md",
                }
            ]
        }
    )[0]

    for finding in (ast, secret, iac, skill):
        assert finding.applicable_frameworks, finding.title


def test_iac_compliance_tags_are_typed_without_conflating_benchmarks() -> None:
    finding = iac_finding_to_finding(
        {
            "rule_id": "TF001",
            "file_path": "main.tf",
            "category": "terraform",
            "severity": "high",
            "title": "Public storage",
            "compliance": [
                "NIST-AC-3",
                "NIST-CSF-PR.DS-1",
                "CIS-AWS-2.1.1",
                "CIS-K8s-5.4.1",
            ],
        }
    )

    controls = {(tag.framework, tag.control) for tag in finding.normalized_controls()}
    assert ("nist_800_53", "AC-3") in controls
    assert ("nist_csf", "PR.DS-1") in controls
    assert ("cis_aws_foundations", "2.1.1") in controls
    assert ("cis_kubernetes_benchmark", "5.4.1") in controls
    assert ("cis", "2.1.1") not in controls
    assert ("generic", "NIST-AC-3") not in controls


def test_prompt_injection_adapters_emit_canonical_weakness_and_owasp_ids() -> None:
    prompt = prompt_scan_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "prompt_injection",
                    "title": "Untrusted input reaches prompt",
                    "source_file": "prompts/system.txt",
                }
            ]
        }
    )[0]
    skill = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "prompt_injection",
                    "title": "Untrusted prompt reaches tool",
                    "source_file": "SKILL.md",
                }
            ]
        }
    )[0]

    for finding in (prompt, skill):
        assert "CWE-1427" in finding.cwe_ids
        assert "LLM01" in finding.owasp_tags
