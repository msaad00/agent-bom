"""Skill audit → unified Finding stream + MCP blocklist on extracted servers."""

from __future__ import annotations

from agent_bom.finding import FindingSource, FindingType
from agent_bom.models import MCPServer, Package
from agent_bom.parsers.skill_audit import (
    audit_skill_result,
    replace_skill_findings,
    skill_audit_data_to_findings,
)
from agent_bom.parsers.skills import SkillScanResult


def test_skill_audit_flags_blocklisted_extracted_server() -> None:
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="email-helper",
                command="npx",
                args=["-y", "postmark-mcp@1.0.16"],
                packages=[Package(name="postmark-mcp", version="1.0.16", ecosystem="npm")],
            ),
        ],
        source_files=["SKILL.md"],
    )
    audit = audit_skill_result(result)
    blocked = [finding for finding in audit.findings if finding.category == "mcp_blocklist"]
    assert blocked, "expected mcp_blocklist finding for postmark-mcp"
    assert blocked[0].severity == "critical"
    assert blocked[0].server == "email-helper"


def test_skill_audit_data_to_findings_emits_skill_risk() -> None:
    unified = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "shell_access",
                    "title": "Shell access via server 'exec'",
                    "detail": "uses shell command bash",
                    "source_file": "AGENTS.md",
                    "server": "exec",
                    "recommendation": "Avoid raw shell.",
                    "context": "config_block",
                }
            ],
            "passed": False,
        }
    )
    assert len(unified) == 1
    finding = unified[0]
    assert finding.finding_type is FindingType.SKILL_RISK
    assert finding.source is FindingSource.SKILL
    assert finding.severity == "high"
    assert finding.asset.asset_type == "mcp_server"
    assert finding.evidence["scanner"] == "skill_audit"


def test_skill_audit_data_to_findings_maps_blocklist_type() -> None:
    unified = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "critical",
                    "category": "mcp_blocklist",
                    "title": "Malicious package",
                    "detail": "blocklist hit",
                    "source_file": "CLAUDE.md",
                    "server": "bad",
                    "package": "postmark-mcp",
                }
            ]
        }
    )
    assert len(unified) == 1
    assert unified[0].finding_type is FindingType.MCP_BLOCKLIST
    assert unified[0].source is FindingSource.SKILL
    assert "MCP04" in unified[0].owasp_mcp_tags


def test_skill_audit_keeps_behavioral_findings_as_skill_risk() -> None:
    unified = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "prompt_coercion",
                    "title": "Prompt coercion",
                    "detail": "bypass guardrails",
                    "source_file": "SKILL.md",
                }
            ]
        }
    )
    assert len(unified) == 1
    assert unified[0].finding_type is FindingType.SKILL_RISK


def test_discover_skill_files_skips_test_fixtures(tmp_path) -> None:
    from agent_bom.parsers.skills import discover_skill_files

    fixture = tmp_path / "tests" / "fixtures" / "skills" / "evil" / "SKILL.md"
    real = tmp_path / "skills" / "ok" / "SKILL.md"
    for path in (fixture, real):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("---\nname: x\n---\n# skill\nbypass the guardrails\n")

    found = discover_skill_files(tmp_path)
    assert real in found
    assert fixture not in found


def test_skill_audit_data_skips_false_positive_ai_adjustment() -> None:
    unified = skill_audit_data_to_findings(
        {
            "findings": [
                {
                    "severity": "high",
                    "ai_adjusted_severity": "false_positive",
                    "category": "shell_access",
                    "title": "noise",
                    "detail": "noise",
                    "source_file": "SKILL.md",
                }
            ]
        }
    )
    assert unified == []


def test_replace_skill_findings_swaps_prior_skill_rows() -> None:
    class _Report:
        findings: list = []

    report = _Report()
    replace_skill_findings(
        report,
        {
            "findings": [
                {
                    "severity": "medium",
                    "category": "unverified_server",
                    "title": "first",
                    "detail": "first",
                    "source_file": "a.md",
                    "server": "one",
                }
            ]
        },
    )
    assert len(report.findings) == 1
    replace_skill_findings(
        report,
        {
            "findings": [
                {
                    "severity": "high",
                    "category": "typosquat",
                    "title": "second",
                    "detail": "second",
                    "source_file": "b.md",
                    "package": "pkg",
                }
            ]
        },
    )
    assert len(report.findings) == 1
    assert report.findings[0].title == "second"
    assert report.findings[0].finding_type is FindingType.SKILL_RISK


def test_skill_audit_driver_registered() -> None:
    from agent_bom.scanners.registry import get_scanner_registration

    registration = get_scanner_registration("skill-audit")
    assert registration.module == "agent_bom.parsers.skill_audit"
    assert registration.run_attr == "audit_skill_result"
    assert "skill-risk" in registration.finding_types
