from __future__ import annotations

from pathlib import Path

from agent_bom.parsers.skill_audit import audit_skill_result
from agent_bom.parsers.skills import parse_skill_file
from agent_bom.parsers.trust_assessment import assess_trust

SKILL_PATH = Path(__file__).resolve().parents[1] / "integrations" / "openclaw" / "discover-aws" / "SKILL.md"


def test_aws_discovery_skill_declares_guardrailed_skill_invoked_inventory_flow() -> None:
    result = parse_skill_file(SKILL_PATH)

    assert result.metadata is not None
    assert result.metadata.name == "agent-bom-discover-aws"
    assert result.metadata.license == "Apache-2.0"
    assert "python" in result.metadata.required_bins
    assert {"darwin", "linux", "windows"}.issubset(set(result.metadata.os_support))

    content = result.raw_content[str(SKILL_PATH)]
    assert "--discovery-method skill_invoked_pull" in content
    assert "--source aws-skill-invoked" in content
    assert "examples/operator_pull/aws_inventory_adapter.py" in content
    assert "Do not ask users to paste access keys" in content
    assert "Do not modify AWS resources" in content
    assert "discover-only by default" in content
    assert "The skill does not push inventory to an API by default" in content
    assert "separate operator-approved handoff" in content
    assert "agent-bom agents --inventory aws-inventory.json" in content


def test_aws_discovery_skill_trust_assessment_stays_review_not_blocked() -> None:
    result = parse_skill_file(SKILL_PATH)
    audit = audit_skill_result(result)
    trust = assess_trust(result, audit)

    assert trust.review_verdict in {"trusted", "review"}
    assert trust.review_verdict != "blocked"
    assert not any(finding.severity == "critical" for finding in audit.findings)
