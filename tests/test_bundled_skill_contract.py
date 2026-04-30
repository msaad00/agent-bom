from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / "integrations" / "openclaw"


REQUIRED_OPENCLAW_FIELDS = (
    "requires:",
    "bins:",
    "env:",
    "credentials:",
    "credential_policy:",
    "credential_handling:",
    "optional_env:",
    "optional_bins:",
    "data_flow:",
    "file_reads:",
    "file_writes:",
    "network_endpoints:",
    "telemetry:",
    "persistence:",
    "privilege_escalation:",
    "autonomous_invocation:",
)


def _bundled_skill_paths() -> list[Path]:
    return sorted(SKILL_ROOT.glob("*/SKILL.md")) + [SKILL_ROOT / "SKILL.md"]


def test_bundled_agent_bom_skills_declare_trust_boundary_contract() -> None:
    """Bundled agent-bom skills must keep the same trust-boundary surface."""
    for skill_path in _bundled_skill_paths():
        content = skill_path.read_text()
        missing = [field for field in REQUIRED_OPENCLAW_FIELDS if field not in content]
        assert not missing, f"{skill_path.relative_to(ROOT)} missing {missing}"


def test_skill_contribution_contract_documents_guardrails() -> None:
    """New skill contributors should have a reviewable guardrail contract."""
    content = (ROOT / "docs" / "CONTRIBUTING_SKILLS.md").read_text()
    for phrase in (
        "credential_policy",
        "credential_handling",
        "data_flow",
        "file_reads",
        "file_writes",
        "network_endpoints",
        "autonomous_invocation",
        "Never print raw credential values",
        "Do not ship a remediation skill",
        "corresponding CLI/API behavior exists and is tested",
        "A1 Tool Poisoning",
        "A7 Identity Spoofing",
    ):
        assert phrase in content


def test_cloud_discovery_and_inventory_ingest_skills_are_bundled() -> None:
    """Cloud skill coverage should match the shipped operator-pull adapters."""
    expected = {
        "discover-aws": "aws_inventory_adapter.py",
        "discover-azure": "azure_inventory_adapter.py",
        "discover-gcp": "gcp_inventory_adapter.py",
        "discover-snowflake": "snowflake_inventory_adapter.py",
        "ingest": "inventory.schema.json",
    }
    for skill_name, expected_receipt in expected.items():
        skill_path = SKILL_ROOT / skill_name / "SKILL.md"
        assert skill_path.exists(), f"missing bundled skill: {skill_name}"
        content = skill_path.read_text()
        assert "source_type" in content
        assert "discovery_provenance" in content
        assert "permissions_used" in content
        assert expected_receipt in content


def test_scan_skill_documents_agentic_workflow_sequences() -> None:
    """The scan skill should tell agents how to chain tools for CI and install-time review."""
    content = (SKILL_ROOT / "scan" / "SKILL.md").read_text()
    for phrase in (
        "Agentic Workflows",
        "registry_lookup",
        "fail on high/critical",
        "SARIF for CI",
        "JSON for automation/graph",
    ):
        assert phrase in content
