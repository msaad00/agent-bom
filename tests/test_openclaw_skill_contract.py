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


def test_bundled_openclaw_skills_declare_trust_boundary_contract() -> None:
    """Bundled skills must keep the same explicit trust-boundary surface."""
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
    ):
        assert phrase in content
