"""Extra discovery passes for shallow-cloned public repositories."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from agent_bom.models import Agent, AgentType, MCPServer


def scan_cloned_repo_tree(
    cloned_path: str,
    *,
    agents: list[Agent],
    warnings: list[str],
    update_progress: Callable[[str], None] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Run skill/instruction and IaC discovery on a cloned repository root.

    Mirrors the high-signal repo passes from the CLI ``--repo`` / ``--project``
    path: agent instruction files, MCP references in markdown, and multi-format
    IaC (Terraform, Kubernetes manifests, CloudFormation, etc.).
    """
    root = Path(cloned_path)
    skill_audit_data: dict[str, Any] | None = None
    iac_findings_data: dict[str, Any] | None = None

    from agent_bom.parsers.skill_audit import audit_skill_result
    from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

    skill_files = discover_skill_files(root)
    if skill_files:
        if update_progress is not None:
            update_progress(f"Scanning {len(skill_files)} skill/instruction file(s)")
        skill_result = scan_skill_files(skill_files)
        if skill_result.servers or skill_result.packages or skill_result.credential_env_vars:
            skill_provenance = {
                "source_type": "skill_invoked_pull",
                "observed_via": ["skill_invoked_pull"],
                "source": "skill-files",
                "collector": "skill_scanner",
                "confidence": "high",
            }
            if skill_result.servers:
                for server in skill_result.servers:
                    for pkg in getattr(server, "packages", []) or []:
                        if getattr(pkg, "discovery_provenance", None) is None:
                            pkg.discovery_provenance = skill_provenance
                agents.append(
                    Agent(
                        name="skill-files",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(skill_files[0]),
                        mcp_servers=skill_result.servers,
                        source="skill-files",
                        discovery_provenance=skill_provenance,
                    )
                )
            if skill_result.packages:
                for pkg in skill_result.packages:
                    if getattr(pkg, "discovery_provenance", None) is None:
                        pkg.discovery_provenance = skill_provenance
                agents.append(
                    Agent(
                        name="skill-packages",
                        agent_type=AgentType.CUSTOM,
                        config_path=", ".join(str(path) for path in skill_files[:3]),
                        mcp_servers=[MCPServer(name="skill-packages", command="(from skill files)", packages=skill_result.packages)],
                        source="skill-files",
                        discovery_provenance=skill_provenance,
                    )
                )
            if skill_result.credential_env_vars:
                warnings.append(
                    f"{len(skill_result.credential_env_vars)} credential env var(s) referenced in skill/instruction files"
                )
            skill_audit = audit_skill_result(skill_result)
            skill_audit_data = {
                "findings": [
                    {
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "detail": finding.detail,
                        "source_file": finding.source_file,
                        "package": finding.package,
                        "server": finding.server,
                        "recommendation": finding.recommendation,
                        "context": finding.context,
                    }
                    for finding in skill_audit.findings
                ],
                "packages_checked": skill_audit.packages_checked,
                "servers_checked": skill_audit.servers_checked,
                "credentials_checked": skill_audit.credentials_checked,
                "passed": skill_audit.passed,
            }

    from agent_bom.iac import scan_iac_with_context
    from agent_bom.iac.models import ScanContext as IaCContext

    if update_progress is not None:
        update_progress("Scanning IaC and cloud config files")
    iac_result = scan_iac_with_context(root, IaCContext(deployment_mode="standalone"))
    if iac_result.findings:
        iac_findings_data = {
            "total": len(iac_result.findings),
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "message": finding.message,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "category": finding.category,
                    "compliance": finding.compliance,
                    "attack_techniques": finding.attack_techniques,
                    "remediation": finding.remediation,
                }
                for finding in iac_result.findings
            ],
        }

    return skill_audit_data, iac_findings_data
