"""Remediation automation — generate actionable fix commands for vulnerabilities and credentials.

Produces executable upgrade commands per ecosystem, credential scope-reduction
guides, and exportable remediation.md / remediation.sh files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agent_bom.models import AIBOMReport, BlastRadius
from agent_bom.output import build_remediation_plan

# ─── Data structures ─────────────────────────────────────────────────────────


@dataclass
class PackageFix:
    """An upgrade command for a vulnerable package."""

    package: str
    ecosystem: str
    current_version: str
    fixed_version: Optional[str]
    command: str
    vulns: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)


@dataclass
class CredentialFix:
    """Remediation guidance for an exposed credential."""

    credential_name: str
    locations: list[str]
    risk_description: str
    fix_steps: list[str]
    fix_commands: list[str] = field(default_factory=list)
    reference_url: str = ""


@dataclass
class RemediationPlan:
    """Complete remediation plan with package upgrades and credential fixes."""

    generated_at: str = ""
    package_fixes: list[PackageFix] = field(default_factory=list)
    credential_fixes: list[CredentialFix] = field(default_factory=list)
    unfixable: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


# ─── Package fix generation ──────────────────────────────────────────────────

_ECOSYSTEM_COMMANDS: dict[str, str] = {
    "npm": "npm install {package}@{version}",
    "pypi": "pip install '{package}>={version}'",
    "PyPI": "pip install '{package}>={version}'",
    "cargo": "cargo update -p {package}",
    "go": "go get {package}@v{version}",
    "maven": "# Update {package} to {version} in pom.xml",
    "nuget": "dotnet add package {package} --version {version}",
    "rubygems": "gem install {package} -v '{version}'",
}


def generate_package_fixes(plan_items: list[dict]) -> tuple[list[PackageFix], list[dict]]:
    """Generate upgrade commands for vulnerable packages.

    Returns (fixable, unfixable) where fixable has concrete commands.
    """
    fixable: list[PackageFix] = []
    unfixable: list[dict] = []

    for item in plan_items:
        if not item.get("fix"):
            unfixable.append({
                "package": item["package"],
                "ecosystem": item["ecosystem"],
                "current_version": item["current"],
                "vulns": item["vulns"],
                "agents": item["agents"],
            })
            continue

        template = _ECOSYSTEM_COMMANDS.get(item["ecosystem"], "# Upgrade {package} to {version}")
        command = template.format(package=item["package"], version=item["fix"])

        fixable.append(PackageFix(
            package=item["package"],
            ecosystem=item["ecosystem"],
            current_version=item["current"],
            fixed_version=item["fix"],
            command=command,
            vulns=item["vulns"],
            agents=item["agents"],
        ))

    return fixable, unfixable


# ─── Credential fix generation ───────────────────────────────────────────────

_CREDENTIAL_TEMPLATES: dict[str, dict] = {
    "GITHUB_PERSONAL_ACCESS_TOKEN": {
        "risk": "Token may have full repo scope, granting read/write access to all repositories.",
        "steps": [
            "Go to https://github.com/settings/tokens?type=beta",
            "Create a fine-grained PAT with:",
            "  - Repository access: Only select repositories needed by the MCP server",
            "  - Permissions: Contents (read-only), Issues (read/write) — minimum needed",
            "Replace the old token in your MCP client config",
            "Revoke the old classic PAT",
        ],
        "commands": [
            "# List current token scopes:",
            "gh auth status",
            "# After creating new fine-grained token, test it:",
            "GITHUB_TOKEN=<new-token> gh api user --jq .login",
        ],
        "url": "https://github.com/settings/tokens?type=beta",
    },
    "POSTGRES_CONNECTION_STRING": {
        "risk": "Connection string may use a superuser role, allowing DROP/DELETE/ALTER.",
        "steps": [
            "Create a read-only database role for the MCP server:",
            "  CREATE ROLE mcp_readonly WITH LOGIN PASSWORD 'secure-password';",
            "  GRANT CONNECT ON DATABASE mydb TO mcp_readonly;",
            "  GRANT USAGE ON SCHEMA public TO mcp_readonly;",
            "  GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;",
            "Update the connection string to use the new role",
            "Test: the MCP server should still work for read queries",
        ],
        "commands": [
            "# Create read-only role (run as superuser):",
            "psql -c \"CREATE ROLE mcp_readonly WITH LOGIN PASSWORD 'change-me';\"",
            "psql -c \"GRANT CONNECT ON DATABASE mydb TO mcp_readonly;\"",
            "psql -c \"GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;\"",
        ],
        "url": "https://www.postgresql.org/docs/current/sql-grant.html",
    },
    "SLACK_BOT_TOKEN": {
        "risk": "Bot token may have broad scopes, allowing message posting to any channel.",
        "steps": [
            "Review current bot scopes at https://api.slack.com/apps",
            "Remove unnecessary scopes — keep only:",
            "  - chat:write (for posting to specific channels)",
            "  - channels:read (for listing channels)",
            "Remove admin scopes if present (admin, admin.conversations, etc.)",
            "Regenerate the bot token after scope changes",
        ],
        "commands": [],
        "url": "https://api.slack.com/apps",
    },
}

# Pattern-based fallbacks for credentials not in the template
_CREDENTIAL_PATTERNS: list[tuple[list[str], dict]] = [
    (
        ["AWS_ACCESS_KEY", "AWS_SECRET", "AWS_SESSION"],
        {
            "risk": "AWS credentials may have broad IAM permissions.",
            "steps": [
                "Create a dedicated IAM role/user with minimum permissions",
                "Use IAM policy conditions to restrict by IP/time/resource",
                "Consider using AWS SSO or temporary credentials (STS) instead",
                "Rotate the access key immediately if over-scoped",
            ],
            "commands": [
                "# Check current identity:",
                "aws sts get-caller-identity",
                "# List attached policies:",
                "aws iam list-attached-user-policies --user-name <user>",
            ],
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        },
    ),
    (
        ["AZURE_", "AZURE_CLIENT", "AZURE_TENANT"],
        {
            "risk": "Azure credentials may have broad role assignments.",
            "steps": [
                "Review role assignments with: az role assignment list",
                "Use managed identities instead of client secrets where possible",
                "Apply least-privilege RBAC roles",
                "Rotate client secrets regularly",
            ],
            "commands": ["az role assignment list --assignee <app-id> --output table"],
            "url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices",
        },
    ),
    (
        ["GCP_", "GOOGLE_", "GCLOUD"],
        {
            "risk": "GCP service account may have broad IAM roles.",
            "steps": [
                "Review IAM bindings: gcloud projects get-iam-policy <project>",
                "Use workload identity instead of service account keys",
                "Apply least-privilege roles (avoid roles/editor, roles/owner)",
                "Rotate service account keys",
            ],
            "commands": ["gcloud iam service-accounts keys list --iam-account <email>"],
            "url": "https://cloud.google.com/iam/docs/understanding-roles",
        },
    ),
    (
        ["API_KEY", "APIKEY", "TOKEN", "SECRET"],
        {
            "risk": "API key/token scope is unknown — may grant excessive access.",
            "steps": [
                "Review the key's permissions in the service's dashboard",
                "Regenerate with minimum required scopes",
                "Set IP allowlist or rate limits if supported",
                "Store in a secrets manager (1Password CLI, Vault, etc.) instead of config files",
                "Rotate the key on a regular schedule",
            ],
            "commands": [],
            "url": "",
        },
    ),
]


def generate_credential_fixes(cred_map: dict[str, list[str]]) -> list[CredentialFix]:
    """Generate fix guidance for exposed credentials.

    Args:
        cred_map: {credential_name: [location_strings]}
    """
    fixes: list[CredentialFix] = []

    for cred_name, locations in sorted(cred_map.items()):
        # Check exact template match first
        if cred_name in _CREDENTIAL_TEMPLATES:
            tmpl = _CREDENTIAL_TEMPLATES[cred_name]
            fixes.append(CredentialFix(
                credential_name=cred_name,
                locations=locations,
                risk_description=tmpl["risk"],
                fix_steps=tmpl["steps"],
                fix_commands=tmpl.get("commands", []),
                reference_url=tmpl.get("url", ""),
            ))
            continue

        # Pattern-based fallback
        matched = False
        for patterns, tmpl in _CREDENTIAL_PATTERNS:
            if any(pat in cred_name.upper() for pat in patterns):
                fixes.append(CredentialFix(
                    credential_name=cred_name,
                    locations=locations,
                    risk_description=tmpl["risk"],
                    fix_steps=tmpl["steps"],
                    fix_commands=tmpl.get("commands", []),
                    reference_url=tmpl.get("url", ""),
                ))
                matched = True
                break

        if not matched:
            # Generic fallback
            fixes.append(CredentialFix(
                credential_name=cred_name,
                locations=locations,
                risk_description="Credential scope is unknown — review and restrict permissions.",
                fix_steps=[
                    "Review the credential's permissions in the issuing service",
                    "Regenerate with minimum required scopes",
                    "Store in a secrets manager instead of plain config files",
                    "Rotate on a regular schedule",
                ],
            ))

    return fixes


# ─── Full plan generation ────────────────────────────────────────────────────


def generate_remediation(
    report: AIBOMReport,
    blast_radii: list[BlastRadius],
) -> RemediationPlan:
    """Generate a full remediation plan with executable commands."""
    plan = RemediationPlan()

    # Package fixes from existing remediation plan builder
    if blast_radii:
        plan_items = build_remediation_plan(blast_radii)
        plan.package_fixes, plan.unfixable = generate_package_fixes(plan_items)

    # Credential fixes from the report
    cred_map: dict[str, list[str]] = {}
    for agent in report.agents:
        for server in agent.mcp_servers:
            for cred in server.credential_names:
                cred_map.setdefault(cred, []).append(f"{agent.name}/{server.name}")

    if cred_map:
        plan.credential_fixes = generate_credential_fixes(cred_map)

    return plan


# ─── Export ──────────────────────────────────────────────────────────────────


def export_remediation_md(plan: RemediationPlan, path: str) -> None:
    """Write remediation.md skill file with all fixes."""
    lines: list[str] = []
    lines.append("# agent-bom Remediation Plan")
    lines.append(f"Generated: {plan.generated_at}")
    lines.append("")

    # Priority 1: Package upgrades
    if plan.package_fixes:
        lines.append("## Priority 1: Package Upgrades")
        lines.append("")
        for i, fix in enumerate(plan.package_fixes, 1):
            lines.append(f"### {i}. {fix.package} {fix.current_version} -> {fix.fixed_version}")
            lines.append(f"- **Ecosystem**: {fix.ecosystem}")
            lines.append(f"- **Clears**: {', '.join(fix.vulns[:5])}")
            if fix.agents:
                lines.append(f"- **Agents affected**: {', '.join(fix.agents[:5])}")
            lines.append("- **Command**:")
            lines.append("  ```bash")
            lines.append(f"  {fix.command}")
            lines.append("  ```")
            lines.append("")

    # Priority 2: Credential scope reduction
    if plan.credential_fixes:
        lines.append("## Priority 2: Credential Scope Reduction")
        lines.append("")
        for fix in plan.credential_fixes:
            lines.append(f"### {fix.credential_name}")
            lines.append(f"- **Used by**: {', '.join(fix.locations[:5])}")
            lines.append(f"- **Risk**: {fix.risk_description}")
            lines.append("- **Fix steps**:")
            for step in fix.fix_steps:
                lines.append(f"  - {step}")
            if fix.fix_commands:
                lines.append("- **Commands**:")
                lines.append("  ```bash")
                for cmd in fix.fix_commands:
                    lines.append(f"  {cmd}")
                lines.append("  ```")
            if fix.reference_url:
                lines.append(f"- **Reference**: {fix.reference_url}")
            lines.append("")

    # Priority 3: No fix available
    if plan.unfixable:
        lines.append("## Priority 3: Monitor (No Fix Available)")
        lines.append("")
        for item in plan.unfixable:
            lines.append(f"- **{item['package']}@{item['current_version']}** — {', '.join(item['vulns'][:3])}")
            if item.get("agents"):
                lines.append(f"  - Agents: {', '.join(item['agents'][:3])}")
        lines.append("")

    Path(path).write_text("\n".join(lines))


def export_remediation_sh(plan: RemediationPlan, path: str) -> None:
    """Write remediation.sh script with package upgrade commands."""
    lines: list[str] = []
    lines.append("#!/usr/bin/env bash")
    lines.append(f"# agent-bom Remediation Script — generated {plan.generated_at}")
    lines.append("# Review each command before running!")
    lines.append("set -euo pipefail")
    lines.append("")

    if plan.package_fixes:
        lines.append("# ── Package Upgrades ──")
        lines.append("")
        for fix in plan.package_fixes:
            vulns = ", ".join(fix.vulns[:3])
            lines.append(f"# {fix.package} {fix.current_version} -> {fix.fixed_version} (fixes: {vulns})")
            lines.append(fix.command)
            lines.append("")

    if plan.credential_fixes:
        lines.append("# ── Credential Remediation (manual steps) ──")
        lines.append("")
        for fix in plan.credential_fixes:
            lines.append(f"# {fix.credential_name}: {fix.risk_description}")
            for cmd in fix.fix_commands:
                lines.append(cmd)
            if not fix.fix_commands:
                lines.append("# See remediation.md for manual steps")
            lines.append("")

    Path(path).write_text("\n".join(lines))
    # Make executable
    Path(path).chmod(0o755)
