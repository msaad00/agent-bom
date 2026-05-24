"""Public docs and bundled skills should teach commands that actually work."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CLI_DOCS = [
    ROOT / "integrations" / "cortex-code" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "analyze" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "compliance" / "SKILL.md",
    ROOT / "integrations" / "openclaw" / "scan-infra" / "SKILL.md",
    ROOT / "site-docs" / "features" / "sbom.md",
    ROOT / "site-docs" / "features" / "scanning.md",
    ROOT / "site-docs" / "features" / "policy.md",
    ROOT / "site-docs" / "features" / "compliance.md",
    ROOT / "site-docs" / "features" / "blast-radius.md",
    ROOT / "site-docs" / "getting-started" / "install.md",
    ROOT / "site-docs" / "reference" / "exit-codes.md",
    ROOT / "site-docs" / "architecture" / "agentic-skills-architecture.md",
]


def test_public_docs_do_not_teach_removed_cli_surfaces() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_CLI_DOCS)

    removed_or_misleading = [
        "agent-bom generate-sbom",
        "agent-bom cloud snowflake",
        "agent-bom cis-benchmark",
        "agent-bom scan --sbom cyclonedx",
        "agent-bom scan --sbom spdx",
        "agent-bom scan --sbom-input",
    ]
    for command in removed_or_misleading:
        assert command not in combined


def test_documented_primary_commands_are_real_cli_surfaces() -> None:
    runner = CliRunner()
    commands = [
        ["agents", "--help"],
        ["image", "--help"],
        ["sbom", "--help"],
        ["cloud", "aws", "--help"],
        ["graph", "--help"],
        ["validate", "--help"],
        ["db", "status", "--help"],
        ["skills", "scan", "--help"],
    ]

    for command in commands:
        result = runner.invoke(main, command)
        assert result.exit_code == 0, f"agent-bom {' '.join(command)} failed:\n{result.output}"


def test_cli_reference_lists_all_visible_root_commands() -> None:
    cli_reference = (ROOT / "site-docs" / "reference" / "cli.md").read_text(encoding="utf-8")
    visible_commands = sorted(name for name, command in main.commands.items() if not getattr(command, "hidden", False))

    missing = [name for name in visible_commands if f"| `{name}` |" not in cli_reference]

    assert missing == []


def test_public_docs_do_not_overclaim_smithery_catalog_liveness() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    smithery_doc = (ROOT / "site-docs" / "integrations" / "smithery.md").read_text(encoding="utf-8")

    assert "agent-bom is published in the [Smithery]" not in smithery_doc
    assert "Also on [Glama]" not in readme
    assert "Smithery manifest" in readme


def test_permissions_doc_keeps_network_boundary_scoped() -> None:
    permissions = (ROOT / "docs" / "PERMISSIONS.md").read_text(encoding="utf-8")

    assert "External API Calls (exhaustive list)" not in permissions
    assert "exhaustive list of all outbound URLs" not in permissions
    assert "Zero network calls unless scanning for vulnerabilities" not in permissions
    assert "No hidden telemetry, analytics, or tracking." in permissions
    assert "Explicit Push, Export, and Integration Destinations" in permissions


def test_mcp_server_instructions_do_not_overclaim_read_only_surface() -> None:
    factory = (ROOT / "src" / "agent_bom" / "mcp_server_factory.py").read_text(encoding="utf-8")

    assert "Read-only, agentless, no credentials required." not in factory
    assert "Scanner and posture tools are read-only" in factory
    assert "Shield write actions require admin role and an audit reason" in factory
