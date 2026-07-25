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


def test_connect_sources_do_not_teach_removed_cli_surfaces() -> None:
    # The `connect <provider>` guidance prints a scan command; it must point at a
    # real surface, not a removed/misleading one (e.g. `agent-bom cloud snowflake`,
    # which the cloud group does not register — Snowflake uses `scan --snowflake`).
    from agent_bom.cli._entry_points import _CONNECT_SOURCES

    removed_or_misleading = [
        "agent-bom generate-sbom",
        "agent-bom cloud snowflake",
        "agent-bom cis-benchmark",
    ]
    for source in _CONNECT_SOURCES.values():
        for bad in removed_or_misleading:
            assert bad not in source.scan_command, f"{source.name} teaches removed surface: {source.scan_command}"


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
        ["findings", "push", "--help"],
        ["fleet", "sync", "--help"],
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


def test_readme_storefront_is_concise_ordered_and_actionable() -> None:
    """README storefront keeps one clear story and a two-command first run."""
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    sections = [
        "What it is",
        "Quick start",
        "How it works",
        "Who it is for",
        "Self-host",
        "Trust",
    ]
    positions = [readme.index(f"## {section}") for section in sections]
    assert positions == sorted(positions)

    hero = readme[: positions[0]]
    assert hero.count("img.shields.io/") <= 2
    assert '<a href="#quick-start"><b>Quick start</b></a>' in hero
    assert '<a href="https://msaad00.github.io/agent-bom/">Docs</a>' in hero
    assert '<a href="https://demo.agent-bom.com">Live demo</a>' in hero

    quick_start = readme.split("## Quick start", 1)[1].split("\n## ", 1)[0]
    primary_block = re.search(r"```bash\n(.*?)\n```", quick_start, re.S)
    assert primary_block is not None
    commands = [line for line in primary_block.group(1).splitlines() if line.strip()]
    assert commands == ["pip install agent-bom", "agent-bom scan ."]

    assert "<summary><b>Try without a repository</b></summary>" in readme
    assert "<summary><b>Product gallery</b></summary>" in readme
    assert "persona-value-dark.svg" not in readme
    assert "persona-value-light.svg" not in readme

    # Persona surfaces keep AppSec and GRC as separate lanes (never one card).
    assert "AppSec/GRC" not in readme
    assert "AppSec / GRC" not in readme
    assert "| AppSec |" in readme
    assert "| GRC / audit |" in readme

    # One architecture visual; product screenshots stay progressive-disclosure.
    assert readme.count("how-it-works-dark.svg") == 1
    assert "blast-radius-dark.svg" not in readme


def test_readme_grc_persona_row_teaches_the_real_compliance_command() -> None:
    """The GRC row must give the same runnable entry point as the other four."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "agent-bom report compliance-narrative" in readme
    # No noun-phrase placeholder where a command belongs.
    assert "| Compliance exports + control-plane evidence |" not in readme

    result = CliRunner().invoke(main, ["report", "compliance-narrative", "--help"])
    assert result.exit_code == 0, result.output
    # The documented invocation passes a saved scan report positionally.
    assert "SCAN_FILE" in result.output


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
    assert "write actions require an authenticated operator token" in factory
    assert "operator_role is audit metadata" in factory
