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


def test_release_prep_does_not_call_unpublished_version_current() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docker_hub = (ROOT / "DOCKER_HUB_README.md").read_text(encoding="utf-8")

    assert "0.98.1` | Current stable" not in docker_hub
    assert "confirm release availability before copying an" in readme
    assert "verify registry availability before pinning" in docker_hub


def test_readme_distinguishes_graph_relationship_provenance() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Graph views use observed nodes and relationships" not in readme
    assert "collected, inferred, static, and runtime" in readme
    assert "observed graph evidence" not in readme


def test_release_verification_blocks_on_stale_registry_surfaces() -> None:
    verification = (ROOT / "docs" / "RELEASE_VERIFICATION.md").read_text(encoding="utf-8")

    assert "Registry surface freshness" in verification
    assert "Glama" in verification
    assert "do not mark the release complete" in verification.lower()
    assert "Browser behavioral lock-in" in verification
    assert "this matrix does not claim one browser test per control" in verification


def test_readme_storefront_is_concise_ordered_and_actionable() -> None:
    """README storefront keeps one clear story and a two-command first run."""
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    markers = [
        "## What it is",
        "<summary><b>Control-plane architecture</b></summary>",
        "## Who it is for",
        "## Quick start",
        "## Self-host",
        "## Trust",
    ]
    positions = [readme.index(marker) for marker in markers]
    assert positions == sorted(positions)

    hero = readme[: positions[0]]
    badges = [
        "label=Build",
        "pypi/v/agent-bom",
        "badge/Python-3.11%E2%80%933.14-blue",
        "docker/pulls/agentbom/agent-bom",
        "License-Apache%202.0",
        "ossf-scorecard/github.com/msaad00/agent-bom",
        "MCP-Glama",
        "MCP-Smithery",
    ]
    assert hero.count("img.shields.io/") == len(badges)
    for badge in badges:
        assert hero.count(badge) == 1
    assert "pypi/pyversions/agent-bom" not in hero

    assert (
        hero.count(
            '<p align="center"><b>Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.</b></p>'
        )
        == 1
    )
    assert (
        "Scan repositories, images, and cloud accounts; centralize evidence across environments; "
        "and enforce AI and MCP runtime policy in infrastructure you control."
    ) in hero
    assert "<b>15</b> package ecosystems" in hero
    assert "<b>16</b> compliance surfaces" in hero
    assert "<b>77</b> MCP tools" in hero
    assert '<a href="#quick-start"><b>Quick start</b></a>' in hero
    assert '<a href="https://msaad00.github.io/agent-bom/">Docs</a>' in hero
    assert '<a href="https://demo.agent-bom.com">Live demo</a>' in hero
    assert "## How it works" not in readme

    current_what_it_is = """`agent-bom` is an open scanner and self-hosted control plane for software,
cloud, identity, AI-agent, and MCP evidence. One Finding + UnifiedGraph model
powers CLI and CI artifacts, fleet and browser investigations, compliance
evidence, and runtime policy.

Use the scanner without an account, or deploy the shared control plane inside
your own cloud, VPC, Kubernetes cluster, database, identity, and audit boundary.

Graph provenance remains explicit: collected, inferred, static, and runtime
relationships stay distinct, and unavailable evidence is never upgraded to
observed."""
    assert current_what_it_is in readme

    quick_start = readme.split("## Quick start", 1)[1].split("\n## ", 1)[0]
    primary_block = re.search(r"```bash\n(.*?)\n```", quick_start, re.S)
    assert primary_block is not None
    commands = [line for line in primary_block.group(1).splitlines() if line.strip()]
    assert commands == ["pip install agent-bom", "agent-bom scan ."]

    assert "<summary><b>Try without a repository</b></summary>" in readme
    assert "<summary><b>Product gallery</b></summary>" in readme
    assert "persona-value-dark.svg" in readme
    assert "persona-value-light.svg" in readme

    # Persona surfaces keep AppSec and GRC as separate lanes (never one card).
    assert "AppSec/GRC" not in readme
    assert "AppSec / GRC" not in readme
    assert "| AppSec |" in readme
    assert "| GRC / audit |" in readme

    # Persona proof stays directly visible. Architecture and product
    # screenshots remain collapsible, with the gallery open by default.
    assert readme.count("architecture-dark.svg") == 1
    assert "<summary><b>Audience workflow map</b></summary>" not in readme
    assert "<summary><b>Control-plane architecture</b></summary>" in readme
    assert "<details open>\n<summary><b>Product gallery</b></summary>" in readme
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
