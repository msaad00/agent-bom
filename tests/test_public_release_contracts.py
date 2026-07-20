"""Contracts for release-facing commands, counts, skills, and install paths."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from agent_bom.discovery.coverage import supported_clients
from agent_bom.mcp_server_metadata import _SERVER_CARD_PROMPTS, _SERVER_CARD_TOOLS

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_base_install_contains_advertised_mcp_runtime() -> None:
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    dependencies = [str(item).lower() for item in project["dependencies"]]
    assert any(item.startswith("mcp>=") for item in dependencies)


def test_public_mcp_counts_match_server_card() -> None:
    count = len(_SERVER_CARD_TOOLS)
    expected = {
        "glama.json": f"Exposes {count} read-first MCP tools",
        "integrations/smithery.yaml": f"Exposes {count} MCP tools",
        "site-docs/index.md": f"| **MCP tools** | AI agents and coding assistants | {count} tools",
        "site-docs/getting-started/mcp-server.md": f"exposing {count} MCP tools",
        "docs/CLAUDE_INTEGRATION.md": f"exposes {count} MCP tools",
        "docs/PRODUCT_BRIEF.md": f"| Agent interface | {count} MCP tools",
    }
    for relative, phrase in expected.items():
        assert phrase in _read(relative), f"{relative} is missing current MCP count"


def test_public_registry_and_client_counts_match_code() -> None:
    registry = json.loads(_read("src/agent_bom/mcp_registry.json"))
    registry_count = len(registry["servers"])
    client_count = len(supported_clients())
    assert registry_count == registry["_total_servers"]

    for relative in (
        "docs/MCP_SERVER.md",
        "site-docs/reference/mcp-tools.md",
        "integrations/openclaw/SKILL.md",
        "integrations/openclaw/registry/SKILL.md",
        "integrations/openclaw/discover/SKILL.md",
    ):
        assert str(registry_count) in _read(relative), f"{relative} is missing current registry count"
    assert f"{client_count} first-class client types" in _read("integrations/openclaw/SKILL.md")


def test_each_mcp_reference_contains_complete_catalog() -> None:
    tool_names = {str(tool["name"]) for tool in _SERVER_CARD_TOOLS}
    prompt_names = {str(prompt["name"]) for prompt in _SERVER_CARD_PROMPTS}
    for relative in ("docs/MCP_SERVER.md", "site-docs/reference/mcp-tools.md"):
        text = _read(relative)
        missing_tools = sorted(name for name in tool_names if f"`{name}`" not in text)
        missing_prompts = sorted(name for name in prompt_names if f"`{name}`" not in text)
        assert not missing_tools, f"{relative} missing tools: {missing_tools}"
        assert not missing_prompts, f"{relative} missing prompts: {missing_prompts}"


def test_public_docs_do_not_teach_removed_or_misparsed_cli_forms() -> None:
    active_docs = "\n".join(
        _read(relative)
        for relative in (
            "site-docs/index.md",
            "site-docs/features/cloud-posture.md",
            "site-docs/getting-started/quickstart.md",
            "site-docs/reference/cli.md",
            "integrations/openclaw/scan/SKILL.md",
            "integrations/openclaw/enforce/SKILL.md",
            "src/agent_bom/output/graph_export.py",
        )
    )
    for stale in (
        "agent-bom cis-benchmark",
        "agent-bom sbom .",
        "agent-bom scan -f table",
        "--compliance owasp-llm",
        "--compliance eu-ai-act",
        "--compliance all",
        "agent-bom graph --from-scan",
        "agent-bom policy apply policy.yaml",
    ):
        assert stale not in active_docs

    enforce = _read("integrations/openclaw/enforce/SKILL.md")
    assert "agent-bom gateway init-policy -o policy.json --format proxy --mode enforce" in enforce
    assert "agent-bom proxy --url https://mcp.example.com --policy policy.json" in enforce


def test_openclaw_redaction_copy_matches_implementation() -> None:
    text = "\n".join(
        _read(relative)
        for relative in (
            "integrations/openclaw/SKILL.md",
            "integrations/openclaw/scan/SKILL.md",
            "integrations/openclaw/discover/SKILL.md",
        )
    )
    assert "replaces ALL env var values" not in text
    assert "Env var values are NEVER extracted" not in text
    assert "security.py#L159" not in text
    assert "benign configuration values may remain" in text


def test_demo_uses_canonical_visible_scan_command() -> None:
    script = _read("scripts/render_demo.sh")
    assert "agent-bom scan --demo --offline -f console" in script
    assert "agent-bom agents --demo" not in script
