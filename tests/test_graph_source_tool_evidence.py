"""Persistence and export parity for source-discovered application tools."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.output.graph import build_graph_elements
from agent_bom.output.graph_export import build_graph_from_scan_data

_AST_TOOLS = {
    "ast_analysis": {
        "tools": [
            {
                "name": "read_customer",
                "description": "Read a customer record",
                "file": "src/mcp_server.py",
                "line": 42,
                "parameters": ["customer_id"],
                "handler": "read_customer_handler",
                "registration_kind": "framework_tool",
                "framework": "LangChain",
                "provenance": "python:LangChain:AgentExecutor.tools[0]:customer_tool->Tool(func=read_customer_handler)",
            }
        ],
        "application_entrypoints": [
            {
                "name": "ordinary-fetch",
                "handler": "main",
                "kind": "console_script",
                "framework": "Python packaging",
                "language": "python",
                "file": "src/cli.py",
                "line": 12,
                "provenance": "metadata:pyproject.toml:[project.scripts]=ordinary.cli:main",
            }
        ],
    }
}


def _scan_json() -> dict[str, object]:
    return {
        "document_type": "AI-BOM",
        "scan_id": "source-tool-scan",
        "agents": [],
        "ai_inventory": _AST_TOOLS,
    }


def test_source_discovered_tool_survives_sqlite_graph_persistence(tmp_path: Path) -> None:
    graph = build_unified_graph_from_report(_scan_json())
    tool = next(node for node in graph.nodes.values() if node.entity_type == EntityType.TOOL)
    source_file = next(node for node in graph.nodes.values() if node.entity_type == EntityType.SOURCE_FILE)
    assert any(
        edge.source == source_file.id and edge.target == tool.id and edge.relationship == RelationshipType.DEFINES for edge in graph.edges
    )

    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(graph)
    restored = store.load_graph(scan_id="source-tool-scan")

    assert restored.nodes[tool.id].attributes["source_file"] == "src/mcp_server.py"
    assert restored.nodes[tool.id].attributes["handler"] == "read_customer_handler"
    assert restored.nodes[tool.id].attributes["registration_kind"] == "framework_tool"
    assert restored.nodes[tool.id].attributes["framework"] == "LangChain"
    assert restored.nodes[tool.id].attributes["provenance"].startswith("python:LangChain")
    assert any(
        edge.source == source_file.id and edge.target == tool.id and edge.relationship == RelationshipType.DEFINES
        for edge in restored.edges
    )


def test_source_discovered_tool_is_in_standalone_graph_export() -> None:
    graph = build_graph_from_scan_data(_scan_json())

    tool = next(node for node in graph.nodes if node.kind == "tool" and node.label == "read_customer")
    assert tool.attributes["handler"] == "read_customer_handler"
    assert tool.attributes["registration_kind"] == "framework_tool"
    assert tool.attributes["framework"] == "LangChain"
    source_file = next(node for node in graph.nodes if node.kind == "source_file")
    assert any(edge.source == source_file.id and edge.target == tool.id and edge.kind == "defines" for edge in graph.edges)


def test_source_discovered_tool_is_in_cytoscape_export() -> None:
    report = AIBOMReport(
        generated_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
        scan_id="source-tool-scan",
        tool_version="0.101.0",
        ai_inventory_data=_AST_TOOLS,
    )

    elements = build_graph_elements(report, [])
    tool = next(item["data"] for item in elements if item.get("data", {}).get("type") == "tool")
    assert tool["handler"] == "read_customer_handler"
    assert tool["registration_kind"] == "framework_tool"
    assert tool["framework"] == "LangChain"
    assert tool["provenance"].startswith("python:LangChain")
    assert tool["tip"].startswith("Framework tool: read_customer")
    source_file = next(item["data"] for item in elements if item.get("data", {}).get("type") == "source_file")
    assert any(
        item.get("data", {}).get("source") == source_file["id"]
        and item["data"].get("target") == tool["id"]
        and item["data"].get("type") == "defines"
        for item in elements
    )


def test_application_entrypoint_provenance_survives_graph_projections() -> None:
    unified = build_unified_graph_from_report(_scan_json())
    entry = next(node for node in unified.nodes.values() if node.attributes.get("node_kind") == "application_entrypoint")
    assert entry.attributes["handler"] == "main"
    assert entry.attributes["entrypoint_kind"] == "console_script"
    assert entry.attributes["provenance"].startswith("metadata:pyproject.toml")

    standalone = build_graph_from_scan_data(_scan_json())
    exported = next(node for node in standalone.nodes if node.attributes.get("node_kind") == "application_entrypoint")
    assert exported.attributes["provenance"] == entry.attributes["provenance"]

    report = AIBOMReport(
        generated_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
        scan_id="source-entrypoint-scan",
        tool_version="0.102.0",
        ai_inventory_data=_AST_TOOLS,
    )
    elements = build_graph_elements(report, [])
    cytoscape = next(item["data"] for item in elements if item.get("data", {}).get("type") == "application_entrypoint")
    assert cytoscape["handler"] == "main"
    assert cytoscape["provenance"] == entry.attributes["provenance"]
