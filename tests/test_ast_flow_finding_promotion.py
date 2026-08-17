"""AST flow risks must reach findings, gates, SARIF, and the graph."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif


def _dangerous_tool_report() -> AIBOMReport:
    return AIBOMReport(
        ai_inventory_data={
            "ast_analysis": {
                "tools": [
                    {
                        "name": "run",
                        "description": "Execute an operator-supplied command",
                        "file": "fs_server.py",
                        "line": 8,
                        "parameters": [{"name": "cmd", "type": "str"}],
                    }
                ],
                "flow_findings": [
                    {
                        "category": "tainted_command_execution",
                        "title": "Tool input reaches shell execution",
                        "detail": "Operator-controlled cmd reaches subprocess.run(shell=True).",
                        "file": "fs_server.py",
                        "line": 9,
                        "entrypoint": "run",
                        "sink": "subprocess.run",
                        "call_path": ["run", "subprocess.run"],
                        "source": "cmd",
                    }
                ],
            }
        },
        scan_sources=["ast_analysis"],
    )


def test_ast_flow_risk_is_a_unified_finding_and_sarif_result() -> None:
    report = _dangerous_tool_report()

    findings = report.to_findings()
    assert len(findings) == 1
    assert findings[0].finding_type.value == "SAST"
    assert findings[0].severity == "critical"
    assert findings[0].asset.location == "fs_server.py"
    assert findings[0].evidence["entrypoint"] == "run"

    payload = to_json(report)
    assert len(payload["findings"]) == 1
    sarif_results = to_sarif(report)["runs"][0]["results"]
    assert len(sarif_results) == 1
    assert sarif_results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 9


def test_ast_tool_signature_is_materialized_in_the_unified_graph() -> None:
    payload = to_json(_dangerous_tool_report())
    graph = build_unified_graph_from_report(payload, scan_id="ast-flow")

    tools = [node for node in graph.nodes.values() if node.entity_type == EntityType.TOOL]
    assert [tool.label for tool in tools] == ["run"]
    assert tools[0].attributes["source_file"] == "fs_server.py"
    assert any(edge.relationship == RelationshipType.DEFINES and edge.target == tools[0].id for edge in graph.edges)


def test_inventory_only_llm_calls_are_not_promoted_to_security_findings() -> None:
    report = AIBOMReport(
        ai_inventory_data={
            "ast_analysis": {
                "flow_findings": [
                    {
                        "category": "go_llm_call",
                        "title": "Go source invokes an LLM client",
                        "detail": "client call",
                        "file": "main.go",
                        "line": 12,
                        "entrypoint": "module",
                        "sink": "openai.ChatCompletion",
                    }
                ]
            }
        }
    )

    assert report.to_findings() == []


def test_overlapping_detectors_share_one_sink_finding() -> None:
    report = _dangerous_tool_report()
    flow_rows = report.ai_inventory_data["ast_analysis"]["flow_findings"]
    flow_rows.append(
        {
            **flow_rows[0],
            "category": "unguarded_tool_sink",
            "title": "Tool entrypoint reaches dangerous sink without validation",
        }
    )

    findings = report.to_findings()
    assert len(findings) == 1
    assert findings[0].severity == "critical"
