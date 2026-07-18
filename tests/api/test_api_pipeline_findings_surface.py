"""API scan pipeline wires graph-derived findings into the report.

The hosted scan (``_run_scan_sync``) previously dropped NHI-governance,
toxic-combination, and MCP tool-rule findings that the CLI surfaced. These tests
assert the pipeline's output phase now builds the unified graph and attaches the
graph-derived findings so ``job.result["findings"]`` (the /v1/findings source)
carries them.
"""

from __future__ import annotations

import json

from agent_bom.api import pipeline as pipeline_mod
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync


def _scan_job(inventory_path: str) -> ScanJob:
    return ScanJob(
        job_id="findings-surface-scan",
        created_at="2026-07-18T00:00:00Z",
        request=ScanRequest(inventory=inventory_path, enrich=False, offline=True),
    )


def _empty_inventory(tmp_path) -> str:
    p = tmp_path / "inv.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "source": "test",
                "agents": [
                    {
                        "name": "inv-agent",
                        "agent_type": "custom",
                        "mcp_servers": [{"name": "inv-server"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return str(p)


def _patch_scan(monkeypatch):
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *a, **k: [])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, **k: [])
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)


def test_pipeline_output_phase_invokes_graph_derived_findings(tmp_path, monkeypatch):
    """The output phase calls the shared attach helper with (report, graph) so
    every hosted scan gets the same finding categories the CLI emits."""
    _patch_scan(monkeypatch)
    calls: list[tuple] = []
    real = pipeline_mod.attach_graph_derived_findings

    def _spy(report, graph):
        calls.append((report, graph))
        return real(report, graph)

    monkeypatch.setattr(pipeline_mod, "attach_graph_derived_findings", _spy)

    job = _scan_job(_empty_inventory(tmp_path))
    _run_scan_sync(job)

    assert job.status == JobStatus.DONE, job.result
    assert calls, "pipeline output phase must invoke attach_graph_derived_findings"
    report_arg, graph_arg = calls[0]
    assert hasattr(graph_arg, "nodes")
    assert report_arg is not None


def test_pipeline_surfaces_mcp_tool_rule_finding_end_to_end(tmp_path, monkeypatch):
    """A discovered MCP tool with a stored schema-rule finding surfaces as a
    unified finding in job.result after the hosted scan completes."""
    _patch_scan(monkeypatch)
    real = pipeline_mod.attach_graph_derived_findings

    def _wrapped(report, graph):
        from agent_bom.models import Agent, AgentType, MCPServer, MCPTool

        tool = MCPTool(name="run_cmd", description="runs a command")
        tool.schema_rule_findings = [
            {
                "rule_id": "MCP-TOOL-01-shell-input",
                "severity": "high",
                "title": "Shell command input",
                "message": "freeform shell command",
                "evidence": "property 'command' is freeform string",
                "tool_name": "run_cmd",
                "property_name": "command",
                "owasp_tags": ["LLM01"],
                "owasp_mcp_tags": ["MCP-A01"],
                "cwe_ids": ["CWE-78"],
            }
        ]
        server = MCPServer(name="exec-server")
        server.tools = [tool]
        agent = Agent(name="agent-x", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/x")
        agent.mcp_servers = [server]
        report.agents = list(report.agents) + [agent]
        return real(report, graph)

    monkeypatch.setattr(pipeline_mod, "attach_graph_derived_findings", _wrapped)

    job = _scan_job(_empty_inventory(tmp_path))
    _run_scan_sync(job)

    assert job.status == JobStatus.DONE, job.result
    findings = job.result.get("findings", [])
    mcp = [f for f in findings if isinstance(f.get("evidence"), dict) and f["evidence"].get("mcp_tool_rule")]
    assert mcp, "hosted scan must surface MCP tool-rule findings in job.result['findings']"
