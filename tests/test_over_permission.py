"""Tests for over-permission analyzer."""

from agent_bom.enforcement import check_over_permission
from agent_bom.models import MCPServer, MCPTool


def _server(tools: list[MCPTool]) -> MCPServer:
    return MCPServer(name="srv", tools=tools)


def test_chat_agent_with_execute_is_over_permissioned():
    srv = _server([MCPTool(name="run_code", description="execute shell command")])
    findings = check_over_permission(srv, agent_type="claude-desktop")
    assert len(findings) == 1
    assert findings[0].category == "over_permission"
    assert "excess capabilities" in findings[0].reason


def test_code_agent_with_execute_is_ok():
    srv = _server(
        [
            MCPTool(name="read_file", description="read a file"),
            MCPTool(name="write_file", description="write to a file"),
            MCPTool(name="run_code", description="execute code"),
        ]
    )
    findings = check_over_permission(srv, agent_type="claude-code")
    assert len(findings) == 0


def test_chat_agent_with_read_only_is_ok():
    srv = _server([MCPTool(name="read_file", description="read a file from disk")])
    findings = check_over_permission(srv, agent_type="claude-desktop")
    assert len(findings) == 0


def test_unknown_agent_type_skips():
    srv = _server([MCPTool(name="run_code", description="execute")])
    findings = check_over_permission(srv, agent_type="unknown-agent")
    assert len(findings) == 0


def test_no_tools_skips():
    srv = _server([])
    findings = check_over_permission(srv, agent_type="claude-desktop")
    assert len(findings) == 0


def test_automation_agent_profile():
    srv = _server(
        [
            MCPTool(name="read_file", description="read a file"),
            MCPTool(name="write_file", description="write a file"),
            MCPTool(name="run_code", description="execute shell command"),
        ]
    )
    findings = check_over_permission(srv, agent_type="goose")
    assert len(findings) >= 1
    assert "excess" in findings[0].reason
