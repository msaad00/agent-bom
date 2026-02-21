"""Tests for the deep risk analyzer — capability classification and server risk scoring."""

from agent_bom.models import MCPTool
from agent_bom.risk_analyzer import (
    ToolCapability,
    classify_tool,
    score_server_risk,
)

# ── classify_tool tests ────────────────────────────────────────────────────


def test_classify_read_tool():
    """'read_file' should be classified as READ."""
    caps = classify_tool("read_file")
    assert ToolCapability.READ in caps


def test_classify_write_tool():
    """'write_file' should be classified as WRITE."""
    caps = classify_tool("write_file")
    assert ToolCapability.WRITE in caps


def test_classify_execute_tool():
    """'run_command' should be classified as EXECUTE."""
    caps = classify_tool("run_command")
    assert ToolCapability.EXECUTE in caps


def test_classify_multi_capability():
    """'execute_and_write' should match both EXECUTE and WRITE."""
    caps = classify_tool("execute_and_write")
    assert ToolCapability.EXECUTE in caps
    assert ToolCapability.WRITE in caps


def test_classify_from_description():
    """A tool named 'foo' with description 'run shell command' should be EXECUTE."""
    caps = classify_tool("foo", description="run shell command")
    assert ToolCapability.EXECUTE in caps


def test_classify_empty():
    """A tool with no matching keywords returns an empty list."""
    caps = classify_tool("unknown_thing")
    assert caps == []


# ── score_server_risk tests ────────────────────────────────────────────────


def test_score_read_only_server():
    """A server with only read tools should have risk_level 'low'."""
    tools = [
        MCPTool(name="list_files", description="List directory contents"),
        MCPTool(name="get_status", description="Get system status"),
    ]
    profile = score_server_risk(tools)
    assert profile.risk_level == "low"


def test_score_full_access_server():
    """A server with read+write+execute tools and credentials should be 'high' or 'critical'."""
    tools = [
        MCPTool(name="read_file", description="Read a file"),
        MCPTool(name="write_file", description="Write a file"),
        MCPTool(name="run_command", description="Execute a shell command"),
        MCPTool(name="delete_file", description="Delete a file from disk"),
        MCPTool(name="fetch_url", description="Download data from a URL"),
    ]
    credentials = ["API_KEY", "DB_PASSWORD", "AWS_SECRET"]
    profile = score_server_risk(tools, credentials=credentials)
    assert profile.risk_level in ("high", "critical")


def test_dangerous_combo_detected():
    """A server with EXECUTE + WRITE tools should flag dangerous combinations."""
    tools = [
        MCPTool(name="write_file", description="Write data to a file"),
        MCPTool(name="run_command", description="Execute a command"),
    ]
    profile = score_server_risk(tools)
    assert len(profile.dangerous_combinations) > 0


def test_justification_generated():
    """Any server with tools should produce a non-empty justification string."""
    tools = [
        MCPTool(name="read_file", description="Read contents of a file"),
    ]
    profile = score_server_risk(tools)
    assert isinstance(profile.justification, str)
    assert len(profile.justification) > 0
