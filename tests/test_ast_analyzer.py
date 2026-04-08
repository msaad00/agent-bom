"""Tests for AST/code analysis enhancements."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.ast_analyzer import analyze_project
from agent_bom.cli import main


def test_analyze_project_scans_js_ts_prompts_tools_and_guardrails(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'const systemPrompt = "You are a helpful assistant with api_key=sk-test-1234567890";\n'
        'server.tool("read_file", "Read a file", async () => "ok");\n'
        "moderation(input);\n"
    )

    result = analyze_project(tmp_path)

    assert result.files_analyzed == 1
    assert any(prompt.file_path == "server.ts" for prompt in result.prompts)
    assert any("credential_in_prompt" in prompt.risk_flags for prompt in result.prompts)
    assert any(tool.name == "read_file" and tool.file_path == "server.ts" for tool in result.tools)
    assert any(guard.file_path == "server.ts" for guard in result.guardrails)


def test_analyze_project_builds_interprocedural_dangerous_flow(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def run_shell(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    return run_shell(cmd)\n"
    )

    result = analyze_project(tmp_path)

    assert any(edge.caller == "execute" and edge.callee == "run_shell" for edge in result.call_edges)
    assert any(
        finding.category == "interprocedural_dangerous_flow" and finding.entrypoint == "execute" and finding.sink == "subprocess.run"
        for finding in result.flow_findings
    )


def test_analyze_project_treats_validation_branch_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def validate_request(cmd):\n"
        "    return bool(cmd)\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if validate_request(cmd):\n"
        "        return subprocess.run(cmd, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

    assert not [finding for finding in result.flow_findings if finding.category == "unguarded_tool_sink"]


def test_code_command_json_includes_ai_component_inventory(tmp_path: Path):
    (tmp_path / "index.js").write_text('import OpenAI from "openai";\n')
    runner = CliRunner()

    result = runner.invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "ai_components" in payload
    assert payload["ai_components"]["stats"]["by_language"]["javascript"] >= 1
