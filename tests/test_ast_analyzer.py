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
        "eval(userInput);\n"
    )

    result = analyze_project(tmp_path)

    assert result.files_analyzed == 1
    assert any(prompt.file_path == "server.ts" for prompt in result.prompts)
    assert any("credential_in_prompt" in prompt.risk_flags for prompt in result.prompts)
    assert any(tool.name == "read_file" and tool.file_path == "server.ts" for tool in result.tools)
    assert any(guard.file_path == "server.ts" for guard in result.guardrails)
    assert any(finding.category == "js_ts_dangerous_call" for finding in result.flow_findings)


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
    assert not [finding for finding in result.flow_findings if finding.category == "tainted_dangerous_sink"]


def test_analyze_project_reports_tainted_prompt_and_sink_flows(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "@tool\n"
        "def execute(user_text):\n"
        "    prompt = f'Execute: {user_text}'\n"
        "    client.chat.completions.create(messages=[{'role': 'user', 'content': prompt}])\n"
        "    return subprocess.run(user_text, shell=True)\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_llm_prompt" and finding.entrypoint == "execute" for finding in result.flow_findings)
    assert any(finding.category == "tainted_dangerous_sink" and finding.entrypoint == "execute" for finding in result.flow_findings)


def test_analyze_project_tracks_helper_return_taint_and_cfg_edges(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def build_command(cmd):\n"
        "    if cmd:\n"
        "        return f'echo {cmd}'\n"
        "    return 'echo safe'\n\n"
        "@tool\n"
        "def execute(cmd, enabled=True):\n"
        "    if enabled:\n"
        "        command = build_command(cmd)\n"
        "        return subprocess.run(command, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_dangerous_sink" and finding.source in {"cmd", "command"} for finding in result.flow_findings)
    cfg_types = {edge.edge_type for edge in result.cfg_edges if edge.function_name == "execute"}
    assert "branch_true" in cfg_types
    assert "branch_false" in cfg_types
    assert result.to_dict()["stats"]["total_cfg_edges"] >= 1


def test_analyze_project_scans_go_source_for_tools_prompts_and_exec(tmp_path: Path):
    (tmp_path / "server.go").write_text(
        "package main\n\n"
        'import "os/exec"\n\n'
        "func main() {\n"
        '    systemPrompt := "You are a helpful operator"\n'
        '    server.AddTool("run_cmd")\n'
        '    exec.Command("sh", "-c", "ls")\n'
        "}\n"
    )

    result = analyze_project(tmp_path)

    assert any(prompt.file_path == "server.go" for prompt in result.prompts)
    assert any(tool.name == "run_cmd" and tool.file_path == "server.go" for tool in result.tools)
    assert any(finding.category == "go_dangerous_call" and finding.sink == "exec.Command" for finding in result.flow_findings)


def test_code_command_json_includes_ai_component_inventory(tmp_path: Path):
    (tmp_path / "index.js").write_text('import OpenAI from "openai";\n')
    runner = CliRunner()

    result = runner.invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "ai_components" in payload
    assert payload["ai_components"]["stats"]["by_language"]["javascript"] >= 1
