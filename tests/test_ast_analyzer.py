"""Tests for AST/code analysis enhancements."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.ast_analyzer import analyze_project
from agent_bom.cli import main


def _js_ts_parser_available() -> bool:
    return (
        importlib.util.find_spec("tree_sitter") is not None
        and importlib.util.find_spec("tree_sitter_javascript") is not None
        and importlib.util.find_spec("tree_sitter_typescript") is not None
    )


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


def test_analyze_project_builds_js_ts_call_edges_and_tool_flow(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync as run } from "node:child_process";\n'
        'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n\n'
        "function runShell(command) {\n"
        "  return run(command);\n"
        "}\n\n"
        "function executeCommand(command) {\n"
        "  return runShell(command);\n"
        "}\n\n"
        'server.tool("run_cmd", "Run a command", async () => executeCommand(userInput));\n'
    )

    result = analyze_project(tmp_path)

    assert "MCP" in result.frameworks_detected
    if _js_ts_parser_available():
        assert any(edge.caller == "executeCommand" and edge.callee == "runShell" for edge in result.call_edges)
        assert any(edge.caller == "run_cmd" and edge.callee == "tool:run_cmd" for edge in result.call_edges)
        assert any(
            finding.category == "js_ts_interprocedural_dangerous_flow"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )


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


def test_analyze_project_treats_allowlist_branch_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if cmd in {'ls', 'pwd'}:\n"
        "        return subprocess.run(cmd, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

    assert not [finding for finding in result.flow_findings if finding.category == "tainted_dangerous_sink"]


def test_analyze_project_treats_regex_branch_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import re\n"
        "import subprocess\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if re.fullmatch(r'[a-z]+', cmd):\n"
        "        return subprocess.run(cmd, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

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


def test_analyze_project_reports_tainted_path_access(tmp_path: Path):
    (tmp_path / "agent.py").write_text("@tool\ndef read_any(path):\n    return open(path, 'r').read()\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_path_access" and finding.entrypoint == "read_any" for finding in result.flow_findings)


def test_analyze_project_reports_tainted_xss_sink(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from markupsafe import Markup\n\n@tool\ndef render_html(user_html):\n    return Markup(user_html)\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_xss_sink" and finding.entrypoint == "render_html" for finding in result.flow_findings)


def test_analyze_project_reports_sql_string_construction(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        'def lookup(cursor, user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return cursor.execute(query)\n'
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "sql_string_construction" and finding.sink == "cursor.execute" for finding in result.flow_findings)


def test_analyze_project_reports_unsafe_deserialization(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import yaml\n\ndef load_payload(data):\n    return yaml.load(data)\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "unsafe_deserialization" and finding.sink == "yaml.load" for finding in result.flow_findings)


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


def test_analyze_project_reports_js_ts_dom_xss_pattern(tmp_path: Path):
    (tmp_path / "ui.tsx").write_text("function render(userHtml) {\n  element.innerHTML = userHtml;\n}\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "js_ts_xss_sink" and finding.sink == "innerHTML" for finding in result.flow_findings)


def test_analyze_project_builds_go_call_edges_and_tool_flow(tmp_path: Path):
    (tmp_path / "server.go").write_text(
        "package main\n\n"
        "import (\n"
        '    "os/exec"\n'
        '    "github.com/modelcontextprotocol/go-sdk/mcp"\n'
        ")\n\n"
        "func runShell(cmd string) error {\n"
        '    return exec.Command("sh", "-c", cmd).Run()\n'
        "}\n\n"
        "func executeCommand(cmd string) error {\n"
        "    return runShell(cmd)\n"
        "}\n\n"
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("run_cmd", executeCommand)\n'
        "}\n"
    )

    result = analyze_project(tmp_path)

    assert "MCP" in result.frameworks_detected
    assert any(edge.caller == "executeCommand" and edge.callee == "runShell" for edge in result.call_edges)
    assert any(edge.caller == "run_cmd" and edge.callee == "executeCommand" for edge in result.call_edges)
    assert any(
        finding.category == "go_interprocedural_dangerous_flow" and finding.entrypoint == "run_cmd" and finding.sink == "exec.Command"
        for finding in result.flow_findings
    )


def test_code_command_json_includes_ai_component_inventory(tmp_path: Path):
    (tmp_path / "index.js").write_text('import OpenAI from "openai";\n')
    runner = CliRunner()

    result = runner.invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "ai_components" in payload
    assert payload["ai_components"]["stats"]["by_language"]["javascript"] >= 1
