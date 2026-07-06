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


def test_analyze_project_builds_cross_file_js_ts_import_flow(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        'import { execSync as run } from "node:child_process";\nexport function runShell(command) {\n  return run(command);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'import { runShell as runner } from "./helpers";\nserver.tool("run_cmd", "Run a command", async () => runner(userInput));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(edge.caller == "tool:run_cmd" and edge.callee.endswith("runShell") for edge in result.call_edges)
        assert any(
            finding.category == "js_ts_interprocedural_dangerous_flow"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )


def test_analyze_project_builds_cross_file_js_ts_module_alias_flow(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        'import { execSync as run } from "node:child_process";\nexport function runShell(command) {\n  return run(command);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'import * as helpers from "./helpers";\nserver.tool("run_cmd", "Run a command", async () => helpers.runShell(userInput));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(edge.caller == "tool:run_cmd" and edge.callee == "runShell" for edge in result.call_edges)
        assert any(
            finding.category == "js_ts_interprocedural_dangerous_flow"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )


def test_analyze_project_builds_cross_file_js_ts_default_export_flow(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        'import { execSync as run } from "node:child_process";\nexport default function runShell(command) {\n  return run(command);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'import runShell from "./helpers";\nserver.tool("run_cmd", "Run a command", async () => runShell(userInput));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(edge.caller == "tool:run_cmd" and edge.callee == "runShell" for edge in result.call_edges)
        assert any(
            finding.category == "js_ts_interprocedural_dangerous_flow"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )


def test_analyze_project_builds_cross_file_js_ts_require_default_flow(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        'import { execSync as run } from "node:child_process";\nexport default function runShell(command) {\n  return run(command);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'const runShell = require("./helpers");\nserver.tool("run_cmd", "Run a command", async () => runShell(userInput));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(edge.caller == "tool:run_cmd" and edge.callee == "runShell" for edge in result.call_edges)
        assert any(
            finding.category == "js_ts_interprocedural_dangerous_flow"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )


def test_analyze_project_reports_js_ts_tainted_command_execution(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        'import { execSync as run } from "node:child_process";\nexport function runShell(command) {\n  return run(command);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'import { runShell } from "./helpers";\nserver.tool("run_cmd", "Run a command", async (userInput) => runShell(userInput));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(
            finding.category == "js_ts_tainted_command_execution"
            and finding.entrypoint == "run_cmd"
            and finding.sink == "child_process.execSync"
            for finding in result.flow_findings
        )
        assert any(
            finding.category == "js_ts_tainted_dangerous_sink" and finding.entrypoint == "run_cmd" and finding.source == "userInput"
            for finding in result.flow_findings
        )


def test_analyze_project_reports_js_ts_tainted_ssrf_sink(tmp_path: Path):
    (tmp_path / "http.ts").write_text("export function fetchRemote(url) {\n  return fetch(url);\n}\n")
    (tmp_path / "server.ts").write_text(
        'import { fetchRemote } from "./http";\nserver.tool("probe_url", "Probe a URL", async (inputUrl) => fetchRemote(inputUrl));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(
            finding.category == "js_ts_tainted_ssrf_sink" and finding.entrypoint == "probe_url" and finding.sink == "fetch"
            for finding in result.flow_findings
        )


def test_analyze_project_reports_js_ts_tainted_sql_query(tmp_path: Path):
    (tmp_path / "db.ts").write_text("export function queryUser(db, userInput) {\n  return db.query(userInput);\n}\n")
    (tmp_path / "server.ts").write_text(
        'import { queryUser } from "./db";\nserver.tool("lookup", "Lookup a user", async (inputValue) => queryUser(db, inputValue));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(
            finding.category == "js_ts_tainted_sql_query" and finding.entrypoint == "lookup" and finding.sink == "db.query"
            for finding in result.flow_findings
        )


def test_analyze_project_reports_js_ts_tainted_path_access(tmp_path: Path):
    (tmp_path / "fs.ts").write_text(
        'import * as fs from "node:fs";\nexport function readTarget(targetPath) {\n  return fs.readFile(targetPath);\n}\n'
    )
    (tmp_path / "server.ts").write_text(
        'import { readTarget } from "./fs";\nserver.tool("read_any", "Read a file", async (requestedPath) => readTarget(requestedPath));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(
            finding.category == "js_ts_tainted_path_access" and finding.entrypoint == "read_any" and finding.sink == "fs.readFile"
            for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_regex_branch_as_guard(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        'server.tool("run_cmd", "Run a command", async (cmd) => {\n'
        "  if (/^[a-z]+$/.test(cmd)) {\n"
        "    return execSync(cmd);\n"
        "  }\n"
        "  return null;\n"
        "});\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category == "js_ts_tainted_command_execution" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )
        assert not any(
            finding.category == "js_ts_tainted_dangerous_sink" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_allowlist_branch_as_guard(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        "const allowed = new Set(['ls', 'pwd']);\n"
        'server.tool("run_cmd", "Run a command", async (cmd) => {\n'
        "  if (allowed.has(cmd)) {\n"
        "    return execSync(cmd);\n"
        "  }\n"
        "  return null;\n"
        "});\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category == "js_ts_tainted_command_execution" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_helper_validator_as_guard(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        "function isSafe(cmd) {\n"
        "  return /^[a-z]+$/.test(cmd);\n"
        "}\n"
        'server.tool("run_cmd", "Run a command", async (cmd) => {\n'
        "  if (isSafe(cmd)) {\n"
        "    return execSync(cmd);\n"
        "  }\n"
        "  return null;\n"
        "});\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category == "js_ts_tainted_command_execution" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_early_return_validator_gate_as_guard(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        "function isSafe(cmd) {\n"
        "  return /^[a-z]+$/.test(cmd);\n"
        "}\n"
        'server.tool("run_cmd", "Run a command", async (cmd) => {\n'
        "  if (!isSafe(cmd)) {\n"
        "    return null;\n"
        "  }\n"
        "  return execSync(cmd);\n"
        "});\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category == "js_ts_tainted_command_execution" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )
        assert not any(
            finding.category == "js_ts_tainted_dangerous_sink" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_early_throw_validator_gate_as_guard(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        "const allowed = new Set(['ls', 'pwd']);\n"
        'server.tool("run_cmd", "Run a command", async (cmd) => {\n'
        "  if (!allowed.has(cmd)) {\n"
        "    throw new Error('bad command');\n"
        "  }\n"
        "  return execSync(cmd);\n"
        "});\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category == "js_ts_tainted_command_execution" and finding.entrypoint == "run_cmd" for finding in result.flow_findings
        )


def test_analyze_project_treats_js_ts_validated_return_helper_as_sanitizing(tmp_path: Path):
    (tmp_path / "helpers.ts").write_text(
        "const ALLOWED = new Set(['ls', 'pwd']);\n\n"
        "export function checkedCommand(cmd) {\n"
        "  if (!ALLOWED.has(cmd)) {\n"
        "    throw new Error('blocked');\n"
        "  }\n"
        "  return cmd;\n"
        "}\n"
    )
    (tmp_path / "server.ts").write_text(
        'import { execSync } from "node:child_process";\n'
        'import { checkedCommand } from "./helpers";\n\n'
        'server.tool("run_cmd", "Run a command", async (cmd) => execSync(checkedCommand(cmd), { shell: true }));\n'
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert not any(
            finding.category in {"js_ts_tainted_command_execution", "js_ts_tainted_dangerous_sink"} and finding.entrypoint == "run_cmd"
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
    finding = next(
        finding
        for finding in result.flow_findings
        if finding.category == "interprocedural_dangerous_flow" and finding.entrypoint == "execute" and finding.sink == "subprocess.run"
    )
    assert finding.call_path == ["execute", "run_shell", "subprocess.run"]
    assert "bounded helper-call chain" in finding.detail


def test_analyze_project_surfaces_dependency_symbol_reach_from_tool(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import requests\n\n@tool\ndef fetch(url):\n    return requests.get(url)\n")

    result = analyze_project(tmp_path)
    payload = result.to_dict()

    assert payload["stats"]["total_dependency_symbol_reach"] == 1
    assert payload["dependency_symbol_reach"] == [
        {
            "entrypoint": "fetch",
            "package": "requests",
            "module": "requests",
            "symbol": "get",
            "file": "agent.py",
            "line": 5,
            "call_path": ["fetch", "requests.get"],
            "depth": 0,
            "confidence": "import-symbol",
            "ecosystem": "pypi",
        }
    ]


def test_analyze_project_surfaces_dependency_symbol_reach_through_helper(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n\n"
        "def ask_model(prompt):\n"
        "    client = OpenAI()\n"
        "    return client.responses.create(input=prompt, model='gpt-test')\n\n"
        "@tool\n"
        "def answer(prompt):\n"
        "    return ask_model(prompt)\n"
    )

    result = analyze_project(tmp_path)
    reaches = result.to_dict()["dependency_symbol_reach"]

    assert reaches == [
        {
            "entrypoint": "answer",
            "package": "openai",
            "module": "openai",
            "symbol": "OpenAI",
            "file": "agent.py",
            "line": 4,
            "call_path": ["answer", "ask_model", "openai.OpenAI"],
            "depth": 1,
            "confidence": "import-symbol",
            "ecosystem": "pypi",
        }
    ]


def test_analyze_project_surfaces_js_dependency_symbol_reach(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        'import axios from "axios";\nserver.tool("fetch_url", "Fetch a URL", async (url: string) => axios.get(url));\n'
    )

    result = analyze_project(tmp_path)
    if _js_ts_parser_available():
        npm_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "npm"]
        assert len(npm_reaches) == 1
        reach = npm_reaches[0]
        assert reach.entrypoint == "fetch_url"
        assert reach.package == "axios"
        assert reach.symbol == "get"
        assert reach.call_path[0] == "fetch_url"


def test_analyze_project_surfaces_go_dependency_symbol_reach(tmp_path: Path):
    (tmp_path / "server.go").write_text(
        "package main\n\n"
        "import (\n"
        '    "net/http"\n'
        '    "github.com/modelcontextprotocol/go-sdk/mcp"\n'
        ")\n\n"
        "func fetchURL(target string) error {\n"
        "    _, err := http.Get(target)\n"
        "    return err\n"
        "}\n\n"
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("fetch_url", fetchURL)\n'
        "}\n"
    )

    result = analyze_project(tmp_path)
    go_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "go"]
    assert len(go_reaches) == 1
    reach = go_reaches[0]
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "net/http"
    assert reach.symbol == "Get"


def test_analyze_project_surfaces_rust_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "server.rs").write_text(
        "use reqwest;\n\n"
        "#[tool]\n"
        "async fn fetch_url(url: String) -> Result<(), reqwest::Error> {\n"
        "    reqwest::get(&url).await?;\n"
        "    Ok(())\n"
        "}\n"
    )

    result = analyze_project(tmp_path)
    cargo_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "cargo"]
    assert len(cargo_reaches) == 1
    reach = cargo_reaches[0]
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "reqwest"
    assert reach.symbol == "get"


def test_analyze_project_surfaces_java_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies>"
        "<dependency><groupId>com.squareup.okhttp3</groupId><artifactId>okhttp</artifactId></dependency>"
        "</dependencies></project>"
    )
    (tmp_path / "Server.java").write_text(
        "import com.squareup.okhttp3.OkHttpClient;\n"
        "import com.squareup.okhttp3.Request;\n\n"
        "class Server {\n"
        "    void register(McpServer server) {\n"
        '        server.addTool("fetch_url", this::fetchUrl);\n'
        "    }\n\n"
        "    void fetchUrl(String url) throws Exception {\n"
        "        OkHttpClient client = new OkHttpClient();\n"
        "        client.newCall(new Request.Builder().url(url).build()).execute();\n"
        "    }\n"
        "}\n"
    )

    result = analyze_project(tmp_path)
    maven_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "maven"]
    assert maven_reaches
    reach = next(item for item in maven_reaches if item.symbol == "newCall")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "com.squareup.okhttp3:okhttp"


def test_analyze_project_surfaces_gradle_only_java_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text('dependencies {\n    implementation "com.squareup.okhttp3:okhttp:4.12.0"\n}\n')
    (tmp_path / "Server.java").write_text(
        "import com.squareup.okhttp3.OkHttpClient;\n"
        "import com.squareup.okhttp3.Request;\n\n"
        "class Server {\n"
        "    void register(McpServer server) {\n"
        '        server.addTool("fetch_url", this::fetchUrl);\n'
        "    }\n\n"
        "    void fetchUrl(String url) throws Exception {\n"
        "        OkHttpClient client = new OkHttpClient();\n"
        "        client.newCall(new Request.Builder().url(url).build()).execute();\n"
        "    }\n"
        "}\n"
    )

    result = analyze_project(tmp_path)
    maven_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "maven"]
    assert maven_reaches
    reach = next(item for item in maven_reaches if item.symbol == "newCall")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "com.squareup.okhttp3:okhttp"


def test_analyze_project_surfaces_csharp_dependency_symbol_reach(tmp_path: Path) -> None:
    import json

    lock = {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "RestSharp": {
                    "type": "Direct",
                    "requested": "[112.0.0, )",
                    "resolved": "112.1.0",
                }
            }
        },
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock))
    (tmp_path / "Server.cs").write_text(
        "using RestSharp;\n\n"
        "class Server {\n"
        "    void Register(dynamic server) {\n"
        '        server.AddTool("fetch_url", FetchUrl);\n'
        "    }\n\n"
        "    void FetchUrl(string url) {\n"
        "        RestSharp.RestClient client = new RestSharp.RestClient();\n"
        "        client.ExecuteAsync(new RestRequest(url));\n"
        "    }\n"
        "}\n"
    )

    result = analyze_project(tmp_path)
    nuget_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "nuget"]
    assert nuget_reaches
    reach = next(item for item in nuget_reaches if item.symbol == "ExecuteAsync")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "RestSharp"


def test_analyze_project_surfaces_ruby_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text('gem "faraday"\n')
    (tmp_path / "Gemfile.lock").write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n    faraday (2.9.0)\n")
    (tmp_path / "server.rb").write_text(
        "require 'faraday'\n\n"
        "class Server\n"
        "  def register(server)\n"
        '    server.add_tool("fetch_url", method(:fetch_url))\n'
        "  end\n\n"
        "  def fetch_url(url)\n"
        "    client = Faraday.new\n"
        "    client.get(url)\n"
        "  end\n"
        "end\n"
    )

    result = analyze_project(tmp_path)
    ruby_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "rubygems"]
    assert ruby_reaches
    reach = next(item for item in ruby_reaches if item.symbol == "get")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "faraday"


def test_analyze_project_surfaces_php_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{"require": {"guzzlehttp/guzzle": "^7.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "composer.lock").write_text(
        '{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.8.1"}]}',
        encoding="utf-8",
    )
    (tmp_path / "Server.php").write_text(
        "<?php\n"
        "use GuzzleHttp\\Client;\n\n"
        "class Server {\n"
        "    public function register($server) {\n"
        '        $server->tool("fetch_url", [$this, "fetchUrl"]);\n'
        "    }\n\n"
        "    public function fetchUrl($url) {\n"
        "        $client = new Client();\n"
        "        return $client->get($url);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)
    composer_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "composer"]
    assert composer_reaches
    reach = next(item for item in composer_reaches if item.symbol == "get")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "guzzlehttp/guzzle"


def test_analyze_project_surfaces_swift_dependency_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "Package.resolved").write_text(
        '{"pins": [{"identity": "alamofire", "state": {"version": "5.9.0"}}], "version": 2}',
        encoding="utf-8",
    )
    (tmp_path / "Server.swift").write_text(
        'import Alamofire\n\n'
        "func register(server: MCPServer) {\n"
        '    server.tool("fetch_url", fetchUrl)\n'
        "}\n\n"
        "func fetchUrl(_ url: String) {\n"
        "    Alamofire.request(url)\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)
    swift_reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "swift"]
    assert swift_reaches
    reach = next(item for item in swift_reaches if item.symbol == "request")
    assert reach.entrypoint == "fetch_url"
    assert reach.package == "alamofire"


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


def test_analyze_project_treats_helper_regex_validator_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import re\n"
        "import subprocess\n\n"
        "def ok(cmd):\n"
        "    return re.fullmatch(r'[a-z]+', cmd) is not None\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if ok(cmd):\n"
        "        return subprocess.run(cmd, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

    assert not [finding for finding in result.flow_findings if finding.category == "tainted_dangerous_sink"]


def test_analyze_project_treats_helper_allowlist_validator_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def ok(cmd):\n"
        "    if cmd in {'ls', 'pwd'}:\n"
        "        return True\n"
        "    return False\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if ok(cmd):\n"
        "        return subprocess.run(cmd, shell=True)\n"
        "    return None\n"
    )

    result = analyze_project(tmp_path)

    assert not [finding for finding in result.flow_findings if finding.category == "tainted_dangerous_sink"]


def test_analyze_project_treats_early_return_validator_gate_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def ok(cmd):\n"
        "    return cmd in {'ls', 'pwd'}\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if not ok(cmd):\n"
        "        return None\n"
        "    return subprocess.run(cmd, shell=True)\n"
    )

    result = analyze_project(tmp_path)

    assert not [finding for finding in result.flow_findings if finding.category == "tainted_dangerous_sink"]


def test_analyze_project_treats_early_raise_validator_gate_as_guard(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import re\n"
        "import subprocess\n\n"
        "def ok(cmd):\n"
        "    return re.fullmatch(r'[a-z]+', cmd) is not None\n\n"
        "@tool\n"
        "def execute(cmd):\n"
        "    if not ok(cmd):\n"
        "        raise ValueError('bad command')\n"
        "    return subprocess.run(cmd, shell=True)\n"
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


def test_analyze_project_flags_prompt_interpolation_from_user_input(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "@tool\ndef execute(user_text):\n    system_prompt = f'Follow this user content: {user_text}'\n    return system_prompt\n"
    )

    result = analyze_project(tmp_path)

    prompt = next(prompt for prompt in result.prompts if prompt.variable_name == "system_prompt")
    assert "untrusted_input_interpolation" in prompt.risk_flags


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


def test_analyze_project_reports_command_string_construction(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n"
        "def execute(user_cmd):\n"
        '    command = f"bash -lc {user_cmd}"\n'
        "    return subprocess.run(command, shell=True)\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "command_string_construction" and finding.sink == "subprocess.run" for finding in result.flow_findings)


def test_analyze_project_reports_ssrf_url_construction(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        'import requests\n\ndef fetch(host):\n    url = f"http://{host}/admin"\n    return requests.get(url)\n'
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "ssrf_url_construction" and finding.sink == "requests.get" for finding in result.flow_findings)


def test_analyze_project_reports_unsafe_deserialization(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import yaml\n\ndef load_payload(data):\n    return yaml.load(data)\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "unsafe_deserialization" and finding.sink == "yaml.load" for finding in result.flow_findings)


def test_analyze_project_skips_safe_yaml_loader(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import yaml\n\ndef load_payload(data):\n    return yaml.load(data, Loader=yaml.SafeLoader)\n")

    result = analyze_project(tmp_path)

    assert not any(finding.category == "unsafe_deserialization" for finding in result.flow_findings)


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


def test_analyze_project_reports_tainted_command_execution(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "import subprocess\n\n@tool\ndef execute(user_cmd):\n    return subprocess.run(user_cmd, shell=True)\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_command_execution" and finding.entrypoint == "execute" for finding in result.flow_findings)


def test_analyze_project_reports_tainted_ssrf_sink(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import requests\n\n@tool\ndef fetch(target_url):\n    return requests.get(target_url)\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "tainted_ssrf_sink" and finding.entrypoint == "fetch" for finding in result.flow_findings)


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


def test_analyze_project_reports_js_ts_dynamic_require(tmp_path: Path):
    (tmp_path / "plugin.ts").write_text("const moduleName = process.env.PLUGIN_NAME;\nconst plugin = require(moduleName);\n")

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert any(finding.category == "js_ts_dynamic_require" for finding in result.flow_findings)


def test_analyze_project_reports_js_ts_dynamic_sql_query(tmp_path: Path):
    (tmp_path / "db.ts").write_text("function lookup(userId) {\n  return db.query(`SELECT * FROM users WHERE id = ${userId}`);\n}\n")

    result = analyze_project(tmp_path)

    assert any(finding.category == "js_ts_sql_query_construction" for finding in result.flow_findings)


def test_analyze_project_reports_js_ts_path_traversal_sink(tmp_path: Path):
    (tmp_path / "fs.ts").write_text(
        "import path from \"node:path\";\nfunction readUserFile(userInput) {\n  return fs.readFile(path.join('/srv/data', userInput));\n}\n"
    )

    result = analyze_project(tmp_path)

    assert any(finding.category == "js_ts_path_traversal_sink" for finding in result.flow_findings)


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


def test_analyze_project_builds_cross_file_go_call_edges_and_tainted_command_flow(tmp_path: Path):
    (tmp_path / "register.go").write_text(
        "package main\n\n"
        'import "github.com/modelcontextprotocol/go-sdk/mcp"\n\n'
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("run_cmd", executeCommand)\n'
        "}\n"
    )
    (tmp_path / "helpers.go").write_text(
        "package main\n\n"
        'import "os/exec"\n\n'
        "func runShell(cmd string) error {\n"
        '    return exec.Command("sh", "-c", cmd).Run()\n'
        "}\n\n"
        "func executeCommand(cmd string) error {\n"
        "    return runShell(cmd)\n"
        "}\n"
    )

    result = analyze_project(tmp_path)

    assert any(edge.caller == "executeCommand" and edge.callee == "runShell" for edge in result.call_edges)
    assert any(edge.caller == "run_cmd" and edge.callee == "executeCommand" for edge in result.call_edges)
    assert any(
        finding.category == "go_tainted_command_execution" and finding.entrypoint == "run_cmd" and finding.sink == "exec.Command"
        for finding in result.flow_findings
    )


def test_analyze_project_reports_go_tainted_ssrf_sink_across_local_package(tmp_path: Path):
    helpers_dir = tmp_path / "helpers"
    helpers_dir.mkdir()
    (tmp_path / "server.go").write_text(
        "package main\n\n"
        "import (\n"
        '    "example/helpers"\n'
        '    "github.com/modelcontextprotocol/go-sdk/mcp"\n'
        ")\n\n"
        "func fetchURL(target string) error {\n"
        "    return helpers.Fetch(target)\n"
        "}\n\n"
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("fetch_url", fetchURL)\n'
        "}\n"
    )
    (helpers_dir / "http.go").write_text(
        'package helpers\n\nimport "net/http"\n\nfunc Fetch(target string) error {\n    _, err := http.Get(target)\n    return err\n}\n'
    )

    result = analyze_project(tmp_path)

    assert any(edge.caller == "fetchURL" and edge.callee == "Fetch" for edge in result.call_edges)
    assert any(
        finding.category == "go_tainted_ssrf_sink" and finding.entrypoint == "fetch_url" and finding.sink == "http.Get"
        for finding in result.flow_findings
    )


def test_analyze_project_reports_go_tainted_sql_and_path_sinks(tmp_path: Path):
    (tmp_path / "db.go").write_text(
        "package main\n\n"
        'import "github.com/modelcontextprotocol/go-sdk/mcp"\n\n'
        "func queryUsers(query string) error {\n"
        "    return db.Query(query)\n"
        "}\n\n"
        "func readUserFile(path string) ([]byte, error) {\n"
        "    return os.ReadFile(path)\n"
        "}\n\n"
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("query_users", queryUsers)\n'
        '    server.AddTool("read_user_file", readUserFile)\n'
        "}\n"
    )

    result = analyze_project(tmp_path)

    assert any(
        finding.category == "go_tainted_sql_query" and finding.entrypoint == "query_users" and finding.sink == "db.Query"
        for finding in result.flow_findings
    )
    assert any(
        finding.category == "go_tainted_path_access" and finding.entrypoint == "read_user_file" and finding.sink == "os.ReadFile"
        for finding in result.flow_findings
    )


def test_analyze_project_reports_go_tainted_html_sink(tmp_path: Path):
    (tmp_path / "render.go").write_text(
        "package main\n\n"
        "import (\n"
        '    "html/template"\n'
        '    "github.com/modelcontextprotocol/go-sdk/mcp"\n'
        ")\n\n"
        "func renderHTML(userHTML string) template.HTML {\n"
        "    return template.HTML(userHTML)\n"
        "}\n\n"
        "func register(server *mcp.Server) {\n"
        '    server.AddTool("render_html", renderHTML)\n'
        "}\n"
    )

    result = analyze_project(tmp_path)

    assert any(
        finding.category == "go_tainted_xss_sink" and finding.entrypoint == "render_html" and finding.sink == "template.HTML"
        for finding in result.flow_findings
    )


def test_analyze_project_resolves_cross_file_import_alias_flow(tmp_path: Path):
    (tmp_path / "helpers.py").write_text("import subprocess\n\ndef run_shell(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    (tmp_path / "agent.py").write_text("from helpers import run_shell as runner\n\n@tool\ndef execute(cmd):\n    return runner(cmd)\n")

    result = analyze_project(tmp_path)

    assert any(edge.caller == "execute" and edge.callee == "run_shell" for edge in result.call_edges)
    assert any(
        finding.category == "interprocedural_dangerous_flow" and finding.entrypoint == "execute" and finding.sink == "subprocess.run"
        for finding in result.flow_findings
    )


def test_analyze_project_resolves_cross_file_module_alias_when_names_are_ambiguous(tmp_path: Path):
    (tmp_path / "helpers.py").write_text("import subprocess\n\ndef run_shell(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    (tmp_path / "other.py").write_text("def run_shell(cmd):\n    return cmd\n")
    (tmp_path / "agent.py").write_text(
        "import helpers as h\nimport other\n\n@tool\ndef execute(cmd):\n    other.run_shell('safe')\n    return h.run_shell(cmd)\n"
    )

    result = analyze_project(tmp_path)

    assert any(edge.caller == "execute" and edge.callee == "run_shell" for edge in result.call_edges)
    assert any(
        finding.category == "interprocedural_dangerous_flow" and finding.entrypoint == "execute" and finding.sink == "subprocess.run"
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
