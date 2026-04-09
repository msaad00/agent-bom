import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from agent_bom.js_ts_ast import analyze_js_ts_block


def test_analyze_js_ts_block_resolves_named_import_alias():
    analysis = analyze_js_ts_block(
        'import { execSync as run } from "node:child_process"; run("id");',
        language_hint="typescript",
    )

    assert "child_process.execSync" in analysis.call_names
    assert analysis.function_aliases["run"] == "child_process.execSync"
    assert analysis.imported_function_refs["run"].module_name == "child_process"
    assert analysis.imported_function_refs["run"].exported_name == "execSync"


def test_analyze_js_ts_block_resolves_namespace_alias():
    analysis = analyze_js_ts_block(
        'import * as fsp from "node:fs/promises"; await fsp.writeFile("a", "b");',
        language_hint="typescript",
    )

    assert "fs.promises.writeFile" in analysis.call_names
    assert analysis.namespace_aliases["fsp"] == "fs.promises"
    assert analysis.imported_module_refs["fsp"].module_name == "fs/promises"


def test_analyze_js_ts_block_resolves_destructured_require_alias():
    analysis = analyze_js_ts_block(
        'const { spawnSync: runNow } = require("child_process"); runNow("sh", ["-lc", "id"]);',
        language_hint="javascript",
    )

    assert "child_process.spawnSync" in analysis.call_names
    assert analysis.function_aliases["runNow"] == "child_process.spawnSync"


def test_analyze_js_ts_block_propagates_dangerous_alias_assignments():
    analysis = analyze_js_ts_block(
        'import { execSync } from "node:child_process"; const run = execSync; run("id");',
        language_hint="javascript",
    )

    assert "child_process.execSync" in analysis.call_names
    assert analysis.function_aliases["run"] == "child_process.execSync"


def test_analyze_js_ts_block_collects_dynamic_code_constructors():
    analysis = analyze_js_ts_block(
        'const source = process.env.RULE_SOURCE; new Function(source ?? "");',
        language_hint="javascript",
    )

    assert "Function" in analysis.call_names


def test_analyze_js_ts_block_collects_tool_handlers_and_imports():
    analysis = analyze_js_ts_block(
        """
        import { Server } from "@modelcontextprotocol/sdk/server/index.js";
        import { execSync as run } from "node:child_process";

        function executeCommand(input) {
          return run(input);
        }

        server.tool("run_cmd", "Run a command", async () => executeCommand(userInput));
        """,
        language_hint="typescript",
    )

    assert "@modelcontextprotocol/sdk/server/index.js" in analysis.imported_modules
    assert "executeCommand" in analysis.functions
    assert analysis.functions["executeCommand"].dangerous_call_sites[0].name == "child_process.execSync"
    assert analysis.functions["executeCommand"].dangerous_call_sites[0].argument_names == [["input"]]
    assert analysis.tool_registrations[0].tool_name == "run_cmd"
    assert analysis.tool_registrations[0].handler_name == "tool:run_cmd"


def test_analyze_js_ts_block_flags_dynamic_require():
    analysis = analyze_js_ts_block(
        "const moduleName = process.env.PLUGIN_NAME; const plugin = require(moduleName);",
        language_hint="javascript",
    )

    assert analysis.dynamic_require_lines == [1]
