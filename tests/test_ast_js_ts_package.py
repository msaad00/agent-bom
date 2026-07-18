"""The agent_bom.ast.js_ts package is the single public JS/TS AST entry point.

Contributors kept picking between two confusingly named top-level modules
(the scanning facade and the tree-sitter engine). These tests pin the
consolidated contract: one package exposes both surfaces, and the legacy
module paths remain importable shims that delegate to the package.
"""

from __future__ import annotations

import warnings


def test_package_exposes_facade_entry_points():
    from agent_bom.ast import js_ts
    from agent_bom.ast.js_ts.facade import (
        _JS_TS_EXTS,
        _js_ts_function_key,
        _npm_package_from_module,
        build_js_ts_dependency_symbol_reach,
        build_js_ts_flow_findings,
        scan_js_ts_file,
    )

    assert js_ts.scan_js_ts_file is scan_js_ts_file
    assert js_ts.build_js_ts_flow_findings is build_js_ts_flow_findings
    assert js_ts.build_js_ts_dependency_symbol_reach is build_js_ts_dependency_symbol_reach
    assert js_ts.JS_TS_EXTS is _JS_TS_EXTS
    assert js_ts.js_ts_function_key is _js_ts_function_key
    assert js_ts.npm_package_from_module is _npm_package_from_module


def test_package_exposes_engine_entry_points():
    from agent_bom.ast import js_ts
    from agent_bom.ast.js_ts import engine

    assert js_ts.analyze_js_ts_block is engine.analyze_js_ts_block
    assert js_ts.JSTSAstUnavailableError is engine.JSTSAstUnavailableError
    assert js_ts.JSTSAstAnalysis is engine.JSTSAstAnalysis
    assert js_ts.JSTSFunction is engine.JSTSFunction
    assert js_ts.JSTSToolRegistration is engine.JSTSToolRegistration
    assert js_ts.JSImportRef is engine.JSImportRef
    assert js_ts.JSTSCallSite is engine.JSTSCallSite


def test_package_declares_public_api():
    from agent_bom.ast import js_ts

    assert set(js_ts.__all__) >= {
        "scan_js_ts_file",
        "build_js_ts_flow_findings",
        "build_js_ts_dependency_symbol_reach",
        "analyze_js_ts_block",
        "JSTSAstUnavailableError",
    }


def test_legacy_facade_module_delegates_to_package():
    from agent_bom.ast.js_ts import facade

    with warnings.catch_warnings():
        warnings.simplefilter("always")
        import agent_bom.ast_js_ts as legacy_facade

        assert legacy_facade.scan_js_ts_file is facade.scan_js_ts_file
        assert legacy_facade.build_js_ts_flow_findings is facade.build_js_ts_flow_findings
        assert legacy_facade.build_js_ts_dependency_symbol_reach is facade.build_js_ts_dependency_symbol_reach
        assert legacy_facade._npm_package_from_module is facade._npm_package_from_module


def test_legacy_engine_module_delegates_to_package():
    from agent_bom.ast.js_ts import engine

    with warnings.catch_warnings():
        warnings.simplefilter("always")
        import agent_bom.js_ts_ast as legacy_engine

        assert legacy_engine.analyze_js_ts_block is engine.analyze_js_ts_block
        assert legacy_engine.JSTSAstUnavailableError is engine.JSTSAstUnavailableError
        assert legacy_engine.JSTSFunction is engine.JSTSFunction


def test_scan_js_ts_file_degrades_to_regex_when_engine_unavailable(tmp_path, monkeypatch):
    """The facade must keep producing regex findings when tree-sitter is missing."""
    from agent_bom.ast.js_ts import JSTSAstUnavailableError, engine, scan_js_ts_file

    def _unavailable(source: str, *, language_hint: str = "javascript"):
        raise JSTSAstUnavailableError("forced unavailable for fallback test")

    monkeypatch.setattr(engine, "analyze_js_ts_block", _unavailable)

    sample = tmp_path / "tool.js"
    sample.write_text(
        'const cp = require("child_process");\ncp.execSync(userInput);\n',
        encoding="utf-8",
    )

    _prompts, _guardrails, _tools, flow_findings, _frameworks, _call_edges, analysis = scan_js_ts_file(sample, "tool.js")

    assert analysis is None
    assert any(finding.category == "js_ts_dangerous_call" and finding.sink == "child_process.exec" for finding in flow_findings)


def test_legacy_modules_warn_deprecation():
    import agent_bom.ast_js_ts as legacy_facade
    import agent_bom.js_ts_ast as legacy_engine

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        getattr(legacy_facade, "scan_js_ts_file")  # noqa: B009
        getattr(legacy_engine, "analyze_js_ts_block")  # noqa: B009

    messages = [str(entry.message) for entry in caught if issubclass(entry.category, DeprecationWarning)]
    assert any("agent_bom.ast.js_ts" in message for message in messages), messages
    assert len(messages) >= 2
