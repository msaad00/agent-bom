"""Regression coverage for AST inputs that were previously false-clean."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from agent_bom.ast.js_ts.facade import scan_js_ts_file
from agent_bom.ast.kotlin.analyzer import scan_kotlin_file
from agent_bom.ast_csharp import scan_csharp_file
from agent_bom.ast_go import scan_go_file
from agent_bom.ast_java import scan_java_file
from agent_bom.ast_php import scan_php_file
from agent_bom.ast_python_analysis import _analyze_file
from agent_bom.ast_ruby import scan_ruby_file
from agent_bom.ast_rust import scan_rust_file
from agent_bom.ast_swift import scan_swift_file
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run, vulnerability_coverage_incomplete
from agent_bom.models import AIBOMReport
from agent_bom.output.html import to_html
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

_MAX_AST_SOURCE_SIZE = 512 * 1024


def _go(path: Path, rel_path: str) -> tuple:
    return scan_go_file(path, rel_path)


def _csharp(path: Path, rel_path: str) -> tuple:
    return scan_csharp_file(path, rel_path, nuget_map={})


def _ruby(path: Path, rel_path: str) -> tuple:
    return scan_ruby_file(path, rel_path, gem_map={})


def _java(path: Path, rel_path: str) -> tuple:
    return scan_java_file(path, rel_path, maven_map={})


def _php(path: Path, rel_path: str) -> tuple:
    return scan_php_file(path, rel_path, package_map={})


def _python(path: Path, rel_path: str) -> tuple:
    return _analyze_file(path, rel_path)


def _swift(path: Path, rel_path: str) -> tuple:
    return scan_swift_file(path, rel_path, package_map={})


def _rust(path: Path, rel_path: str) -> tuple:
    return scan_rust_file(path, rel_path)


def _kotlin(path: Path, rel_path: str) -> tuple:
    return scan_kotlin_file(path, rel_path, maven_map={})


def _js_ts(path: Path, rel_path: str) -> tuple:
    return scan_js_ts_file(path, rel_path)


_AST_SCANNERS: tuple[tuple[str, str, Callable[[Path, str], tuple]], ...] = (
    ("ast-go", "go", _go),
    ("ast-csharp", "cs", _csharp),
    ("ast-ruby", "rb", _ruby),
    ("ast-java", "java", _java),
    ("ast-php", "php", _php),
    ("ast-python", "py", _python),
    ("ast-swift", "swift", _swift),
    ("ast-rust", "rs", _rust),
    ("ast-kotlin", "kt", _kotlin),
    ("ast-js-ts", "ts", _js_ts),
)


@pytest.fixture(autouse=True)
def _reset_coverage_state() -> None:
    reset_scan_warnings()
    yield
    reset_scan_warnings()


@pytest.mark.parametrize(("scanner", "extension", "run_scan"), _AST_SCANNERS)
def test_unreadable_ast_source_records_partial_coverage_without_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scanner: str,
    extension: str,
    run_scan: Callable[[Path, str], tuple],
) -> None:
    rel_path = f"src/unreadable.{extension}"

    def _unreadable(*args: object, **kwargs: object) -> str:
        raise OSError("sentinel-private-read-detail")

    monkeypatch.setattr(Path, "read_text", _unreadable)
    run_scan(tmp_path / f"unreadable.{extension}", rel_path)

    assert consume_coverage_warnings() == [
        {
            "ecosystem": scanner,
            "release": f"{scanner}:{rel_path}",
            "reason": "source_read_error",
            "detail": "Source file could not be read; AST analysis is incomplete.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]


@pytest.mark.parametrize(("scanner", "extension", "run_scan"), _AST_SCANNERS)
def test_oversized_ast_source_records_partial_coverage(
    tmp_path: Path,
    scanner: str,
    extension: str,
    run_scan: Callable[[Path, str], tuple],
) -> None:
    rel_path = f"src/oversized.{extension}"
    source = tmp_path / f"oversized.{extension}"
    source.write_text("x" * (_MAX_AST_SOURCE_SIZE + 1), encoding="utf-8")

    run_scan(source, rel_path)

    assert consume_coverage_warnings() == [
        {
            "ecosystem": scanner,
            "release": f"{scanner}:{rel_path}",
            "reason": "source_size_limit",
            "detail": "Source file exceeds the 524,288-character AST analysis limit.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]


def test_ast_warning_marks_run_partial_without_invalidating_vulnerability_coverage() -> None:
    warning = {
        "ecosystem": "ast-python",
        "release": "ast-python:src/agent.py",
        "reason": "source_read_error",
        "detail": "Source file could not be read; AST analysis is incomplete.",
        "package_count": 0,
        "advisory_rows": 0,
    }
    report = AIBOMReport(coverage_warnings=[warning])

    run = effective_scan_run(report)

    assert run.outcome is ScanOutcome.PARTIAL
    assert [issue.code for issue in run.issues] == ["scanner_coverage_gap"]
    assert vulnerability_coverage_incomplete(report) is False


def test_partial_js_ts_metadata_and_warning_project_to_json_sarif_and_html(tmp_path: Path) -> None:
    from agent_bom.ast_analyzer import analyze_project

    (tmp_path / "server.ts").write_text(
        'import * as cp from "node:child_process";\nserver.tool("run", "Run", async () => cp.execSync("id"));\nfunction unfinished(\n',
        encoding="utf-8",
    )
    result = analyze_project(tmp_path)
    report = AIBOMReport(
        ai_inventory_data={"ast_analysis": result.to_dict()},
        coverage_warnings=consume_coverage_warnings(),
    )

    json_report = to_json(report)
    sarif_run = to_sarif(report)["runs"][0]
    html = to_html(report, [])

    assert json_report["ai_inventory"]["ast_analysis"]["analysis_coverage"]["status"] == "partial"
    assert json_report["scan_run"]["outcome"] == "partial"
    notification = sarif_run["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["descriptor"]["id"] == "scanner_coverage_gap"
    assert sarif_run["properties"]["scan_outcome"] == "partial"
    assert "PARTIAL COVERAGE" in html
    assert "CLEAN" not in html


def test_project_file_budget_prioritizes_entrypoints_and_records_partial_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_bom.ast_analyzer as ast_analyzer

    monkeypatch.setattr(ast_analyzer, "_MAX_FILES", 2)
    for index in range(3):
        (tmp_path / f"a_regular_{index}.py").write_text(
            f"def helper_{index}():\n    return {index}\n",
            encoding="utf-8",
        )
    late = tmp_path / "zzzz"
    late.mkdir()
    (late / "mcp_server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('late')\n\n@mcp.tool()\ndef late_tool() -> str:\n    return 'ok'\n",
        encoding="utf-8",
    )

    result = ast_analyzer.analyze_project(tmp_path)

    assert result.files_analyzed == 2
    assert result.analysis_coverage.status == "partial"
    assert any(tool.name == "late_tool" and tool.file_path == "zzzz/mcp_server.py" for tool in result.tools)
    assert result.warnings == ["AST analysis stopped at 2 of 4 eligible source files"]
    assert consume_coverage_warnings() == [
        {
            "ecosystem": "ast-analysis",
            "release": "ast-analysis:project-file-budget",
            "reason": "source_file_limit",
            "detail": "AST analysis stopped at 2 of 4 eligible source files.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]
