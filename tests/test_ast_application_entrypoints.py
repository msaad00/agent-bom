"""Application roots populate symbol reach without MCP tool declarations."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from agent_bom.ast.application_entrypoints import detect_application_entrypoints
from agent_bom.ast_analyzer import analyze_project
from agent_bom.reachability_cve import SymbolReachIndex

_FIXTURE = Path(__file__).parent / "fixtures" / "ordinary-python-app"


def _js_ts_parser_available() -> bool:
    return all(
        importlib.util.find_spec(module) is not None for module in ("tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript")
    )


def test_ordinary_repository_reaches_used_dependency_only() -> None:
    result = analyze_project(_FIXTURE)
    payload = result.to_dict()

    assert result.tools == []
    assert {entry.kind for entry in result.application_entrypoints} == {"console_script", "language_main"}
    assert {entry.handler for entry in result.application_entrypoints} == {"main"}
    assert {reach.package for reach in result.dependency_symbol_reach} == {"requests"}
    assert all(reach.package != "httpx" for reach in result.dependency_symbol_reach)
    reach_index = SymbolReachIndex.from_ast_result(result)
    assert reach_index.is_package_reached("requests", ecosystem="pypi") is True
    assert reach_index.is_package_reached("httpx", ecosystem="pypi") is False
    assert all(reach.entrypoint_kind in {"console_script", "language_main"} for reach in result.dependency_symbol_reach)
    assert all(reach.entrypoint_provenance for reach in result.dependency_symbol_reach)
    assert payload["stats"]["total_application_entrypoints"] == 2
    assert payload["application_entrypoints"][0]["provenance"]
    assert payload["dependency_symbol_reach"][0]["entrypoint_provenance"]


def test_python_framework_routes_and_commands_are_explicit_roots(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "from flask import Flask\n"
        "import click\n"
        "import typer\n\n"
        "api = FastAPI()\n"
        "web = Flask(__name__)\n"
        "cli = typer.Typer()\n\n"
        "@api.get('/health')\n"
        "def health(): return {'ok': True}\n\n"
        "@web.route('/ready')\n"
        "def ready(): return 'ready'\n\n"
        "@click.command()\n"
        "def click_run(): return 0\n\n"
        "@cli.command()\n"
        "def typer_run(): return 0\n\n"
        "def exported_but_unused(): return 0\n"
    )

    entries = detect_application_entrypoints(tmp_path, [source])

    assert {(entry.kind, entry.handler, entry.framework) for entry in entries} == {
        ("http_route", "health", "FastAPI"),
        ("http_route", "ready", "Flask"),
        ("cli_command", "click_run", "Click"),
        ("cli_command", "typer_run", "Typer"),
    }
    assert "exported_but_unused" not in {entry.handler for entry in entries}


def test_go_main_populates_dependency_reach_without_tool_registration(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        "package main\n\n"
        'import "net/http"\n\n'
        'func fetch() { http.Get("https://example.com") }\n'
        "func exportedButUnused() {}\n"
        "func main() { fetch() }\n"
    )

    result = analyze_project(tmp_path)

    assert result.tools == []
    entry = next(entry for entry in result.application_entrypoints if entry.language == "go")
    assert entry.handler == "main"
    reach = next(reach for reach in result.dependency_symbol_reach if reach.ecosystem == "go")
    assert reach.package == "net/http"
    assert reach.symbol == "Get"
    assert reach.entrypoint_kind == "language_main"
    assert reach.entrypoint_provenance == entry.provenance


def test_js_route_populates_dependency_reach_without_export_promotion(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'import axios from "axios";\n'
        "function health() { return axios.get('/health'); }\n"
        "export function exportedButUnused() { return axios.post('/unused'); }\n"
        "app.get('/health', health);\n"
    )

    result = analyze_project(tmp_path)

    if _js_ts_parser_available():
        assert result.tools == []
        entry = next(entry for entry in result.application_entrypoints if entry.language == "javascript_typescript")
        assert entry.handler == "health"
        reaches = [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "npm"]
        assert {(reach.package, reach.symbol) for reach in reaches} == {("axios", "get")}
        assert all("exportedButUnused" not in reach.call_path for reach in reaches)
        assert all(reach.entrypoint_provenance == entry.provenance for reach in reaches)


@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        ("main.go", "package main\nfunc main() {}\n", ("go", "language_main", "main")),
        ("main.rs", "fn main() {}\n", ("rust", "language_main", "main")),
        (
            "Application.java",
            "class Application { public static void main(String[] args) {} }\n",
            ("java", "language_main", "main"),
        ),
        ("Main.kt", "fun main() {}\n", ("kotlin", "language_main", "main")),
        ("Program.cs", "class Program { static void Main(string[] args) {} }\n", ("csharp", "language_main", "Main")),
        ("main.swift", "@main struct App { static func main() {} }\n", ("swift", "language_main", "main")),
        (
            "server.ts",
            "import express from 'express';\nconst app = express();\nfunction health() {}\napp.get('/health', health);\n",
            ("javascript_typescript", "http_route", "health"),
        ),
        (
            "routes.php",
            "<?php Route::get('/health', [HealthController::class, 'show']);\n",
            ("php", "http_route", "HealthController.show"),
        ),
        (
            "routes.rb",
            "Rails.application.routes.draw do\n  get '/health', to: 'health#show'\nend\n",
            ("ruby", "http_route", "HealthController.show"),
        ),
    ],
)
def test_supported_language_main_and_route_registrations_are_detected(
    tmp_path: Path,
    filename: str,
    source: str,
    expected: tuple[str, str, str],
) -> None:
    path = tmp_path / filename
    path.write_text(source)

    entries = detect_application_entrypoints(tmp_path, [path])

    assert (entries[0].language, entries[0].kind, entries[0].handler) == expected
    assert entries[0].provenance


def test_commented_or_quoted_registrations_are_not_entrypoints(tmp_path: Path) -> None:
    go_source = tmp_path / "commented.go"
    go_source.write_text('package helper\n// func main() {}\nvar example = "func main() {}"\n// http.HandleFunc("/health", health)\n')
    js_source = tmp_path / "commented.ts"
    js_source.write_text(
        '// app.get(\'/health\', health);\nconst example = "app.post(\\"/ready\\", ready)";\nexport function health() {}\n'
    )

    entries = detect_application_entrypoints(tmp_path, [go_source, js_source])

    assert entries == []
