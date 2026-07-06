"""Regression tests for conservative regex symbol-reach guards."""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project
from agent_bom.ast_symbol_reach_guards import (
    is_actionable_dependency_symbol,
    is_external_rust_crate,
    is_verified_maven_coord,
)


def test_symbol_denylist_blocks_builder_but_allows_newcall() -> None:
    assert not is_actionable_dependency_symbol("Builder")
    assert is_actionable_dependency_symbol("newCall")
    assert is_actionable_dependency_symbol("get")


def test_rust_intrinsic_crates_are_excluded() -> None:
    assert not is_external_rust_crate("std")
    assert is_external_rust_crate("reqwest")


def test_maven_coord_requires_manifest_entry() -> None:
    maven_map = {"okhttp": "com.squareup.okhttp3:okhttp"}
    assert is_verified_maven_coord("com.squareup.okhttp3:okhttp", maven_map)
    assert not is_verified_maven_coord("com.invented:guess", maven_map)


def test_analyze_project_java_without_pom_emits_no_maven_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "Server.java").write_text(
        "import com.squareup.okhttp3.OkHttpClient;\n"
        "class Server {\n"
        "  void fetchUrl(String url) throws Exception {\n"
        "    new OkHttpClient().newCall(null).execute();\n"
        "  }\n"
        "}\n"
    )
    result = analyze_project(tmp_path)
    assert not [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "maven"]


def test_analyze_project_rust_skips_std_and_unresolved_tool(tmp_path: Path) -> None:
    (tmp_path / "server.rs").write_text(
        "use std::fs;\n\n"
        "fn orphan() {\n"
        "    fs::read_to_string(\"x\").unwrap();\n"
        "}\n\n"
        "fn main() {\n"
        '    server.tool("orphan_tool");\n'
        "}\n"
    )
    result = analyze_project(tmp_path)
    assert not result.dependency_symbol_reach
