"""Regression tests for conservative regex symbol-reach guards."""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project
from agent_bom.ast_symbol_reach_guards import (
    is_actionable_dependency_symbol,
    is_external_rust_crate,
    is_verified_composer_package,
    is_verified_maven_coord,
    is_verified_nuget_package,
    is_verified_ruby_gem,
    is_verified_swift_package,
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


def test_nuget_package_requires_manifest_entry() -> None:
    nuget_map = {"RestSharp": "RestSharp", "Rest": "RestSharp"}
    assert is_verified_nuget_package("RestSharp", nuget_map)
    assert not is_verified_nuget_package("Invented.Package", nuget_map)


def test_ruby_gem_requires_manifest_entry() -> None:
    gem_map = {"faraday": "faraday", "Faraday": "faraday"}
    assert is_verified_ruby_gem("faraday", gem_map)
    assert not is_verified_ruby_gem("invented-gem", gem_map)


def test_composer_package_requires_manifest_entry() -> None:
    package_map = {"guzzlehttp/guzzle": "guzzlehttp/guzzle"}
    assert is_verified_composer_package("guzzlehttp/guzzle", package_map)
    assert not is_verified_composer_package("invented/package", package_map)


def test_swift_package_requires_manifest_entry() -> None:
    package_map = {"alamofire": "alamofire", "Alamofire": "alamofire"}
    assert is_verified_swift_package("alamofire", package_map)
    assert not is_verified_swift_package("invented-pkg", package_map)


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


def test_analyze_project_csharp_without_lock_emits_no_nuget_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "Server.cs").write_text(
        "using RestSharp;\n"
        "class Server {\n"
        "  void FetchUrl(string url) {\n"
        "    RestSharp.RestClient client = new RestSharp.RestClient();\n"
        "    client.ExecuteAsync(null);\n"
        "  }\n"
        "}\n"
    )
    result = analyze_project(tmp_path)
    assert not [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "nuget"]


def test_analyze_project_ruby_without_lock_emits_no_rubygems_symbol_reach(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text(
        "require 'faraday'\n"
        "class Server\n"
        "  def fetch_url(url)\n"
        "    client = Faraday.new\n"
        "    client.get(url)\n"
        "  end\n"
        "end\n"
    )
    result = analyze_project(tmp_path)
    assert not [reach for reach in result.dependency_symbol_reach if reach.ecosystem == "rubygems"]


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
