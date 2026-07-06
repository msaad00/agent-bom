"""Tests for the function-level reachability-to-CVE join.

Pins the contract that:

1. Affected symbols are extracted from OSV/GHSA ``ecosystem_specific.imports``
   and from the ``Vulnerability.affected_symbols`` field.
2. A vulnerable package whose affected symbol IS reached from an entrypoint
   classifies as ``function_reachable``.
3. A reached package whose affected symbol is NOT reached, or an advisory
   with no symbol data, classifies as ``package_reachable`` — never an
   over-claimed function reach.
4. A package present but not reached classifies as ``unreachable``.
5. The thin ``apply_symbol_reachability_to_blast_radii`` hook stamps the
   signal onto Python and npm BlastRadius rows and leaves unsupported
   ecosystems untouched.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project
from agent_bom.ast_js_ts import _npm_package_from_module
from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
from agent_bom.graph.blast_reach import apply_symbol_reachability_to_blast_radii
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.reachability_cve import (
    FUNCTION_REACHABLE,
    PACKAGE_REACHABLE,
    UNREACHABLE,
    SymbolReachIndex,
    classify_reachability,
    extract_advisory_identifiers,
    extract_affected_symbols,
)


def _reach(package: str, module: str, symbol: str) -> DependencySymbolReach:
    return DependencySymbolReach(
        entrypoint="tool_entry",
        package=package,
        module=module,
        symbol=symbol,
        file_path="agent.py",
        line_number=5,
        call_path=["tool_entry", f"{module}.{symbol}"],
    )


def _osv_with_symbols(symbols: list[str], *, path: str = "jinja2.sandbox") -> dict:
    return {
        "id": "CVE-2099-1234",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ecosystem_specific": {"imports": [{"path": path, "symbols": symbols}]},
            }
        ],
    }


# ── extraction ────────────────────────────────────────────────────────────


def test_extract_symbols_from_osv_imports() -> None:
    tokens = extract_affected_symbols(_osv_with_symbols(["SandboxedEnvironment"]))
    assert "SandboxedEnvironment" in tokens


def test_extract_symbols_from_vulnerability_field() -> None:
    vuln = Vulnerability(
        id="CVE-2099-1", summary="x", severity=Severity.HIGH, affected_symbols=["dangerous_load"]
    )
    assert "dangerous_load" in extract_affected_symbols(vuln)


def test_extract_returns_empty_without_symbol_data() -> None:
    advisory = {"id": "CVE-2099-2", "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"}}]}
    assert extract_affected_symbols(advisory) == set()
    assert extract_affected_symbols(None) == set()


def test_extract_symbols_from_ghsa_vulnerable_functions() -> None:
    advisory = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "database_specific": {"vulnerable_functions": ["axios.get", "request"]},
    }
    tokens = extract_affected_symbols(advisory)
    assert "axios.get" in tokens
    assert "axios" in tokens
    assert "request" in tokens


def test_extract_advisory_identifiers_from_vulnerability_model() -> None:
    vuln = Vulnerability(
        id="CVE-2099-42",
        summary="x",
        severity=Severity.HIGH,
        cwe_ids=["CWE-79"],
        aliases=["GHSA-abcd-efgh-ijkl"],
    )
    ids = extract_advisory_identifiers(vuln)
    assert ids.cve_ids == ("CVE-2099-42",)
    assert ids.cwe_ids == ("CWE-79",)


def test_extract_advisory_identifiers_from_osv_cpe() -> None:
    advisory = {
        "id": "CVE-2099-99",
        "aliases": ["CVE-2099-99"],
        "database_specific": {"cwe_ids": ["CWE-502"]},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "pickle", "cpe": "cpe:2.3:a:python:pickle:*:*:*:*:*:*:*:*"}}],
    }
    ids = extract_advisory_identifiers(advisory)
    assert ids.cve_ids == ("CVE-2099-99",)
    assert ids.cwe_ids == ("CWE-502",)
    assert ids.cpe_ids == ("cpe:2.3:a:python:pickle:*:*:*:*:*:*:*:*",)


def test_extract_ignores_malformed_blocks() -> None:
    advisory = {"affected": ["not-a-dict", {"ecosystem_specific": {"imports": "nope"}}]}
    assert extract_affected_symbols(advisory) == set()


# ── classification ────────────────────────────────────────────────────────


def test_function_reachable_when_affected_symbol_is_reached() -> None:
    index = SymbolReachIndex.from_reaches([_reach("jinja2", "jinja2.sandbox", "SandboxedEnvironment")])
    signal = classify_reachability(
        package="jinja2", advisory=_osv_with_symbols(["SandboxedEnvironment"]), index=index
    )
    assert signal.state == FUNCTION_REACHABLE
    assert signal.matched_symbols == ("SandboxedEnvironment",)
    assert signal.function_reachable is True


def test_function_reachable_matches_method_on_reached_class() -> None:
    # Reached symbol is the method ``SandboxedEnvironment.from_string``; the
    # advisory names the type. The leading-component token must still match.
    index = SymbolReachIndex.from_reaches(
        [_reach("jinja2", "jinja2.sandbox", "SandboxedEnvironment.from_string")]
    )
    signal = classify_reachability(
        package="jinja2", advisory=_osv_with_symbols(["SandboxedEnvironment"]), index=index
    )
    assert signal.state == FUNCTION_REACHABLE


def test_package_reachable_when_affected_symbol_not_reached() -> None:
    # The reached symbol is a different, benign function in the same package.
    index = SymbolReachIndex.from_reaches([_reach("jinja2", "jinja2", "escape")])
    signal = classify_reachability(
        package="jinja2", advisory=_osv_with_symbols(["SandboxedEnvironment"]), index=index
    )
    assert signal.state == PACKAGE_REACHABLE
    assert signal.matched_symbols == ()


def test_package_reachable_when_advisory_has_no_symbols() -> None:
    index = SymbolReachIndex.from_reaches([_reach("jinja2", "jinja2", "escape")])
    advisory = {"id": "CVE-2099-3", "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"}}]}
    signal = classify_reachability(package="jinja2", advisory=advisory, index=index)
    assert signal.state == PACKAGE_REACHABLE
    assert "no symbol data" in signal.reason


def test_unreachable_when_package_not_reached() -> None:
    index = SymbolReachIndex.from_reaches([_reach("requests", "requests", "get")])
    signal = classify_reachability(
        package="jinja2", advisory=_osv_with_symbols(["SandboxedEnvironment"]), index=index
    )
    assert signal.state == UNREACHABLE


def test_graph_reach_fallback_yields_package_reachable() -> None:
    # No symbol-level reach captured for the package, but the graph layer says
    # it is in the reachable dependency closure → package_reachable, not
    # unreachable.
    empty_index = SymbolReachIndex.from_reaches([])
    signal = classify_reachability(
        package="jinja2",
        advisory=_osv_with_symbols(["SandboxedEnvironment"]),
        index=empty_index,
        package_reachable=True,
    )
    assert signal.state == PACKAGE_REACHABLE


def test_package_name_normalization_matches() -> None:
    index = SymbolReachIndex.from_reaches([_reach("Jinja2", "jinja2.sandbox", "SandboxedEnvironment")])
    signal = classify_reachability(
        package="jinja2", advisory=_osv_with_symbols(["SandboxedEnvironment"]), index=index
    )
    assert signal.state == FUNCTION_REACHABLE


def test_ecosystem_keys_do_not_cross_match() -> None:
    npm_reach = DependencySymbolReach(
        entrypoint="fetch_url",
        package="lodash",
        module="lodash",
        symbol="get",
        file_path="server.ts",
        line_number=3,
        call_path=["fetch_url", "lodash.get"],
        ecosystem="npm",
    )
    index = SymbolReachIndex.from_reaches([npm_reach])
    signal = classify_reachability(
        package="lodash",
        advisory={"id": "CVE-2099-8", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]},
        index=index,
        ecosystem="pypi",
    )
    assert signal.state == UNREACHABLE


def test_npm_function_reachable_when_affected_symbol_is_reached() -> None:
    npm_reach = DependencySymbolReach(
        entrypoint="fetch_url",
        package="axios",
        module="axios",
        symbol="get",
        file_path="server.ts",
        line_number=3,
        call_path=["fetch_url", "axios.get"],
        ecosystem="npm",
    )
    index = SymbolReachIndex.from_reaches([npm_reach])
    advisory = {
        "id": "CVE-2099-9",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "axios"},
                "ecosystem_specific": {"imports": [{"path": "axios", "symbols": ["get"]}]},
            }
        ],
    }
    signal = classify_reachability(package="axios", advisory=advisory, index=index, ecosystem="npm")
    assert signal.state == FUNCTION_REACHABLE
    assert signal.matched_symbols == ("get",)


# ── end-to-end through the real AST call graph ────────────────────────────


def test_function_reachable_from_real_ast_analysis(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import requests\n\n@tool\ndef fetch(url):\n    return requests.get(url)\n"
    )
    result = analyze_project(tmp_path)
    index = SymbolReachIndex.from_ast_result(result)

    # Advisory flags requests.get — which the entrypoint reaches.
    advisory = {
        "id": "CVE-2099-9999",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ecosystem_specific": {"imports": [{"path": "requests", "symbols": ["get"]}]},
            }
        ],
    }
    signal = classify_reachability(package="requests", advisory=advisory, index=index)
    assert signal.state == FUNCTION_REACHABLE
    assert signal.matched_symbols == ("get",)

    # A different symbol of the same reached package is not function-reachable.
    other = {
        "id": "CVE-2099-0000",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ecosystem_specific": {"imports": [{"path": "requests", "symbols": ["post"]}]},
            }
        ],
    }
    assert classify_reachability(package="requests", advisory=other, index=index).state == PACKAGE_REACHABLE


# ── thin wiring hook ──────────────────────────────────────────────────────


def _python_br(symbols: list[str], pkg_name: str = "requests") -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2099-7", summary="x", severity=Severity.HIGH, affected_symbols=symbols
    )
    pkg = Package(name=pkg_name, version="2.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _ast_result_with_get() -> ASTAnalysisResult:
    return ASTAnalysisResult(dependency_symbol_reach=[_reach("requests", "requests", "get")])


def test_wiring_stamps_function_reachable_on_python_row() -> None:
    br = _python_br(["get"])
    stamped = apply_symbol_reachability_to_blast_radii([br], _ast_result_with_get())
    assert stamped == 1
    assert br.symbol_reachability == FUNCTION_REACHABLE
    assert br.reachable_affected_symbols == ["get"]


def test_wiring_stamps_unreachable_when_symbol_absent() -> None:
    br = _python_br(["get"], pkg_name="leftpad")
    stamped = apply_symbol_reachability_to_blast_radii([br], _ast_result_with_get())
    assert stamped == 1
    assert br.symbol_reachability == UNREACHABLE


def test_wiring_skips_unsupported_ecosystem_rows() -> None:
    br = _python_br(["get"])
    br.package.ecosystem = "maven"
    stamped = apply_symbol_reachability_to_blast_radii([br], _ast_result_with_get())
    assert stamped == 0
    assert br.symbol_reachability is None


def test_wiring_stamps_npm_row() -> None:
    br = _python_br(["get"], pkg_name="axios")
    br.package.ecosystem = "npm"
    npm_reach = DependencySymbolReach(
        entrypoint="fetch_url",
        package="axios",
        module="axios",
        symbol="get",
        file_path="server.ts",
        line_number=3,
        call_path=["fetch_url", "axios.get"],
        ecosystem="npm",
    )
    stamped = apply_symbol_reachability_to_blast_radii([br], ASTAnalysisResult(dependency_symbol_reach=[npm_reach]))
    assert stamped == 1
    assert br.symbol_reachability == FUNCTION_REACHABLE
    assert br.reachable_affected_symbols == ["get"]


def test_wiring_stamps_go_row() -> None:
    br = _python_br(["Get"], pkg_name="net/http")
    br.package.ecosystem = "go"
    go_reach = DependencySymbolReach(
        entrypoint="fetch_url",
        package="net/http",
        module="net/http",
        symbol="Get",
        file_path="server.go",
        line_number=8,
        call_path=["fetch_url", "fetchURL", "net/http.Get"],
        ecosystem="go",
    )
    stamped = apply_symbol_reachability_to_blast_radii([br], ASTAnalysisResult(dependency_symbol_reach=[go_reach]))
    assert stamped == 1
    assert br.symbol_reachability == FUNCTION_REACHABLE
    assert br.reachable_affected_symbols == ["Get"]


def test_wiring_no_op_without_symbol_reach_evidence() -> None:
    # AST ran but captured no symbol reach → no basis to mark anything
    # unreachable, so the hook leaves every row untouched.
    br = _python_br(["get"])
    stamped = apply_symbol_reachability_to_blast_radii([br], ASTAnalysisResult())
    assert stamped == 0
    assert br.symbol_reachability is None


def test_wiring_is_best_effort_no_op(monkeypatch) -> None:
    br = _python_br(["get"])

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr("agent_bom.reachability_cve.SymbolReachIndex.from_ast_result", explode)
    assert apply_symbol_reachability_to_blast_radii([br], _ast_result_with_get()) == 0
    assert br.symbol_reachability is None


def test_npm_package_from_module() -> None:
    assert _npm_package_from_module("axios") == "axios"
    assert _npm_package_from_module("@scope/pkg/subpath") == "@scope/pkg"
    assert _npm_package_from_module("./relative") is None
    assert _npm_package_from_module("node:fs") is None
