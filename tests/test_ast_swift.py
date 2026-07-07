"""Swift bare-call reachability precision (issue #3499 tail).

Covers the call-site extraction refinements in ``agent_bom.ast_swift`` — trailing
closures, optional chaining, labeled args, ``try``/``await`` — and the enclosing
-type scoping that prevents cross-type same-name false ``function_reachable``
edges, while keeping string/comment mentions and non-calls masked out.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project
from agent_bom.ast_swift import _collect_swift_functions, _swift_call_sites


def _names(body: str) -> set[str]:
    return {site.name for site in _swift_call_sites(body, line_offset=0)}


# --------------------------------------------------------------------------- #
# Real calls that must be captured                                            #
# --------------------------------------------------------------------------- #


def test_trailing_closure_bare_call_captured() -> None:
    assert "helper" in _names("helper { doWork() }")


def test_trailing_closure_dot_call_captured() -> None:
    assert "Alamofire.request" in _names("Alamofire.request { resp in handle(resp) }")


def test_optional_chaining_call_captured() -> None:
    assert "session.load" in _names("session?.load(url)")


def test_optional_chaining_trailing_closure_captured() -> None:
    assert "session.load" in _names("session?.load { data in use(data) }")


def test_labeled_argument_call_captured() -> None:
    assert "fetch" in _names("fetch(url: target, retries: 3)")


def test_try_await_call_captured() -> None:
    assert "download" in _names("let bytes = try await download(url)")


def test_static_type_call_captured_without_duplicate() -> None:
    sites = _swift_call_sites("URLSession.shared", line_offset=0)  # not a call
    assert not sites
    call = [s for s in _swift_call_sites("Logger.log(message)", line_offset=0)]
    assert [s.name for s in call] == ["Logger.log"]


# --------------------------------------------------------------------------- #
# Non-calls and masked mentions that must NOT be captured                     #
# --------------------------------------------------------------------------- #


def test_computed_property_not_a_call() -> None:
    assert _names("var total: Int { count + 1 }") == set()


def test_type_declaration_not_a_call() -> None:
    assert _names("struct Payload { let value: Int }") == set()


def test_control_flow_brace_not_a_call() -> None:
    assert _names("if isReady { proceed() }") == {"proceed"}


def test_string_and_comment_mentions_masked() -> None:
    body = 'let note = "danger(secret)"\n// audit(token)\n'
    assert _names(body) == set()


# --------------------------------------------------------------------------- #
# Enclosing-type scoping: no cross-type same-name collision / false edge      #
# --------------------------------------------------------------------------- #


def test_same_name_methods_scoped_by_enclosing_type() -> None:
    src = (
        "class Alpha {\n"
        "    func helper() { Alamofire.request(a) }\n"
        "    func run() { helper() }\n"
        "}\n"
        "class Beta {\n"
        "    func helper() { print(b) }\n"
        "    func go() { helper() }\n"
        "}\n"
    )
    functions = _collect_swift_functions(src, rel_path="F.swift", scope_name="F", bindings={})
    # No dict collision: both helpers survive under distinct type scopes.
    assert {"Alpha:helper", "Beta:helper", "Alpha:run", "Beta:go"} <= set(functions)
    assert functions["Alpha:run"].scope_name == "Alpha"
    assert functions["Beta:go"].scope_name == "Beta"


def test_swift_cross_type_same_name_not_falsely_linked(tmp_path: Path) -> None:
    (tmp_path / "Package.resolved").write_text(
        '{"pins": [{"identity": "alamofire", "state": {"version": "5.9.0"}}], "version": 2}',
        encoding="utf-8",
    )
    # Beta.handler reaches only Beta.helper (safe). Alpha.helper (which hits
    # Alamofire) must NOT be linked in via the shared ``helper`` name.
    (tmp_path / "Server.swift").write_text(
        "import Alamofire\n\n"
        "func register(server: MCPServer) {\n"
        '    server.tool("safe_log", handler)\n'
        "}\n\n"
        "class Alpha {\n"
        "    func helper(_ url: String) { Alamofire.request(url) }\n"
        "}\n\n"
        "class Beta {\n"
        "    func handler(_ url: String) { helper(url) }\n"
        "    func helper(_ url: String) { print(url) }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)
    swift_reaches = [r for r in result.dependency_symbol_reach if r.ecosystem == "swift"]
    assert all(r.entrypoint != "safe_log" for r in swift_reaches)


def test_swift_same_type_helper_chain_still_reaches(tmp_path: Path) -> None:
    (tmp_path / "Package.resolved").write_text(
        '{"pins": [{"identity": "alamofire", "state": {"version": "5.9.0"}}], "version": 2}',
        encoding="utf-8",
    )
    (tmp_path / "Server.swift").write_text(
        "import Alamofire\n\n"
        "func register(server: MCPServer) {\n"
        '    server.tool("fetch_url", handler)\n'
        "}\n\n"
        "class Fetcher {\n"
        "    func handler(_ url: String) { helper(url) }\n"
        "    func helper(_ url: String) { Alamofire.request(url) }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)
    swift_reaches = [r for r in result.dependency_symbol_reach if r.ecosystem == "swift"]
    assert any(r.symbol == "request" and r.entrypoint == "fetch_url" for r in swift_reaches)


def test_swift_trailing_closure_reaches_dependency(tmp_path: Path) -> None:
    (tmp_path / "Package.resolved").write_text(
        '{"pins": [{"identity": "alamofire", "state": {"version": "5.9.0"}}], "version": 2}',
        encoding="utf-8",
    )
    # The dependency call uses trailing-closure syntax (no parens).
    (tmp_path / "Server.swift").write_text(
        "import Alamofire\n\n"
        "func register(server: MCPServer) {\n"
        '    server.tool("fetch_url", fetchUrl)\n'
        "}\n\n"
        "func fetchUrl(_ url: String) {\n"
        "    Alamofire.request { req in send(req) }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)
    swift_reaches = [r for r in result.dependency_symbol_reach if r.ecosystem == "swift"]
    assert any(r.symbol == "request" and r.entrypoint == "fetch_url" for r in swift_reaches)
