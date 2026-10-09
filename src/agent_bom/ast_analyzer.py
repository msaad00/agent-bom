"""Deep code analysis for AI agent source code.

Extends the regex-based scanner with semantic analysis:

- **System prompt extraction** — finds prompts assigned to agent constructors
- **Guardrail detection** — identifies content filters, safety validators
- **Tool signature extraction** — full function signatures with types
- **Credential flow analysis** — tracks env var → agent parameter paths
- **Framework-specific patterns** — LangChain chains, CrewAI crews, MCP servers, etc.
- **Call graph extraction** — function-to-function edges for Python entrypoints
- **Application entrypoints** — evidence-backed CLI, main, and route invocation roots
- **Bounded helper-chain findings** — lightweight call-path detection from tool entrypoints to dangerous sinks

Python files use full AST parsing. JS/TS files contribute prompt/tool/guardrail
signals plus parser-backed import, handler, and call-chain extraction so
non-Python agent projects participate in the same inventory and flow model.
Go, Rust, Java, Kotlin, C#, Ruby, PHP (Composer), and Swift sources also contribute
MCP tool and application entrypoints plus dependency-symbol reach for
Cargo/Maven/NuGet/RubyGems/Composer/SPM CVE joins.

Compliance mapping:
- OWASP LLM01 (Prompt Injection) — prompt inventory and risk review signals
- OWASP LLM02 (Insecure Output) — guardrail detection validates defenses
- NIST AI RMF MAP-3.5 — inventories AI components at code level
- EU AI Act ART-15 — transparency of AI system instructions
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from agent_bom.ast.application_entrypoints import detect_application_entrypoints
from agent_bom.ast.js_ts import JS_TS_EXTS as _JS_TS_EXTS
from agent_bom.ast.js_ts import JSTSToolRegistration, build_js_ts_dependency_symbol_reach
from agent_bom.ast.js_ts import build_js_ts_flow_findings as _build_js_ts_flow_findings
from agent_bom.ast.js_ts import js_ts_function_key as _js_ts_function_key
from agent_bom.ast.js_ts import scan_js_ts_file as _scan_js_ts_file
from agent_bom.ast.kotlin import KOTLIN_EXTS as _KOTLIN_EXTS
from agent_bom.ast.kotlin import build_kotlin_dependency_symbol_reach
from agent_bom.ast.kotlin import kotlin_function_key as _kotlin_function_key
from agent_bom.ast.kotlin import scan_kotlin_file as _scan_kotlin_file
from agent_bom.ast_csharp import _csharp_method_key, build_csharp_dependency_symbol_reach, load_nuget_namespace_map
from agent_bom.ast_csharp import scan_csharp_file as _scan_csharp_file
from agent_bom.ast_go import _go_function_key, build_go_dependency_symbol_reach
from agent_bom.ast_go import build_go_flow_findings as _build_go_flow_findings
from agent_bom.ast_go import scan_go_file as _scan_go_file
from agent_bom.ast_java import _java_method_key, _load_maven_dependency_map, build_java_dependency_symbol_reach
from agent_bom.ast_java import scan_java_file as _scan_java_file
from agent_bom.ast_models import (
    ApplicationEntrypoint,
    ASTAnalysisResult,
    ASTCoverageGap,
    CallEdge,
    DependencySymbolReach,
    _CSharpToolRegistration,
    _FunctionAnalysis,
    _GoToolRegistration,
    _JavaToolRegistration,
    _KotlinToolRegistration,
    _PhpToolRegistration,
    _RubyToolRegistration,
    _RustToolRegistration,
    _SwiftToolRegistration,
)
from agent_bom.ast_php import _php_method_key, build_php_dependency_symbol_reach, load_composer_package_map
from agent_bom.ast_php import scan_php_file as _scan_php_file
from agent_bom.ast_python_analysis import (
    _MAX_FILES,
    _SKIP_DIRS,
    _SKIP_FILE_PATTERNS,
    _analyze_file,
    _build_call_graph,
    _build_dependency_symbol_reach,
    _build_taint_findings,
)
from agent_bom.ast_python_analysis import (
    _max_taint_depth as _python_max_taint_depth,
)
from agent_bom.ast_ruby import _ruby_method_key, build_ruby_dependency_symbol_reach, load_ruby_gem_map
from agent_bom.ast_ruby import scan_ruby_file as _scan_ruby_file
from agent_bom.ast_rust import _rust_function_key, build_rust_dependency_symbol_reach
from agent_bom.ast_rust import scan_rust_file as _scan_rust_file
from agent_bom.ast_swift import _swift_function_key, build_swift_dependency_symbol_reach, load_swift_package_map
from agent_bom.ast_swift import scan_swift_file as _scan_swift_file
from agent_bom.scanners.repo_ignore import RepositoryIgnore
from agent_bom.traversal import iter_discovery_files

# ── Public API ───────────────────────────────────────────────────────────────

_max_taint_depth = _python_max_taint_depth

_ANALYZABLE_SUFFIXES = frozenset({".py", ".go", ".java", ".rb", ".php", ".swift", ".rs", ".cs", *_JS_TS_EXTS, *_KOTLIN_EXTS})

# A bounded analysis must spend its budget on the files most likely to define
# externally reachable agent/tool behavior. Lexical order alone excluded this
# project's own ``mcp_server.py`` once the source tree exceeded ``_MAX_FILES``.
_HIGH_SIGNAL_SOURCE_NAMES = frozenset(
    {
        "agent.py",
        "app.py",
        "cli.py",
        "gateway.py",
        "gateway_server.py",
        "main.py",
        "mcp_server.py",
        "proxy.py",
        "server.py",
        "tools.py",
    }
)

_TEST_SOURCE_PARTS = frozenset({"test", "tests", "testing", "__tests__", "fixtures", "__fixtures__"})


def _application_handler(
    entry: ApplicationEntrypoint,
    analyses: Mapping[str, Any],
) -> tuple[str, Any] | None:
    """Resolve a declared application handler to one parsed function only."""
    handler_name = entry.handler.rsplit(".", 1)[-1]
    class_hint = entry.handler.rsplit(".", 1)[0] if "." in entry.handler else ""
    candidates: list[tuple[str, Any]] = []
    for key, analysis in analyses.items():
        if getattr(analysis, "name", "") != handler_name:
            continue
        owner = str(getattr(analysis, "class_name", "") or getattr(analysis, "scope_name", ""))
        if class_hint and owner and owner.rsplit(".", 1)[-1] != class_hint.rsplit(".", 1)[-1]:
            continue
        candidates.append((key, analysis))
    same_file = [candidate for candidate in candidates if getattr(candidate[1], "file_path", "") == entry.file_path]
    if len(same_file) == 1:
        return same_file[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _stamp_application_reaches(
    reaches: list[DependencySymbolReach],
    entries_by_token: Mapping[str, ApplicationEntrypoint],
) -> None:
    """Replace internal traversal tokens with public entrypoint evidence."""
    for reach in reaches:
        entry = entries_by_token.get(reach.entrypoint)
        if entry is None:
            continue
        reach.entrypoint = entry.name
        if reach.call_path:
            reach.call_path[0] = entry.name
        reach.entrypoint_kind = entry.kind
        reach.entrypoint_framework = entry.framework
        reach.entrypoint_provenance = entry.provenance


def _is_test_source_path(path: str) -> bool:
    """Return whether analysis evidence came from test-only source material."""
    candidate = Path(path)
    name = candidate.name.lower()
    return (
        any(part.lower() in _TEST_SOURCE_PARTS for part in candidate.parts)
        or name.startswith("test_")
        or any(marker in name for marker in ("_test.", ".test.", ".spec."))
    )


def _analysis_priority(project: Path, path: Path) -> tuple[int, str]:
    """Rank public entrypoints ahead of helpers, then remain deterministic."""
    relative = path.relative_to(project).as_posix()
    return (0 if path.name.lower() in _HIGH_SIGNAL_SOURCE_NAMES else 1, relative)


def project_has_analyzable_sources(project_path: str | Path) -> bool:
    """Return True when *project_path* contains AST-analyzable source files."""
    project = Path(project_path)
    if not project.is_dir():
        return False
    for path in iter_discovery_files(project, extra_skip_dirs=_SKIP_DIRS, ignore=RepositoryIgnore.for_root(project)):
        if not path.is_file():
            continue
        # Only consider path components RELATIVE to the scan root — an ancestor
        # directory of where the user keeps the project (e.g. ~/dev/test/proj,
        # /ci/build/app) must never disable analysis.
        if any(part in _SKIP_DIRS for part in path.relative_to(project).parts):
            continue
        if any(skip in path.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        if path.suffix.lower() in _ANALYZABLE_SUFFIXES:
            return True
    return False


_SOURCE_GLOBS: tuple[tuple[str, frozenset[str] | None], ...] = (
    ("*.py", None),
    ("*", frozenset(_JS_TS_EXTS)),
    ("*.go", None),
    ("*.rs", None),
    ("*.java", None),
    ("*.cs", None),
    ("*.rb", None),
    ("*.php", None),
    ("*.swift", None),
    ("*", frozenset(_KOTLIN_EXTS)),
)


@dataclass(frozen=True)
class _LanguageSpec:
    """How one non-Python language is scanned, keyed, bound and reached."""

    scan: Callable[[Path, str], tuple[Any, ...]]
    key: Callable[[Any], str]
    app_registration: Callable[[str, str, Any, ApplicationEntrypoint], Any]
    reach: Callable[[dict[str, Any], list[Any]], list[DependencySymbolReach]]


@dataclass
class _LanguageLane:
    spec: _LanguageSpec
    files: list[Path]
    functions: dict[str, Any] = field(default_factory=dict)
    tool_registrations: list[Any] = field(default_factory=list)
    application_registrations: list[Any] = field(default_factory=list)


def _collect_sources(project: Path) -> list[list[Path]]:
    """Walk *project* once and bucket candidate sources per ``_SOURCE_GLOBS`` entry."""
    groups: list[list[Path]] = [[] for _ in _SOURCE_GLOBS]
    for f in sorted(iter_discovery_files(project, extra_skip_dirs=_SKIP_DIRS, ignore=RepositoryIgnore.for_root(project))):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        # Skip test/fixture/pattern files to avoid false positives
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        for group, (pattern, suffixes) in zip(groups, _SOURCE_GLOBS):
            if f.match(pattern) and (suffixes is None or f.suffix.lower() in suffixes):
                group.append(f)
    return groups


def _record_file_budget(result: ASTAnalysisResult, selected_count: int, eligible_count: int) -> None:
    result.analysis_coverage.status = "partial"
    warning = f"AST analysis stopped at {selected_count} of {eligible_count} eligible source files"
    result.warnings.append(warning)
    from agent_bom.scanners.state import record_coverage_warning

    record_coverage_warning(
        {
            "ecosystem": "ast-analysis",
            "release": "ast-analysis:project-file-budget",
            "reason": "source_file_limit",
            "detail": f"{warning}.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    )


def _select_source_files(project: Path, result: ASTAnalysisResult) -> list[list[Path]]:
    """Collect every language's sources, then keep the highest-priority budget."""
    file_groups = _collect_sources(project)
    eligible_count = sum(len(group) for group in file_groups)
    selected = set(
        sorted((path for group in file_groups for path in group), key=lambda path: _analysis_priority(project, path))[:_MAX_FILES]
    )
    groups = [[path for path in group if path in selected] for group in file_groups]
    if eligible_count > len(selected):
        _record_file_budget(result, len(selected), eligible_count)
    result.files_analyzed = sum(len(group) for group in groups)
    result.analysis_coverage.eligible_files = eligible_count
    result.analysis_coverage.analyzed_files = result.files_analyzed
    return groups


def _js_ts_app_registration(token: str, handler_key: str, _handler: Any, entry: ApplicationEntrypoint) -> JSTSToolRegistration:
    return JSTSToolRegistration(tool_name=token, handler_name=handler_key, line_number=entry.line_number)


def _go_app_registration(token: str, _handler_key: str, handler: Any, entry: ApplicationEntrypoint) -> _GoToolRegistration:
    return _GoToolRegistration(
        tool_name=token,
        handler_name=handler.name,
        line_number=entry.line_number,
        file_path=entry.file_path,
        scope_name=handler.scope_name,
        imported_aliases=handler.imported_aliases,
    )


def _bound_app_registration(registration_type: type, owner: str, bindings: str) -> Callable[[str, str, Any, ApplicationEntrypoint], Any]:
    def build(token: str, handler_key: str, handler: Any, entry: ApplicationEntrypoint) -> Any:
        return registration_type(
            tool_name=token,
            handler_name=handler_key,
            line_number=entry.line_number,
            file_path=entry.file_path,
            **{owner: getattr(handler, owner), bindings: getattr(handler, bindings)},
        )

    return build


def _language_specs(project: Path) -> dict[str, _LanguageSpec]:
    """Per-language adapters in analysis order, keyed by entrypoint language."""
    maven_map = _load_maven_dependency_map(project)
    nuget_map = load_nuget_namespace_map(project)
    gem_map = load_ruby_gem_map(project)
    composer_map = load_composer_package_map(project)
    swift_map = load_swift_package_map(project)
    return {
        "javascript_typescript": _LanguageSpec(
            _scan_js_ts_file,
            lambda fn: _js_ts_function_key(fn.module_name, fn.name),
            _js_ts_app_registration,
            lambda fns, regs: build_js_ts_dependency_symbol_reach(
                functions=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()
            ),
        ),
        "go": _LanguageSpec(
            _scan_go_file,
            lambda fn: _go_function_key(fn.scope_name, fn.name),
            _go_app_registration,
            lambda fns, regs: build_go_dependency_symbol_reach(functions=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()),
        ),
        "rust": _LanguageSpec(
            _scan_rust_file,
            lambda fn: _rust_function_key(fn.module_name, fn.name),
            _bound_app_registration(_RustToolRegistration, "module_name", "crate_bindings"),
            lambda fns, regs: build_rust_dependency_symbol_reach(
                functions=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()
            ),
        ),
        "java": _LanguageSpec(
            lambda path, rel: _scan_java_file(path, rel, maven_map=maven_map),
            lambda fn: _java_method_key(fn.class_name, fn.name),
            _bound_app_registration(_JavaToolRegistration, "class_name", "import_bindings"),
            lambda fns, regs: build_java_dependency_symbol_reach(methods=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()),
        ),
        "csharp": _LanguageSpec(
            lambda path, rel: _scan_csharp_file(path, rel, nuget_map=nuget_map),
            lambda fn: _csharp_method_key(fn.class_name, fn.name),
            _bound_app_registration(_CSharpToolRegistration, "class_name", "import_bindings"),
            lambda fns, regs: build_csharp_dependency_symbol_reach(
                methods=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()
            ),
        ),
        "ruby": _LanguageSpec(
            lambda path, rel: _scan_ruby_file(path, rel, gem_map=gem_map),
            lambda fn: _ruby_method_key(fn.class_name, fn.name),
            _bound_app_registration(_RubyToolRegistration, "class_name", "import_bindings"),
            lambda fns, regs: build_ruby_dependency_symbol_reach(methods=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()),
        ),
        "php": _LanguageSpec(
            lambda path, rel: _scan_php_file(path, rel, package_map=composer_map),
            lambda fn: _php_method_key(fn.class_name, fn.name),
            _bound_app_registration(_PhpToolRegistration, "class_name", "import_bindings"),
            lambda fns, regs: build_php_dependency_symbol_reach(
                methods=fns, tool_registrations=regs, package_map=composer_map, max_depth=_python_max_taint_depth()
            ),
        ),
        "swift": _LanguageSpec(
            lambda path, rel: _scan_swift_file(path, rel, package_map=swift_map),
            lambda fn: _swift_function_key(fn.scope_name, fn.name),
            _bound_app_registration(_SwiftToolRegistration, "scope_name", "import_bindings"),
            lambda fns, regs: build_swift_dependency_symbol_reach(
                functions=fns, tool_registrations=regs, package_map=swift_map, max_depth=_python_max_taint_depth()
            ),
        ),
        "kotlin": _LanguageSpec(
            lambda path, rel: _scan_kotlin_file(path, rel, maven_map=maven_map),
            lambda fn: _kotlin_function_key(fn.scope_name, fn.name),
            _bound_app_registration(_KotlinToolRegistration, "scope_name", "import_bindings"),
            lambda fns, regs: build_kotlin_dependency_symbol_reach(
                functions=fns, tool_registrations=regs, max_depth=_python_max_taint_depth()
            ),
        ),
    }


def _record_scan(result: ASTAnalysisResult, scanned: tuple[Any, ...]) -> Any:
    prompts, guardrails, tools, flow_findings, frameworks, call_edges, analysis = scanned
    result.prompts.extend(prompts)
    result.guardrails.extend(guardrails)
    result.tools.extend(tools)
    result.flow_findings.extend(flow_findings)
    result.frameworks_detected.extend(frameworks)
    result.call_edges.extend(call_edges)
    return analysis


def _scan_python_files(project: Path, py_files: list[Path], result: ASTAnalysisResult) -> list[_FunctionAnalysis]:
    function_analyses: list[_FunctionAnalysis] = []
    for py_file in py_files:
        rel = str(py_file.relative_to(project))
        prompts, guardrails, tools, frameworks, file_functions, flow_findings = _analyze_file(py_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.frameworks_detected.extend(frameworks)
        result.flow_findings.extend(flow_findings)
        function_analyses.extend(file_functions)
        for function in file_functions:
            result.cfg_edges.extend(function.cfg_edges)
    return function_analyses


def _record_js_ts_gap(result: ASTAnalysisResult, js_ts_file: Path, rel: str) -> None:
    result.analysis_coverage.status = "partial"
    result.analysis_coverage.partial_files.append(
        ASTCoverageGap(
            file_path=rel,
            language="typescript" if js_ts_file.suffix.lower() in {".ts", ".tsx"} else "javascript",
            reason="structured_analysis_unavailable",
        )
    )
    result.warnings.append(f"Partial JS/TS structured analysis for {rel}; fallback findings were retained")


def _scan_js_ts_lane(project: Path, lane: _LanguageLane, result: ASTAnalysisResult) -> None:
    for js_ts_file in lane.files:
        rel = str(js_ts_file.relative_to(project))
        analysis = _record_scan(result, lane.spec.scan(js_ts_file, rel))
        if analysis is None:
            _record_js_ts_gap(result, js_ts_file, rel)
            continue
        for js_ts_function in analysis.functions.values():
            lane.functions[lane.spec.key(js_ts_function)] = js_ts_function
        if analysis.default_export_name:
            default_function = analysis.functions.get(analysis.default_export_name)
            if default_function is not None:
                lane.functions[_js_ts_function_key(default_function.module_name, "default")] = default_function
        lane.tool_registrations.extend(analysis.tool_registrations)


def _scan_language_lane(project: Path, lane: _LanguageLane, result: ASTAnalysisResult) -> None:
    for source_file in lane.files:
        rel = str(source_file.relative_to(project))
        analysis = _record_scan(result, lane.spec.scan(source_file, rel))
        if analysis is None:
            continue
        for function in analysis.functions.values():
            lane.functions[lane.spec.key(function)] = function
        lane.tool_registrations.extend(analysis.tool_registrations)


def _bind_application_entrypoints(result: ASTAnalysisResult, lanes: Mapping[str, _LanguageLane]) -> dict[str, ApplicationEntrypoint]:
    """Register each resolvable non-Python entrypoint as a synthetic tool token."""
    entries_by_token: dict[str, ApplicationEntrypoint] = {}
    for index, entry in enumerate(result.application_entrypoints):
        lane = lanes.get(entry.language)
        if lane is None:
            continue
        resolved = _application_handler(entry, lane.functions)
        if resolved is None:
            continue
        token = f"__application_entrypoint_{index}"
        handler_key, handler = resolved
        lane.application_registrations.append(lane.spec.app_registration(token, handler_key, handler, entry))
        entries_by_token[token] = entry
    return entries_by_token


def _add_python_flows(result: ASTAnalysisResult, function_analyses: list[_FunctionAnalysis]) -> None:
    python_call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.call_edges.extend(python_call_edges)
    result.flow_findings.extend(interprocedural_findings)
    python_application_entrypoints = [entry for entry in result.application_entrypoints if entry.language == "python"]
    result.dependency_symbol_reach.extend(_build_dependency_symbol_reach(function_analyses, python_application_entrypoints))
    result.flow_findings.extend(_build_taint_findings(function_analyses, python_application_entrypoints))


def _add_language_flows(result: ASTAnalysisResult, lanes: Mapping[str, _LanguageLane]) -> None:
    js_ts, go = lanes["javascript_typescript"], lanes["go"]
    js_ts_call_edges, js_ts_findings = _build_js_ts_flow_findings(functions=js_ts.functions, tool_registrations=js_ts.tool_registrations)
    result.call_edges.extend(js_ts_call_edges)
    result.flow_findings.extend(js_ts_findings)
    go_call_edges, go_findings = _build_go_flow_findings(functions=go.functions, tool_registrations=go.tool_registrations)
    result.call_edges.extend(go_call_edges)
    result.flow_findings.extend(go_findings)
    for lane in lanes.values():
        result.dependency_symbol_reach.extend(lane.spec.reach(lane.functions, lane.tool_registrations))


def _add_application_reaches(
    result: ASTAnalysisResult, lanes: Mapping[str, _LanguageLane], entries_by_token: Mapping[str, ApplicationEntrypoint]
) -> None:
    application_reaches: list[DependencySymbolReach] = []
    for lane in lanes.values():
        application_reaches.extend(lane.spec.reach(lane.functions, lane.application_registrations))
    _stamp_application_reaches(application_reaches, entries_by_token)
    result.dependency_symbol_reach.extend(application_reaches)


def _finalize_result(result: ASTAnalysisResult) -> None:
    # Test fixtures remain visible in inventory, but are not production
    # reachability evidence. Otherwise dev-only imports become build-blocking
    # production CVEs.
    result.flow_findings = [finding for finding in result.flow_findings if not _is_test_source_path(finding.file_path)]
    result.dependency_symbol_reach = [reach for reach in result.dependency_symbol_reach if not _is_test_source_path(reach.file_path)]
    deduped_call_edges: list[CallEdge] = []
    seen_call_edges: set[tuple[str, str, str, int]] = set()
    for edge in result.call_edges:
        key = (edge.caller, edge.callee, edge.file_path, edge.line_number)
        if key in seen_call_edges:
            continue
        seen_call_edges.add(key)
        deduped_call_edges.append(edge)
    result.call_edges = deduped_call_edges
    result.frameworks_detected = sorted(set(result.frameworks_detected))


def analyze_project(project_path: str | Path) -> ASTAnalysisResult:
    """Analyze a project directory for prompts, tools, and risky call paths.

    Extracts system prompts, guardrails, tool signatures, explicit application
    entrypoints, taint/data-flow findings, and a lightweight CFG/call graph.
    Non-Python source participates in the same inventory and reachability model.

    Args:
        project_path: Root directory to scan.

    Returns:
        ASTAnalysisResult with prompts, guardrails, tools, and metadata.
    """
    project = Path(project_path)
    if not project.is_dir():
        return ASTAnalysisResult(warnings=[f"{project_path} is not a directory"])

    result = ASTAnalysisResult()
    py_files, *language_files = _select_source_files(project, result)
    result.application_entrypoints = detect_application_entrypoints(
        project, [path for group in (py_files, *language_files) for path in group]
    )
    lanes = {
        language: _LanguageLane(spec, files)
        for (language, spec), files in zip(_language_specs(project).items(), language_files, strict=True)
    }
    function_analyses = _scan_python_files(project, py_files, result)
    for language, lane in lanes.items():
        (_scan_js_ts_lane if language == "javascript_typescript" else _scan_language_lane)(project, lane, result)
    entries_by_token = _bind_application_entrypoints(result, lanes)
    _add_python_flows(result, function_analyses)
    _add_language_flows(result, lanes)
    _add_application_reaches(result, lanes, entries_by_token)
    _finalize_result(result)
    return result
