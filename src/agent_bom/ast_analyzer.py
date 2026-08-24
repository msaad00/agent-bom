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

from pathlib import Path
from typing import Any, Mapping

from agent_bom.ast.application_entrypoints import detect_application_entrypoints
from agent_bom.ast.js_ts import JS_TS_EXTS as _JS_TS_EXTS
from agent_bom.ast.js_ts import JSTSFunction, JSTSToolRegistration, build_js_ts_dependency_symbol_reach
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
    CallEdge,
    DependencySymbolReach,
    _CSharpMethodAnalysis,
    _CSharpToolRegistration,
    _FunctionAnalysis,
    _GoFunctionAnalysis,
    _GoToolRegistration,
    _JavaMethodAnalysis,
    _JavaToolRegistration,
    _KotlinFunctionAnalysis,
    _KotlinToolRegistration,
    _PhpMethodAnalysis,
    _PhpToolRegistration,
    _RubyMethodAnalysis,
    _RubyToolRegistration,
    _RustFunctionAnalysis,
    _RustToolRegistration,
    _SwiftFunctionAnalysis,
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
    for path in project.rglob("*"):
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

    # Collect source files
    py_files = []
    for f in sorted(project.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        # Skip test/fixture/pattern files to avoid false positives
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        py_files.append(f)

    js_ts_files = []
    for f in sorted(project.rglob("*")):
        if f.suffix.lower() not in _JS_TS_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        js_ts_files.append(f)

    go_files = []
    for f in sorted(project.rglob("*.go")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        go_files.append(f)

    rust_files = []
    for f in sorted(project.rglob("*.rs")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        rust_files.append(f)

    java_files = []
    for f in sorted(project.rglob("*.java")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        java_files.append(f)

    kotlin_files = []
    for f in sorted(project.rglob("*")):
        if f.suffix.lower() not in _KOTLIN_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        kotlin_files.append(f)

    csharp_files = []
    for f in sorted(project.rglob("*.cs")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        csharp_files.append(f)

    ruby_files = []
    for f in sorted(project.rglob("*.rb")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        ruby_files.append(f)

    php_files = []
    for f in sorted(project.rglob("*.php")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        php_files.append(f)

    swift_files = []
    for f in sorted(project.rglob("*.swift")):
        if any(part in _SKIP_DIRS for part in f.relative_to(project).parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        swift_files.append(f)

    file_groups = (
        py_files,
        js_ts_files,
        go_files,
        rust_files,
        java_files,
        csharp_files,
        ruby_files,
        php_files,
        swift_files,
        kotlin_files,
    )
    eligible_count = sum(len(group) for group in file_groups)
    selected = set(
        sorted((path for group in file_groups for path in group), key=lambda path: _analysis_priority(project, path))[:_MAX_FILES]
    )
    (
        py_files,
        js_ts_files,
        go_files,
        rust_files,
        java_files,
        csharp_files,
        ruby_files,
        php_files,
        swift_files,
        kotlin_files,
    ) = tuple([path for path in group if path in selected] for group in file_groups)
    if eligible_count > len(selected):
        warning = f"AST analysis stopped at {len(selected)} of {eligible_count} eligible source files"
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
    result.files_analyzed = (
        len(py_files)
        + len(js_ts_files)
        + len(go_files)
        + len(rust_files)
        + len(java_files)
        + len(csharp_files)
        + len(ruby_files)
        + len(php_files)
        + len(swift_files)
        + len(kotlin_files)
    )
    selected_source_files = [path for group in file_groups for path in group if path in selected]
    result.application_entrypoints = detect_application_entrypoints(project, selected_source_files)
    function_analyses: list[_FunctionAnalysis] = []
    js_ts_functions: dict[str, JSTSFunction] = {}
    js_ts_tool_registrations: list[JSTSToolRegistration] = []
    go_functions: dict[str, _GoFunctionAnalysis] = {}
    go_tool_registrations: list[_GoToolRegistration] = []
    rust_functions: dict[str, _RustFunctionAnalysis] = {}
    rust_tool_registrations: list[_RustToolRegistration] = []
    java_methods: dict[str, _JavaMethodAnalysis] = {}
    java_tool_registrations: list[_JavaToolRegistration] = []
    csharp_methods: dict[str, _CSharpMethodAnalysis] = {}
    csharp_tool_registrations: list[_CSharpToolRegistration] = []
    ruby_methods: dict[str, _RubyMethodAnalysis] = {}
    ruby_tool_registrations: list[_RubyToolRegistration] = []
    php_methods: dict[str, _PhpMethodAnalysis] = {}
    php_tool_registrations: list[_PhpToolRegistration] = []
    swift_functions: dict[str, _SwiftFunctionAnalysis] = {}
    swift_tool_registrations: list[_SwiftToolRegistration] = []
    kotlin_functions: dict[str, _KotlinFunctionAnalysis] = {}
    kotlin_tool_registrations: list[_KotlinToolRegistration] = []
    js_ts_application_registrations: list[JSTSToolRegistration] = []
    go_application_registrations: list[_GoToolRegistration] = []
    rust_application_registrations: list[_RustToolRegistration] = []
    java_application_registrations: list[_JavaToolRegistration] = []
    csharp_application_registrations: list[_CSharpToolRegistration] = []
    ruby_application_registrations: list[_RubyToolRegistration] = []
    php_application_registrations: list[_PhpToolRegistration] = []
    swift_application_registrations: list[_SwiftToolRegistration] = []
    kotlin_application_registrations: list[_KotlinToolRegistration] = []
    maven_dependency_map = _load_maven_dependency_map(project)
    nuget_namespace_map = load_nuget_namespace_map(project)
    ruby_gem_map = load_ruby_gem_map(project)
    composer_package_map = load_composer_package_map(project)
    swift_package_map = load_swift_package_map(project)

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

    for js_ts_file in js_ts_files:
        rel = str(js_ts_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, js_ts_call_edges, js_ts_analysis = _scan_js_ts_file(js_ts_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(js_ts_call_edges)
        if js_ts_analysis is not None:
            for js_ts_function in js_ts_analysis.functions.values():
                js_ts_functions[_js_ts_function_key(js_ts_function.module_name, js_ts_function.name)] = js_ts_function
            if js_ts_analysis.default_export_name:
                default_function = js_ts_analysis.functions.get(js_ts_analysis.default_export_name)
                if default_function is not None:
                    js_ts_functions[_js_ts_function_key(default_function.module_name, "default")] = default_function
            js_ts_tool_registrations.extend(js_ts_analysis.tool_registrations)

    for go_file in go_files:
        rel = str(go_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, go_call_edges, go_analysis = _scan_go_file(go_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(go_call_edges)
        if go_analysis is not None:
            for go_function in go_analysis.functions.values():
                go_functions[_go_function_key(go_function.scope_name, go_function.name)] = go_function
            go_tool_registrations.extend(go_analysis.tool_registrations)

    for rust_file in rust_files:
        rel = str(rust_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, rust_call_edges, rust_analysis = _scan_rust_file(rust_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(rust_call_edges)
        if rust_analysis is not None:
            for rust_function in rust_analysis.functions.values():
                rust_functions[_rust_function_key(rust_function.module_name, rust_function.name)] = rust_function
            rust_tool_registrations.extend(rust_analysis.tool_registrations)

    for java_file in java_files:
        rel = str(java_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, java_call_edges, java_analysis = _scan_java_file(
            java_file,
            rel,
            maven_map=maven_dependency_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(java_call_edges)
        if java_analysis is not None:
            for java_method in java_analysis.functions.values():
                java_methods[_java_method_key(java_method.class_name, java_method.name)] = java_method
            java_tool_registrations.extend(java_analysis.tool_registrations)

    for csharp_file in csharp_files:
        rel = str(csharp_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, csharp_call_edges, csharp_analysis = _scan_csharp_file(
            csharp_file,
            rel,
            nuget_map=nuget_namespace_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(csharp_call_edges)
        if csharp_analysis is not None:
            for csharp_method in csharp_analysis.functions.values():
                csharp_methods[_csharp_method_key(csharp_method.class_name, csharp_method.name)] = csharp_method
            csharp_tool_registrations.extend(csharp_analysis.tool_registrations)

    for ruby_file in ruby_files:
        rel = str(ruby_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, ruby_call_edges, ruby_analysis = _scan_ruby_file(
            ruby_file,
            rel,
            gem_map=ruby_gem_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(ruby_call_edges)
        if ruby_analysis is not None:
            for ruby_method in ruby_analysis.functions.values():
                ruby_methods[_ruby_method_key(ruby_method.class_name, ruby_method.name)] = ruby_method
            ruby_tool_registrations.extend(ruby_analysis.tool_registrations)

    for php_file in php_files:
        rel = str(php_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, php_call_edges, php_analysis = _scan_php_file(
            php_file,
            rel,
            package_map=composer_package_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(php_call_edges)
        if php_analysis is not None:
            for php_method in php_analysis.functions.values():
                php_methods[_php_method_key(php_method.class_name, php_method.name)] = php_method
            php_tool_registrations.extend(php_analysis.tool_registrations)

    for swift_file in swift_files:
        rel = str(swift_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, swift_call_edges, swift_analysis = _scan_swift_file(
            swift_file,
            rel,
            package_map=swift_package_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(swift_call_edges)
        if swift_analysis is not None:
            for swift_function in swift_analysis.functions.values():
                swift_functions[_swift_function_key(swift_function.scope_name, swift_function.name)] = swift_function
            swift_tool_registrations.extend(swift_analysis.tool_registrations)

    for kotlin_file in kotlin_files:
        rel = str(kotlin_file.relative_to(project))
        prompts, guardrails, tools, flow_findings, frameworks, kotlin_call_edges, kotlin_analysis = _scan_kotlin_file(
            kotlin_file,
            rel,
            maven_map=maven_dependency_map,
        )
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(kotlin_call_edges)
        if kotlin_analysis is not None:
            for kotlin_function in kotlin_analysis.functions.values():
                kotlin_functions[_kotlin_function_key(kotlin_function.scope_name, kotlin_function.name)] = kotlin_function
            kotlin_tool_registrations.extend(kotlin_analysis.tool_registrations)

    application_entries_by_token: dict[str, ApplicationEntrypoint] = {}
    for index, entry in enumerate(result.application_entrypoints):
        if entry.language == "python":
            continue
        token = f"__application_entrypoint_{index}"
        if entry.language == "javascript_typescript":
            resolved = _application_handler(entry, js_ts_functions)
            if resolved is None:
                continue
            handler_key, _handler = resolved
            js_ts_application_registrations.append(
                JSTSToolRegistration(tool_name=token, handler_name=handler_key, line_number=entry.line_number)
            )
        elif entry.language == "go":
            resolved = _application_handler(entry, go_functions)
            if resolved is None:
                continue
            _handler_key, handler = resolved
            go_application_registrations.append(
                _GoToolRegistration(
                    tool_name=token,
                    handler_name=handler.name,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    scope_name=handler.scope_name,
                    imported_aliases=handler.imported_aliases,
                )
            )
        elif entry.language == "rust":
            resolved = _application_handler(entry, rust_functions)
            if resolved is None:
                continue
            handler_key, handler = resolved
            rust_application_registrations.append(
                _RustToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    module_name=handler.module_name,
                    crate_bindings=handler.crate_bindings,
                )
            )
        elif entry.language == "java":
            resolved = _application_handler(entry, java_methods)
            if resolved is None:
                continue
            handler_key, handler = resolved
            java_application_registrations.append(
                _JavaToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    class_name=handler.class_name,
                    import_bindings=handler.import_bindings,
                )
            )
        elif entry.language == "csharp":
            resolved = _application_handler(entry, csharp_methods)
            if resolved is None:
                continue
            handler_key, handler = resolved
            csharp_application_registrations.append(
                _CSharpToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    class_name=handler.class_name,
                    import_bindings=handler.import_bindings,
                )
            )
        elif entry.language == "ruby":
            resolved = _application_handler(entry, ruby_methods)
            if resolved is None:
                continue
            handler_key, handler = resolved
            ruby_application_registrations.append(
                _RubyToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    class_name=handler.class_name,
                    import_bindings=handler.import_bindings,
                )
            )
        elif entry.language == "php":
            resolved = _application_handler(entry, php_methods)
            if resolved is None:
                continue
            handler_key, handler = resolved
            php_application_registrations.append(
                _PhpToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    class_name=handler.class_name,
                    import_bindings=handler.import_bindings,
                )
            )
        elif entry.language == "swift":
            resolved = _application_handler(entry, swift_functions)
            if resolved is None:
                continue
            handler_key, handler = resolved
            swift_application_registrations.append(
                _SwiftToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    scope_name=handler.scope_name,
                    import_bindings=handler.import_bindings,
                )
            )
        elif entry.language == "kotlin":
            resolved = _application_handler(entry, kotlin_functions)
            if resolved is None:
                continue
            handler_key, handler = resolved
            kotlin_application_registrations.append(
                _KotlinToolRegistration(
                    tool_name=token,
                    handler_name=handler_key,
                    line_number=entry.line_number,
                    file_path=entry.file_path,
                    scope_name=handler.scope_name,
                    import_bindings=handler.import_bindings,
                )
            )
        else:
            continue
        application_entries_by_token[token] = entry

    python_call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.call_edges.extend(python_call_edges)
    result.flow_findings.extend(interprocedural_findings)
    result.dependency_symbol_reach.extend(
        _build_dependency_symbol_reach(
            function_analyses,
            [entry for entry in result.application_entrypoints if entry.language == "python"],
        )
    )
    result.flow_findings.extend(_build_taint_findings(function_analyses))
    js_ts_call_edges, js_ts_interprocedural_findings = _build_js_ts_flow_findings(
        functions=js_ts_functions,
        tool_registrations=js_ts_tool_registrations,
    )
    result.call_edges.extend(js_ts_call_edges)
    result.flow_findings.extend(js_ts_interprocedural_findings)
    go_call_edges, go_interprocedural_findings = _build_go_flow_findings(
        functions=go_functions,
        tool_registrations=go_tool_registrations,
    )
    result.call_edges.extend(go_call_edges)
    result.flow_findings.extend(go_interprocedural_findings)
    result.dependency_symbol_reach.extend(
        build_js_ts_dependency_symbol_reach(
            functions=js_ts_functions,
            tool_registrations=js_ts_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_go_dependency_symbol_reach(
            functions=go_functions,
            tool_registrations=go_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_rust_dependency_symbol_reach(
            functions=rust_functions,
            tool_registrations=rust_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_java_dependency_symbol_reach(
            methods=java_methods,
            tool_registrations=java_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_csharp_dependency_symbol_reach(
            methods=csharp_methods,
            tool_registrations=csharp_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_ruby_dependency_symbol_reach(
            methods=ruby_methods,
            tool_registrations=ruby_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_php_dependency_symbol_reach(
            methods=php_methods,
            tool_registrations=php_tool_registrations,
            package_map=composer_package_map,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_swift_dependency_symbol_reach(
            functions=swift_functions,
            tool_registrations=swift_tool_registrations,
            package_map=swift_package_map,
            max_depth=_python_max_taint_depth(),
        )
    )
    result.dependency_symbol_reach.extend(
        build_kotlin_dependency_symbol_reach(
            functions=kotlin_functions,
            tool_registrations=kotlin_tool_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )

    application_reaches: list[DependencySymbolReach] = []
    application_reaches.extend(
        build_js_ts_dependency_symbol_reach(
            functions=js_ts_functions,
            tool_registrations=js_ts_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_go_dependency_symbol_reach(
            functions=go_functions,
            tool_registrations=go_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_rust_dependency_symbol_reach(
            functions=rust_functions,
            tool_registrations=rust_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_java_dependency_symbol_reach(
            methods=java_methods,
            tool_registrations=java_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_csharp_dependency_symbol_reach(
            methods=csharp_methods,
            tool_registrations=csharp_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_ruby_dependency_symbol_reach(
            methods=ruby_methods,
            tool_registrations=ruby_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_php_dependency_symbol_reach(
            methods=php_methods,
            tool_registrations=php_application_registrations,
            package_map=composer_package_map,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_swift_dependency_symbol_reach(
            functions=swift_functions,
            tool_registrations=swift_application_registrations,
            package_map=swift_package_map,
            max_depth=_python_max_taint_depth(),
        )
    )
    application_reaches.extend(
        build_kotlin_dependency_symbol_reach(
            functions=kotlin_functions,
            tool_registrations=kotlin_application_registrations,
            max_depth=_python_max_taint_depth(),
        )
    )
    _stamp_application_reaches(application_reaches, application_entries_by_token)
    result.dependency_symbol_reach.extend(application_reaches)

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

    # Deduplicate frameworks
    result.frameworks_detected = sorted(set(result.frameworks_detected))

    return result
