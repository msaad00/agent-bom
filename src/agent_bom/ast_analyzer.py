"""Deep code analysis for AI agent source code.

Extends the regex-based scanner with semantic analysis:

- **System prompt extraction** — finds prompts assigned to agent constructors
- **Guardrail detection** — identifies content filters, safety validators
- **Tool signature extraction** — full function signatures with types
- **Credential flow analysis** — tracks env var → agent parameter paths
- **Framework-specific patterns** — LangChain chains, CrewAI crews, MCP servers, etc.
- **Call graph extraction** — function-to-function edges for Python entrypoints
- **Bounded helper-chain findings** — lightweight call-path detection from tool entrypoints to dangerous sinks

Python files use full AST parsing. JS/TS files contribute prompt/tool/guardrail
signals plus parser-backed import, handler, and call-chain extraction so
non-Python agent projects participate in the same inventory and flow model.
Go, Rust, Java, C#, Ruby, PHP (Composer), and Swift sources also contribute MCP tool
entrypoints and dependency-symbol reach for Cargo/Maven/NuGet/RubyGems/Composer/SPM CVE join.

Compliance mapping:
- OWASP LLM01 (Prompt Injection) — prompt inventory and risk review signals
- OWASP LLM02 (Insecure Output) — guardrail detection validates defenses
- NIST AI RMF MAP-3.5 — inventories AI components at code level
- EU AI Act ART-15 — transparency of AI system instructions
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.ast.js_ts import JSTSFunction, JSTSToolRegistration
from agent_bom.ast.js_ts import JS_TS_EXTS as _JS_TS_EXTS
from agent_bom.ast.js_ts import build_js_ts_dependency_symbol_reach
from agent_bom.ast.js_ts import build_js_ts_flow_findings as _build_js_ts_flow_findings
from agent_bom.ast.js_ts import js_ts_function_key as _js_ts_function_key
from agent_bom.ast.js_ts import scan_js_ts_file as _scan_js_ts_file
from agent_bom.ast_csharp import _csharp_method_key, build_csharp_dependency_symbol_reach, load_nuget_namespace_map
from agent_bom.ast_csharp import scan_csharp_file as _scan_csharp_file
from agent_bom.ast_go import _go_function_key, build_go_dependency_symbol_reach
from agent_bom.ast_go import build_go_flow_findings as _build_go_flow_findings
from agent_bom.ast_go import scan_go_file as _scan_go_file
from agent_bom.ast_java import _java_method_key, _load_maven_dependency_map, build_java_dependency_symbol_reach
from agent_bom.ast_java import scan_java_file as _scan_java_file
from agent_bom.ast_models import (
    ASTAnalysisResult,
    CallEdge,
    _CSharpMethodAnalysis,
    _CSharpToolRegistration,
    _FunctionAnalysis,
    _GoFunctionAnalysis,
    _GoToolRegistration,
    _JavaMethodAnalysis,
    _JavaToolRegistration,
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

_ANALYZABLE_SUFFIXES = frozenset(
    {".py", ".go", ".java", ".rb", ".php", ".swift", ".rs", ".cs", *_JS_TS_EXTS}
)


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

    Extracts system prompts, guardrails, tool signatures, taint/data-flow
    findings, and a lightweight CFG/call graph from Python source code. Also
    performs prompt/tool/guardrail and dangerous-call extraction for JS/TS and
    Go source files so non-Python MCP projects show up in the same path.

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

    py_files = py_files[:_MAX_FILES]
    js_ts_files = js_ts_files[: max(0, _MAX_FILES - len(py_files))]
    go_files = go_files[: max(0, _MAX_FILES - len(py_files) - len(js_ts_files))]
    remaining = max(0, _MAX_FILES - len(py_files) - len(js_ts_files) - len(go_files))
    rust_files = rust_files[:remaining]
    java_files = java_files[: max(0, remaining - len(rust_files))]
    csharp_files = csharp_files[: max(0, remaining - len(rust_files) - len(java_files))]
    ruby_files = ruby_files[: max(0, remaining - len(rust_files) - len(java_files) - len(csharp_files))]
    php_files = php_files[: max(0, remaining - len(rust_files) - len(java_files) - len(csharp_files) - len(ruby_files))]
    swift_files = swift_files[
        : max(0, remaining - len(rust_files) - len(java_files) - len(csharp_files) - len(ruby_files) - len(php_files))
    ]
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
    )
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

    python_call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.call_edges.extend(python_call_edges)
    result.flow_findings.extend(interprocedural_findings)
    result.dependency_symbol_reach.extend(_build_dependency_symbol_reach(function_analyses))
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
