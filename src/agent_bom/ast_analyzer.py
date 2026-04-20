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
    from agent_bom.js_ts_ast import JSTSFunction, JSTSToolRegistration
from agent_bom.ast_go import _go_function_key
from agent_bom.ast_go import build_go_flow_findings as _build_go_flow_findings
from agent_bom.ast_go import scan_go_file as _scan_go_file
from agent_bom.ast_js_ts import _JS_TS_EXTS, _js_ts_function_key
from agent_bom.ast_js_ts import build_js_ts_flow_findings as _build_js_ts_flow_findings
from agent_bom.ast_js_ts import scan_js_ts_file as _scan_js_ts_file
from agent_bom.ast_models import ASTAnalysisResult, CallEdge, _FunctionAnalysis, _GoFunctionAnalysis, _GoToolRegistration
from agent_bom.ast_python_analysis import (
    _MAX_FILES,
    _SKIP_DIRS,
    _SKIP_FILE_PATTERNS,
    _analyze_file,
    _build_call_graph,
    _build_taint_findings,
)
from agent_bom.ast_python_analysis import (
    _max_taint_depth as _python_max_taint_depth,
)

# ── Public API ───────────────────────────────────────────────────────────────

_max_taint_depth = _python_max_taint_depth


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
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        # Skip test/fixture/pattern files to avoid false positives
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        py_files.append(f)

    js_ts_files = []
    for f in sorted(project.rglob("*")):
        if f.suffix.lower() not in _JS_TS_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        js_ts_files.append(f)

    go_files = []
    for f in sorted(project.rglob("*.go")):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        go_files.append(f)

    py_files = py_files[:_MAX_FILES]
    js_ts_files = js_ts_files[: max(0, _MAX_FILES - len(py_files))]
    go_files = go_files[: max(0, _MAX_FILES - len(py_files) - len(js_ts_files))]
    result.files_analyzed = len(py_files) + len(js_ts_files) + len(go_files)
    function_analyses: list[_FunctionAnalysis] = []
    js_ts_functions: dict[str, JSTSFunction] = {}
    js_ts_tool_registrations: list[JSTSToolRegistration] = []
    go_functions: dict[str, _GoFunctionAnalysis] = {}
    go_tool_registrations: list[_GoToolRegistration] = []

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

    python_call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.call_edges.extend(python_call_edges)
    result.flow_findings.extend(interprocedural_findings)
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
