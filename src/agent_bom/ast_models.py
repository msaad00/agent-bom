"""Shared data models for AST analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ExtractedPrompt:
    """A system prompt or instruction extracted from source code."""

    text: str
    variable_name: str
    file_path: str
    line_number: int
    framework: str
    prompt_type: str
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class DetectedGuardrail:
    """A content filter or safety validator found in code."""

    name: str
    guardrail_type: str
    file_path: str
    line_number: int
    framework: str
    description: str = ""


@dataclass
class ToolSignature:
    """Full tool/function signature extracted from code."""

    name: str
    parameters: list[dict]
    return_type: str
    description: str
    file_path: str
    line_number: int
    decorators: list[str] = field(default_factory=list)
    is_async: bool = False


@dataclass
class CallEdge:
    """A function-to-function edge in the project call graph."""

    caller: str
    callee: str
    file_path: str
    line_number: int


@dataclass
class ControlFlowEdge:
    """A coarse control-flow edge inside a function."""

    source: str
    target: str
    edge_type: str
    file_path: str
    function_name: str


@dataclass
class FlowFinding:
    """A lightweight control-flow or inter-procedural finding."""

    category: str
    title: str
    detail: str
    file_path: str
    line_number: int
    entrypoint: str
    sink: str
    call_path: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class DependencySymbolReach:
    """Imported dependency symbol reachable from a tool entrypoint."""

    entrypoint: str
    package: str
    module: str
    symbol: str
    file_path: str
    line_number: int
    call_path: list[str] = field(default_factory=list)
    depth: int = 0
    confidence: str = "import-symbol"
    ecosystem: str = "pypi"


@dataclass
class ASTAnalysisResult:
    """Complete AST analysis result for a project."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    guardrails: list[DetectedGuardrail] = field(default_factory=list)
    tools: list[ToolSignature] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    flow_findings: list[FlowFinding] = field(default_factory=list)
    dependency_symbol_reach: list[DependencySymbolReach] = field(default_factory=list)
    frameworks_detected: list[str] = field(default_factory=list)
    files_analyzed: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize for JSON output / AIBOMReport."""
        return {
            "prompts": [
                {
                    "text": p.text[:500],
                    "variable": p.variable_name,
                    "file": p.file_path,
                    "line": p.line_number,
                    "framework": p.framework,
                    "type": p.prompt_type,
                    "risk_flags": p.risk_flags,
                }
                for p in self.prompts
            ],
            "guardrails": [
                {
                    "name": g.name,
                    "type": g.guardrail_type,
                    "file": g.file_path,
                    "line": g.line_number,
                    "framework": g.framework,
                    "description": g.description,
                }
                for g in self.guardrails
            ],
            "tools": [
                {
                    "name": t.name,
                    "parameters": t.parameters,
                    "return_type": t.return_type,
                    "description": t.description,
                    "file": t.file_path,
                    "line": t.line_number,
                    "is_async": t.is_async,
                }
                for t in self.tools
            ],
            "call_graph": [
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "file": edge.file_path,
                    "line": edge.line_number,
                }
                for edge in self.call_edges
            ],
            "cfg_edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type,
                    "file": edge.file_path,
                    "function": edge.function_name,
                }
                for edge in self.cfg_edges
            ],
            "flow_findings": [
                {
                    "category": finding.category,
                    "title": finding.title,
                    "detail": finding.detail,
                    "file": finding.file_path,
                    "line": finding.line_number,
                    "entrypoint": finding.entrypoint,
                    "sink": finding.sink,
                    "call_path": finding.call_path,
                    "source": finding.source,
                }
                for finding in self.flow_findings
            ],
            "dependency_symbol_reach": [
                {
                    "entrypoint": reach.entrypoint,
                    "package": reach.package,
                    "module": reach.module,
                    "symbol": reach.symbol,
                    "file": reach.file_path,
                    "line": reach.line_number,
                    "call_path": reach.call_path,
                    "depth": reach.depth,
                    "confidence": reach.confidence,
                    "ecosystem": reach.ecosystem,
                }
                for reach in self.dependency_symbol_reach
            ],
            "frameworks": self.frameworks_detected,
            "files_analyzed": self.files_analyzed,
            "warnings": self.warnings,
            "stats": {
                "total_prompts": len(self.prompts),
                "total_guardrails": len(self.guardrails),
                "total_tools": len(self.tools),
                "total_call_edges": len(self.call_edges),
                "total_cfg_edges": len(self.cfg_edges),
                "total_flow_findings": len(self.flow_findings),
                "total_dependency_symbol_reach": len(self.dependency_symbol_reach),
                "prompts_with_risks": sum(1 for p in self.prompts if p.risk_flags),
            },
        }


@dataclass
class _GoCallSite:
    name: str
    line_number: int
    argument_names: list[list[str]] = field(default_factory=list)


@dataclass
class _GoFunctionAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    scope_name: str = ""
    package_name: str = ""
    param_names: list[str] = field(default_factory=list)
    imported_aliases: dict[str, str] = field(default_factory=dict)
    call_sites: list[_GoCallSite] = field(default_factory=list)
    dangerous_call_sites: list[_GoCallSite] = field(default_factory=list)


@dataclass
class _GoToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    scope_name: str = ""
    imported_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class _GoFileAnalysis:
    scope_name: str
    package_name: str
    functions: dict[str, _GoFunctionAnalysis] = field(default_factory=dict)
    tool_registrations: list[_GoToolRegistration] = field(default_factory=list)


@dataclass
class _RustCallSite:
    name: str
    line_number: int


@dataclass
class _RustFunctionAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    module_name: str = ""
    crate_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_RustCallSite] = field(default_factory=list)


@dataclass
class _RustToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    module_name: str = ""
    crate_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _RustFileAnalysis:
    module_name: str
    functions: dict[str, _RustFunctionAnalysis] = field(default_factory=dict)
    tool_registrations: list[_RustToolRegistration] = field(default_factory=list)


@dataclass
class _JavaCallSite:
    name: str
    line_number: int


@dataclass
class _JavaMethodAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_JavaCallSite] = field(default_factory=list)


@dataclass
class _JavaToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _JavaFileAnalysis:
    class_name: str
    functions: dict[str, _JavaMethodAnalysis] = field(default_factory=dict)
    tool_registrations: list[_JavaToolRegistration] = field(default_factory=list)


@dataclass
class _CSharpCallSite:
    name: str
    line_number: int


@dataclass
class _CSharpMethodAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_CSharpCallSite] = field(default_factory=list)


@dataclass
class _CSharpToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _CSharpFileAnalysis:
    class_name: str
    functions: dict[str, _CSharpMethodAnalysis] = field(default_factory=dict)
    tool_registrations: list[_CSharpToolRegistration] = field(default_factory=list)


@dataclass
class _RubyCallSite:
    name: str
    line_number: int


@dataclass
class _RubyMethodAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_RubyCallSite] = field(default_factory=list)


@dataclass
class _RubyToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _RubyFileAnalysis:
    class_name: str
    functions: dict[str, _RubyMethodAnalysis] = field(default_factory=dict)
    tool_registrations: list[_RubyToolRegistration] = field(default_factory=list)


@dataclass
class _PhpCallSite:
    name: str
    line_number: int


@dataclass
class _PhpMethodAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)
    local_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_PhpCallSite] = field(default_factory=list)


@dataclass
class _PhpToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    class_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _PhpFileAnalysis:
    class_name: str
    functions: dict[str, _PhpMethodAnalysis] = field(default_factory=dict)
    tool_registrations: list[_PhpToolRegistration] = field(default_factory=list)


@dataclass
class _SwiftCallSite:
    name: str
    line_number: int


@dataclass
class _SwiftFunctionAnalysis:
    name: str
    line_number: int
    file_path: str = ""
    scope_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)
    call_sites: list[_SwiftCallSite] = field(default_factory=list)


@dataclass
class _SwiftToolRegistration:
    tool_name: str
    handler_name: str
    line_number: int
    file_path: str = ""
    scope_name: str = ""
    import_bindings: dict[str, str] = field(default_factory=dict)


@dataclass
class _SwiftFileAnalysis:
    scope_name: str
    functions: dict[str, _SwiftFunctionAnalysis] = field(default_factory=dict)
    tool_registrations: list[_SwiftToolRegistration] = field(default_factory=list)


@dataclass
class _FunctionAnalysis:
    """Internal representation of a function for call-graph construction."""

    qualified_name: str
    simple_name: str
    file_path: str
    line_number: int
    is_tool: bool
    module_name: str = ""
    param_names: list[str] = field(default_factory=list)
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    parent_map: dict[ast.AST, ast.AST] = field(default_factory=dict, repr=False)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    called_names: list[tuple[str, int]] = field(default_factory=list)
    dangerous_calls: list[tuple[str, int, bool]] = field(default_factory=list)
    imported_modules: dict[str, str] = field(default_factory=dict, repr=False)
    imported_functions: dict[str, tuple[str, str]] = field(default_factory=dict, repr=False)
