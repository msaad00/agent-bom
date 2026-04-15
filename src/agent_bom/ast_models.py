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
class ASTAnalysisResult:
    """Complete AST analysis result for a project."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    guardrails: list[DetectedGuardrail] = field(default_factory=list)
    tools: list[ToolSignature] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    flow_findings: list[FlowFinding] = field(default_factory=list)
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
