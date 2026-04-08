"""Deep code analysis for AI agent source code.

Extends the regex-based scanner with semantic analysis:

- **System prompt extraction** — finds prompts assigned to agent constructors
- **Guardrail detection** — identifies content filters, safety validators
- **Tool signature extraction** — full function signatures with types
- **Credential flow analysis** — tracks env var → agent parameter paths
- **Framework-specific patterns** — LangChain chains, CrewAI crews, MCP servers, etc.
- **Call graph extraction** — function-to-function edges for Python entrypoints
- **Inter-procedural flow findings** — helper-chain reachability to dangerous sinks

Python files use full AST parsing. JS/TS files contribute prompt/tool/guardrail
signals plus parser-backed import, handler, and call-chain extraction so
non-Python agent projects participate in the same inventory and flow model.

Compliance mapping:
- OWASP LLM01 (Prompt Injection) — prompt extraction enables review
- OWASP LLM02 (Insecure Output) — guardrail detection validates defenses
- NIST AI RMF MAP-3.5 — inventories AI components at code level
- EU AI Act ART-15 — transparency of AI system instructions
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from agent_bom.js_ts_ast import JSTSFunction, JSTSToolRegistration

# ── Data models ──────────────────────────────────────────────────────────────


@dataclass
class ExtractedPrompt:
    """A system prompt or instruction extracted from source code."""

    text: str  # The prompt content (truncated to 2000 chars)
    variable_name: str  # Variable or parameter it was assigned to
    file_path: str
    line_number: int
    framework: str  # Which AI framework uses this prompt
    prompt_type: str  # "system_prompt", "instructions", "template", "prefix"
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class DetectedGuardrail:
    """A content filter or safety validator found in code."""

    name: str
    guardrail_type: str  # "content_filter", "input_validator", "output_validator", "rate_limiter", "pii_filter"
    file_path: str
    line_number: int
    framework: str
    description: str = ""


@dataclass
class ToolSignature:
    """Full tool/function signature extracted from code."""

    name: str
    parameters: list[dict]  # [{"name": "path", "type": "str", "default": None}]
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


# ── Prompt extraction patterns ───────────────────────────────────────────────

# Field names that are NOT system prompts — excluded from prompt detection
# to prevent false positives on common documentation/UI fields.
_NON_PROMPT_KEYS = frozenset(
    {
        "description",
        "help",
        "help_text",
        "__doc__",
        "title",
        "label",
        "placeholder",
        "tooltip",
        "error_message",
        "docstring",
    }
)

# Variable/parameter names that typically hold system prompts
_PROMPT_VAR_NAMES = (
    frozenset(
        {
            "system_prompt",
            "system_message",
            "instructions",
            "system_instructions",
            "system_content",
            "prefix",
            "suffix",
            "preamble",
            "context",
            "system",
            "prompt_template",
            "template",
            "system_template",
            "initial_message",
            "persona",
            "role_description",
        }
    )
    - _NON_PROMPT_KEYS
)

# Keyword argument names in agent/LLM constructors that hold prompts
_PROMPT_KWARG_NAMES = (
    frozenset(
        {
            "system_prompt",
            "instructions",
            "system_message",
            "system",
            "prefix",
            "preamble",
            "prompt",
            "template",
            "system_template",
            "instruction",
            "backstory",
            "goal",
            "role",
            "system_instruction",
            "safety_settings",
        }
    )
    - _NON_PROMPT_KEYS
)

# ── Guardrail patterns ───────────────────────────────────────────────────────

# Import patterns that indicate guardrail usage
_GUARDRAIL_IMPORTS = {
    "guardrails": ("Guardrails AI", "content_filter"),
    "nemoguardrails": ("NeMo Guardrails", "content_filter"),
    "llm_guard": ("LLM Guard", "input_validator"),
    "rebuff": ("Rebuff", "input_validator"),
    "lakera": ("Lakera Guard", "input_validator"),
    "presidio_analyzer": ("Presidio", "pii_filter"),
    "presidio_anonymizer": ("Presidio Anonymizer", "pii_filter"),
    "langchain.callbacks": ("LangChain Callbacks", "output_validator"),
    "anthropic.types": ("Anthropic Safety", "content_filter"),
}

# Function/class names that indicate guardrail behavior
_GUARDRAIL_CALL_PATTERNS = re.compile(
    r"\b(?:content_filter|safety_check|moderate|moderation|validate_input|"
    r"validate_output|check_toxicity|check_bias|filter_response|sanitize|"
    r"guard|guardrail|rate_limit|throttle|pii_detect|anonymize|redact)\b",
    re.IGNORECASE,
)

# ── Prompt risk analysis ─────────────────────────────────────────────────────

_PROMPT_RISK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("credential_in_prompt", re.compile(r"(?:api[_-]?key|password|secret|token)\s*[=:]\s*\S+", re.IGNORECASE)),
    ("unrestricted_access", re.compile(r"\b(?:full\s+access|no\s+restrictions?|unrestricted|admin\s+privileges?)\b", re.IGNORECASE)),
    ("code_execution", re.compile(r"\b(?:execute|run|eval|exec)\s+(?:any|all|arbitrary)\s+(?:code|command|script)\b", re.IGNORECASE)),
    ("data_exfil_instruction", re.compile(r"\b(?:send|forward|transmit|upload)\s+(?:data|results|output|findings)\s+to\b", re.IGNORECASE)),
    ("no_safety", re.compile(r"\b(?:bypass|skip|ignore|disable)\s+(?:safety|security|guardrail|filter|moderation)\b", re.IGNORECASE)),
]
_DYNAMIC_CODE_CALLS = {"eval", "exec", "compile", "__import__"}
_SUBPROCESS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
_FILE_MUTATION_CALLS = {
    "open",
    "Path.write_text",
    "Path.write_bytes",
    "Path.touch",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
}
_SQL_CALLS = {"execute", "executemany", "cursor.execute", "cursor.executemany"}
_LLM_CALL_SUBSTRINGS = (
    "chat.completions.create",
    "responses.create",
    "messages.create",
    "completions.create",
    "generate_content",
    "generatecontent",
    "ollama.chat",
    "ollama.generate",
)
_UNTRUSTED_SOURCE_CALLS = {
    "input",
    "request.get_json",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.headers.get",
    "sys.argv",
}
_SANITIZER_CALLS = {
    "html.escape",
    "markupsafe.escape",
    "shlex.quote",
    "urllib.parse.quote",
}

# ── Skip directories ─────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "env",
        ".env",
        "node_modules",
        "__pycache__",
        ".git",
        "dist",
        "build",
        "site-packages",
        ".tox",
        ".eggs",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "tests",
        "test",
        "testing",
        "fixtures",
        "fuzz",
    }
)

# Files that contain pattern definitions or test data — skip to avoid FP
_SKIP_FILE_PATTERNS = frozenset(
    {
        "patterns.py",
        "conftest.py",
        "test_",
        "_test.py",
        "fixture",
        "mock",
        "fake",
        "sample",
    }
)

_MAX_FILE_SIZE = 512 * 1024  # 512KB
_MAX_FILES = 500
_JS_TS_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx"})
_GO_EXTS = frozenset({".go"})
_VALIDATION_HINTS = (
    "allow",
    "approve",
    "auth",
    "check",
    "confirm",
    "guard",
    "permit",
    "safe",
    "sanitize",
    "validate",
    "verify",
)
_DANGEROUS_CALLS = _DYNAMIC_CODE_CALLS | _SUBPROCESS_CALLS | _FILE_MUTATION_CALLS
_JS_TOOL_CALL_RE = re.compile(
    r"""\b(?:[A-Za-z_$][\w$]*\.)?tool\s*\(\s*["'`](?P<name>[^"'`]+)["'`]""",
    re.IGNORECASE,
)
_JS_IMPORT_MODULE_RE = re.compile(
    r"""\bimport\s+(?:[\s\S]{0,200}?\s+from\s+)?["'`](?P<module>[^"'`]+)["'`]""",
    re.IGNORECASE,
)
_JS_REQUIRE_MODULE_RE = re.compile(
    r"""\brequire\s*\(\s*["'`](?P<module>[^"'`]+)["'`]\s*\)""",
    re.IGNORECASE,
)
_JS_PROMPT_ASSIGN_RE = re.compile(
    r"""
    (?P<name>system_prompt|systemPrompt|system_message|systemMessage|instructions|systemInstructions|
    prompt_template|promptTemplate|template|prefix|preamble|persona|backstory|role)\s*[:=]\s*
    (?P<quote>["'`])(?P<text>[\s\S]{0,2000}?)(?P=quote)
    """,
    re.VERBOSE | re.IGNORECASE,
)
_JS_FALLBACK_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("child_process.exec", re.compile(r"\b(?:child_process|cp)\.exec(?:Sync)?\s*\(")),
    ("fs.writeFile", re.compile(r"\b(?:fs\.)?writeFile(?:Sync)?\s*\(")),
]
_JS_TS_FRAMEWORK_HINTS: dict[str, str] = {
    "@modelcontextprotocol/sdk": "MCP",
    "@anthropic-ai/sdk": "Anthropic",
    "anthropic": "Anthropic",
    "@langchain": "LangChain",
    "langchain": "LangChain",
    "@openai/agents": "OpenAI Agents",
    "openai": "OpenAI",
    "@mastra/core": "Mastra",
    "mastra": "Mastra",
    "@vercel/ai": "Vercel AI SDK",
}
_GO_PROMPT_ASSIGN_RE = re.compile(
    r"""
    (?P<name>systemPrompt|system_prompt|instructions|promptTemplate|prompt_template|template|prefix|preamble|persona|backstory|role)\s*
    (?::=|=)\s*(?P<quote>`|"|')(?P<text>[\s\S]{0,2000}?)(?P=quote)
    """,
    re.VERBOSE | re.IGNORECASE,
)
_GO_TOOL_CALL_RE = re.compile(
    r"""\b(?:AddTool|RegisterTool|NewTool|Tool)\s*\(\s*(?P<quote>`|"|')(?P<name>[^`"']+)(?P=quote)""",
    re.IGNORECASE,
)
_GO_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("exec.Command", re.compile(r"\bexec\.Command(?:Context)?\s*\(")),
    ("os.WriteFile", re.compile(r"\bos\.WriteFile\s*\(")),
    ("ioutil.WriteFile", re.compile(r"\bioutil\.WriteFile\s*\(")),
]
_GO_LLM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai.ChatCompletion", re.compile(r"\bCreateChatCompletion\b")),
    ("anthropic.Messages", re.compile(r"\bMessages\.Create\b")),
]


@dataclass
class _FunctionAnalysis:
    """Internal representation of a function for call-graph construction."""

    qualified_name: str
    simple_name: str
    file_path: str
    line_number: int
    is_tool: bool
    param_names: list[str] = field(default_factory=list)
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    parent_map: dict[ast.AST, ast.AST] = field(default_factory=dict, repr=False)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    called_names: list[tuple[str, int]] = field(default_factory=list)
    dangerous_calls: list[tuple[str, int, bool]] = field(default_factory=list)


# ── AST extraction ───────────────────────────────────────────────────────────


def _extract_string_value(node: ast.expr) -> str | None:
    """Extract string value from an AST node (str literal, f-string, joined)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string — extract the literal parts
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            else:
                parts.append("{...}")
        return "".join(parts)
    return None


def _call_name(node: ast.AST) -> str:
    """Return a dotted call name when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _open_mode_is_mutating(call: ast.Call) -> bool:
    """Return True when open(...) uses a mutating mode."""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return any(flag in call.args[1].value for flag in ("w", "a", "+"))
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return any(flag in keyword.value.value for flag in ("w", "a", "+"))
    return False


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Return a child→parent map for AST nodes."""
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


def _expr_contains_validation_hint(node: ast.AST) -> bool:
    """Return True when an expression contains validation/authorization hints."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and any(hint in child.id.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Attribute) and any(hint in child.attr.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Call):
            call_name = _call_name(child.func).lower()
            if any(hint in call_name for hint in _VALIDATION_HINTS):
                return True
    return False


def _is_guarded_call(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """Return True when a dangerous call sits behind a validation-oriented branch."""
    current = parent_map.get(node)
    while current is not None and not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
        if isinstance(current, ast.If) and _expr_contains_validation_hint(current.test):
            return True
        if isinstance(current, ast.Assert) and _expr_contains_validation_hint(current.test):
            return True
        current = parent_map.get(current)
    return False


def _target_names(node: ast.AST) -> set[str]:
    """Extract assigned identifier names from a target expression."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for child in node.elts:
            names.update(_target_names(child))
        return names
    return set()


def _names_in_expr(node: ast.AST | None) -> set[str]:
    """Collect identifier names used by an expression."""
    if node is None:
        return set()
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _cfg_node_id(rel_path: str, function_name: str, label: str) -> str:
    return f"{rel_path}:{function_name}:{label}"


def _stmt_cfg_node_id(rel_path: str, function_name: str, stmt: ast.stmt) -> str:
    return _cfg_node_id(rel_path, function_name, f"L{getattr(stmt, 'lineno', 0)}")


def _first_stmt_cfg_node_id(rel_path: str, function_name: str, statements: list[ast.stmt]) -> str | None:
    if not statements:
        return None
    return _stmt_cfg_node_id(rel_path, function_name, statements[0])


def _build_function_cfg_edges(func_node: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str) -> list[ControlFlowEdge]:
    """Build a coarse CFG for a function body."""
    function_name = func_node.name
    entry_id = _cfg_node_id(rel_path, function_name, "entry")
    exit_id = _cfg_node_id(rel_path, function_name, "exit")
    edges: list[ControlFlowEdge] = []
    seen: set[tuple[str, str, str]] = set()

    def add_edge(source: str | None, target: str | None, edge_type: str) -> None:
        if not source or not target:
            return
        key = (source, target, edge_type)
        if key in seen:
            return
        seen.add(key)
        edges.append(
            ControlFlowEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                file_path=rel_path,
                function_name=function_name,
            )
        )

    def walk_block(statements: list[ast.stmt], next_node: str) -> None:
        for index, stmt in enumerate(statements):
            stmt_id = _stmt_cfg_node_id(rel_path, function_name, stmt)
            after_id = _stmt_cfg_node_id(rel_path, function_name, statements[index + 1]) if index + 1 < len(statements) else next_node
            if isinstance(stmt, ast.If):
                body_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.body) or after_id
                orelse_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.orelse) or after_id
                add_edge(stmt_id, body_first, "branch_true")
                add_edge(stmt_id, orelse_first, "branch_false")
                walk_block(stmt.body, after_id)
                walk_block(stmt.orelse, after_id)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                loop_body_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.body)
                if loop_body_first:
                    add_edge(stmt_id, loop_body_first, "loop_true")
                    walk_block(stmt.body, stmt_id)
                add_edge(stmt_id, after_id, "loop_false")
                if stmt.orelse:
                    orelse_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.orelse) or after_id
                    add_edge(stmt_id, orelse_first, "loop_orelse")
                    walk_block(stmt.orelse, after_id)
                continue
            if isinstance(stmt, ast.Try):
                body_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.body) or after_id
                add_edge(stmt_id, body_first, "try_body")
                walk_block(stmt.body, after_id)
                for handler in stmt.handlers:
                    handler_first = _first_stmt_cfg_node_id(rel_path, function_name, handler.body) or after_id
                    add_edge(stmt_id, handler_first, "except")
                    walk_block(handler.body, after_id)
                if stmt.orelse:
                    orelse_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.orelse) or after_id
                    add_edge(stmt_id, orelse_first, "try_else")
                    walk_block(stmt.orelse, after_id)
                if stmt.finalbody:
                    final_first = _first_stmt_cfg_node_id(rel_path, function_name, stmt.finalbody) or after_id
                    add_edge(stmt_id, final_first, "finally")
                    walk_block(stmt.finalbody, after_id)
                continue
            if isinstance(stmt, ast.Return):
                add_edge(stmt_id, exit_id, "return")
                continue
            if isinstance(stmt, ast.Break):
                add_edge(stmt_id, next_node, "break")
                continue
            if isinstance(stmt, ast.Continue):
                add_edge(stmt_id, next_node, "continue")
                continue
            add_edge(stmt_id, after_id, "next")

    if func_node.body:
        add_edge(entry_id, _stmt_cfg_node_id(rel_path, function_name, func_node.body[0]), "entry")
        walk_block(func_node.body, exit_id)
    else:
        add_edge(entry_id, exit_id, "entry")

    return edges


def _is_llm_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if any(fragment in lower_name for fragment in _LLM_CALL_SUBSTRINGS):
        return True
    if lower_name.endswith((".invoke", ".ainvoke", ".predict", ".apredict")) and any(
        hint in lower_name for hint in ("llm", "model", "chain", "agent")
    ):
        return True
    return False


def _is_sql_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _SQL_CALLS or lower_name.endswith(".execute") or lower_name.endswith(".executemany")


def _is_untrusted_source_call(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _UNTRUSTED_SOURCE_CALLS or lower_name.endswith(".get_json")


def _is_sanitizer_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if lower_name in _SANITIZER_CALLS:
        return True
    return any(hint in lower_name for hint in _VALIDATION_HINTS)


def _first_match_line(source: str, pattern: str) -> int:
    index = source.find(pattern)
    if index < 0:
        return 1
    return source[:index].count("\n") + 1


def _frameworks_from_js_modules(module_names: set[str]) -> list[str]:
    frameworks: set[str] = set()
    for module_name in module_names:
        normalized = module_name.strip().lower()
        for prefix, framework in _JS_TS_FRAMEWORK_HINTS.items():
            if normalized == prefix or normalized.startswith(f"{prefix}/"):
                frameworks.add(framework)
    return sorted(frameworks)


def _source_js_modules(source: str) -> set[str]:
    modules = {match.group("module").strip() for match in _JS_IMPORT_MODULE_RE.finditer(source)}
    modules.update(match.group("module").strip() for match in _JS_REQUIRE_MODULE_RE.finditer(source))
    return {module for module in modules if module}


def _local_js_ts_callee(reference_name: str, function_names: set[str]) -> str | None:
    if reference_name in function_names:
        return reference_name
    tail = reference_name.split(".")[-1]
    if tail in function_names:
        return tail
    return None


def _build_js_ts_flow_findings(
    *,
    rel_path: str,
    functions: Mapping[str, JSTSFunction],
    tool_registrations: Sequence[JSTSToolRegistration],
) -> tuple[list[CallEdge], list[FlowFinding]]:
    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    call_edges: list[CallEdge] = []
    seen_edges: set[tuple[str, str, int]] = set()
    function_names = set(functions)

    for function_name, function in functions.items():
        for call_site in getattr(function, "call_sites", []):
            callee = _local_js_ts_callee(call_site.name, function_names)
            if not callee or callee == function_name:
                continue
            adjacency[function_name].add(callee)
            edge_key = (function_name, callee, call_site.line_number)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            call_edges.append(
                CallEdge(
                    caller=function_name,
                    callee=callee,
                    file_path=rel_path,
                    line_number=call_site.line_number,
                )
            )

    for registration in tool_registrations:
        edge_key = (registration.tool_name, registration.handler_name, registration.line_number)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        call_edges.append(
            CallEdge(
                caller=registration.tool_name,
                callee=registration.handler_name,
                file_path=rel_path,
                line_number=registration.line_number,
            )
        )

    findings: list[FlowFinding] = []
    seen_findings: set[tuple[str, str, int, str]] = set()
    for registration in tool_registrations:
        if registration.handler_name not in functions:
            continue
        queue: list[tuple[str, list[str]]] = [(registration.handler_name, [registration.handler_name])]
        visited: set[str] = set()
        while queue:
            current_name, path = queue.pop(0)
            if current_name in visited:
                continue
            visited.add(current_name)
            current = functions[current_name]
            for sink in getattr(current, "dangerous_call_sites", []):
                dedup_key = (registration.tool_name, sink.name, sink.line_number, current_name)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                is_interprocedural = len(path) > 1
                findings.append(
                    FlowFinding(
                        category=("js_ts_interprocedural_dangerous_flow" if is_interprocedural else "js_ts_tool_dangerous_flow"),
                        title=(
                            "JS/TS tool reaches dangerous sink through helper flow"
                            if is_interprocedural
                            else "JS/TS tool handler reaches dangerous sink"
                        ),
                        detail=f"Tool `{registration.tool_name}` reaches `{sink.name}` through JS/TS code in {rel_path}.",
                        file_path=rel_path,
                        line_number=sink.line_number,
                        entrypoint=registration.tool_name,
                        sink=sink.name,
                        call_path=[registration.tool_name] + path + [sink.name],
                    )
                )
            for callee in sorted(adjacency.get(current_name, ())):
                queue.append((callee, path + [callee]))

    return call_edges, findings


def _scan_js_ts_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
]:
    """Extract prompt/tool/guardrail signals from JS/TS source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], []

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], []

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []
    flow_findings: list[FlowFinding] = []
    frameworks: list[str] = _frameworks_from_js_modules(_source_js_modules(source))
    call_edges: list[CallEdge] = []

    for match in _JS_PROMPT_ASSIGN_RE.finditer(source):
        text = match.group("text").strip()
        if len(text) <= 10:
            continue
        line_num = source[: match.start()].count("\n") + 1
        var_name = match.group("name")
        prompts.append(
            ExtractedPrompt(
                text=text[:2000],
                variable_name=var_name,
                file_path=rel_path,
                line_number=line_num,
                framework="generic-js",
                prompt_type=_classify_prompt_type(var_name),
                risk_flags=_check_prompt_risks(text),
            )
        )

    seen_tool_names: set[tuple[str, int]] = set()
    for match in _JS_TOOL_CALL_RE.finditer(source):
        tool_name = match.group("name").strip()
        line_num = source[: match.start()].count("\n") + 1
        dedup_key = (tool_name, line_num)
        if not tool_name or dedup_key in seen_tool_names:
            continue
        seen_tool_names.add(dedup_key)
        tools.append(
            ToolSignature(
                name=tool_name,
                parameters=[],
                return_type="unknown",
                description="JS/TS MCP tool definition",
                file_path=rel_path,
                line_number=line_num,
                decorators=["tool()"],
                is_async=False,
            )
        )

    seen_guardrails: set[tuple[str, int]] = set()
    for match in _GUARDRAIL_CALL_PATTERNS.finditer(source):
        line_num = source[: match.start()].count("\n") + 1
        guard_name = match.group(0)
        dedup_key = (guard_name.lower(), line_num)
        if dedup_key in seen_guardrails:
            continue
        seen_guardrails.add(dedup_key)
        guardrails.append(
            DetectedGuardrail(
                name=guard_name,
                guardrail_type="content_filter",
                file_path=rel_path,
                line_number=line_num,
                framework="generic-js",
                description=f"Function/method call: {guard_name}",
            )
        )

    dangerous_call_names: set[str] = set()
    try:
        from agent_bom.js_ts_ast import JSTSAstUnavailableError, analyze_js_ts_block

        language_hint = {
            ".ts": "typescript",
            ".tsx": "tsx",
        }.get(file_path.suffix.lower(), "javascript")
        analysis = analyze_js_ts_block(source, language_hint=language_hint)
        dangerous_call_names.update(analysis.call_names)
        frameworks = sorted(set(frameworks) | set(_frameworks_from_js_modules(analysis.imported_modules)))

        seen_tool_signatures = {(tool.name, tool.line_number) for tool in tools}
        for registration in analysis.tool_registrations:
            dedup_key = (registration.tool_name, registration.line_number)
            if dedup_key in seen_tool_signatures:
                continue
            seen_tool_signatures.add(dedup_key)
            tools.append(
                ToolSignature(
                    name=registration.tool_name,
                    parameters=[],
                    return_type="unknown",
                    description="JS/TS MCP tool definition",
                    file_path=rel_path,
                    line_number=registration.line_number,
                    decorators=["tool()"],
                    is_async=False,
                )
            )

        call_edges, js_ts_flow_findings = _build_js_ts_flow_findings(
            rel_path=rel_path,
            functions=analysis.functions,
            tool_registrations=analysis.tool_registrations,
        )
        flow_findings.extend(js_ts_flow_findings)
    except (ImportError, JSTSAstUnavailableError):
        for call_name, pattern in _JS_FALLBACK_DANGEROUS_PATTERNS:
            if pattern.search(source):
                dangerous_call_names.add(call_name)

    tool_name = tools[0].name if tools else "module"
    for call_name in sorted(dangerous_call_names):
        flow_findings.append(
            FlowFinding(
                category="js_ts_dangerous_call",
                title="JS/TS source invokes a dangerous capability",
                detail=f"{rel_path} invokes `{call_name}` in code that may be reachable from tool handlers.",
                file_path=rel_path,
                line_number=_first_match_line(source, call_name.split(".")[-1].replace("Sync", "")),
                entrypoint=tool_name,
                sink=call_name,
                call_path=[tool_name, call_name] if tools else [call_name],
            )
        )

    return prompts, guardrails, tools, flow_findings, frameworks, call_edges


def _scan_go_file(
    file_path: Path,
    rel_path: str,
) -> tuple[list[ExtractedPrompt], list[DetectedGuardrail], list[ToolSignature], list[FlowFinding]]:
    """Extract prompt/tool/guardrail/dangerous-call signals from Go source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], []

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], []

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []
    flow_findings: list[FlowFinding] = []

    for match in _GO_PROMPT_ASSIGN_RE.finditer(source):
        text = match.group("text").strip()
        if len(text) <= 10:
            continue
        var_name = match.group("name")
        prompts.append(
            ExtractedPrompt(
                text=text[:2000],
                variable_name=var_name,
                file_path=rel_path,
                line_number=source[: match.start()].count("\n") + 1,
                framework="generic-go",
                prompt_type=_classify_prompt_type(var_name),
                risk_flags=_check_prompt_risks(text),
            )
        )

    for match in _GO_TOOL_CALL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        tools.append(
            ToolSignature(
                name=tool_name,
                parameters=[],
                return_type="unknown",
                description="Go MCP/tool registration",
                file_path=rel_path,
                line_number=source[: match.start()].count("\n") + 1,
                decorators=["go-tool"],
                is_async=False,
            )
        )

    seen_guardrails: set[tuple[str, int]] = set()
    for match in _GUARDRAIL_CALL_PATTERNS.finditer(source):
        line_num = source[: match.start()].count("\n") + 1
        guard_name = match.group(0)
        dedup_key = (guard_name.lower(), line_num)
        if dedup_key in seen_guardrails:
            continue
        seen_guardrails.add(dedup_key)
        guardrails.append(
            DetectedGuardrail(
                name=guard_name,
                guardrail_type="content_filter",
                file_path=rel_path,
                line_number=line_num,
                framework="generic-go",
                description=f"Function/method call: {guard_name}",
            )
        )

    entrypoint = tools[0].name if tools else "module"
    for sink_name, pattern in [*_GO_DANGEROUS_PATTERNS, *_GO_LLM_PATTERNS]:
        for match in pattern.finditer(source):
            category = "go_llm_call" if sink_name.startswith(("openai", "anthropic")) else "go_dangerous_call"
            title = "Go source invokes an LLM client" if category == "go_llm_call" else "Go source invokes a dangerous capability"
            flow_findings.append(
                FlowFinding(
                    category=category,
                    title=title,
                    detail=f"{rel_path} invokes `{sink_name}` in Go source.",
                    file_path=rel_path,
                    line_number=source[: match.start()].count("\n") + 1,
                    entrypoint=entrypoint,
                    sink=sink_name,
                    call_path=[entrypoint, sink_name] if tools else [sink_name],
                )
            )

    return prompts, guardrails, tools, flow_findings


def _analyze_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[str],
    list[_FunctionAnalysis],
    list[FlowFinding],
]:
    """Analyze a single Python file with full AST parsing."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], []

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return [], [], [], [], [], []

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []
    frameworks: list[str] = []
    function_analyses: list[_FunctionAnalysis] = []
    flow_findings: list[FlowFinding] = []
    parent_map = _build_parent_map(tree)

    # Pass 1: Detect frameworks and guardrails from imports
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = ""
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
            elif node.module:
                module = node.module

            # Check guardrail imports
            for guard_module, (name, gtype) in _GUARDRAIL_IMPORTS.items():
                if guard_module in module:
                    guardrails.append(
                        DetectedGuardrail(
                            name=name,
                            guardrail_type=gtype,
                            file_path=rel_path,
                            line_number=node.lineno,
                            framework=name,
                            description=f"Imported from {module}",
                        )
                    )

    # Pass 2: Extract prompts from assignments and function calls
    for node in ast.walk(tree):
        # Variable assignments: system_prompt = "You are..."
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() in _PROMPT_VAR_NAMES:
                    text = _extract_string_value(node.value)
                    if text and len(text) > 10:
                        risk_flags = _check_prompt_risks(text)
                        prompts.append(
                            ExtractedPrompt(
                                text=text[:2000],
                                variable_name=target.id,
                                file_path=rel_path,
                                line_number=node.lineno,
                                framework="generic",
                                prompt_type=_classify_prompt_type(target.id),
                                risk_flags=risk_flags,
                            )
                        )

        # Keyword arguments: Agent(system_prompt="You are...", instructions="...")
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and kw.arg.lower() in _PROMPT_KWARG_NAMES:
                    text = _extract_string_value(kw.value)
                    if text and len(text) > 10:
                        risk_flags = _check_prompt_risks(text)
                        prompts.append(
                            ExtractedPrompt(
                                text=text[:2000],
                                variable_name=kw.arg,
                                file_path=rel_path,
                                line_number=node.lineno,
                                framework="generic",
                                prompt_type=_classify_prompt_type(kw.arg),
                                risk_flags=risk_flags,
                            )
                        )

    # Pass 3: Extract tool signatures from decorated functions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = []
            is_tool = False
            for dec in node.decorator_list:
                dec_name = _get_decorator_name(dec)
                if dec_name:
                    decorators.append(dec_name)
                    if any(t in dec_name.lower() for t in ("tool", "function_tool", "skill", "action")):
                        is_tool = True

            if is_tool:
                params = _extract_params(node)
                return_type = _get_return_annotation(node)
                docstring = ast.get_docstring(node) or ""
                tools.append(
                    ToolSignature(
                        name=node.name,
                        parameters=params,
                        return_type=return_type,
                        description=docstring[:300],
                        file_path=rel_path,
                        line_number=node.lineno,
                        decorators=decorators,
                        is_async=isinstance(node, ast.AsyncFunctionDef),
                    )
                )

            func_info = _FunctionAnalysis(
                qualified_name=f"{rel_path}:{node.name}",
                simple_name=node.name,
                file_path=rel_path,
                line_number=node.lineno,
                is_tool=is_tool,
                param_names=[arg.arg for arg in node.args.args if arg.arg != "self"],
                node=node,
                parent_map=parent_map,
                cfg_edges=_build_function_cfg_edges(node, rel_path),
            )
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                call_name = _call_name(inner.func)
                if call_name:
                    func_info.called_names.append((call_name, getattr(inner, "lineno", node.lineno)))
                is_file_mutation = call_name in _FILE_MUTATION_CALLS and (call_name != "open" or _open_mode_is_mutating(inner))
                if call_name in _DYNAMIC_CODE_CALLS or call_name in _SUBPROCESS_CALLS or is_file_mutation:
                    guarded = _is_guarded_call(inner, parent_map)
                    line_num = getattr(inner, "lineno", node.lineno)
                    func_info.dangerous_calls.append((call_name, line_num, guarded))
                    if is_tool and not guarded:
                        flow_findings.append(
                            FlowFinding(
                                category="unguarded_tool_sink",
                                title="Tool entrypoint reaches dangerous sink without validation",
                                detail=(
                                    f"Tool `{node.name}` in {rel_path} calls `{call_name}` without an obvious "
                                    "validation or authorization branch."
                                ),
                                file_path=rel_path,
                                line_number=line_num,
                                entrypoint=node.name,
                                sink=call_name,
                                call_path=[node.name, call_name],
                            )
                        )
            function_analyses.append(func_info)

    # Pass 4: Detect guardrail function calls in source (regex fallback)
    for match in _GUARDRAIL_CALL_PATTERNS.finditer(source):
        # Find line number
        line_num = source[: match.start()].count("\n") + 1
        guard_name = match.group(0)
        # Avoid duplicates with import-based detection
        if not any(g.line_number == line_num for g in guardrails):
            guardrails.append(
                DetectedGuardrail(
                    name=guard_name,
                    guardrail_type="content_filter",
                    file_path=rel_path,
                    line_number=line_num,
                    framework="generic",
                    description=f"Function/method call: {guard_name}",
                )
            )

    return prompts, guardrails, tools, frameworks, function_analyses, flow_findings


def _check_prompt_risks(text: str) -> list[str]:
    """Check a prompt for security risk patterns."""
    flags = []
    for flag_name, pattern in _PROMPT_RISK_PATTERNS:
        if pattern.search(text):
            flags.append(flag_name)
    return flags


def _classify_prompt_type(var_name: str) -> str:
    """Classify prompt type from variable/parameter name."""
    name = var_name.lower()
    if "system" in name:
        return "system_prompt"
    if "instruct" in name:
        return "instructions"
    if "template" in name:
        return "template"
    if "prefix" in name or "preamble" in name:
        return "prefix"
    if "backstory" in name or "persona" in name or "role" in name:
        return "persona"
    return "prompt"


def _get_decorator_name(node: ast.expr) -> str | None:
    """Extract decorator name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return None


def _extract_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict]:
    """Extract function parameters with type annotations."""
    params = []
    for arg in func.args.args:
        if arg.arg == "self":
            continue
        param: dict = {"name": arg.arg, "type": "Any", "default": None}
        if arg.annotation:
            param["type"] = _annotation_to_str(arg.annotation)
        params.append(param)
    # Add defaults (aligned from the right)
    defaults = func.args.defaults
    if defaults:
        offset = len(params) - len(defaults)
        for i, d in enumerate(defaults):
            if isinstance(d, ast.Constant):
                params[offset + i]["default"] = repr(d.value)
    return params


def _get_return_annotation(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Extract return type annotation as string."""
    if func.returns:
        return _annotation_to_str(func.returns)
    return "None"


def _annotation_to_str(node: ast.expr) -> str:
    """Convert a type annotation AST node to a string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Attribute):
        return f"{_annotation_to_str(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return f"{_annotation_to_str(node.value)}[{_annotation_to_str(node.slice)}]"
    return "Any"


def _build_flow_finding(
    *,
    category: str,
    title: str,
    detail: str,
    file_path: str,
    line_number: int,
    entrypoint: str,
    sink: str,
    call_path: list[str],
    source: str = "",
) -> FlowFinding:
    return FlowFinding(
        category=category,
        title=title,
        detail=detail,
        file_path=file_path,
        line_number=line_number,
        entrypoint=entrypoint,
        sink=sink,
        call_path=call_path,
        source=source,
    )


def _resolve_called_function(
    caller: _FunctionAnalysis,
    raw_name: str,
    by_name: dict[str, list[_FunctionAnalysis]],
) -> _FunctionAnalysis | None:
    """Resolve a call target using same-file preference, then unique global match."""
    simple_name = raw_name.split(".")[-1]
    candidates = by_name.get(simple_name, [])
    if not candidates:
        return None

    same_file = [candidate for candidate in candidates if candidate.file_path == caller.file_path]
    if len(same_file) == 1:
        return same_file[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _build_taint_findings(functions: list[_FunctionAnalysis]) -> list[FlowFinding]:
    """Build taint/data-flow findings from tool entrypoints into sinks and LLM calls."""
    by_name: dict[str, list[_FunctionAnalysis]] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)

    seen_findings: set[tuple[str, str, str, int, str]] = set()

    def analyze_function(
        func: _FunctionAnalysis,
        tainted_params: set[str],
        call_path: list[str],
        visited: set[tuple[str, tuple[str, ...]]],
    ) -> tuple[list[FlowFinding], bool]:
        visit_key = (func.qualified_name, tuple(sorted(tainted_params)))
        if visit_key in visited or func.node is None:
            return [], False
        visited = set(visited)
        visited.add(visit_key)

        tainted_vars = set(tainted_params)
        sanitized_vars: set[str] = set()
        findings: list[FlowFinding] = []
        returns_tainted = False

        def expr_taint(expr: ast.AST | None, current_sanitized: set[str]) -> tuple[bool, list[FlowFinding]]:
            if expr is None:
                return False, []
            if isinstance(expr, ast.Name):
                return expr.id in tainted_vars and expr.id not in current_sanitized, []
            if isinstance(expr, ast.Constant):
                return False, []
            if isinstance(expr, ast.Attribute):
                return expr_taint(expr.value, current_sanitized)
            if isinstance(expr, ast.Subscript):
                return expr_taint(expr.value, current_sanitized)
            if isinstance(expr, ast.JoinedStr):
                findings_acc: list[FlowFinding] = []
                tainted = False
                for value in expr.values:
                    child_tainted, child_findings = expr_taint(value, current_sanitized)
                    findings_acc.extend(child_findings)
                    tainted |= child_tainted
                return tainted, findings_acc
            if isinstance(expr, ast.FormattedValue):
                return expr_taint(expr.value, current_sanitized)
            if isinstance(expr, ast.BinOp):
                left_tainted, left_findings = expr_taint(expr.left, current_sanitized)
                right_tainted, right_findings = expr_taint(expr.right, current_sanitized)
                return left_tainted or right_tainted, left_findings + right_findings
            if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
                sequence_findings: list[FlowFinding] = []
                tainted = False
                for elt in expr.elts:
                    child_tainted, child_findings = expr_taint(elt, current_sanitized)
                    sequence_findings.extend(child_findings)
                    tainted |= child_tainted
                return tainted, sequence_findings
            if isinstance(expr, ast.Dict):
                dict_findings: list[FlowFinding] = []
                tainted = False
                for key, value in zip(expr.keys, expr.values, strict=False):
                    for child in (key, value):
                        child_tainted, child_findings = expr_taint(child, current_sanitized)
                        dict_findings.extend(child_findings)
                        tainted |= child_tainted
                return tainted, dict_findings
            if isinstance(expr, ast.BoolOp):
                bool_findings: list[FlowFinding] = []
                tainted = False
                for value in expr.values:
                    child_tainted, child_findings = expr_taint(value, current_sanitized)
                    bool_findings.extend(child_findings)
                    tainted |= child_tainted
                return tainted, bool_findings
            if isinstance(expr, ast.Compare):
                compare_findings: list[FlowFinding] = []
                left_tainted, left_findings = expr_taint(expr.left, current_sanitized)
                compare_findings.extend(left_findings)
                tainted = left_tainted
                for comparator in expr.comparators:
                    child_tainted, child_findings = expr_taint(comparator, current_sanitized)
                    compare_findings.extend(child_findings)
                    tainted |= child_tainted
                return tainted, compare_findings
            if isinstance(expr, ast.Call):
                return call_taint(expr, current_sanitized)
            return any(name in tainted_vars and name not in current_sanitized for name in _names_in_expr(expr)), []

        def call_taint(call: ast.Call, current_sanitized: set[str]) -> tuple[bool, list[FlowFinding]]:
            call_name = _call_name(call.func)
            arg_results = [expr_taint(arg, current_sanitized) for arg in call.args]
            kw_results = [(kw.arg, *expr_taint(kw.value, current_sanitized)) for kw in call.keywords]
            arg_tainted = any(result[0] for result in arg_results) or any(result[1] for result in kw_results)
            nested_findings: list[FlowFinding] = []
            for _, child_findings in arg_results:
                nested_findings.extend(child_findings)
            for _, _, child_findings in kw_results:
                nested_findings.extend(child_findings)

            if _is_untrusted_source_call(call_name):
                return True, nested_findings
            if _is_sanitizer_call_name(call_name):
                return False, nested_findings

            source_names: set[str] = set()
            for arg, (is_tainted, _) in zip(call.args, arg_results, strict=False):
                if is_tainted:
                    source_names.update(name for name in _names_in_expr(arg) if name in tainted_vars)
            for kw in call.keywords:
                kw_tainted, _ = expr_taint(kw.value, current_sanitized)
                if kw_tainted:
                    source_names.update(name for name in _names_in_expr(kw.value) if name in tainted_vars)
            source_label = ", ".join(sorted(source_names)) or "untrusted input"
            guarded = _is_guarded_call(call, func.parent_map)

            if call_name and arg_tainted and not guarded:
                line_number = getattr(call, "lineno", func.line_number)
                if call_name in _DANGEROUS_CALLS:
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_dangerous_sink",
                            title="Untrusted data reaches a dangerous sink",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )
                elif _is_sql_call_name(call_name):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_sql_query",
                            title="Untrusted data reaches SQL execution",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )
                elif _is_llm_call_name(call_name):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_llm_prompt",
                            title="Untrusted data reaches an LLM invocation",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )

            callee = _resolve_called_function(func, call_name, by_name) if call_name else None
            if callee is not None:
                callee_tainted_params: set[str] = set()
                for param_name, (is_tainted, _) in zip(callee.param_names, arg_results, strict=False):
                    if is_tainted:
                        callee_tainted_params.add(param_name)
                for kw_name, is_tainted, _ in kw_results:
                    if kw_name and is_tainted and kw_name in callee.param_names:
                        callee_tainted_params.add(kw_name)
                if callee_tainted_params:
                    sub_findings, callee_returns_tainted = analyze_function(
                        callee,
                        callee_tainted_params,
                        call_path + [callee.simple_name],
                        visited,
                    )
                    nested_findings.extend(sub_findings)
                    return callee_returns_tainted, nested_findings
            return False, nested_findings

        def walk_statements(statements: list[ast.stmt], current_sanitized: set[str]) -> tuple[set[str], list[FlowFinding], bool]:
            local_tainted = set(tainted_vars)
            findings_acc: list[FlowFinding] = []
            local_returns_tainted = False

            for statement in statements:
                if isinstance(statement, ast.Assign):
                    value_tainted, value_findings = expr_taint(statement.value, current_sanitized)
                    findings_acc.extend(value_findings)
                    target_names: set[str] = set()
                    for target in statement.targets:
                        target_names.update(_target_names(target))
                    if value_tainted:
                        local_tainted.update(target_names)
                        tainted_vars.update(target_names)
                    else:
                        local_tainted.difference_update(target_names)
                        tainted_vars.difference_update(target_names)
                        current_sanitized.difference_update(target_names)
                    continue
                if isinstance(statement, ast.AnnAssign):
                    value_tainted, value_findings = expr_taint(statement.value, current_sanitized)
                    findings_acc.extend(value_findings)
                    target_names = _target_names(statement.target)
                    if value_tainted:
                        local_tainted.update(target_names)
                        tainted_vars.update(target_names)
                    else:
                        local_tainted.difference_update(target_names)
                        tainted_vars.difference_update(target_names)
                        current_sanitized.difference_update(target_names)
                    continue
                if isinstance(statement, ast.AugAssign):
                    target_names = _target_names(statement.target)
                    value_tainted, value_findings = expr_taint(statement.value, current_sanitized)
                    findings_acc.extend(value_findings)
                    target_tainted = any(name in tainted_vars for name in target_names)
                    if value_tainted or target_tainted:
                        local_tainted.update(target_names)
                        tainted_vars.update(target_names)
                    continue
                if isinstance(statement, ast.Expr):
                    _, value_findings = expr_taint(statement.value, current_sanitized)
                    findings_acc.extend(value_findings)
                    continue
                if isinstance(statement, ast.Assert):
                    _, test_findings = expr_taint(statement.test, current_sanitized)
                    findings_acc.extend(test_findings)
                    if _expr_contains_validation_hint(statement.test):
                        current_sanitized.update(_names_in_expr(statement.test))
                    continue
                if isinstance(statement, ast.If):
                    _, test_findings = expr_taint(statement.test, current_sanitized)
                    findings_acc.extend(test_findings)
                    guarded_names = _names_in_expr(statement.test) if _expr_contains_validation_hint(statement.test) else set()
                    body_tainted, body_findings, body_returns_tainted = walk_statements(statement.body, current_sanitized | guarded_names)
                    orelse_tainted, orelse_findings, orelse_returns_tainted = walk_statements(statement.orelse, set(current_sanitized))
                    findings_acc.extend(body_findings)
                    findings_acc.extend(orelse_findings)
                    tainted_vars.update(body_tainted | orelse_tainted)
                    local_tainted.update(body_tainted | orelse_tainted)
                    local_returns_tainted |= body_returns_tainted or orelse_returns_tainted
                    continue
                if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                    iter_expr = statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test
                    iter_tainted, iter_findings = expr_taint(iter_expr, current_sanitized)
                    findings_acc.extend(iter_findings)
                    body_sanitized = set(current_sanitized)
                    if isinstance(statement, (ast.For, ast.AsyncFor)) and iter_tainted:
                        tainted_loop_names = _target_names(statement.target)
                        body_sanitized.difference_update(tainted_loop_names)
                        tainted_vars.update(tainted_loop_names)
                    body_tainted, body_findings, body_returns_tainted = walk_statements(statement.body, body_sanitized)
                    orelse_tainted, orelse_findings, orelse_returns_tainted = walk_statements(statement.orelse, set(current_sanitized))
                    findings_acc.extend(body_findings)
                    findings_acc.extend(orelse_findings)
                    tainted_vars.update(body_tainted | orelse_tainted)
                    local_tainted.update(body_tainted | orelse_tainted)
                    local_returns_tainted |= body_returns_tainted or orelse_returns_tainted
                    continue
                if isinstance(statement, ast.With):
                    for item in statement.items:
                        context_tainted, context_findings = expr_taint(item.context_expr, current_sanitized)
                        findings_acc.extend(context_findings)
                        if context_tainted and item.optional_vars is not None:
                            names = _target_names(item.optional_vars)
                            tainted_vars.update(names)
                            local_tainted.update(names)
                    body_tainted, body_findings, body_returns_tainted = walk_statements(statement.body, set(current_sanitized))
                    findings_acc.extend(body_findings)
                    tainted_vars.update(body_tainted)
                    local_tainted.update(body_tainted)
                    local_returns_tainted |= body_returns_tainted
                    continue
                if isinstance(statement, ast.Try):
                    body_tainted, body_findings, body_returns_tainted = walk_statements(statement.body, set(current_sanitized))
                    findings_acc.extend(body_findings)
                    local_returns_tainted |= body_returns_tainted
                    branch_tainted: set[str] = set(body_tainted)
                    for handler in statement.handlers:
                        handler_tainted, handler_findings, handler_returns_tainted = walk_statements(handler.body, set(current_sanitized))
                        findings_acc.extend(handler_findings)
                        branch_tainted.update(handler_tainted)
                        local_returns_tainted |= handler_returns_tainted
                    orelse_tainted, orelse_findings, orelse_returns_tainted = walk_statements(statement.orelse, set(current_sanitized))
                    findings_acc.extend(orelse_findings)
                    branch_tainted.update(orelse_tainted)
                    local_returns_tainted |= orelse_returns_tainted
                    final_tainted, final_findings, final_returns_tainted = walk_statements(statement.finalbody, set(current_sanitized))
                    findings_acc.extend(final_findings)
                    branch_tainted.update(final_tainted)
                    local_returns_tainted |= final_returns_tainted
                    tainted_vars.update(branch_tainted)
                    local_tainted.update(branch_tainted)
                    continue
                if isinstance(statement, ast.Return):
                    ret_tainted, ret_findings = expr_taint(statement.value, current_sanitized)
                    findings_acc.extend(ret_findings)
                    local_returns_tainted |= ret_tainted
                    continue

            return local_tainted, findings_acc, local_returns_tainted

        _, findings, returns_tainted = walk_statements(func.node.body, sanitized_vars)
        return findings, returns_tainted

    aggregated_findings: list[FlowFinding] = []
    for func in functions:
        if not func.is_tool or not func.param_names:
            continue
        tool_findings, _ = analyze_function(func, set(func.param_names), [func.simple_name], set())
        for finding in tool_findings:
            dedup_key = (finding.category, finding.file_path, finding.sink, finding.line_number, finding.entrypoint)
            if dedup_key in seen_findings:
                continue
            seen_findings.add(dedup_key)
            aggregated_findings.append(finding)

    return aggregated_findings


def _build_call_graph(functions: list[_FunctionAnalysis]) -> tuple[list[CallEdge], list[FlowFinding]]:
    """Build a lightweight call graph and inter-procedural findings."""
    by_name: dict[str, list[_FunctionAnalysis]] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)

    adjacency: dict[str, list[_FunctionAnalysis]] = {func.qualified_name: [] for func in functions}
    edges: list[CallEdge] = []
    for func in functions:
        for raw_name, line_num in func.called_names:
            callee = _resolve_called_function(func, raw_name, by_name)
            if callee is None:
                continue
            adjacency[func.qualified_name].append(callee)
            edges.append(
                CallEdge(
                    caller=func.simple_name,
                    callee=callee.simple_name,
                    file_path=func.file_path,
                    line_number=line_num,
                )
            )

    findings: list[FlowFinding] = []
    seen_findings: set[tuple[str, str, str, int]] = set()
    function_by_id = {func.qualified_name: func for func in functions}
    for func in functions:
        if not func.is_tool:
            continue
        queue: list[tuple[str, list[str]]] = [(func.qualified_name, [func.simple_name])]
        visited: set[str] = set()
        while queue:
            current_id, path = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            current = function_by_id[current_id]
            for sink_name, line_num, guarded in current.dangerous_calls:
                if guarded:
                    continue
                if len(path) <= 1:
                    continue
                dedup_key = (func.simple_name, sink_name, current.file_path, line_num)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                findings.append(
                    FlowFinding(
                        category="interprocedural_dangerous_flow",
                        title="Tool call chain reaches dangerous sink",
                        detail=(f"Tool `{func.simple_name}` reaches `{sink_name}` through helper calls in {current.file_path}."),
                        file_path=current.file_path,
                        line_number=line_num,
                        entrypoint=func.simple_name,
                        sink=sink_name,
                        call_path=path + [sink_name],
                    )
                )
            for callee in adjacency.get(current_id, []):
                queue.append((callee.qualified_name, path + [callee.simple_name]))

    return edges, findings


# ── Public API ───────────────────────────────────────────────────────────────


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
        prompts, guardrails, tools, flow_findings, frameworks, js_ts_call_edges = _scan_js_ts_file(js_ts_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)
        result.frameworks_detected.extend(frameworks)
        result.call_edges.extend(js_ts_call_edges)

    for go_file in go_files:
        rel = str(go_file.relative_to(project))
        prompts, guardrails, tools, flow_findings = _scan_go_file(go_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.flow_findings.extend(flow_findings)

    python_call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.call_edges.extend(python_call_edges)
    result.flow_findings.extend(interprocedural_findings)
    result.flow_findings.extend(_build_taint_findings(function_analyses))

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
