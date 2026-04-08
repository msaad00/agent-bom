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
signals through lightweight source extraction. Zero external dependencies.

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


@dataclass
class ASTAnalysisResult:
    """Complete AST analysis result for a project."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    guardrails: list[DetectedGuardrail] = field(default_factory=list)
    tools: list[ToolSignature] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
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
_JS_PROMPT_ASSIGN_RE = re.compile(
    r"""
    (?P<name>system_prompt|systemPrompt|system_message|systemMessage|instructions|systemInstructions|
    prompt_template|promptTemplate|template|prefix|preamble|persona|backstory|role)\s*[:=]\s*
    (?P<quote>["'`])(?P<text>[\s\S]{0,2000}?)(?P=quote)
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass
class _FunctionAnalysis:
    """Internal representation of a function for call-graph construction."""

    qualified_name: str
    simple_name: str
    file_path: str
    line_number: int
    is_tool: bool
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


def _scan_js_ts_file(file_path: Path, rel_path: str) -> tuple[list[ExtractedPrompt], list[DetectedGuardrail], list[ToolSignature]]:
    """Extract prompt/tool/guardrail signals from JS/TS source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], []

    if len(source) > _MAX_FILE_SIZE:
        return [], [], []

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []

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

    return prompts, guardrails, tools


def _analyze_file(
    file_path: Path,
    rel_path: str,
) -> tuple[list[ExtractedPrompt], list[DetectedGuardrail], list[ToolSignature], list[str], list[_FunctionAnalysis], list[FlowFinding]]:
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

    Extracts system prompts, guardrails, tool signatures, and a lightweight
    call graph from Python source code. Also performs prompt/tool/guardrail
    extraction for JS/TS source files so Node-based MCP projects show up in
    the same analysis path.

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

    py_files = py_files[:_MAX_FILES]
    js_ts_files = js_ts_files[: max(0, _MAX_FILES - len(py_files))]
    result.files_analyzed = len(py_files) + len(js_ts_files)
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

    for js_ts_file in js_ts_files:
        rel = str(js_ts_file.relative_to(project))
        prompts, guardrails, tools = _scan_js_ts_file(js_ts_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)

    result.call_edges, interprocedural_findings = _build_call_graph(function_analyses)
    result.flow_findings.extend(interprocedural_findings)

    # Deduplicate frameworks
    result.frameworks_detected = sorted(set(result.frameworks_detected))

    return result
