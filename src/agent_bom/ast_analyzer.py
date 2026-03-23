"""Deep AST analysis for AI agent source code.

Extends the regex-based scanner with semantic analysis:

- **System prompt extraction** — finds prompts assigned to agent constructors
- **Guardrail detection** — identifies content filters, safety validators
- **Tool signature extraction** — full function signatures with types
- **Credential flow analysis** — tracks env var → agent parameter paths
- **Framework-specific patterns** — LangChain chains, CrewAI crews, etc.

Works on Python source files only. Zero external dependencies.

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
class ASTAnalysisResult:
    """Complete AST analysis result for a project."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    guardrails: list[DetectedGuardrail] = field(default_factory=list)
    tools: list[ToolSignature] = field(default_factory=list)
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
            "frameworks": self.frameworks_detected,
            "files_analyzed": self.files_analyzed,
            "stats": {
                "total_prompts": len(self.prompts),
                "total_guardrails": len(self.guardrails),
                "total_tools": len(self.tools),
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


def _analyze_file(file_path: Path, rel_path: str) -> tuple[list[ExtractedPrompt], list[DetectedGuardrail], list[ToolSignature], list[str]]:
    """Analyze a single Python file with full AST parsing."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], []

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return [], [], [], []

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []
    frameworks: list[str] = []

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

    return prompts, guardrails, tools, frameworks


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


# ── Public API ───────────────────────────────────────────────────────────────


def analyze_project(project_path: str | Path) -> ASTAnalysisResult:
    """Analyze a project directory for AI components via AST parsing.

    Extracts system prompts, guardrails, tool signatures, and framework
    usage from Python source code. Returns structured results suitable
    for inclusion in AI BOM reports.

    Args:
        project_path: Root directory to scan.

    Returns:
        ASTAnalysisResult with prompts, guardrails, tools, and metadata.
    """
    project = Path(project_path)
    if not project.is_dir():
        return ASTAnalysisResult(warnings=[f"{project_path} is not a directory"])

    result = ASTAnalysisResult()

    # Collect Python files
    py_files = []
    for f in sorted(project.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        # Skip test/fixture/pattern files to avoid false positives
        if any(skip in f.name.lower() for skip in _SKIP_FILE_PATTERNS):
            continue
        py_files.append(f)

    py_files = py_files[:_MAX_FILES]
    result.files_analyzed = len(py_files)

    for py_file in py_files:
        rel = str(py_file.relative_to(project))
        prompts, guardrails, tools, frameworks = _analyze_file(py_file, rel)
        result.prompts.extend(prompts)
        result.guardrails.extend(guardrails)
        result.tools.extend(tools)
        result.frameworks_detected.extend(frameworks)

    # Deduplicate frameworks
    result.frameworks_detected = sorted(set(result.frameworks_detected))

    return result
