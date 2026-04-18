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

import ast
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.js_ts_ast import JSTSFunction, JSTSToolRegistration
from agent_bom.ast_go import (
    _go_function_key,
)
from agent_bom.ast_go import (
    build_go_flow_findings as _build_go_flow_findings,
)
from agent_bom.ast_go import (
    scan_go_file as _scan_go_file,
)
from agent_bom.ast_js_ts import (
    _JS_TS_EXTS,
    _js_ts_function_key,
)
from agent_bom.ast_js_ts import (
    build_js_ts_flow_findings as _build_js_ts_flow_findings,
)
from agent_bom.ast_js_ts import (
    scan_js_ts_file as _scan_js_ts_file,
)
from agent_bom.ast_models import (
    ASTAnalysisResult,
    CallEdge,
    ControlFlowEdge,
    DetectedGuardrail,
    ExtractedPrompt,
    FlowFinding,
    ToolSignature,
    _FunctionAnalysis,
    _GoFunctionAnalysis,
    _GoToolRegistration,
)
from agent_bom.ast_signal_utils import (
    _GUARDRAIL_CALL_PATTERNS,
)
from agent_bom.ast_signal_utils import (
    check_prompt_risks as _check_prompt_risks,
)
from agent_bom.ast_signal_utils import (
    classify_prompt_type as _classify_prompt_type,
)


# Bounded depth for inter-procedural taint propagation. The taint analyzer
# already follows tainted parameters across helper-call boundaries with
# per-callsite parameter mapping; this cap pins the "bounded" claim with
# a concrete number so operators understand exactly how many hops the
# analyzer commits to following before it stops. Defaults to 4 — three
# helper hops past the tool entrypoint plus the entrypoint itself —
# which matches the depth the prior PR (#1488) committed to in writing.
def _max_taint_depth() -> int:
    raw = os.environ.get("AGENT_BOM_TAINT_MAX_DEPTH", "").strip()
    if not raw:
        return 4
    try:
        value = int(raw)
    except ValueError:
        return 4
    # Clamp to a sane operational range. Going deeper than 8 in practice
    # explodes the visit-set and produces near-duplicate findings; going
    # below 2 disables the inter-procedural pass entirely.
    return max(2, min(value, 8))


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
_PATH_ACCESS_CALLS = {
    "open",
    "Path.open",
    "Path.read_text",
    "Path.read_bytes",
    "Path.write_text",
    "Path.write_bytes",
    "send_file",
    "send_from_directory",
}
_HTTP_CLIENT_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "urllib.request.urlopen",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.request",
}
_SQL_CALLS = {"execute", "executemany", "cursor.execute", "cursor.executemany"}
_UNSAFE_DESERIALIZATION_CALLS = {
    "pickle.load",
    "pickle.loads",
    "yaml.load",
    "yaml.unsafe_load",
    "marshal.loads",
    "dill.loads",
    "jsonpickle.decode",
}
_XSS_CALLS = {"render_template_string", "Markup", "markupsafe.Markup"}
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
    "secure_filename",
    "werkzeug.utils.secure_filename",
    "safe_join",
    "werkzeug.utils.safe_join",
    "os.path.basename",
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
_JS_TS_UNTRUSTED_DATA_RE = re.compile(
    r"\b(?:user[A-Z_]\w*|user\w*|input|payload|req(?:uest)?\.(?:body|query|params)|ctx\.(?:body|query|params)|process\.env)\b",
    re.IGNORECASE,
)
_PROMPT_UNTRUSTED_INPUT_RE = re.compile(
    r"\b(?:user\w*|input|payload|message|content|query|prompt|instruction|body|request)\b",
    re.IGNORECASE,
)


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
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _extract_string_value(node.left)
        right = _extract_string_value(node.right)
        if left is not None or right is not None:
            left = left if left is not None else "{...}"
            right = right if right is not None else "{...}"
            return f"{left}{right}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        template = _extract_string_value(node.func.value)
        if template is not None:
            return template
    return None


def _expr_contains_untrusted_prompt_input(node: ast.AST) -> bool:
    """Return True when a prompt expression interpolates likely untrusted input."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and _PROMPT_UNTRUSTED_INPUT_RE.search(child.id):
            return True
        if isinstance(child, ast.Attribute):
            attr_name = _expr_name(child)
            if attr_name and _PROMPT_UNTRUSTED_INPUT_RE.search(attr_name):
                return True
        if isinstance(child, ast.Call):
            call_name = _call_name(child.func).lower()
            if call_name in {"input", "request.get_json", "request.args.get", "request.form.get"}:
                return True
    return False


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


def _module_name_for_rel_path(rel_path: str) -> str:
    path = Path(rel_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _package_name_for_module(module_name: str, rel_path: str) -> str:
    if Path(rel_path).name == "__init__.py":
        return module_name
    if "." not in module_name:
        return ""
    return module_name.rsplit(".", 1)[0]


def _resolve_imported_module(module: str | None, level: int, current_module: str, rel_path: str) -> str:
    if level <= 0:
        return module or ""
    package_name = _package_name_for_module(current_module, rel_path)
    package_parts = package_name.split(".") if package_name else []
    trim = max(level - 1, 0)
    if trim:
        package_parts = package_parts[: max(0, len(package_parts) - trim)]
    resolved_parts = [*package_parts]
    if module:
        resolved_parts.append(module)
    return ".".join(part for part in resolved_parts if part)


def _collect_python_import_aliases(
    tree: ast.AST,
    *,
    current_module: str,
    rel_path: str,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    imported_modules: dict[str, str] = {}
    imported_functions: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible_name = alias.asname or alias.name
                imported_modules[visible_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            resolved_module = _resolve_imported_module(node.module, node.level, current_module, rel_path)
            if not resolved_module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                visible_name = alias.asname or alias.name
                imported_functions[visible_name] = (resolved_module, alias.name)
    return imported_modules, imported_functions


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

    def is_literal_allowlist(expr: ast.AST) -> bool:
        if isinstance(expr, (ast.Set, ast.List, ast.Tuple)):
            return bool(expr.elts) and all(isinstance(elt, ast.Constant) for elt in expr.elts)
        return False

    for child in ast.walk(node):
        if isinstance(child, ast.Name) and any(hint in child.id.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Attribute) and any(hint in child.attr.lower() for hint in _VALIDATION_HINTS):
            return True
        if isinstance(child, ast.Compare):
            if any(isinstance(op, ast.In) for op in child.ops) and any(
                is_literal_allowlist(expr) for expr in [child.left, *child.comparators]
            ):
                return True
        if isinstance(child, ast.Call):
            call_name = _call_name(child.func).lower()
            if any(hint in call_name for hint in _VALIDATION_HINTS):
                return True
            if call_name in {"re.fullmatch", "re.match"} or call_name.endswith((".fullmatch", ".match")):
                return True
    return False


def _validation_source_names_from_expr(expr: ast.AST | None) -> set[str]:
    """Return identifiers directly constrained by a validation expression."""
    if expr is None:
        return set()
    if isinstance(expr, ast.Call):
        names: set[str] = set()
        if isinstance(expr.func, ast.Attribute):
            names.update(_names_in_expr(expr.func.value))
        for arg in expr.args:
            names.update(_names_in_expr(arg))
        for keyword in expr.keywords:
            names.update(_names_in_expr(keyword.value))
        return names
    return _names_in_expr(expr)


def _returns_boolean_constant(statements: list[ast.stmt], value: bool) -> bool:
    return any(
        isinstance(statement, ast.Return) and isinstance(statement.value, ast.Constant) and statement.value.value is value
        for statement in statements
    )


def _branch_definitely_exits(statements: list[ast.stmt]) -> bool:
    """Return True when a branch definitely stops control flow."""
    if not statements:
        return False
    last_statement = statements[-1]
    if isinstance(last_statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(last_statement, ast.If):
        return _branch_definitely_exits(last_statement.body) and _branch_definitely_exits(last_statement.orelse)
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


def _is_http_client_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _HTTP_CLIENT_CALLS


def _is_path_access_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if lower_name in {name.lower() for name in _PATH_ACCESS_CALLS}:
        return True
    return lower_name.endswith((".read_text", ".read_bytes", ".write_text", ".write_bytes", ".open"))


def _is_unsafe_deserialization_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _UNSAFE_DESERIALIZATION_CALLS}


def _expr_name(expr: ast.AST | None) -> str:
    if expr is None:
        return ""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _expr_name(expr.value)
        return f"{base}.{expr.attr}" if base else expr.attr
    return ""


def _uses_safe_yaml_loader(call: ast.Call) -> bool:
    call_name = _call_name(call.func).lower()
    if call_name != "yaml.load":
        return False
    safe_loader_names = {
        "yaml.safeloader",
        "safeloader",
        "yaml.csafeloader",
        "csafeloader",
    }
    for keyword in call.keywords:
        if keyword.arg != "Loader":
            continue
        if _expr_name(keyword.value).lower() in safe_loader_names:
            return True
    if len(call.args) >= 2 and _expr_name(call.args[1]).lower() in safe_loader_names:
        return True
    return False


def _call_keyword_bool(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
            return keyword.value.value
    return False


def _call_argument_expr(call: ast.Call, *, primary_arg_names: set[str] | None = None) -> ast.AST | None:
    if call.args:
        return call.args[0]
    if primary_arg_names:
        for keyword in call.keywords:
            if keyword.arg in primary_arg_names:
                return keyword.value
    return None


def _is_command_execution_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _SUBPROCESS_CALLS}


def _is_shell_execution_call(call_name: str, call: ast.Call) -> bool:
    lower_name = call_name.lower()
    if lower_name in {"os.system", "os.popen"}:
        return True
    return _call_keyword_bool(call, "shell")


def _expr_is_dynamic_or_tracked(expr: ast.AST | None, tracked_names: set[str]) -> bool:
    if _expr_uses_dynamic_string(expr):
        return True
    return isinstance(expr, ast.Name) and expr.id in tracked_names


def _is_xss_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in {name.lower() for name in _XSS_CALLS}


def _is_untrusted_source_call(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _UNTRUSTED_SOURCE_CALLS or lower_name.endswith(".get_json")


def _is_sanitizer_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    if lower_name in _SANITIZER_CALLS:
        return True
    return any(hint in lower_name for hint in _VALIDATION_HINTS)


def _expr_uses_dynamic_string(expr: ast.AST | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True
    return False


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
    current_module = _module_name_for_rel_path(rel_path)
    imported_modules, imported_functions = _collect_python_import_aliases(
        tree,
        current_module=current_module,
        rel_path=rel_path,
    )

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
                        if _expr_contains_untrusted_prompt_input(node.value):
                            risk_flags = [*risk_flags, "untrusted_input_interpolation"]
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
                        if _expr_contains_untrusted_prompt_input(kw.value):
                            risk_flags = [*risk_flags, "untrusted_input_interpolation"]
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
                module_name=current_module,
                param_names=[arg.arg for arg in node.args.args if arg.arg != "self"],
                node=node,
                parent_map=parent_map,
                cfg_edges=_build_function_cfg_edges(node, rel_path),
                imported_modules=dict(imported_modules),
                imported_functions=dict(imported_functions),
            )
            dynamic_string_names: set[str] = set()
            for inner_stmt in ast.walk(node):
                if isinstance(inner_stmt, ast.Assign) and _expr_uses_dynamic_string(inner_stmt.value):
                    for target in inner_stmt.targets:
                        dynamic_string_names.update(_target_names(target))
                elif isinstance(inner_stmt, ast.AnnAssign) and _expr_uses_dynamic_string(inner_stmt.value):
                    dynamic_string_names.update(_target_names(inner_stmt.target))
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
                if _is_unsafe_deserialization_call_name(call_name) and not _uses_safe_yaml_loader(inner):
                    flow_findings.append(
                        FlowFinding(
                            category="unsafe_deserialization",
                            title="Unsafe deserialization primitive detected",
                            detail=(
                                f"{rel_path} calls `{call_name}` which can deserialize attacker-controlled content without a safe loader."
                            ),
                            file_path=rel_path,
                            line_number=getattr(inner, "lineno", node.lineno),
                            entrypoint=node.name,
                            sink=call_name,
                            call_path=[node.name, call_name],
                        )
                    )
                if _is_command_execution_call_name(call_name) and _is_shell_execution_call(call_name, inner):
                    command_expr = _call_argument_expr(inner, primary_arg_names={"args", "command"})
                    if _expr_is_dynamic_or_tracked(command_expr, dynamic_string_names):
                        flow_findings.append(
                            FlowFinding(
                                category="command_string_construction",
                                title="Shell command is built through string interpolation",
                                detail=(
                                    f"{rel_path} builds a shell command dynamically before calling `{call_name}`, "
                                    "which is a common command injection pattern."
                                ),
                                file_path=rel_path,
                                line_number=getattr(inner, "lineno", node.lineno),
                                entrypoint=node.name,
                                sink=call_name,
                                call_path=[node.name, call_name],
                            )
                        )
                if _is_http_client_call_name(call_name):
                    url_expr = _call_argument_expr(inner, primary_arg_names={"url", "uri", "endpoint"})
                    if _expr_is_dynamic_or_tracked(url_expr, dynamic_string_names):
                        flow_findings.append(
                            FlowFinding(
                                category="ssrf_url_construction",
                                title="Outbound URL is built through string interpolation",
                                detail=(
                                    f"{rel_path} builds an outbound URL dynamically before calling `{call_name}`, "
                                    "which is a common SSRF pattern."
                                ),
                                file_path=rel_path,
                                line_number=getattr(inner, "lineno", node.lineno),
                                entrypoint=node.name,
                                sink=call_name,
                                call_path=[node.name, call_name],
                            )
                        )
                if _is_sql_call_name(call_name):
                    query_expr = inner.args[0] if inner.args else None
                    query_is_dynamic = _expr_uses_dynamic_string(query_expr)
                    if isinstance(query_expr, ast.Name) and query_expr.id in dynamic_string_names:
                        query_is_dynamic = True
                    if query_is_dynamic:
                        flow_findings.append(
                            FlowFinding(
                                category="sql_string_construction",
                                title="SQL query is built through string interpolation",
                                detail=(
                                    f"{rel_path} builds a SQL query dynamically before calling `{call_name}`, "
                                    "which is a common SQL injection pattern."
                                ),
                                file_path=rel_path,
                                line_number=getattr(inner, "lineno", node.lineno),
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
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis],
) -> _FunctionAnalysis | None:
    """Resolve a call target using same-file preference, then unique global match."""
    imported_target = caller.imported_functions.get(raw_name)
    if imported_target:
        resolved = by_module_and_name.get(imported_target)
        if resolved is not None:
            return resolved

    for alias, module_name in sorted(caller.imported_modules.items(), key=lambda item: len(item[0]), reverse=True):
        if not raw_name.startswith(f"{alias}."):
            continue
        target_name = raw_name[len(alias) + 1 :].split(".")[-1]
        resolved = by_module_and_name.get((module_name, target_name))
        if resolved is not None:
            return resolved

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
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)
        if func.module_name:
            by_module_and_name[(func.module_name, func.simple_name)] = func

    seen_findings: set[tuple[str, str, str, int, str]] = set()
    validator_summary_cache: dict[str, set[str]] = {}

    def validator_param_names(
        func: _FunctionAnalysis,
        seen: set[str] | None = None,
    ) -> set[str]:
        cached = validator_summary_cache.get(func.qualified_name)
        if cached is not None:
            return cached
        if func.node is None:
            validator_summary_cache[func.qualified_name] = set()
            return set()

        seen = set(seen or ())
        if func.qualified_name in seen:
            return set()
        seen.add(func.qualified_name)

        validated: set[str] = set()
        body_statements = list(func.node.body)
        for statement in ast.walk(func.node):
            if isinstance(statement, ast.Return):
                if statement.value is not None and _expr_contains_validation_hint(statement.value):
                    validated.update(name for name in _validation_source_names_from_expr(statement.value) if name in func.param_names)
                    continue
                if isinstance(statement.value, ast.Call):
                    call_name = _call_name(statement.value.func)
                    callee = _resolve_called_function(func, call_name, by_name, by_module_and_name) if call_name else None
                    if callee is not None:
                        callee_validated = validator_param_names(callee, seen)
                        for param_name, arg in zip(callee.param_names, statement.value.args, strict=False):
                            if param_name in callee_validated:
                                validated.update(name for name in _names_in_expr(arg) if name in func.param_names)
                        for keyword in statement.value.keywords:
                            if keyword.arg and keyword.arg in callee_validated:
                                validated.update(name for name in _names_in_expr(keyword.value) if name in func.param_names)
            if isinstance(statement, ast.If) and _expr_contains_validation_hint(statement.test):
                branch_validated = {name for name in _validation_source_names_from_expr(statement.test) if name in func.param_names}
                if branch_validated and (
                    (_returns_boolean_constant(statement.body, True) and _returns_boolean_constant(statement.orelse, False))
                    or (_returns_boolean_constant(statement.body, False) and _returns_boolean_constant(statement.orelse, True))
                ):
                    validated.update(branch_validated)
        for index, statement in enumerate(body_statements):
            if not isinstance(statement, ast.If) or not _expr_contains_validation_hint(statement.test):
                continue
            branch_validated = {name for name in _validation_source_names_from_expr(statement.test) if name in func.param_names}
            if not branch_validated:
                continue
            tail_statements = body_statements[index + 1 :]
            if (_returns_boolean_constant(statement.body, True) and _returns_boolean_constant(tail_statements, False)) or (
                _returns_boolean_constant(statement.body, False) and _returns_boolean_constant(tail_statements, True)
            ):
                validated.update(branch_validated)

        validator_summary_cache[func.qualified_name] = validated
        return validated

    def guarded_names_from_expr(
        func: _FunctionAnalysis,
        expr: ast.AST | None,
    ) -> set[str]:
        if expr is None:
            return set()
        if _expr_contains_validation_hint(expr):
            return _validation_source_names_from_expr(expr)
        if isinstance(expr, ast.Call):
            call_name = _call_name(expr.func)
            callee = _resolve_called_function(func, call_name, by_name, by_module_and_name) if call_name else None
            if callee is None:
                return set()
            callee_validated = validator_param_names(callee)
            guarded: set[str] = set()
            for param_name, arg in zip(callee.param_names, expr.args, strict=False):
                if param_name in callee_validated:
                    guarded.update(_names_in_expr(arg))
            for keyword in expr.keywords:
                if keyword.arg and keyword.arg in callee_validated:
                    guarded.update(_names_in_expr(keyword.value))
            return guarded
        if isinstance(expr, ast.BoolOp):
            guarded_names: set[str] = set()
            for value in expr.values:
                guarded_names.update(guarded_names_from_expr(func, value))
            return guarded_names
        if isinstance(expr, ast.UnaryOp):
            return guarded_names_from_expr(func, expr.operand)
        return set()

    def post_if_guarded_names(
        func: _FunctionAnalysis,
        statement: ast.If,
    ) -> set[str]:
        """Return names guarded on the path that continues after an if-statement."""
        test = statement.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            guarded = guarded_names_from_expr(func, test.operand)
            if guarded and _branch_definitely_exits(statement.body):
                return guarded
            return set()

        guarded = guarded_names_from_expr(func, test)
        if guarded and _branch_definitely_exits(statement.orelse):
            return guarded
        return set()

    max_depth = _max_taint_depth()

    def analyze_function(
        func: _FunctionAnalysis,
        tainted_params: set[str],
        call_path: list[str],
        visited: set[tuple[str, tuple[str, ...]]],
    ) -> tuple[list[FlowFinding], bool]:
        # Bounded inter-procedural traversal: the visit-set already prevents
        # cycles, but a long fan-out chain could still explode the work
        # without surfacing a finding the operator can act on. Cap the
        # call_path length so the analyzer commits to a documented depth.
        if len(call_path) > max_depth:
            return [], False
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
            receiver_tainted = False
            receiver_findings: list[FlowFinding] = []
            if isinstance(call.func, ast.Attribute):
                receiver_tainted, receiver_findings = expr_taint(call.func.value, current_sanitized)

            arg_tainted = receiver_tainted or any(result[0] for result in arg_results) or any(result[1] for result in kw_results)
            nested_findings: list[FlowFinding] = []
            nested_findings.extend(receiver_findings)
            for _, child_findings in arg_results:
                nested_findings.extend(child_findings)
            for _, _, child_findings in kw_results:
                nested_findings.extend(child_findings)

            if _is_untrusted_source_call(call_name):
                return True, nested_findings
            if _is_sanitizer_call_name(call_name):
                return False, nested_findings

            source_names: set[str] = set()
            if receiver_tainted and isinstance(call.func, ast.Attribute):
                source_names.update(name for name in _names_in_expr(call.func.value) if name in tainted_vars)
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
                if _is_path_access_call_name(call_name):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_path_access",
                            title="Untrusted data reaches a file-system path sink",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )
                elif _is_http_client_call_name(call_name):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_ssrf_sink",
                            title="Untrusted data reaches an outbound URL sink",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )
                elif _is_command_execution_call_name(call_name) and _is_shell_execution_call(call_name, call):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_command_execution",
                            title="Untrusted data reaches shell command execution",
                            detail=f"Untrusted data ({source_label}) reaches `{call_name}` with shell execution in {func.file_path}.",
                            file_path=func.file_path,
                            line_number=line_number,
                            entrypoint=call_path[0],
                            sink=call_name,
                            call_path=call_path + [call_name],
                            source=source_label,
                        )
                    )
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
                elif call_name in _DANGEROUS_CALLS:
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
                elif _is_xss_sink_call_name(call_name):
                    nested_findings.append(
                        _build_flow_finding(
                            category="tainted_xss_sink",
                            title="Untrusted data reaches an HTML rendering sink",
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

            callee = _resolve_called_function(func, call_name, by_name, by_module_and_name) if call_name else None
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
                    current_sanitized.update(guarded_names_from_expr(func, statement.test))
                    continue
                if isinstance(statement, ast.If):
                    _, test_findings = expr_taint(statement.test, current_sanitized)
                    findings_acc.extend(test_findings)
                    guarded_names = guarded_names_from_expr(func, statement.test)
                    body_tainted, body_findings, body_returns_tainted = walk_statements(statement.body, current_sanitized | guarded_names)
                    orelse_tainted, orelse_findings, orelse_returns_tainted = walk_statements(statement.orelse, set(current_sanitized))
                    findings_acc.extend(body_findings)
                    findings_acc.extend(orelse_findings)
                    tainted_vars.update(body_tainted | orelse_tainted)
                    local_tainted.update(body_tainted | orelse_tainted)
                    current_sanitized.update(post_if_guarded_names(func, statement))
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
    """Build a lightweight call graph and bounded helper-chain findings.

    This path is intentionally lightweight: it follows resolved helper-call
    chains from tool entrypoints to already-detected dangerous sinks, but it
    does not claim full inter-procedural taint propagation or proof-grade
    reachability across arbitrary call graphs.
    """
    by_name: dict[str, list[_FunctionAnalysis]] = {}
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)
        if func.module_name:
            by_module_and_name[(func.module_name, func.simple_name)] = func

    adjacency: dict[str, list[_FunctionAnalysis]] = {func.qualified_name: [] for func in functions}
    edges: list[CallEdge] = []
    for func in functions:
        for raw_name, line_num in func.called_names:
            callee = _resolve_called_function(func, raw_name, by_name, by_module_and_name)
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
    max_depth = _max_taint_depth()
    for func in functions:
        if not func.is_tool:
            continue
        queue: list[tuple[str, list[str]]] = [(func.qualified_name, [func.simple_name])]
        visited: set[str] = set()
        while queue:
            current_id, path = queue.pop(0)
            if len(path) > max_depth:
                # Stop following helper chains past the configured depth so
                # the bounded claim is honored uniformly across the two
                # taint surfaces (this BFS + the parameter-level recursion
                # in _build_taint_findings).
                continue
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
                        title="Tool helper chain reaches dangerous sink",
                        detail=(
                            f"Tool `{func.simple_name}` reaches `{sink_name}` through a bounded helper-call chain in {current.file_path}."
                        ),
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
