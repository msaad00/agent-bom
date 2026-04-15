"""Go analyzer helpers extracted from ast_analyzer."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from agent_bom.ast_models import (
    CallEdge,
    DetectedGuardrail,
    ExtractedPrompt,
    FlowFinding,
    ToolSignature,
    _GoCallSite,
    _GoFileAnalysis,
    _GoFunctionAnalysis,
    _GoToolRegistration,
)
from agent_bom.ast_signal_utils import _GUARDRAIL_CALL_PATTERNS, check_prompt_risks, classify_prompt_type

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024  # 512KB
_GO_PROMPT_ASSIGN_RE = re.compile(
    r"""
    (?P<name>systemPrompt|system_prompt|instructions|promptTemplate|prompt_template|template|prefix|preamble|persona|backstory|role)\s*
    (?::=|=)\s*(?P<quote>`|"|')(?P<text>[\s\S]{0,2000}?)(?P=quote)
    """,
    re.VERBOSE | re.IGNORECASE,
)
_GO_TOOL_START_RE = re.compile(r"""\b(?:AddTool|RegisterTool|NewTool|Tool)\s*\(""", re.IGNORECASE)
_GO_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("exec.Command", re.compile(r"\bexec\.Command(?:Context)?\s*\(")),
    ("os.WriteFile", re.compile(r"\bos\.WriteFile\s*\(")),
    ("ioutil.WriteFile", re.compile(r"\bioutil\.WriteFile\s*\(")),
    ("template.HTML", re.compile(r"\btemplate\.HTML\s*\(")),
    ("template.JS", re.compile(r"\btemplate\.JS\s*\(")),
]
_GO_LLM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai.ChatCompletion", re.compile(r"\bCreateChatCompletion\b")),
    ("anthropic.Messages", re.compile(r"\bMessages\.Create\b")),
]
_GO_DANGEROUS_NAMES = frozenset(name for name, _ in [*_GO_DANGEROUS_PATTERNS, *_GO_LLM_PATTERNS])
_GO_FRAMEWORK_HINTS: dict[str, str] = {
    "github.com/modelcontextprotocol": "MCP",
    "github.com/openai/openai-go": "OpenAI",
    "github.com/anthropics/anthropic-sdk-go": "Anthropic",
    "github.com/tmc/langchaingo": "LangChain",
}
_GO_PACKAGE_RE = re.compile(r"""^\s*package\s+(?P<name>[A-Za-z_]\w*)""", re.MULTILINE)
_GO_IMPORT_SINGLE_RE = re.compile(
    r"""^\s*import(?:\s+[A-Za-z_][\w]*)?\s+(?P<quote>`|"|')(?P<module>[^`"']+)(?P=quote)""",
    re.MULTILINE,
)
_GO_IMPORT_BLOCK_RE = re.compile(r"""^\s*import\s*\((?P<body>[\s\S]*?)^\s*\)""", re.MULTILINE)
_GO_IMPORT_LITERAL_RE = re.compile(r"""(?:(?P<alias>[A-Za-z_][\w]*)\s+)?(?P<quote>`|"|')(?P<module>[^`"']+)(?P=quote)""")
_GO_FUNC_DECL_RE = re.compile(
    r"""\bfunc\s+(?:\([^)]+\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*(?:\([^)]*\)\s*)?(?:[A-Za-z_][\w\.\*\[\]]*\s*)?\{""",
    re.MULTILINE,
)
_GO_CALL_RE = re.compile(r"""\b(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(""")
_GO_CALL_SKIP = frozenset({"if", "for", "switch", "select", "return", "defer", "go", "func", "make", "append", "len", "cap"})
_GO_HTTP_CALL_SUFFIXES = frozenset({"get", "post", "postform", "do", "head"})
_GO_SQL_CALL_SUFFIXES = frozenset({"query", "querycontext", "queryrow", "queryrowcontext", "exec", "execcontext"})
_GO_PATH_CALL_SUFFIXES = frozenset({"open", "openfile", "readfile", "writefile"})
_GO_UNTRUSTED_DATA_RE = re.compile(
    r"\b(?:user[A-Z_]\w*|user\w*|input|payload|req(?:uest)?\.(?:body|query|params)|ctx\.(?:body|query|params)|process\.env)\b",
    re.IGNORECASE,
)


def _frameworks_from_go_modules(module_names: set[str]) -> list[str]:
    frameworks: set[str] = set()
    for module_name in module_names:
        normalized = module_name.strip().lower()
        for prefix, framework in _GO_FRAMEWORK_HINTS.items():
            if normalized == prefix or normalized.startswith(f"{prefix}/"):
                frameworks.add(framework)
    return sorted(frameworks)


def _go_scope_name_for_rel_path(rel_path: str) -> str:
    parent = PurePosixPath(rel_path).parent.as_posix()
    return "." if parent in {"", "."} else parent


def _go_package_name(source: str) -> str:
    match = _GO_PACKAGE_RE.search(source)
    return match.group("name") if match else ""


def _go_function_key(scope_name: str, function_name: str) -> str:
    return f"{scope_name}:{function_name}"


def _go_function_display_name(scope_name: str, function_name: str, name_counts: Mapping[str, int]) -> str:
    if name_counts.get(function_name, 0) <= 1:
        return function_name
    if scope_name in {"", "."}:
        return function_name
    return f"{scope_name.replace('/', '.')}.{function_name}"


def _go_identifier_names(expr: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"\b[A-Za-z_]\w*\b", expr):
        name = match.group(0)
        lower_name = name.lower()
        if lower_name in _GO_CALL_SKIP or name in {"nil", "true", "false"}:
            continue
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _split_top_level_args(args_body: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    paren_depth = brace_depth = bracket_depth = 0
    in_quote = ""
    escaped = False
    for char in args_body:
        if in_quote:
            current.append(char)
            if in_quote != "`" and char == "\\" and not escaped:
                escaped = True
                continue
            if char == in_quote and (in_quote == "`" or not escaped):
                in_quote = ""
            escaped = False
            continue
        if char in {'"', "'", "`"}:
            in_quote = char
            current.append(char)
            escaped = False
            continue
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        elif char == "," and paren_depth == 0 and brace_depth == 0 and bracket_depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _go_param_names(params_segment: str) -> list[str]:
    params: list[str] = []
    pending_names: list[str] = []
    for part in _split_top_level_args(params_segment):
        normalized = part.strip()
        if not normalized:
            continue
        normalized = normalized.lstrip("*")
        if " " not in normalized:
            if re.fullmatch(r"[A-Za-z_]\w*", normalized):
                pending_names.append(normalized)
            continue
        tokens = [token for token in normalized.replace("...", " ").split() if token]
        if len(tokens) < 2:
            continue
        explicit_names = [token.rstrip(",") for token in tokens[:-1] if re.fullmatch(r"[A-Za-z_]\w*", token.rstrip(","))]
        if pending_names or explicit_names:
            params.extend(pending_names + explicit_names)
            pending_names = []
    params.extend(pending_names)
    deduped: list[str] = []
    seen: set[str] = set()
    for name in params:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _go_identifier_looks_untrusted(name: str) -> bool:
    return bool(name and _GO_UNTRUSTED_DATA_RE.search(name))


def _is_go_command_sink_call_name(call_name: str) -> bool:
    return call_name == "exec.Command"


def _is_go_http_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return any(lower_name == suffix or lower_name.endswith(f".{suffix}") for suffix in _GO_HTTP_CALL_SUFFIXES)


def _is_go_sql_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return any(lower_name == suffix or lower_name.endswith(f".{suffix}") for suffix in _GO_SQL_CALL_SUFFIXES)


def _is_go_path_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return any(lower_name == suffix or lower_name.endswith(f".{suffix}") for suffix in _GO_PATH_CALL_SUFFIXES)


def _is_go_xss_sink_call_name(call_name: str) -> bool:
    return call_name in {"template.HTML", "template.JS"}


def _is_go_dangerous_call_name(call_name: str) -> bool:
    return _is_go_command_sink_call_name(call_name) or _is_go_path_sink_call_name(call_name) or _is_go_xss_sink_call_name(call_name)


def _balanced_segment(source: str, open_index: int, *, open_char: str, close_char: str) -> tuple[str, int] | None:
    if open_index < 0 or open_index >= len(source) or source[open_index] != open_char:
        return None
    depth = 0
    in_quote = ""
    escaped = False
    for index in range(open_index, len(source)):
        char = source[index]
        if in_quote:
            if in_quote != "`" and char == "\\" and not escaped:
                escaped = True
                continue
            if char == in_quote and (in_quote == "`" or not escaped):
                in_quote = ""
            escaped = False
            continue
        if char in {'"', "'", "`"}:
            in_quote = char
            escaped = False
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return source[open_index : index + 1], index + 1
    return None


def _line_number_from_index(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _go_import_aliases(source: str) -> tuple[dict[str, str], set[str], dict[str, str]]:
    alias_map: dict[str, str] = {}
    modules: set[str] = set()
    imported_aliases: dict[str, str] = {}

    def register(module_name: str, alias: str | None) -> None:
        normalized = module_name.strip()
        if not normalized:
            return
        modules.add(normalized)
        module_tail = normalized.rsplit("/", 1)[-1]
        canonical = module_tail.split(".", 1)[0]
        if alias and alias not in {".", "_"}:
            alias_map[alias] = canonical
            imported_aliases[alias] = normalized
        alias_map.setdefault(canonical, canonical)
        imported_aliases.setdefault(canonical, normalized)

    for match in _GO_IMPORT_SINGLE_RE.finditer(source):
        register(match.group("module"), None)
    for match in _GO_IMPORT_BLOCK_RE.finditer(source):
        body = match.group("body")
        for item in _GO_IMPORT_LITERAL_RE.finditer(body):
            register(item.group("module"), item.group("alias"))

    return alias_map, modules, imported_aliases


def _canonicalize_go_call_name(raw_name: str, alias_map: dict[str, str]) -> str:
    if "." not in raw_name:
        return raw_name
    base, remainder = raw_name.split(".", 1)
    canonical_base = alias_map.get(base, base)
    return f"{canonical_base}.{remainder}"


def _go_call_sites(body: str, *, line_offset: int, alias_map: dict[str, str]) -> list[_GoCallSite]:
    call_sites: list[_GoCallSite] = []
    for match in _GO_CALL_RE.finditer(body):
        raw_name = match.group("name")
        if raw_name in _GO_CALL_SKIP:
            continue
        canonical = _canonicalize_go_call_name(raw_name, alias_map)
        if canonical in _GO_CALL_SKIP:
            continue
        open_index = match.end() - 1
        args_segment = _balanced_segment(body, open_index, open_char="(", close_char=")")
        argument_names: list[list[str]] = []
        if args_segment is not None:
            args_text, _ = args_segment
            argument_names = [_go_identifier_names(part) for part in _split_top_level_args(args_text[1:-1])]
        call_sites.append(
            _GoCallSite(
                name=canonical,
                line_number=line_offset + body[: match.start()].count("\n"),
                argument_names=argument_names,
            )
        )
    return call_sites


def _collect_go_functions(
    source: str,
    alias_map: dict[str, str],
    *,
    rel_path: str,
    scope_name: str,
    package_name: str,
    imported_aliases: dict[str, str],
) -> dict[str, _GoFunctionAnalysis]:
    functions: dict[str, _GoFunctionAnalysis] = {}
    for match in _GO_FUNC_DECL_RE.finditer(source):
        function_name = match.group("name")
        brace_index = source.find("{", match.end() - 1)
        if brace_index < 0:
            continue
        body_segment = _balanced_segment(source, brace_index, open_char="{", close_char="}")
        if body_segment is None:
            continue
        body_text, _ = body_segment
        line_number = _line_number_from_index(source, match.start())
        body_line_offset = _line_number_from_index(source, brace_index) - 1
        params_start = source.find("(", match.end("name"))
        params_segment = _balanced_segment(source, params_start, open_char="(", close_char=")") if params_start >= 0 else None
        call_sites = _go_call_sites(body_text, line_offset=body_line_offset, alias_map=alias_map)
        functions[function_name] = _GoFunctionAnalysis(
            name=function_name,
            line_number=line_number,
            file_path=rel_path,
            scope_name=scope_name,
            package_name=package_name,
            param_names=_go_param_names(params_segment[0][1:-1]) if params_segment is not None else [],
            imported_aliases=dict(imported_aliases),
            call_sites=call_sites,
            dangerous_call_sites=[site for site in call_sites if site.name in _GO_DANGEROUS_NAMES],
        )
    return functions


def _collect_go_tool_registrations(
    source: str,
    *,
    alias_map: dict[str, str],
    rel_path: str,
    scope_name: str,
    imported_aliases: dict[str, str],
    package_name: str,
    functions: dict[str, _GoFunctionAnalysis],
) -> list[_GoToolRegistration]:
    registrations: list[_GoToolRegistration] = []
    for match in _GO_TOOL_START_RE.finditer(source):
        open_index = source.find("(", match.start())
        args_segment = _balanced_segment(source, open_index, open_char="(", close_char=")")
        if args_segment is None:
            continue
        args_text, _ = args_segment
        args = _split_top_level_args(args_text[1:-1])
        if not args:
            continue
        tool_name = ""
        if args[0] and args[0][0] in {'"', "'", "`"} and args[0][-1] == args[0][0]:
            tool_name = args[0][1:-1]
        if not tool_name:
            continue

        handler_name = f"tool:{tool_name}"
        inline_func_index = args_text.rfind("func(")
        if inline_func_index >= 0:
            inline_global_index = open_index + inline_func_index
            brace_index = source.find("{", inline_global_index)
            body_segment = _balanced_segment(source, brace_index, open_char="{", close_char="}") if brace_index >= 0 else None
            if body_segment is not None:
                body_text, _ = body_segment
                body_line_offset = _line_number_from_index(source, brace_index) - 1
                call_sites = _go_call_sites(body_text, line_offset=body_line_offset, alias_map=alias_map)
                functions[handler_name] = _GoFunctionAnalysis(
                    name=handler_name,
                    line_number=_line_number_from_index(source, inline_global_index),
                    file_path=rel_path,
                    scope_name=scope_name,
                    package_name=package_name,
                    imported_aliases=dict(imported_aliases),
                    call_sites=call_sites,
                    dangerous_call_sites=[site for site in call_sites if site.name in _GO_DANGEROUS_NAMES],
                )
        else:
            for candidate in reversed(args[1:]):
                bare = candidate.strip().lstrip("&").strip()
                if re.fullmatch(r"[A-Za-z_]\w*", bare):
                    handler_name = bare
                    break

        registrations.append(
            _GoToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                scope_name=scope_name,
                imported_aliases=dict(imported_aliases),
            )
        )
    return registrations


def _resolve_go_scope_from_module(
    module_name: str,
    *,
    known_scopes: set[str],
    package_scopes: Mapping[str, set[str]],
    basename_scopes: Mapping[str, set[str]],
) -> str | None:
    normalized = module_name.strip().strip("/")
    if not normalized:
        return None
    candidates: set[str] = set()
    if normalized in known_scopes:
        candidates.add(normalized)
    tail = normalized.rsplit("/", 1)[-1]
    candidates.update(package_scopes.get(tail, set()))
    candidates.update(basename_scopes.get(tail, set()))
    candidates.update(scope for scope in known_scopes if scope not in {"", "."} and normalized.endswith(scope))
    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def _resolve_go_callee_key(
    reference_name: str,
    function: _GoFunctionAnalysis,
    same_scope_names: set[str],
    function_registry: Mapping[str, _GoFunctionAnalysis],
    *,
    known_scopes: set[str],
    package_scopes: Mapping[str, set[str]],
    basename_scopes: Mapping[str, set[str]],
) -> str | None:
    if reference_name in same_scope_names:
        key = _go_function_key(function.scope_name, reference_name)
        if key in function_registry:
            return key

    if "." not in reference_name:
        return None

    alias, remainder = reference_name.split(".", 1)
    imported_module = function.imported_aliases.get(alias)
    if not imported_module:
        return None
    local_scope = _resolve_go_scope_from_module(
        imported_module,
        known_scopes=known_scopes,
        package_scopes=package_scopes,
        basename_scopes=basename_scopes,
    )
    if not local_scope:
        return None
    function_name = remainder.split(".", 1)[0]
    key = _go_function_key(local_scope, function_name)
    if key in function_registry:
        return key
    return None


def build_go_flow_findings(
    *,
    functions: Mapping[str, _GoFunctionAnalysis],
    tool_registrations: Sequence[_GoToolRegistration],
) -> tuple[list[CallEdge], list[FlowFinding]]:
    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    call_edges: list[CallEdge] = []
    seen_edges: set[tuple[str, str, int]] = set()
    name_counts: dict[str, int] = {}
    scope_function_names: dict[str, set[str]] = {}
    package_scopes: dict[str, set[str]] = {}
    basename_scopes: dict[str, set[str]] = {}
    known_scopes: set[str] = set()

    for function in functions.values():
        name_counts[function.name] = name_counts.get(function.name, 0) + 1
        scope_function_names.setdefault(function.scope_name, set()).add(function.name)
        known_scopes.add(function.scope_name)
        if function.package_name:
            package_scopes.setdefault(function.package_name, set()).add(function.scope_name)
        scope_basename = PurePosixPath(function.scope_name).name if function.scope_name not in {"", "."} else "."
        basename_scopes.setdefault(scope_basename, set()).add(function.scope_name)

    def display_name(function_key: str) -> str:
        function = functions[function_key]
        return _go_function_display_name(function.scope_name, function.name, name_counts)

    for function_key, function in functions.items():
        for call_site in function.call_sites:
            callee_key = _resolve_go_callee_key(
                call_site.name,
                function,
                scope_function_names.get(function.scope_name, set()),
                functions,
                known_scopes=known_scopes,
                package_scopes=package_scopes,
                basename_scopes=basename_scopes,
            )
            if not callee_key or callee_key == function_key:
                continue
            adjacency[function_key].add(callee_key)
            edge_key = (display_name(function_key), display_name(callee_key), call_site.line_number)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            call_edges.append(
                CallEdge(
                    caller=display_name(function_key),
                    callee=display_name(callee_key),
                    file_path=function.file_path,
                    line_number=call_site.line_number,
                )
            )

    def resolve_registration_handler(registration: _GoToolRegistration) -> str | None:
        key = _go_function_key(registration.scope_name, registration.handler_name)
        if key in functions:
            return key
        imported_module = registration.imported_aliases.get(registration.handler_name.split(".", 1)[0], "")
        if imported_module or "." in registration.handler_name:
            pseudo_function = _GoFunctionAnalysis(
                name=registration.handler_name,
                line_number=registration.line_number,
                file_path=registration.file_path,
                scope_name=registration.scope_name,
                imported_aliases=registration.imported_aliases,
            )
            return _resolve_go_callee_key(
                registration.handler_name,
                pseudo_function,
                scope_function_names.get(registration.scope_name, set()),
                functions,
                known_scopes=known_scopes,
                package_scopes=package_scopes,
                basename_scopes=basename_scopes,
            )
        return None

    findings: list[FlowFinding] = []
    seen_findings: set[tuple[str, str, int, str]] = set()
    seen_taint_findings: set[tuple[str, str, str, int, str]] = set()

    for registration in tool_registrations:
        handler_key = resolve_registration_handler(registration)
        handler_display_name = registration.handler_name
        handler_file_path = registration.file_path
        if handler_key is not None:
            handler_display_name = display_name(handler_key)
            handler_file_path = functions[handler_key].file_path
        edge_key = (registration.tool_name, handler_display_name, registration.line_number)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            call_edges.append(
                CallEdge(
                    caller=registration.tool_name,
                    callee=handler_display_name,
                    file_path=handler_file_path,
                    line_number=registration.line_number,
                )
            )

        if handler_key is None:
            continue

        queue: list[tuple[str, list[str]]] = [(handler_key, [handler_key])]
        visited: set[str] = set()
        while queue:
            current_key, path = queue.pop(0)
            if current_key in visited:
                continue
            visited.add(current_key)
            current = functions[current_key]
            current_display_name = display_name(current_key)
            for sink in current.dangerous_call_sites:
                if sink.name not in _GO_DANGEROUS_NAMES:
                    continue
                dedup_key = (registration.tool_name, sink.name, sink.line_number, current_display_name)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                is_interprocedural = len(path) > 1
                findings.append(
                    FlowFinding(
                        category="go_interprocedural_dangerous_flow" if is_interprocedural else "go_tool_dangerous_flow",
                        title=(
                            "Go tool reaches dangerous sink through helper flow"
                            if is_interprocedural
                            else "Go tool handler reaches dangerous sink"
                        ),
                        detail=f"Tool `{registration.tool_name}` reaches `{sink.name}` through Go code in {current.file_path}.",
                        file_path=current.file_path,
                        line_number=sink.line_number,
                        entrypoint=registration.tool_name,
                        sink=sink.name,
                        call_path=[registration.tool_name, *[display_name(name) for name in path], sink.name],
                    )
                )
            for next_callee_key in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee_key, path + [next_callee_key]))

        initial_tainted = set(functions[handler_key].param_names)
        if not initial_tainted:
            for call_site in functions[handler_key].call_sites:
                for arg_names in call_site.argument_names:
                    initial_tainted.update(name for name in arg_names if _go_identifier_looks_untrusted(name))
        if not initial_tainted:
            continue

        taint_queue: list[tuple[str, list[str], frozenset[str]]] = [(handler_key, [handler_key], frozenset(initial_tainted))]
        visited_states: set[tuple[str, tuple[str, ...]]] = set()
        while taint_queue:
            current_key, path, tainted_params = taint_queue.pop(0)
            visit_key = (current_key, tuple(sorted(tainted_params)))
            if visit_key in visited_states:
                continue
            visited_states.add(visit_key)
            current = functions[current_key]
            current_display_name = display_name(current_key)
            current_tainted = set(tainted_params)

            for call_site in current.call_sites:
                tainted_sources = sorted(
                    {
                        name
                        for arg_names in call_site.argument_names
                        for name in arg_names
                        if name in current_tainted or _go_identifier_looks_untrusted(name)
                    }
                )
                if not tainted_sources:
                    continue

                sink_category = ""
                title = ""
                if _is_go_command_sink_call_name(call_site.name):
                    sink_category = "go_tainted_command_execution"
                    title = "Go tool routes tainted input into command execution"
                elif _is_go_http_sink_call_name(call_site.name):
                    sink_category = "go_tainted_ssrf_sink"
                    title = "Go tool routes tainted input into an outbound HTTP sink"
                elif _is_go_sql_sink_call_name(call_site.name):
                    sink_category = "go_tainted_sql_query"
                    title = "Go tool routes tainted input into a SQL sink"
                elif _is_go_path_sink_call_name(call_site.name):
                    sink_category = "go_tainted_path_access"
                    title = "Go tool routes tainted input into a filesystem path sink"
                elif _is_go_xss_sink_call_name(call_site.name):
                    sink_category = "go_tainted_xss_sink"
                    title = "Go tool routes tainted input into an HTML rendering sink"

                if sink_category:
                    taint_dedup_key = (sink_category, registration.tool_name, call_site.name, call_site.line_number, current_display_name)
                    if taint_dedup_key not in seen_taint_findings:
                        seen_taint_findings.add(taint_dedup_key)
                        findings.append(
                            FlowFinding(
                                category=sink_category,
                                title=title,
                                detail=(
                                    f"Tool `{registration.tool_name}` passes tainted Go input into "
                                    f"`{call_site.name}` in {current.file_path}."
                                ),
                                file_path=current.file_path,
                                line_number=call_site.line_number,
                                entrypoint=registration.tool_name,
                                sink=call_site.name,
                                call_path=[registration.tool_name, *[display_name(name) for name in path], call_site.name],
                                source=", ".join(tainted_sources),
                            )
                        )

                if _is_go_dangerous_call_name(call_site.name):
                    taint_dedup_key = (
                        "go_tainted_dangerous_sink",
                        registration.tool_name,
                        call_site.name,
                        call_site.line_number,
                        current_display_name,
                    )
                    if taint_dedup_key not in seen_taint_findings:
                        seen_taint_findings.add(taint_dedup_key)
                        findings.append(
                            FlowFinding(
                                category="go_tainted_dangerous_sink",
                                title="Go tool routes tainted input into a dangerous sink",
                                detail=(
                                    f"Tool `{registration.tool_name}` passes tainted Go input into "
                                    f"`{call_site.name}` in {current.file_path}."
                                ),
                                file_path=current.file_path,
                                line_number=call_site.line_number,
                                entrypoint=registration.tool_name,
                                sink=call_site.name,
                                call_path=[registration.tool_name, *[display_name(name) for name in path], call_site.name],
                                source=", ".join(tainted_sources),
                            )
                        )

                callee_key = _resolve_go_callee_key(
                    call_site.name,
                    current,
                    scope_function_names.get(current.scope_name, set()),
                    functions,
                    known_scopes=known_scopes,
                    package_scopes=package_scopes,
                    basename_scopes=basename_scopes,
                )
                if not callee_key or callee_key == current_key:
                    continue
                callee = functions[callee_key]
                tainted_callee_params: set[str] = set()
                for index, arg_names in enumerate(call_site.argument_names):
                    if index >= len(callee.param_names):
                        break
                    if any(name in current_tainted or _go_identifier_looks_untrusted(name) for name in arg_names):
                        tainted_callee_params.add(callee.param_names[index])
                if tainted_callee_params:
                    taint_queue.append((callee_key, path + [callee_key], frozenset(tainted_callee_params)))

    return call_edges, findings


def scan_go_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _GoFileAnalysis | None,
]:
    """Extract prompt/tool/guardrail/dangerous-call signals from Go source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    prompts: list[ExtractedPrompt] = []
    guardrails: list[DetectedGuardrail] = []
    tools: list[ToolSignature] = []
    flow_findings: list[FlowFinding] = []
    frameworks: list[str] = []
    call_edges: list[CallEdge] = []

    scope_name = _go_scope_name_for_rel_path(rel_path)
    package_name = _go_package_name(source)
    alias_map, imported_modules, imported_aliases = _go_import_aliases(source)
    frameworks = _frameworks_from_go_modules(imported_modules)
    functions = _collect_go_functions(
        source,
        alias_map,
        rel_path=rel_path,
        scope_name=scope_name,
        package_name=package_name,
        imported_aliases=imported_aliases,
    )
    tool_registrations = _collect_go_tool_registrations(
        source,
        alias_map=alias_map,
        rel_path=rel_path,
        scope_name=scope_name,
        imported_aliases=imported_aliases,
        package_name=package_name,
        functions=functions,
    )
    go_analysis = _GoFileAnalysis(
        scope_name=scope_name,
        package_name=package_name,
        functions=functions,
        tool_registrations=tool_registrations,
    )

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
                prompt_type=classify_prompt_type(var_name),
                risk_flags=check_prompt_risks(text),
            )
        )

    seen_tool_names: set[tuple[str, int]] = set()
    for registration in tool_registrations:
        tool_name = registration.tool_name.strip()
        dedup_key = (tool_name, registration.line_number)
        if not tool_name or dedup_key in seen_tool_names:
            continue
        seen_tool_names.add(dedup_key)
        tools.append(
            ToolSignature(
                name=tool_name,
                parameters=[],
                return_type="unknown",
                description="Go MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
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

    return prompts, guardrails, tools, flow_findings, frameworks, call_edges, go_analysis
