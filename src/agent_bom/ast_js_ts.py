"""JS/TS analyzer helpers extracted from ast_analyzer."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from agent_bom.ast_models import CallEdge, DetectedGuardrail, ExtractedPrompt, FlowFinding, ToolSignature
from agent_bom.ast_signal_utils import _GUARDRAIL_CALL_PATTERNS, check_prompt_risks, classify_prompt_type

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from agent_bom.js_ts_ast import JSTSAstAnalysis, JSTSFunction, JSTSToolRegistration

_MAX_FILE_SIZE = 512 * 1024  # 512KB
_JS_TS_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx"})
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
_JS_XSS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dangerouslySetInnerHTML", re.compile(r"\bdangerouslySetInnerHTML\b")),
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
]
_JS_TS_SQL_SINK_RE = re.compile(r"\b(?:query|execute|queryRawUnsafe|raw)\s*\(", re.IGNORECASE)
_JS_TS_PATH_SINK_RE = re.compile(
    r"\b(?:path\.(?:join|resolve|normalize)|(?:fs|fsp|fs\.promises)\.(?:readFile|readFileSync|writeFile|writeFileSync|open))\s*\(",
    re.IGNORECASE,
)
_JS_TS_SQL_CALL_SUFFIXES = ("query", "execute", "raw", "queryRawUnsafe")
_JS_TS_HTTP_CALL_NAMES = frozenset(
    {
        "fetch",
        "axios",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.delete",
        "axios.request",
        "got",
        "got.get",
        "got.post",
        "got.put",
        "got.delete",
        "http.request",
        "https.request",
    }
)
_JS_TS_UNTRUSTED_DATA_RE = re.compile(
    r"\b(?:user[A-Z_]\w*|user\w*|input|payload|req(?:uest)?\.(?:body|query|params)|ctx\.(?:body|query|params)|process\.env)\b",
    re.IGNORECASE,
)
_JS_TS_DYNAMIC_STRING_RE = re.compile(r"\$\{|(?:^|[^=])[+]\s*|\.concat\s*\(", re.IGNORECASE)
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


def _js_ts_module_name_for_rel_path(rel_path: str) -> str:
    path = PurePosixPath(rel_path)
    without_suffix = path.with_suffix("")
    if without_suffix.name == "index" and len(without_suffix.parts) > 1:
        without_suffix = without_suffix.parent
    return without_suffix.as_posix()


def _resolve_js_ts_import_module(module_name: str, current_module: str) -> str:
    normalized = module_name.strip()
    if not normalized.startswith("."):
        return normalized

    current_path = PurePosixPath(current_module)
    candidate = (current_path.parent / normalized).as_posix()
    if candidate.endswith((".js", ".jsx", ".ts", ".tsx")):
        candidate = str(PurePosixPath(candidate).with_suffix(""))
    if candidate.endswith("/index"):
        candidate = candidate[: -len("/index")]
    return PurePosixPath(candidate).as_posix()


def _js_ts_function_key(module_name: str, function_name: str) -> str:
    return f"{module_name}:{function_name}"


def _js_ts_function_display_name(module_name: str, function_name: str, name_counts: Mapping[str, int]) -> str:
    if not module_name or name_counts.get(function_name, 0) <= 1:
        return function_name
    return f"{module_name}.{function_name}"


def _local_js_ts_callee(reference_name: str, function_names: set[str]) -> str | None:
    if reference_name in function_names:
        return reference_name
    tail = reference_name.split(".")[-1]
    if tail in function_names:
        return tail
    return None


def _js_ts_identifier_looks_untrusted(name: str) -> bool:
    return bool(name and _JS_TS_UNTRUSTED_DATA_RE.search(name))


def _is_js_ts_command_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name == "eval" or lower_name == "function" or lower_name.startswith("child_process.")


def _is_js_ts_dangerous_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return _is_js_ts_command_sink_call_name(call_name) or lower_name.startswith(("fs.", "fs.promises.", "bun.", "deno."))


def _is_js_ts_http_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name in _JS_TS_HTTP_CALL_NAMES


def _is_js_ts_sql_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return any(lower_name == suffix or lower_name.endswith(f".{suffix}") for suffix in _JS_TS_SQL_CALL_SUFFIXES)


def _is_js_ts_path_sink_call_name(call_name: str) -> bool:
    lower_name = call_name.lower()
    return lower_name.startswith("fs.") or lower_name.startswith("fs.promises.") or lower_name.endswith(".open")


def _is_direct_js_ts_sanitizer_wrapper_name(call_name: str) -> bool:
    lower_name = call_name.strip().lower()
    if lower_name in {
        "dompurify.sanitize",
        "validator.escape",
        "he.encode",
        "escapehtml",
        "sanitizehtml",
    }:
        return True
    return lower_name.endswith((".escape", ".sanitize"))


def _resolve_js_ts_callee_key(
    reference_name: str,
    function: JSTSFunction,
    same_module_names: set[str],
    function_registry: Mapping[str, JSTSFunction],
) -> str | None:
    local_callee = _local_js_ts_callee(reference_name, same_module_names)
    if local_callee:
        key = _js_ts_function_key(function.module_name, local_callee)
        if key in function_registry:
            return key

    imported_function_ref = function.imported_function_refs.get(reference_name)
    if imported_function_ref and imported_function_ref.exported_name:
        key = _js_ts_function_key(imported_function_ref.module_name, imported_function_ref.exported_name)
        if key in function_registry:
            return key

    if "." not in reference_name:
        return None

    alias, remainder = reference_name.split(".", 1)
    imported_module_ref = function.imported_module_refs.get(alias)
    if not imported_module_ref:
        return None
    exported_name = remainder.split(".", 1)[0]
    key = _js_ts_function_key(imported_module_ref.module_name, exported_name)
    if key in function_registry:
        return key
    return None


def _js_ts_argument_is_sanitized(
    *,
    wrapper_name: str,
    function: JSTSFunction,
    same_module_names: set[str],
    function_registry: Mapping[str, JSTSFunction],
) -> bool:
    if not wrapper_name:
        return False
    if _is_direct_js_ts_sanitizer_wrapper_name(wrapper_name):
        return True
    callee_key = _resolve_js_ts_callee_key(wrapper_name, function, same_module_names, function_registry)
    if not callee_key:
        return False
    callee = function_registry.get(callee_key)
    return bool(callee and callee.sanitizing_params)


def build_js_ts_flow_findings(
    *,
    functions: Mapping[str, JSTSFunction],
    tool_registrations: Sequence[JSTSToolRegistration],
) -> tuple[list[CallEdge], list[FlowFinding]]:
    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    call_edges: list[CallEdge] = []
    seen_edges: set[tuple[str, str, int]] = set()
    name_counts: dict[str, int] = {}
    same_module_names: dict[str, set[str]] = {}
    for function in functions.values():
        name_counts[function.name] = name_counts.get(function.name, 0) + 1
        same_module_names.setdefault(function.module_name, set()).add(function.name)

    for function_key, function in functions.items():
        for call_site in getattr(function, "call_sites", []):
            callee_key = _resolve_js_ts_callee_key(
                call_site.name,
                function,
                same_module_names.get(function.module_name, set()),
                functions,
            )
            if not callee_key or callee_key == function_key:
                continue
            adjacency[function_key].add(callee_key)
            caller_name = _js_ts_function_display_name(function.module_name, function.name, name_counts)
            callee = functions[callee_key]
            callee_name = _js_ts_function_display_name(callee.module_name, callee.name, name_counts)
            edge_key = (caller_name, callee_name, call_site.line_number)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            call_edges.append(
                CallEdge(
                    caller=caller_name,
                    callee=callee_name,
                    file_path=function.file_path,
                    line_number=call_site.line_number,
                )
            )

    for registration in tool_registrations:
        handler = functions.get(registration.handler_name)
        handler_name = registration.handler_name
        file_path = ""
        if handler is not None:
            handler_name = _js_ts_function_display_name(handler.module_name, handler.name, name_counts)
            file_path = handler.file_path
        edge_key = (registration.tool_name, handler_name, registration.line_number)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        call_edges.append(
            CallEdge(
                caller=registration.tool_name,
                callee=handler_name,
                file_path=file_path,
                line_number=registration.line_number,
            )
        )

    findings: list[FlowFinding] = []
    seen_findings: set[tuple[str, str, int, str]] = set()

    def display_name(function_key: str) -> str:
        function = functions[function_key]
        return _js_ts_function_display_name(function.module_name, function.name, name_counts)

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
            current_display_name = display_name(current_name)
            for sink in getattr(current, "dangerous_call_sites", []):
                dedup_key = (registration.tool_name, sink.name, sink.line_number, current_display_name)
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
                        detail=f"Tool `{registration.tool_name}` reaches `{sink.name}` through JS/TS code in {current.file_path}.",
                        file_path=current.file_path,
                        line_number=sink.line_number,
                        entrypoint=registration.tool_name,
                        sink=sink.name,
                        call_path=[
                            registration.tool_name,
                            *[display_name(name) for name in path],
                            sink.name,
                        ],
                    )
                )
            for next_callee_key in sorted(adjacency.get(current_name, ())):
                queue.append((next_callee_key, path + [next_callee_key]))

    seen_taint_findings: set[tuple[str, str, str, int, str]] = set()
    for registration in tool_registrations:
        handler = functions.get(registration.handler_name)
        if handler is None:
            continue

        initial_tainted = set(handler.param_names)
        if not initial_tainted:
            for call_site in handler.call_sites:
                for arg_names in call_site.argument_names:
                    initial_tainted.update(name for name in arg_names if _js_ts_identifier_looks_untrusted(name))
        if not initial_tainted:
            continue

        taint_queue: list[tuple[str, list[str], frozenset[str]]] = [
            (registration.handler_name, [registration.handler_name], frozenset(initial_tainted))
        ]
        visited_states: set[tuple[str, tuple[str, ...]]] = set()
        while taint_queue:
            current_name, path, tainted_params = taint_queue.pop(0)
            visit_key = (current_name, tuple(sorted(tainted_params)))
            if visit_key in visited_states:
                continue
            visited_states.add(visit_key)
            current = functions[current_name]
            current_tainted = set(tainted_params)
            current_display_name = display_name(current_name)
            same_module = same_module_names.get(current.module_name, set())

            for call_site in current.call_sites:
                tainted_sources: list[str] = []
                for index, arg_names in enumerate(call_site.argument_names):
                    wrapper_name = call_site.argument_wrapper_names[index] if index < len(call_site.argument_wrapper_names) else ""
                    if _js_ts_argument_is_sanitized(
                        wrapper_name=wrapper_name,
                        function=current,
                        same_module_names=same_module,
                        function_registry=functions,
                    ):
                        continue
                    for name in arg_names:
                        if (
                            (name in current_tainted or _js_ts_identifier_looks_untrusted(name))
                            and name not in call_site.guarded_names
                            and name not in tainted_sources
                        ):
                            tainted_sources.append(name)
                if not tainted_sources:
                    continue

                sink_category = ""
                title = ""
                if _is_js_ts_command_sink_call_name(call_site.name):
                    sink_category = "js_ts_tainted_command_execution"
                    title = "JS/TS tool routes tainted input into command execution"
                elif _is_js_ts_http_sink_call_name(call_site.name):
                    sink_category = "js_ts_tainted_ssrf_sink"
                    title = "JS/TS tool routes tainted input into an outbound HTTP sink"
                elif _is_js_ts_sql_sink_call_name(call_site.name):
                    sink_category = "js_ts_tainted_sql_query"
                    title = "JS/TS tool routes tainted input into a SQL sink"
                elif _is_js_ts_path_sink_call_name(call_site.name):
                    sink_category = "js_ts_tainted_path_access"
                    title = "JS/TS tool routes tainted input into a filesystem path sink"

                if sink_category:
                    taint_dedup_key = (sink_category, registration.tool_name, call_site.name, call_site.line_number, current_display_name)
                    if taint_dedup_key not in seen_taint_findings:
                        seen_taint_findings.add(taint_dedup_key)
                        findings.append(
                            FlowFinding(
                                category=sink_category,
                                title=title,
                                detail=(
                                    f"Tool `{registration.tool_name}` passes tainted JS/TS input into `{call_site.name}` "
                                    f"in {current.file_path}."
                                ),
                                file_path=current.file_path,
                                line_number=call_site.line_number,
                                entrypoint=registration.tool_name,
                                sink=call_site.name,
                                call_path=[registration.tool_name, *[display_name(name) for name in path], call_site.name],
                                source=", ".join(tainted_sources),
                            )
                        )

                if _is_js_ts_dangerous_call_name(call_site.name):
                    taint_dedup_key = (
                        "js_ts_tainted_dangerous_sink",
                        registration.tool_name,
                        call_site.name,
                        call_site.line_number,
                        current_display_name,
                    )
                    if taint_dedup_key not in seen_taint_findings:
                        seen_taint_findings.add(taint_dedup_key)
                        findings.append(
                            FlowFinding(
                                category="js_ts_tainted_dangerous_sink",
                                title="JS/TS tool routes tainted input into a dangerous sink",
                                detail=(
                                    f"Tool `{registration.tool_name}` passes tainted JS/TS input into `{call_site.name}` "
                                    f"in {current.file_path}."
                                ),
                                file_path=current.file_path,
                                line_number=call_site.line_number,
                                entrypoint=registration.tool_name,
                                sink=call_site.name,
                                call_path=[registration.tool_name, *[display_name(name) for name in path], call_site.name],
                                source=", ".join(tainted_sources),
                            )
                        )

                callee_key = _resolve_js_ts_callee_key(
                    call_site.name,
                    current,
                    same_module,
                    functions,
                )
                if not callee_key or callee_key == current_name:
                    continue

                callee = functions[callee_key]
                tainted_callee_params: set[str] = set()
                for index, arg_names in enumerate(call_site.argument_names):
                    if index >= len(callee.param_names):
                        break
                    wrapper_name = call_site.argument_wrapper_names[index] if index < len(call_site.argument_wrapper_names) else ""
                    if _js_ts_argument_is_sanitized(
                        wrapper_name=wrapper_name,
                        function=current,
                        same_module_names=same_module,
                        function_registry=functions,
                    ):
                        continue
                    if any(
                        (name in current_tainted or _js_ts_identifier_looks_untrusted(name)) and name not in call_site.guarded_names
                        for name in arg_names
                    ):
                        tainted_callee_params.add(callee.param_names[index])
                if tainted_callee_params:
                    taint_queue.append((callee_key, path + [callee_key], frozenset(tainted_callee_params)))

    return call_edges, findings


def scan_js_ts_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    JSTSAstAnalysis | None,
]:
    """Extract prompt/tool/guardrail/dangerous-call signals from JS/TS source files."""
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
    frameworks: list[str] = _frameworks_from_js_modules(_source_js_modules(source))
    call_edges: list[CallEdge] = []
    analysis_result = None

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
                prompt_type=classify_prompt_type(var_name),
                risk_flags=check_prompt_risks(text),
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
        from agent_bom.js_ts_ast import JSImportRef, JSTSAstUnavailableError, JSTSToolRegistration, analyze_js_ts_block

        language_hint = {
            ".ts": "typescript",
            ".tsx": "tsx",
        }.get(file_path.suffix.lower(), "javascript")
        analysis = analyze_js_ts_block(source, language_hint=language_hint)
        module_name = _js_ts_module_name_for_rel_path(rel_path)
        analysis.imported_function_refs = {
            alias: JSImportRef(
                module_name=_resolve_js_ts_import_module(ref.module_name, module_name),
                exported_name=ref.exported_name,
            )
            for alias, ref in analysis.imported_function_refs.items()
        }
        analysis.imported_module_refs = {
            alias: JSImportRef(module_name=_resolve_js_ts_import_module(ref.module_name, module_name))
            for alias, ref in analysis.imported_module_refs.items()
        }
        for function in analysis.functions.values():
            function.module_name = module_name
            function.file_path = rel_path
            function.imported_function_refs = dict(analysis.imported_function_refs)
            function.imported_module_refs = dict(analysis.imported_module_refs)
        resolved_registrations: list[JSTSToolRegistration] = []
        for registration in analysis.tool_registrations:
            handler_name = registration.handler_name
            imported_function_ref = analysis.imported_function_refs.get(handler_name)
            if handler_name in analysis.functions:
                handler_name = _js_ts_function_key(module_name, handler_name)
            elif imported_function_ref and imported_function_ref.exported_name:
                handler_name = _js_ts_function_key(imported_function_ref.module_name, imported_function_ref.exported_name)
            elif "." in handler_name:
                alias, remainder = handler_name.split(".", 1)
                imported_module_ref = analysis.imported_module_refs.get(alias)
                if imported_module_ref:
                    handler_name = _js_ts_function_key(imported_module_ref.module_name, remainder.split(".", 1)[0])
            resolved_registrations.append(
                JSTSToolRegistration(
                    tool_name=registration.tool_name,
                    handler_name=handler_name,
                    line_number=registration.line_number,
                )
            )
        analysis.tool_registrations = resolved_registrations
        analysis_result = analysis
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

    if analysis_result is not None:
        for line_number in analysis_result.dynamic_require_lines:
            flow_findings.append(
                FlowFinding(
                    category="js_ts_dynamic_require",
                    title="JS/TS source resolves a module name dynamically",
                    detail=(
                        f"{rel_path} uses `require(...)` with a non-literal module name, "
                        "which weakens code review and can hide unsafe dependency loading."
                    ),
                    file_path=rel_path,
                    line_number=line_number,
                    entrypoint=tool_name,
                    sink="require",
                    call_path=[tool_name, "require"] if tools else ["require"],
                )
            )

    seen_js_sql_lines: set[int] = set()
    seen_js_path_lines: set[int] = set()
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if (
            line_number not in seen_js_sql_lines
            and _JS_TS_SQL_SINK_RE.search(stripped)
            and _JS_TS_DYNAMIC_STRING_RE.search(stripped)
            and _JS_TS_UNTRUSTED_DATA_RE.search(stripped)
        ):
            seen_js_sql_lines.add(line_number)
            flow_findings.append(
                FlowFinding(
                    category="js_ts_sql_query_construction",
                    title="JS/TS source builds a dynamic SQL query",
                    detail=f"{rel_path} constructs a SQL-like query with dynamic or untrusted data before sending it to a database sink.",
                    file_path=rel_path,
                    line_number=line_number,
                    entrypoint=tool_name,
                    sink="query",
                    call_path=[tool_name, "query"] if tools else ["query"],
                )
            )

        if line_number not in seen_js_path_lines and _JS_TS_PATH_SINK_RE.search(stripped) and _JS_TS_UNTRUSTED_DATA_RE.search(stripped):
            seen_js_path_lines.add(line_number)
            flow_findings.append(
                FlowFinding(
                    category="js_ts_path_traversal_sink",
                    title="JS/TS source uses untrusted input in a filesystem path sink",
                    detail=f"{rel_path} sends dynamic or untrusted path data into a filesystem operation, which can enable path traversal.",
                    file_path=rel_path,
                    line_number=line_number,
                    entrypoint=tool_name,
                    sink="path",
                    call_path=[tool_name, "path"] if tools else ["path"],
                )
            )

    seen_xss_lines: set[int] = set()
    for sink_name, pattern in _JS_XSS_PATTERNS:
        for match in pattern.finditer(source):
            line_number = source[: match.start()].count("\n") + 1
            if line_number in seen_xss_lines:
                continue
            seen_xss_lines.add(line_number)
            flow_findings.append(
                FlowFinding(
                    category="js_ts_xss_sink",
                    title="JS/TS source writes dynamic HTML into the DOM",
                    detail=f"{rel_path} uses `{sink_name}` in a pattern that can enable DOM XSS if fed untrusted input.",
                    file_path=rel_path,
                    line_number=line_number,
                    entrypoint=tool_name,
                    sink=sink_name,
                    call_path=[tool_name, sink_name] if tools else [sink_name],
                )
            )

    return prompts, guardrails, tools, flow_findings, frameworks, call_edges, analysis_result
