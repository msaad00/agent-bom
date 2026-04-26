"""First-class non-MCP agent framework discovery.

This module keeps framework-native agents separate from MCP server records.
The output is relationship-oriented so graph/fleet callers can attach
capabilities, model references, credentials, and provenance without pretending
LangGraph, AutoGen, CrewAI, or Assistants code is an MCP server.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_bom.finding import stable_id

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "env",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".claude",
    ".codex",
}
_MAX_FILE_SIZE = 512 * 1024

_FRAMEWORK_IMPORTS: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain", "langchain_core", "langchain_community"),
    "langgraph": ("langgraph",),
    "autogen": ("autogen", "autogen_agentchat"),
    "crewai": ("crewai",),
    "openai-agents": ("agents",),
    "openai-assistants": ("openai",),
    "claude-agents": ("claude_agent_sdk", "anthropic"),
}
_FRAMEWORK_PRIORITY = (
    "langgraph",
    "langchain",
    "autogen",
    "crewai",
    "openai-agents",
    "openai-assistants",
    "claude-agents",
)
_AGENT_CALLS = {
    "Agent",
    "AssistantAgent",
    "UserProxyAgent",
    "ConversableAgent",
    "AgentExecutor",
    "Crew",
    "GroupChat",
    "StateGraph",
    "create_react_agent",
    "create_openai_functions_agent",
}
_TOOL_CALLS = {"Tool", "StructuredTool", "FunctionTool", "tool", "from_function"}
_TOOL_REGISTRATION_CALLS = {"register_function", "register_for_llm", "register_for_execution", "add_node", "add_tool"}


@dataclass(frozen=True)
class FrameworkCapability:
    """A capability registered to a framework-native agent."""

    name: str
    source: str
    line_number: int
    confidence: str = "medium"
    dynamic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "dynamic": self.dynamic,
        }


@dataclass(frozen=True)
class FrameworkTopologyEdge:
    """A static relationship observed between framework-native agents."""

    source_id: str
    source_name: str
    target_id: str
    target_name: str
    relationship: str
    file_path: str
    line_number: int
    framework: str
    evidence: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "relationship": self.relationship,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "framework": self.framework,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class FrameworkAgent:
    """A non-MCP framework agent with relationship evidence."""

    framework: str
    name: str
    file_path: str
    line_number: int
    capabilities: list[FrameworkCapability] = field(default_factory=list)
    model_refs: list[str] = field(default_factory=list)
    credential_refs: list[str] = field(default_factory=list)
    topology_edges: list[FrameworkTopologyEdge] = field(default_factory=list)
    dynamic_edges: bool = False
    confidence: str = "medium"

    @property
    def stable_id(self) -> str:
        return stable_id("framework_agent", self.framework, self.name, self.file_path, str(self.line_number))

    def to_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "kind": "framework_agent",
            "framework": self.framework,
            "name": self.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "model_refs": list(self.model_refs),
            "credential_refs": list(self.credential_refs),
            "topology_edges": [edge.to_dict() for edge in self.topology_edges],
            "dynamic_edges": self.dynamic_edges,
            "provenance": {
                "source": "source-ast",
                "language": "python",
                "relationship_model": "non-mcp-framework",
            },
        }


def scan_framework_agents(*paths: str | Path) -> list[FrameworkAgent]:
    """Scan Python source for framework-native agents and relationships."""
    agents: list[FrameworkAgent] = []
    seen: set[str] = set()
    for path in paths:
        root = Path(path)
        files = [root] if root.is_file() else _iter_python_files(root)
        for filepath in files:
            for agent in _scan_python_file(filepath, root if root.is_dir() else filepath.parent):
                key = agent.stable_id
                if key in seen:
                    continue
                seen.add(key)
                agents.append(agent)
    return agents


def _iter_python_files(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir():
        return []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.endswith(".egg-info")]
        for filename in filenames:
            if filename.endswith(".py"):
                files.append(Path(dirpath) / filename)
    return files[:500]


def _scan_python_file(filepath: Path, root: Path) -> list[FrameworkAgent]:
    try:
        if filepath.stat().st_size > _MAX_FILE_SIZE:
            return []
        content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(filepath))
    except (OSError, SyntaxError):
        return []

    imports = _detect_frameworks(tree)
    if not imports:
        return []

    rel_path = str(filepath.relative_to(root)) if filepath.is_relative_to(root) else str(filepath)
    credential_refs = _extract_credential_refs(tree)
    known_tools = _collect_tools(tree)
    framework_agents: list[FrameworkAgent] = []
    agent_by_binding: dict[str, FrameworkAgent] = {}
    agent_by_line: dict[int, FrameworkAgent] = {}
    langgraph_nodes: dict[str, dict[str, FrameworkAgent]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        binding = _first_target_name(node.targets)
        if not binding:
            continue
        agent = _agent_from_call(node.value, imports, rel_path, credential_refs, known_tools, fallback_name=binding)
        if not agent:
            continue
        framework_agents.append(agent)
        agent_by_binding[binding] = agent
        agent_by_line[getattr(node.value, "lineno", 1)] = agent

    graph_bindings = {binding for binding, agent in agent_by_binding.items() if agent.framework == "langgraph"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "add_node":
            continue
        graph_name = _call_name(func.value)
        if graph_name not in graph_bindings or not node.args:
            continue
        node_name = _string_literal(node.args[0])
        if not node_name:
            continue
        graph_nodes = langgraph_nodes.setdefault(graph_name, {})
        if node_name in graph_nodes:
            continue
        graph_agent = FrameworkAgent(
            framework="langgraph",
            name=node_name,
            file_path=rel_path,
            line_number=getattr(node, "lineno", 1),
            credential_refs=credential_refs,
            dynamic_edges=False,
            confidence="medium",
        )
        graph_nodes[node_name] = graph_agent
        framework_agents.append(graph_agent)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node, "lineno", 1) in agent_by_line:
            continue
        agent = _agent_from_call(node, imports, rel_path, credential_refs, known_tools)
        if agent:
            framework_agents.append(agent)

    topology_edges = _collect_topology_edges(tree, rel_path, agent_by_binding, agent_by_line, langgraph_nodes)
    if topology_edges:
        by_source: dict[str, list[FrameworkTopologyEdge]] = {}
        for edge in topology_edges:
            by_source.setdefault(edge.source_id, []).append(edge)
        framework_agents = [
            FrameworkAgent(
                framework=agent.framework,
                name=agent.name,
                file_path=agent.file_path,
                line_number=agent.line_number,
                capabilities=agent.capabilities,
                model_refs=agent.model_refs,
                credential_refs=agent.credential_refs,
                topology_edges=by_source.get(agent.stable_id, []),
                dynamic_edges=agent.dynamic_edges,
                confidence=agent.confidence,
            )
            for agent in framework_agents
        ]

    return framework_agents


def _agent_from_call(
    node: ast.Call,
    imports: set[str],
    rel_path: str,
    credential_refs: list[str],
    known_tools: dict[str, FrameworkCapability],
    *,
    fallback_name: str = "",
) -> FrameworkAgent | None:
    call_name = _call_name(node.func)
    short_name = call_name.split(".")[-1]
    framework = _framework_for_call(imports, call_name, short_name)
    if framework is None:
        return None
    return FrameworkAgent(
        framework=framework,
        name=_agent_name(node, rel_path, framework, fallback_name=fallback_name),
        file_path=rel_path,
        line_number=getattr(node, "lineno", 1),
        capabilities=_dedupe_capabilities(_extract_capabilities(node, known_tools)),
        model_refs=_dedupe_strings(_extract_model_refs(node)),
        credential_refs=credential_refs,
        dynamic_edges=_has_dynamic_edges(node),
        confidence="high" if short_name in _AGENT_CALLS or "assistants.create" in call_name else "medium",
    )


def _detect_frameworks(tree: ast.Module) -> set[str]:
    frameworks: set[str] = set()
    for node in ast.walk(tree):
        roots: list[str] = []
        if isinstance(node, ast.Import):
            roots.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.append(node.module.split(".")[0])
        for framework, import_roots in _FRAMEWORK_IMPORTS.items():
            if any(root in import_roots for root in roots):
                frameworks.add(framework)
    return frameworks


def _framework_for_call(imports: set[str], call_name: str, short_name: str) -> str | None:
    if short_name not in _AGENT_CALLS and "assistants.create" not in call_name:
        return None
    if "assistants.create" in call_name and "openai-assistants" in imports:
        return "openai-assistants"
    if short_name == "StateGraph" and "langgraph" in imports:
        return "langgraph"
    if short_name in {"AssistantAgent", "UserProxyAgent", "ConversableAgent"} and "autogen" in imports:
        return "autogen"
    if short_name == "GroupChat" and "autogen" in imports:
        return "autogen"
    if short_name in {"Crew", "Agent"} and "crewai" in imports:
        return "crewai"
    if short_name in {"Agent", "create_react_agent", "create_openai_functions_agent", "AgentExecutor"}:
        for framework in _FRAMEWORK_PRIORITY:
            if framework in imports:
                return framework
    return None


def _collect_tools(tree: ast.Module) -> dict[str, FrameworkCapability]:
    tools: dict[str, FrameworkCapability] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                decorator_name = _call_name(decorator).split(".")[-1]
                if decorator_name in {"tool", "function_tool", "skill", "action"}:
                    tools[node.name] = FrameworkCapability(node.name, "decorator", node.lineno, "high")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    capability = _tool_from_expr(node.value, getattr(node, "lineno", 1))
                    if capability:
                        tools[target.id] = capability
        elif isinstance(node, ast.Call):
            short_name = _call_name(node.func).split(".")[-1]
            if short_name in _TOOL_REGISTRATION_CALLS and node.args:
                name = _name_from_expr(node.args[0]) or short_name
                tools[name] = FrameworkCapability(name, short_name, getattr(node, "lineno", 1), "medium", dynamic=True)
    return tools


def _extract_capabilities(node: ast.Call, known_tools: dict[str, FrameworkCapability]) -> list[FrameworkCapability]:
    capabilities: list[FrameworkCapability] = []
    tools_node = _keyword_value(node, "tools")
    if tools_node is None and _call_name(node.func).split(".")[-1] == "create_react_agent" and len(node.args) >= 2:
        tools_node = node.args[1]
    capabilities.extend(_capabilities_from_expr(tools_node, known_tools))
    if _call_name(node.func).split(".")[-1] == "StateGraph":
        capabilities.append(FrameworkCapability("state-graph", "graph-constructor", getattr(node, "lineno", 1), "medium", True))
    return capabilities


def _capabilities_from_expr(node: ast.AST | None, known_tools: dict[str, FrameworkCapability]) -> list[FrameworkCapability]:
    if node is None:
        return []
    if isinstance(node, ast.Name):
        return [known_tools.get(node.id, FrameworkCapability(node.id, "name-reference", getattr(node, "lineno", 1), "low"))]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [FrameworkCapability(node.value, "literal-tool-name", getattr(node, "lineno", 1), "medium")]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        capabilities: list[FrameworkCapability] = []
        for item in node.elts:
            capabilities.extend(_capabilities_from_expr(item, known_tools))
        return capabilities
    if isinstance(node, ast.Dict):
        tool_type = _dict_value(node, "type")
        function_name = _dict_nested_value(node, "function", "name")
        name = function_name or tool_type
        if name:
            return [FrameworkCapability(name, "tool-dict", getattr(node, "lineno", 1), "medium")]
    if isinstance(node, ast.Call):
        capability = _tool_from_expr(node, getattr(node, "lineno", 1))
        return [capability] if capability else []
    return []


def _tool_from_expr(node: ast.AST, line_number: int) -> FrameworkCapability | None:
    if not isinstance(node, ast.Call):
        return None
    short_name = _call_name(node.func).split(".")[-1]
    if short_name not in _TOOL_CALLS:
        return None
    name = _string_keyword(node, "name")
    if not name and node.args:
        name = _name_from_expr(node.args[0])
    return FrameworkCapability(name or short_name, "tool-constructor", line_number, "medium")


def _extract_model_refs(node: ast.Call) -> list[str]:
    refs = []
    for keyword in ("model", "model_name", "llm"):
        value = _string_keyword(node, keyword)
        if value:
            refs.append(value)
    if _call_name(node.func).split(".")[-1] == "create_react_agent" and node.args:
        value = _string_literal(node.args[0])
        if value:
            refs.append(value)
    return refs


def _extract_credential_refs(tree: ast.Module) -> list[str]:
    refs: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in {"os.getenv", "getenv", "os.environ.get"} and node.args:
                value = _string_literal(node.args[0])
                if value and any(marker in value for marker in ("KEY", "TOKEN", "SECRET", "CREDENTIAL")):
                    refs.append(value)
        elif isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
            value = _string_literal(node.slice)
            if value and any(marker in value for marker in ("KEY", "TOKEN", "SECRET", "CREDENTIAL")):
                refs.append(value)
    return _dedupe_strings(refs)


def _agent_name(node: ast.Call, rel_path: str, framework: str, *, fallback_name: str = "") -> str:
    for keyword in ("name", "role"):
        value = _string_keyword(node, keyword)
        if value:
            return value
    if fallback_name:
        return fallback_name
    if node.args:
        value = _string_literal(node.args[0])
        if value:
            return value
    return f"{Path(rel_path).stem}:{framework}:{getattr(node, 'lineno', 1)}"


def _collect_topology_edges(
    tree: ast.Module,
    rel_path: str,
    agent_by_binding: dict[str, FrameworkAgent],
    agent_by_line: dict[int, FrameworkAgent],
    langgraph_nodes: dict[str, dict[str, FrameworkAgent]],
) -> list[FrameworkTopologyEdge]:
    edges: list[FrameworkTopologyEdge] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node.func)
        short_name = call_name.split(".")[-1]
        if short_name in {"Crew", "GroupChat"}:
            source = agent_by_line.get(getattr(node, "lineno", 1))
            members = _agents_from_expr(_keyword_value(node, "agents"), agent_by_binding)
            if source:
                for member in members:
                    edges.append(
                        _topology_edge(
                            source,
                            member,
                            "delegated_to",
                            rel_path,
                            getattr(node, "lineno", 1),
                            f"{short_name}(agents=[...])",
                            "high",
                        )
                    )
            for left, right in _member_pairs(members):
                edges.append(
                    _topology_edge(
                        left,
                        right,
                        "shares_server",
                        rel_path,
                        getattr(node, "lineno", 1),
                        f"shared {short_name} membership",
                        "medium",
                    )
                )
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "add_edge" and len(node.args) >= 2:
            graph_name = _call_name(node.func.value)
            graph_nodes = langgraph_nodes.get(graph_name, {})
            source_name = _string_literal(node.args[0])
            target_name = _string_literal(node.args[1])
            source = graph_nodes.get(source_name)
            target = graph_nodes.get(target_name)
            if source and target:
                edges.append(
                    _topology_edge(
                        source,
                        target,
                        "delegated_to",
                        rel_path,
                        getattr(node, "lineno", 1),
                        "StateGraph.add_edge",
                        "high",
                    )
                )
    return edges


def _topology_edge(
    source: FrameworkAgent,
    target: FrameworkAgent,
    relationship: str,
    file_path: str,
    line_number: int,
    evidence: str,
    confidence: str,
) -> FrameworkTopologyEdge:
    return FrameworkTopologyEdge(
        source_id=source.stable_id,
        source_name=source.name,
        target_id=target.stable_id,
        target_name=target.name,
        relationship=relationship,
        file_path=file_path,
        line_number=line_number,
        framework=source.framework,
        evidence=evidence,
        confidence=confidence,
    )


def _agents_from_expr(node: ast.AST | None, agent_by_binding: dict[str, FrameworkAgent]) -> list[FrameworkAgent]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    agents: list[FrameworkAgent] = []
    for item in node.elts:
        if isinstance(item, ast.Name) and item.id in agent_by_binding:
            agents.append(agent_by_binding[item.id])
    return agents


def _member_pairs(agents: list[FrameworkAgent]) -> list[tuple[FrameworkAgent, FrameworkAgent]]:
    pairs: list[tuple[FrameworkAgent, FrameworkAgent]] = []
    for index, left in enumerate(agents):
        for right in agents[index + 1 :]:
            pairs.append((left, right))
    return pairs


def _first_target_name(targets: list[ast.expr]) -> str:
    for target in targets:
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _has_dynamic_edges(node: ast.Call) -> bool:
    tools_node = _keyword_value(node, "tools")
    if tools_node is None:
        return False
    return not isinstance(tools_node, (ast.List, ast.Tuple, ast.Set))


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _string_keyword(node: ast.Call, name: str) -> str:
    return _string_literal(_keyword_value(node, name))


def _string_literal(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _name_from_expr(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _dict_value(node: ast.Dict, key: str) -> str:
    for dict_key, dict_value in zip(node.keys, node.values, strict=False):
        if _string_literal(dict_key) == key:
            return _string_literal(dict_value)
    return ""


def _dict_nested_value(node: ast.Dict, key: str, nested_key: str) -> str:
    for dict_key, dict_value in zip(node.keys, node.values, strict=False):
        if _string_literal(dict_key) == key and isinstance(dict_value, ast.Dict):
            return _dict_value(dict_value, nested_key)
    return ""


def _dedupe_capabilities(capabilities: list[FrameworkCapability]) -> list[FrameworkCapability]:
    seen: set[str] = set()
    deduped: list[FrameworkCapability] = []
    for capability in capabilities:
        if capability.name in seen:
            continue
        seen.add(capability.name)
        deduped.append(capability)
    return deduped


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
