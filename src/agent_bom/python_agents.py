"""Python agent framework scanner for agent-bom.

Scans a Python project directory for AI agent framework usage and extracts:

- **Agent definitions** — name, tools, model, credentials referenced in code
- **Framework packages** — exact version from requirements files for OSV scanning
- **Credential exposure** — env var references passed to agents/LLMs

Frameworks supported
--------------------
| Framework           | Package(s)                          | Org          |
|---------------------|-------------------------------------|--------------|
| OpenAI Agents SDK   | openai-agents                       | OpenAI       |
| Google ADK          | google-adk                          | Google       |
| LangChain / Graph   | langchain, langgraph                | LangChain AI |
| AutoGen             | pyautogen, autogen-agentchat        | Microsoft    |
| CrewAI              | crewai                              | CrewAI       |
| LlamaIndex          | llama-index-core, llama_index       | LlamaIndex   |
| Pydantic AI         | pydantic-ai                         | Pydantic     |
| smolagents          | smolagents                          | HuggingFace  |
| Semantic Kernel     | semantic-kernel                     | Microsoft    |
| Haystack            | haystack-ai, farm-haystack          | deepset      |

Zero extra dependencies — uses only ``re``, ``ast``, and ``pathlib`` from stdlib.

Usage::

    from agent_bom.python_agents import scan_python_agents

    agents, warnings = scan_python_agents("/path/to/my-agent-project")
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

# ─── Framework registry ───────────────────────────────────────────────────────
# Maps canonical PyPI package name → (display_name, framework_key, import_roots)

_FRAMEWORKS: dict[str, tuple[str, str, list[str]]] = {
    "openai-agents": ("OpenAI Agents SDK", "openai-agents", ["agents"]),
    "google-adk": ("Google ADK", "google-adk", ["google.adk", "google.adk.agents"]),
    "langchain": ("LangChain", "langchain", ["langchain", "langchain_core", "langchain_community"]),
    "langgraph": ("LangGraph", "langchain", ["langgraph"]),
    "langchain-openai": ("LangChain-OpenAI", "langchain", ["langchain_openai"]),
    "langchain-anthropic": ("LangChain-Anthropic", "langchain", ["langchain_anthropic"]),
    "pyautogen": ("AutoGen", "autogen", ["autogen"]),
    "autogen-agentchat": ("AutoGen AgentChat", "autogen", ["autogen_agentchat", "autogen"]),
    "crewai": ("CrewAI", "crewai", ["crewai"]),
    "llama-index-core": ("LlamaIndex", "llamaindex", ["llama_index", "llama_index.core"]),
    "llama_index": ("LlamaIndex (legacy)", "llamaindex", ["llama_index"]),
    "pydantic-ai": ("Pydantic AI", "pydantic-ai", ["pydantic_ai"]),
    "smolagents": ("smolagents", "smolagents", ["smolagents"]),
    "semantic-kernel": ("Semantic Kernel", "semantic-kernel", ["semantic_kernel"]),
    "haystack-ai": ("Haystack", "haystack", ["haystack"]),
    "farm-haystack": ("Haystack (legacy)", "haystack", ["haystack"]),
}

# Flat set of all import roots for fast lookup
_ALL_IMPORT_ROOTS: frozenset[str] = frozenset(root for _, _, roots in _FRAMEWORKS.values() for root in roots)

# ─── Credential env var patterns ──────────────────────────────────────────────

_CRED_ENV_RE = re.compile(
    r"(?:OPENAI|ANTHROPIC|GOOGLE|GEMINI|AZURE|GROQ|COHERE|MISTRAL|"
    r"HUGGINGFACE|HF_TOKEN|LANGCHAIN|LLAMA|TOGETHER|REPLICATE|"
    r"AI21|VERTEX|BEDROCK|AWS_SECRET|API_KEY|API_TOKEN|SECRET_KEY)",
    re.IGNORECASE,
)

# ─── Agent instantiation patterns (per framework) ─────────────────────────────

# Generic: Agent(name="...", ...) or Agent("...", ...)
_AGENT_NAME_RE = re.compile(
    r'Agent\s*\(\s*(?:name\s*=\s*)?["\']([^"\']+)["\']',
)

# Tool decorators: @tool, @function_tool, @agent.tool
_TOOL_DECORATOR_RE = re.compile(
    r"@(?:\w+\.)?(?:function_tool|tool|skill|action)\s*\n\s*(?:async\s+)?def\s+(\w+)",
)

# tools=[foo, bar, baz] argument
_TOOLS_ARG_RE = re.compile(
    r"tools\s*=\s*\[([^\]]*)\]",
)

# model= argument
_MODEL_ARG_RE = re.compile(
    r'model\s*=\s*["\']([^"\']+)["\']',
)

# os.environ / os.getenv / env variable references
_ENV_REF_RE = re.compile(
    r'(?:os\.environ(?:\.get)?\s*[\[(]["\']|os\.getenv\s*\(\s*["\']|getenv\s*\(\s*["\'])'
    r"([A-Z][A-Z0-9_]+)",
)


# ─── Data classes ─────────────────────────────────────────────────────────────


class _PythonAgentDef(NamedTuple):
    name: str
    framework: str
    tools: list[str]
    model: str
    env_refs: list[str]  # credential env var names referenced (never values)
    file: str


# ─── Requirement file parsers ─────────────────────────────────────────────────


def _parse_requirements_txt(path: Path) -> dict[str, str]:
    """Parse requirements.txt / constraints.txt → {package: version}."""
    pkgs: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # name==1.2.3, name>=1.2, name~=1.2, name[extra]==1.2
        m = re.match(r"^([A-Za-z0-9_\-]+)(?:\[[^\]]*\])?\s*[=~!<>]+\s*([^\s;#,]+)", line)
        if m:
            pkgs[m.group(1).lower().replace("_", "-")] = m.group(2)
        else:
            # bare name with no version
            bare = re.match(r"^([A-Za-z0-9_\-]+)", line)
            if bare:
                pkgs[bare.group(1).lower().replace("_", "-")] = "unknown"
    return pkgs


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    """Parse pyproject.toml dependencies → {package: version}."""
    pkgs: dict[str, str] = {}
    text = path.read_text(encoding="utf-8", errors="replace")
    # Find [project.dependencies] or [tool.poetry.dependencies] sections
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^\[(?:project\.dependencies|tool\.poetry\.dependencies)\]", stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
        if not in_deps:
            continue
        # "package>=1.2" or package = ">=1.2"
        m = re.match(r'^["\']?([A-Za-z0-9_\-]+)["\']?\s*(?:=\s*["\'])?[=~!<>^]*\s*([0-9][^\s"\']*)?', stripped)
        if m and m.group(1):
            name = m.group(1).lower().replace("_", "-")
            ver = m.group(2) or "unknown"
            pkgs[name] = ver
    return pkgs


def _collect_requirements(project: Path) -> dict[str, str]:
    """Collect {package: version} from all requirement files in the project."""
    pkgs: dict[str, str] = {}
    for req_file in project.rglob("requirements*.txt"):
        try:
            pkgs.update(_parse_requirements_txt(req_file))
        except OSError:
            pass
    for ppt in project.rglob("pyproject.toml"):
        try:
            pkgs.update(_parse_pyproject_toml(ppt))
        except OSError:
            pass
    return pkgs


# ─── Python file analysis ─────────────────────────────────────────────────────


def _detect_frameworks_in_imports(tree: ast.Module) -> set[str]:
    """Return set of framework_keys found via import statements."""
    found: set[str] = set()
    for node in ast.walk(tree):
        root: str | None = None
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
        if root and root in _ALL_IMPORT_ROOTS:
            for pkg, (_, fkey, roots) in _FRAMEWORKS.items():
                if root in roots:
                    found.add(fkey)
    return found


def _extract_agent_defs(content: str, filename: str) -> list[_PythonAgentDef]:
    """Extract agent definitions from Python source via regex (AST-free fallback)."""
    defs: list[_PythonAgentDef] = []

    # Detect framework from imports
    framework = "unknown"
    for root in _ALL_IMPORT_ROOTS:
        if re.search(rf"\bimport\s+{re.escape(root)}\b|from\s+{re.escape(root)}\b", content):
            for pkg, (_, fkey, roots) in _FRAMEWORKS.items():
                if root in roots:
                    framework = fkey
                    break
            if framework != "unknown":
                break

    # Extract @tool / @function_tool decorated functions
    tool_names = _TOOL_DECORATOR_RE.findall(content)

    # Extract env var references
    env_refs = [v for v in _ENV_REF_RE.findall(content) if _CRED_ENV_RE.search(v)]
    env_refs = list(dict.fromkeys(env_refs))  # dedupe preserving order

    # Extract Agent(...) instantiations
    for agent_m in _AGENT_NAME_RE.finditer(content):
        agent_name = agent_m.group(1)

        # Look for tools=[...] near this agent definition (within 500 chars)
        nearby = content[agent_m.start() : agent_m.start() + 500]
        tools_in_call: list[str] = []
        tools_m = _TOOLS_ARG_RE.search(nearby)
        if tools_m:
            raw = tools_m.group(1)
            tools_in_call = [t.strip().strip("\"'") for t in raw.split(",") if t.strip()]

        model_m = _MODEL_ARG_RE.search(nearby)
        model = model_m.group(1) if model_m else ""

        # Merge tools from decorators + call-site
        all_tools = list(dict.fromkeys(tool_names + tools_in_call))

        defs.append(
            _PythonAgentDef(
                name=agent_name,
                framework=framework,
                tools=all_tools,
                model=model,
                env_refs=env_refs,
                file=filename,
            )
        )

    return defs


def _scan_python_files(project: Path) -> list[_PythonAgentDef]:
    """Walk Python files and extract agent definitions."""
    all_defs: list[_PythonAgentDef] = []
    seen_names: set[str] = set()

    py_files = sorted(project.rglob("*.py"))
    # Exclude common non-project dirs
    py_files = [
        f
        for f in py_files
        if not any(
            part in f.parts
            for part in (
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
                "tests",
                "test",
            )
        )
    ]

    for py_file in py_files[:200]:  # cap at 200 files for performance
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Quick pre-filter: skip files with no agent framework imports
        if not any(root in content for root in _ALL_IMPORT_ROOTS):
            continue

        defs = _extract_agent_defs(content, py_file.name)
        for d in defs:
            key = f"{d.framework}:{d.name}"
            if key not in seen_names:
                seen_names.add(key)
                all_defs.append(d)

    return all_defs


# ─── Public API ───────────────────────────────────────────────────────────────


def scan_python_agents(project_path: str) -> tuple[list[Agent], list[str]]:
    """Scan a Python project for AI agent framework usage.

    Detects agents built with OpenAI Agents SDK, Google ADK, LangChain,
    AutoGen, CrewAI, LlamaIndex, Pydantic AI, smolagents, Semantic Kernel,
    and Haystack. Extracts tool definitions, model names, credential references,
    and package versions for OSV vulnerability scanning.

    Parameters
    ----------
    project_path:
        Root of a Python project directory.

    Returns
    -------
    (agents, warnings)
        ``agents`` — list of :class:`~agent_bom.models.Agent` objects, one per
        discovered agent definition. Each agent has one
        :class:`~agent_bom.models.MCPServer` whose ``packages`` are the AI
        framework packages found in requirements files (with versions for OSV
        scanning), ``tools`` are the tool functions registered to the agent,
        and ``env`` contains the *names* of any credential env vars referenced
        (values are never logged).

        ``warnings`` — human-readable strings about credential exposure or
        missing version information.
    """
    project = Path(project_path).expanduser().resolve()  # lgtm[py/path-injection]
    if not project.is_dir():
        return [], [f"Not a directory: {project_path}"]

    # 1. Collect all package versions from requirements files
    req_pkgs = _collect_requirements(project)

    # 2. Determine which AI frameworks are present
    active_frameworks: dict[str, str] = {}  # framework_key → display_name
    framework_packages: dict[str, list[Package]] = {}  # framework_key → [Package]

    for pkg_name, (display, fkey, _) in _FRAMEWORKS.items():
        version = req_pkgs.get(pkg_name, req_pkgs.get(pkg_name.replace("-", "_")))
        if version:
            active_frameworks[fkey] = display
            pkg = Package(
                name=pkg_name,
                version=version,
                ecosystem="pypi",
                purl=f"pkg:pypi/{pkg_name}@{version}",
            )
            framework_packages.setdefault(fkey, []).append(pkg)

    # 3. Scan Python files for agent definitions
    agent_defs = _scan_python_files(project)

    # If no agent definitions found but frameworks detected in requirements,
    # create one synthetic entry per framework so CVE scanning still runs
    if not agent_defs and active_frameworks:
        for fkey, display in active_frameworks.items():
            agent_defs.append(
                _PythonAgentDef(
                    name=f"{display} project",
                    framework=fkey,
                    tools=[],
                    model="",
                    env_refs=[],
                    file=project.name,
                )
            )

    if not agent_defs:
        return [], []

    # 4. Build warnings for credential exposure
    warnings: list[str] = []
    for d in agent_defs:
        if d.env_refs:
            warnings.append(f"Credential env vars referenced in {d.file} ({d.name}): " + ", ".join(d.env_refs))

    # 5. Build Agent objects
    agents: list[Agent] = []
    for d in agent_defs:
        pkgs = framework_packages.get(d.framework, [])

        # Include ALL non-AI packages too (for full CVE coverage)
        if not pkgs:
            # Framework not in requirements but used in code — add as unknown version
            display = dict((fkey, dn) for _, (dn, fkey, _) in _FRAMEWORKS.items()).get(d.framework, d.framework)
            pkgs = [
                Package(
                    name=d.framework,
                    version="unknown",
                    ecosystem="pypi",
                )
            ]
            warnings.append(
                f"Framework '{d.framework}' used in {d.file} but not found in "
                f"requirements files — version unknown, CVE scan may be incomplete"
            )

        tools = [MCPTool(name=t, description="agent tool") for t in d.tools]
        if d.model:
            tools.append(MCPTool(name=d.model, description="LLM model"))

        cred_env = {k: "***REDACTED***" for k in d.env_refs}

        server = MCPServer(
            name=f"{d.framework}:{d.name}",
            command="python",
            args=[],
            env=cred_env,
            transport=TransportType.STDIO,
            packages=pkgs,
            config_path=str(project),
            tools=tools,
        )
        agent = Agent(
            name=f"{d.framework}:{d.name}",
            agent_type=AgentType.CUSTOM,
            config_path=str(project),
            mcp_servers=[server],
            source="python-agents",
        )
        agents.append(agent)

    return agents, warnings
