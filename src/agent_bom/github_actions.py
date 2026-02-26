"""GitHub Actions workflow scanner for agent-bom.

Scans ``.github/workflows/*.yml`` files to discover:
- **AI API credentials** exposed as ``env:`` variables or ``secrets:`` references
- **AI SDK usage** in ``run:`` steps (openai, anthropic, langchain, etc.)
- **Third-party AI actions** (e.g. ``openai/openai-github-action``)
- **pip / npm packages** installed in workflow steps that are AI-related

Treats each workflow file as a synthetic agent entry so blast radius
analysis can show which CI pipelines are using AI with credential exposure.

Zero extra dependencies — uses only ``re``, ``pathlib``, and stdlib ``json``.
YAML is parsed with a simple line-by-line approach (no PyYAML required) so
there are no extra dependencies.

Usage::

    from agent_bom.github_actions import scan_github_actions

    agents, warnings = scan_github_actions("/path/to/repo")
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

# ─── AI-related env var name patterns ────────────────────────────────────────

_AI_ENV_NAMES = re.compile(
    r'(?:OPENAI|ANTHROPIC|COHERE|MISTRAL|GROQ|GEMINI|PERPLEXITY|'
    r'HUGGINGFACE|HF_TOKEN|LANGCHAIN|LLAMA|TOGETHER|REPLICATE|'
    r'AI21|DEEPMIND|VERTEX|BEDROCK|SAGEMAKER|AZURE_OPENAI|'
    r'GOOGLE_AI|GOOGLE_GENERATIVE)',
    re.IGNORECASE,
)

# ─── Third-party AI GitHub Actions ────────────────────────────────────────────

_AI_ACTIONS: dict[str, str] = {
    "anthropic/":             "Anthropic action",
    "openai/":                "OpenAI action",
    "huggingface/":           "HuggingFace action",
    "langchain-ai/":          "LangChain action",
    "run-llama/":             "LlamaIndex action",
    "aws-actions/amazon-bedrock": "AWS Bedrock action",
    "google-github-actions/vertex": "Vertex AI action",
}

# ─── AI SDK patterns in run: steps ────────────────────────────────────────────

_AI_RUN_PATTERNS = [
    (re.compile(r'\bopenai\b', re.IGNORECASE),       "OpenAI SDK"),
    (re.compile(r'\banthropics?\b', re.IGNORECASE),  "Anthropic SDK"),
    (re.compile(r'\blangchain\b', re.IGNORECASE),    "LangChain"),
    (re.compile(r'\bllamaindex\b|llama.index', re.IGNORECASE), "LlamaIndex"),
    (re.compile(r'\btransformers\b', re.IGNORECASE), "HuggingFace Transformers"),
    (re.compile(r'\bcohere\b', re.IGNORECASE),       "Cohere SDK"),
    (re.compile(r'\bmistralai\b', re.IGNORECASE),    "Mistral SDK"),
    (re.compile(r'\bgroq\b', re.IGNORECASE),         "Groq SDK"),
    (re.compile(r'\bbedrock\b', re.IGNORECASE),      "AWS Bedrock"),
    (re.compile(r'\bvertexai\b|vertex.ai', re.IGNORECASE), "Vertex AI"),
]

# pip install / npm install AI packages in run steps
_PIP_RE  = re.compile(r'pip\s+install\s+([^\n&;]+)', re.IGNORECASE)
_NPM_RE  = re.compile(r'npm\s+(?:install|i)\s+([^\n&;]+)', re.IGNORECASE)

_AI_PACKAGES_PIP = frozenset([
    "openai", "anthropic", "langchain", "langchain-openai", "langchain-anthropic",
    "llama-index", "llama_index", "transformers", "cohere", "mistralai",
    "groq", "google-generativeai", "boto3", "amazon-bedrock", "vertexai",
    "google-cloud-aiplatform", "together", "replicate", "ai21",
])
_AI_PACKAGES_NPM = frozenset([
    "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
    "@langchain/openai", "cohere-ai", "mistral-ai", "groq-sdk",
    "@google/generative-ai", "replicate",
])


# ─── Simple YAML line-level parser ────────────────────────────────────────────


def _extract_workflow_info(content: str) -> dict:
    """Very lightweight extraction of relevant fields from a GitHub Actions YAML.

    Does NOT implement a full YAML parser — just extracts what we need:
    env var names, ``uses:`` references, and ``run:`` block content.
    """
    result: dict = {
        "env_vars": [],          # env var names (not values)
        "used_actions": [],      # "uses: owner/action@version"
        "run_blocks": [],        # content of run: steps
        "pip_packages": [],      # packages from pip install lines
        "npm_packages": [],      # packages from npm install lines
    }

    lines = content.splitlines()
    in_run_block = False
    run_indent = 0
    current_run: list[str] = []

    i = 0
    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()

        # Track env: block — collect key names
        env_m = re.match(r'\s*env\s*:', raw_line)
        if env_m and not stripped.startswith('#'):
            # Read following lines while indented deeper
            env_indent = len(raw_line) - len(raw_line.lstrip())
            j = i + 1
            while j < len(lines):
                env_line = lines[j]
                if not env_line.strip() or env_line.strip().startswith('#'):
                    j += 1
                    continue
                cur_indent = len(env_line) - len(env_line.lstrip())
                if cur_indent <= env_indent and env_line.strip():
                    break
                # Key: value pattern
                key_m = re.match(r'\s*([A-Z_][A-Z0-9_]+)\s*:', env_line)
                if key_m:
                    result["env_vars"].append(key_m.group(1))
                j += 1

        # uses: action references
        uses_m = re.match(r'\s*-?\s*uses\s*:\s*(.+)', raw_line)
        if uses_m:
            result["used_actions"].append(uses_m.group(1).strip())

        # run: blocks
        run_m = re.match(r'(\s*)-?\s*run\s*:\s*\|?\s*(.*)', raw_line)
        if run_m:
            run_indent = len(run_m.group(1)) + 2
            inline = run_m.group(2).strip()
            if inline:
                current_run.append(inline)
            in_run_block = True
            i += 1
            continue

        if in_run_block:
            cur_indent = len(raw_line) - len(raw_line.lstrip()) if raw_line.strip() else run_indent
            if raw_line.strip() and cur_indent < run_indent:
                # Run block ended
                result["run_blocks"].append("\n".join(current_run))
                current_run = []
                in_run_block = False
            else:
                current_run.append(raw_line)
        i += 1

    if current_run:
        result["run_blocks"].append("\n".join(current_run))

    # Extract pip/npm packages from run blocks
    for run_text in result["run_blocks"]:
        for pip_m in _PIP_RE.finditer(run_text):
            pkgs = re.split(r'\s+', pip_m.group(1).strip())
            result["pip_packages"].extend(p.split("==")[0].split(">=")[0].split("[")[0].strip()
                                          for p in pkgs if p and not p.startswith("-"))
        for npm_m in _NPM_RE.finditer(run_text):
            pkgs = re.split(r'\s+', npm_m.group(1).strip())
            result["npm_packages"].extend(p.strip() for p in pkgs if p and not p.startswith("-"))

    return result


# ─── Public API ───────────────────────────────────────────────────────────────


def scan_github_actions(repo_path: str) -> tuple[list[Agent], list[str]]:
    """Scan GitHub Actions workflows in a repository for AI usage and credential exposure.

    Looks at ``.github/workflows/*.yml`` and ``.github/workflows/*.yaml``.

    Parameters
    ----------
    repo_path:
        Root of a git repository (or any directory containing ``.github/workflows/``).

    Returns
    -------
    (agents, warnings)
        ``agents`` — list of :class:`~agent_bom.models.Agent` objects, one per workflow
        file that uses AI. Each agent has one :class:`~agent_bom.models.MCPServer`
        whose ``env`` contains the *names* of AI-related credentials found in the
        workflow, and whose packages are AI SDK packages installed in ``run:`` steps.

        ``warnings`` — human-readable strings (credential exposure notes, etc.)
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.is_dir():
        return [], [f"Not a directory: {repo_path}"]
    workflows_dir = repo / ".github" / "workflows"

    if not workflows_dir.is_dir():
        return [], []

    workflow_files = sorted(
        list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    )
    if not workflow_files:
        return [], []

    agents: list[Agent] = []
    warnings: list[str] = []

    for wf_path in workflow_files:
        try:
            content = wf_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        info = _extract_workflow_info(content)

        # ── Check AI env vars ────────────────────────────────────────────────
        ai_env_keys: list[str] = [
            k for k in info["env_vars"] if _AI_ENV_NAMES.search(k)
        ]

        # ── Check used actions ────────────────────────────────────────────────
        ai_action_refs: list[str] = []
        for action in info["used_actions"]:
            for prefix, label in _AI_ACTIONS.items():
                if action.startswith(prefix):
                    ai_action_refs.append(f"{label} ({action})")
                    break

        # ── Check run blocks for AI SDK usage ─────────────────────────────────
        ai_sdk_uses: list[str] = []
        for run_text in info["run_blocks"]:
            for pattern, name in _AI_RUN_PATTERNS:
                if pattern.search(run_text) and name not in ai_sdk_uses:
                    ai_sdk_uses.append(name)

        # ── Build AI packages from pip/npm installs ───────────────────────────
        ai_packages: list[Package] = []
        for pkg_name in info["pip_packages"]:
            if pkg_name.lower() in _AI_PACKAGES_PIP:
                ai_packages.append(Package(
                    name=pkg_name,
                    version="unknown",
                    ecosystem="pypi",
                ))
        for pkg_name in info["npm_packages"]:
            if pkg_name.lower() in _AI_PACKAGES_NPM or pkg_name.startswith("@anthropic") or pkg_name.startswith("@langchain"):
                ai_packages.append(Package(
                    name=pkg_name,
                    version="unknown",
                    ecosystem="npm",
                ))

        # ── Only create an agent if something AI-related was found ─────────────
        if not (ai_env_keys or ai_action_refs or ai_sdk_uses or ai_packages):
            continue

        # Build tools list from AI actions + SDK usage found
        tools: list[MCPTool] = [
            MCPTool(name=ref, description="GitHub Action") for ref in ai_action_refs
        ] + [
            MCPTool(name=sdk, description="AI SDK used in run step") for sdk in ai_sdk_uses
        ]

        # Credential env block (names only)
        cred_env: dict[str, str] = {k: "***REDACTED***" for k in ai_env_keys}

        if ai_env_keys:
            warnings.append(
                f"AI credentials exposed in {wf_path.name}: "
                + ", ".join(ai_env_keys)
            )

        server = MCPServer(
            name=f"gha:{wf_path.stem}",
            command=".github/workflows/" + wf_path.name,
            args=[],
            env=cred_env,
            transport=TransportType.STDIO,
            packages=ai_packages,
            config_path=str(wf_path),
            tools=tools,
        )
        agent = Agent(
            name=f"gha:{wf_path.stem}",
            agent_type=AgentType.CUSTOM,
            config_path=str(wf_path),
            mcp_servers=[server],
            source="github-actions",
        )
        agents.append(agent)

    return agents, warnings
