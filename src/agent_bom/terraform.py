"""Terraform / Infrastructure-as-Code scanner for agent-bom.

Scans ``.tf`` files to discover:
- **AI agent resources** — AWS Bedrock, Google Vertex AI, Azure OpenAI, Snowflake Cortex, OpenAI
- **Hardcoded credentials** — API keys and secrets in ``default`` values or ``locals``
- **Provider versions** — scanned against OSV (Go ecosystem, since providers are Go binaries)
- **Variable credential exposure** — env-var-like variables passed into AI resources

Zero extra dependencies — uses only ``re`` and ``pathlib`` from stdlib.

Usage::

    from agent_bom.terraform import scan_terraform_dir

    agents, warnings = scan_terraform_dir("/path/to/terraform")
    # warnings list contains human-readable strings about hardcoded secrets
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

# ─── AI resource type → (display_name, category) ─────────────────────────────

_AI_RESOURCES: dict[str, tuple[str, str]] = {
    # AWS Bedrock
    "aws_bedrockagent_agent":              ("AWS Bedrock Agent", "aws-bedrock"),
    "aws_bedrockagent_agent_action_group": ("Bedrock Action Group", "aws-bedrock"),
    "aws_bedrockagent_knowledge_base":     ("Bedrock Knowledge Base", "aws-bedrock"),
    "aws_bedrockagent_agent_alias":        ("Bedrock Agent Alias", "aws-bedrock"),
    # AWS SageMaker
    "aws_sagemaker_endpoint":              ("SageMaker Endpoint", "aws-sagemaker"),
    "aws_sagemaker_model":                 ("SageMaker Model", "aws-sagemaker"),
    # Google Vertex AI / Dialogflow
    "google_vertex_ai_endpoint":           ("Vertex AI Endpoint", "vertex-ai"),
    "google_vertex_ai_featurestore":       ("Vertex AI Feature Store", "vertex-ai"),
    "google_dialogflow_cx_agent":          ("Dialogflow CX Agent", "vertex-ai"),
    "google_discovery_engine_data_store":  ("Vertex AI Search", "vertex-ai"),
    # Azure OpenAI / Cognitive
    "azurerm_cognitive_account":           ("Azure Cognitive Services", "azure-openai"),
    "azurerm_bot_service_azure_bot":       ("Azure Bot Service", "azure-openai"),
    "azurerm_machine_learning_workspace":  ("Azure ML Workspace", "azure-openai"),
    # Snowflake Cortex
    "snowflake_cortex_search_service":     ("Snowflake Cortex Search", "snowflake-cortex"),
    # OpenAI provider (github.com/openai/terraform-provider-openai or similar)
    "openai_assistant":                    ("OpenAI Assistant", "openai"),
    "openai_fine_tuning_job":              ("OpenAI Fine-tuning", "openai"),
}

# ─── Provider source → Go module path (for OSV scanning) ─────────────────────

_PROVIDER_GO_MODULES: dict[str, str] = {
    "hashicorp/aws":        "github.com/hashicorp/terraform-provider-aws",
    "hashicorp/google":     "github.com/hashicorp/terraform-provider-google",
    "hashicorp/azurerm":    "github.com/hashicorp/terraform-provider-azurerm",
    "hashicorp/kubernetes": "github.com/hashicorp/terraform-provider-kubernetes",
    "hashicorp/helm":       "github.com/hashicorp/terraform-provider-helm",
    "hashicorp/tls":        "github.com/hashicorp/terraform-provider-tls",
    "hashicorp/vault":      "github.com/hashicorp/terraform-provider-vault",
    "snowflake-labs/snowflake": "github.com/Snowflake-Labs/terraform-provider-snowflake",
}

# ─── Sensitive key name patterns ──────────────────────────────────────────────

_SENSITIVE_PATTERNS = [
    "api_key", "apikey", "api-key",
    "secret", "password", "token", "credential",
    "private_key", "private-key", "privatekey",
    "access_key", "secret_key",
    "auth_token", "bearer_token",
    "openai", "anthropic", "cohere", "mistral",
    "huggingface", "hf_token",
]

# ─── Hardcoded secret regex (inside default = "..." or = "..." assignments) ───

_HARDCODED_RE = re.compile(
    r'(?:default\s*=\s*|=\s*)'                   # assignment or default =
    r'"([^"]{12,})"',                             # a string value >= 12 chars
)

# Variable / local name patterns that suggest a credential
_CRED_NAME_RE = re.compile(
    r'(?:api[_\-]?key|api[_\-]?token|secret|password|token|credential|'
    r'access[_\-]?key|private[_\-]?key|openai|anthropic|cohere|mistral|hf[_\-]?token)',
    re.IGNORECASE,
)

# resource "type" "name" pattern
_RESOURCE_RE = re.compile(r'^resource\s+"([a-zA-Z][a-zA-Z0-9_]+)"\s+"([^"]+)"', re.MULTILINE)

# required_providers block
_REQ_PROV_RE = re.compile(r'required_providers\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', re.DOTALL)

# source = "hashicorp/aws" inside a provider stanza
_PROV_SOURCE_RE = re.compile(r'source\s*=\s*"([^"]+)"')
_PROV_VER_RE    = re.compile(r'version\s*=\s*"([^"]+)"')

# variable "name" { ... } block — name capture
_VAR_BLOCK_RE = re.compile(r'variable\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', re.DOTALL)

# Placeholder values we should not flag
_PLACEHOLDERS = frozenset([
    "your_key_here", "placeholder", "change_me", "changeme",
    "xxx", "yyy", "zzz", "example", "your-key", "your_token",
    "your_secret", "insert_here", "replace_me", "todo",
    "<your_api_key>", "<api_key>", "sk-example",
])


class TerraformSecret(NamedTuple):
    """A detected hardcoded secret in a .tf file."""
    file: str
    line: int
    variable_name: str   # terraform variable name (not the value)


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _read_tf_files(tf_dir: Path) -> list[tuple[Path, str]]:
    """Read all .tf files in a directory.  Looks recursively only if none at root."""
    files = list(tf_dir.glob("*.tf"))
    if not files:
        files = list(tf_dir.rglob("*.tf"))
    return [(f, f.read_text(encoding="utf-8", errors="replace")) for f in sorted(files)]


def _extract_block(content: str, start: int) -> str:
    """Extract the body of a brace-delimited block starting at ``start`` (after ``{``)."""
    depth = 1
    pos = start
    while pos < len(content) and depth > 0:
        if content[pos] == '{':
            depth += 1
        elif content[pos] == '}':
            depth -= 1
        pos += 1
    return content[start: pos - 1]


def _extract_providers(tf_contents: list[tuple[Path, str]]) -> dict[str, str]:
    """Return {provider_source: version_string} from required_providers blocks.

    Uses brace-counting instead of a single regex so multiple providers
    in the same block are all captured correctly.
    """
    providers: dict[str, str] = {}
    _req_open_re = re.compile(r'required_providers\s*\{')
    _nested_open_re = re.compile(r'\w+\s*=\s*\{')

    for _path, content in tf_contents:
        for open_m in _req_open_re.finditer(content):
            outer_block = _extract_block(content, open_m.end())
            # Each provider is a nested: name = { source = "..." version = "..." }
            for nested_m in _nested_open_re.finditer(outer_block):
                inner_block = _extract_block(outer_block, nested_m.end())
                src_m = _PROV_SOURCE_RE.search(inner_block)
                ver_m = _PROV_VER_RE.search(inner_block)
                if src_m:
                    source  = src_m.group(1)
                    version = ver_m.group(1).lstrip("~>=<^! ") if ver_m else "unknown"
                    version = re.sub(r'[,\s].*', '', version)
                    if source:
                        providers[source] = version
    return providers


def _extract_ai_resources(tf_contents: list[tuple[Path, str]]) -> list[tuple[str, str, str]]:
    """Return list of (resource_type, resource_name, filename) for AI resources found."""
    found: list[tuple[str, str, str]] = []
    for path, content in tf_contents:
        for m in _RESOURCE_RE.finditer(content):
            rtype, rname = m.group(1), m.group(2)
            if rtype in _AI_RESOURCES:
                found.append((rtype, rname, path.name))
    return found


def _detect_hardcoded_secrets(tf_contents: list[tuple[Path, str]]) -> list[TerraformSecret]:
    """Detect hardcoded credential values in variable defaults and local assignments."""
    secrets: list[TerraformSecret] = []

    for path, content in tf_contents:
        lines = content.splitlines()

        # Check variable blocks: variable "OPENAI_API_KEY" { default = "sk-..." }
        for var_m in _VAR_BLOCK_RE.finditer(content):
            var_name = var_m.group(1)
            if not _CRED_NAME_RE.search(var_name):
                continue
            block = var_m.group(2)
            val_m = _HARDCODED_RE.search(block)
            if not val_m:
                continue
            value = val_m.group(1)
            if any(p in value.lower() for p in _PLACEHOLDERS):
                continue
            if len(value) < 12:
                continue
            # Find line number of the variable block
            var_start = content[:var_m.start()].count('\n') + 1
            secrets.append(TerraformSecret(path.name, var_start, var_name))

        # Check inline assignments for names matching credential patterns
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            # Pattern: openai_api_key = "sk-abc123..."
            assign_m = re.match(
                r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"]{12,})"',
                stripped,
            )
            if not assign_m:
                continue
            key = assign_m.group(1)
            value = assign_m.group(2)
            if not _CRED_NAME_RE.search(key):
                continue
            if any(p in value.lower() for p in _PLACEHOLDERS):
                continue
            secrets.append(TerraformSecret(path.name, i, key.upper()))

    # Deduplicate by (file, variable_name)
    seen: set[tuple[str, str]] = set()
    deduped: list[TerraformSecret] = []
    for s in secrets:
        key = (s.file, s.variable_name)
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped


# ─── Public API ───────────────────────────────────────────────────────────────


def scan_terraform_dir(tf_dir: str) -> tuple[list[Agent], list[str]]:
    """Scan a Terraform directory for AI agent resources, providers, and hardcoded secrets.

    Parameters
    ----------
    tf_dir:
        Path to a Terraform workspace directory containing ``.tf`` files.

    Returns
    -------
    (agents, warnings)
        ``agents`` — list of :class:`~agent_bom.models.Agent` objects representing
        discovered AI services.  Each agent has one :class:`~agent_bom.models.MCPServer`
        whose packages are the Terraform providers used (mapped to Go module paths for
        OSV scanning) and whose ``env`` contains the *names* (not values) of any
        detected hardcoded credentials.

        ``warnings`` — human-readable warning strings about hardcoded secrets.
        Values are **never** included.
    """
    tf_path = Path(tf_dir).expanduser().resolve()  # lgtm[py/path-injection]
    tf_contents = _read_tf_files(tf_path)

    if not tf_contents:
        return [], [f"No .tf files found in {tf_dir}"]

    providers    = _extract_providers(tf_contents)
    ai_resources = _extract_ai_resources(tf_contents)
    secrets      = _detect_hardcoded_secrets(tf_contents)

    # Build warnings (names only — never log values)
    warnings: list[str] = []
    cred_env: dict[str, str] = {}
    for s in secrets:
        cred_env[s.variable_name] = "***REDACTED***"
        warnings.append(
            f"Hardcoded credential in {s.file}:{s.line} — variable '{s.variable_name}'"
        )

    # Build provider packages (Go module ecosystem so OSV can scan them)
    provider_packages: list[Package] = []
    for source, version in providers.items():
        go_module = _PROVIDER_GO_MODULES.get(source)
        if go_module and version != "unknown":
            provider_packages.append(Package(
                name=go_module,
                version=version,
                ecosystem="Go",
                purl=f"pkg:golang/{go_module}@{version}",
            ))

    agents: list[Agent] = []

    if ai_resources:
        # Group by category to create one agent entry per AI service category
        by_category: dict[str, list[tuple[str, str, str]]] = {}
        for rtype, rname, fname in ai_resources:
            _display, category = _AI_RESOURCES[rtype]
            by_category.setdefault(category, []).append((rtype, rname, fname))

        for category, resources in by_category.items():
            tools = [
                MCPTool(
                    name=rname,
                    description=f"{_AI_RESOURCES[rtype][0]} ({fname})",
                )
                for rtype, rname, fname in resources
            ]
            server = MCPServer(
                name=f"terraform:{category}",
                command="terraform",
                args=["apply"],
                env=cred_env,
                transport=TransportType.STDIO,
                packages=list(provider_packages),
                config_path=str(tf_path),
                tools=tools,
            )
            agent = Agent(
                name=f"tf:{tf_path.name}/{category}",
                agent_type=AgentType.CUSTOM,
                config_path=str(tf_path),
                mcp_servers=[server],
                source="terraform",
            )
            agents.append(agent)

    elif provider_packages:
        # No AI resources found but there are providers to scan for CVEs
        server = MCPServer(
            name=f"terraform:{tf_path.name}",
            command="terraform",
            args=["apply"],
            env=cred_env,
            transport=TransportType.STDIO,
            packages=provider_packages,
            config_path=str(tf_path),
        )
        agent = Agent(
            name=f"tf:{tf_path.name}",
            agent_type=AgentType.CUSTOM,
            config_path=str(tf_path),
            mcp_servers=[server],
            source="terraform",
        )
        agents.append(agent)

    elif cred_env:
        # Only secrets found — still report so credentials show up in the BOM
        server = MCPServer(
            name=f"terraform:{tf_path.name}",
            command="terraform",
            args=["apply"],
            env=cred_env,
            transport=TransportType.STDIO,
            config_path=str(tf_path),
        )
        agent = Agent(
            name=f"tf:{tf_path.name}",
            agent_type=AgentType.CUSTOM,
            config_path=str(tf_path),
            mcp_servers=[server],
            source="terraform",
        )
        agents.append(agent)

    return agents, warnings
