"""Parse skill/instruction markdown files for MCP server references, packages, and credentials.

Supported files: CLAUDE.md, .cursorrules, skill.md, skills/*.md,
.github/copilot-instructions.md, .windsurfrules, AGENTS.md, and any .md
file passed via --skill.

Extracts:
  1. Code blocks with npx/uvx/pip/npm commands → Package objects
  2. MCP server config JSON blocks → MCPServer objects
  3. Env var references matching credential patterns → credential names
  4. YAML frontmatter metadata (SKILL.md format) → SkillMetadata
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.models import MCPServer, Package, TransportType

logger = logging.getLogger(__name__)

# ─── Well-known skill file names ─────────────────────────────────────────────

SKILL_FILE_NAMES: list[str] = [
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    ".cursorrules",
    ".cursor/rules",
    "skill.md",
    "skills",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    "AGENTS.md",
]

# ─── Regex patterns ──────────────────────────────────────────────────────────

_NPX_RE = re.compile(
    r"(?:npx|bunx)\s+(?:-[yYp]\s+)*(@?[\w./-]+(?:@[\w.^~<>=+-]+)?)",
)
_UVX_RE = re.compile(
    r"(?:uvx|uv\s+(?:run|tool\s+run))\s+([\w][\w.-]*(?:==[\w.+-]+)?)",
)
_PIP_INSTALL_RE = re.compile(
    r"pip\s+install\s+(?:-[\w-]+\s+)*(.+?)(?:\s*$|\s*&&|\s*\\)",
    re.MULTILINE,
)
_NPM_INSTALL_RE = re.compile(
    r"npm\s+install\s+(?:-[\w-]+\s+)*(.+?)(?:\s*$|\s*&&|\s*\\)",
    re.MULTILINE,
)
_ENV_VAR_RE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\b")
_MCP_JSON_RE = re.compile(
    r"```(?:json|jsonc)?\s*\n(\{[\s\S]*?\"mcpServers\"[\s\S]*?\})\s*\n```",
    re.MULTILINE,
)
_CODE_BLOCK_RE = re.compile(r"```[\w]*\n([\s\S]*?)```", re.MULTILINE)

# Credential env var heuristics
_CREDENTIAL_KEYWORDS = {
    "key", "token", "secret", "password", "credential",
    "apikey", "api_key", "auth", "private",
}
_ENV_VAR_EXCLUDE = {
    "PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "DISPLAY",
    "PORT", "HOST", "NODE_ENV", "DEBUG", "LOG_LEVEL", "PYTHONPATH",
    "GOPATH", "GOROOT", "JAVA_HOME", "TMPDIR", "EDITOR", "VISUAL",
    "TZ", "LC_ALL", "LC_CTYPE", "PWD", "OLDPWD", "SHLVL",
    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "GITHUB_SHA", "GITHUB_REF", "GITHUB_ACTIONS", "GITHUB_WORKSPACE",
    "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID",
    "CI", "RUNNER_OS", "RUNNER_TEMP", "BUILD_NUMBER", "HOSTNAME",
    "COLUMNS", "LINES", "PAGER", "LESS", "MORE", "MANPATH",
    "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
}


# ─── YAML frontmatter parsing ────────────────────────────────────────────────

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# Lightweight YAML-ish parser for skill frontmatter (avoids PyYAML dependency).
# Handles simple key: value pairs and nested metadata.openclaw blocks.
_YAML_KV_RE = re.compile(r"^(\w[\w.-]*):\s*(.+)$", re.MULTILINE)
_YAML_LIST_ITEM_RE = re.compile(r"^\s+-\s+(.+)$", re.MULTILINE)


@dataclass
class SkillMetadata:
    """Parsed metadata from SKILL.md YAML frontmatter."""

    name: str = ""
    description: str = ""
    version: str = ""
    homepage: str = ""
    source: str = ""
    license: str = ""
    required_bins: list[str] = field(default_factory=list)
    optional_bins: list[str] = field(default_factory=list)
    install_methods: list[str] = field(default_factory=list)  # e.g. ["uv", "pip", "pipx"]
    os_support: list[str] = field(default_factory=list)
    raw_frontmatter: str = ""


def _parse_frontmatter(content: str) -> SkillMetadata | None:
    """Extract and parse YAML frontmatter from skill file content.

    Returns None if no frontmatter found.
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return None

    raw = match.group(1)
    meta = SkillMetadata(raw_frontmatter=raw)

    # Parse top-level simple key: value pairs
    for kv in _YAML_KV_RE.finditer(raw):
        key, value = kv.group(1), kv.group(2).strip().strip("'\"")
        if key == "name":
            meta.name = value
        elif key == "description":
            meta.description = value
        elif key == "version":
            meta.version = value

    # Parse nested metadata block (openclaw section)
    # Extract homepage, source, license from anywhere in frontmatter (may be indented)
    indented_kv = re.compile(r"^\s*(\w[\w.-]*):\s*(.+)$", re.MULTILINE)
    for kv in indented_kv.finditer(raw):
        key, value = kv.group(1), kv.group(2).strip().strip("'\"")
        if key == "homepage":
            meta.homepage = value
        elif key == "source":
            meta.source = value
        elif key == "license":
            meta.license = value

    # Extract required bins (under requires: bins:)
    bins_section = re.search(
        r"requires:\s*\n\s+bins:\s*\n((?:\s+-\s+\S+\n?)+)", raw
    )
    if bins_section:
        meta.required_bins = _YAML_LIST_ITEM_RE.findall(bins_section.group(1))

    # Extract optional bins
    opt_bins_section = re.search(
        r"optional_bins:\s*\n((?:\s+-\s+\S+\n?)+)", raw
    )
    if opt_bins_section:
        meta.optional_bins = _YAML_LIST_ITEM_RE.findall(opt_bins_section.group(1))

    # Extract install methods (kind: values)
    for kind_match in re.finditer(r"kind:\s*(\w+)", raw):
        meta.install_methods.append(kind_match.group(1))

    # Extract OS support
    os_section = re.search(r"os:\s*\n((?:\s+-\s+\S+\n?)+)", raw)
    if os_section:
        meta.os_support = _YAML_LIST_ITEM_RE.findall(os_section.group(1))

    return meta


# ─── Data structure ──────────────────────────────────────────────────────────


@dataclass
class SkillScanResult:
    """Result of scanning skill/instruction files."""

    packages: list[Package] = field(default_factory=list)
    servers: list[MCPServer] = field(default_factory=list)
    credential_env_vars: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    raw_content: dict[str, str] = field(default_factory=dict)  # source_file -> raw text (truncated)
    metadata: SkillMetadata | None = None  # Parsed frontmatter (SKILL.md format)


# ─── Parsing ─────────────────────────────────────────────────────────────────


def parse_skill_file(path: Path) -> SkillScanResult:
    """Parse a single skill/instruction markdown file.

    Extracts packages from code blocks, MCP server configs from JSON blocks,
    and credential env var references from the full text.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        truncated_content = content[:8000] if len(content) > 8000 else content
    except OSError:
        logger.warning("Could not read skill file: %s", path)
        return SkillScanResult()

    if not content.strip():
        return SkillScanResult(source_files=[str(path)], raw_content={str(path): truncated_content})

    packages: list[Package] = []
    servers: list[MCPServer] = []
    seen_packages: set[tuple[str, str]] = set()

    # Extract code blocks for package command parsing
    code_blocks = _CODE_BLOCK_RE.findall(content)
    code_text = "\n".join(code_blocks) if code_blocks else content

    # NPX packages
    for match in _NPX_RE.finditer(code_text):
        raw = match.group(1)
        name, version = _parse_pkg_spec(raw, "@")
        key = (name.lower(), "npm")
        if key not in seen_packages:
            seen_packages.add(key)
            packages.append(Package(name=name, version=version or "latest", ecosystem="npm"))

    # UVX packages
    for match in _UVX_RE.finditer(code_text):
        raw = match.group(1)
        name, version = _parse_pkg_spec(raw, "==")
        key = (name.lower(), "pypi")
        if key not in seen_packages:
            seen_packages.add(key)
            packages.append(Package(name=name, version=version or "latest", ecosystem="pypi"))

    # pip install packages
    for match in _PIP_INSTALL_RE.finditer(code_text):
        specs = match.group(1).strip()
        # Strip inline comments before splitting into package specs
        specs = specs.split("#")[0].strip()
        if not specs:
            continue
        for spec in re.split(r"\s+", specs):
            spec = spec.strip("'\"")
            if not spec or spec.startswith("-"):
                continue
            name = re.split(r"[><=!~]", spec)[0].split("[")[0]
            if not name or len(name) < 2 or not re.match(r"^[\w][\w.-]*$", name):
                continue
            key = (name.lower(), "pypi")
            if key not in seen_packages:
                seen_packages.add(key)
                version = spec[len(name):].lstrip("><=!~") if len(spec) > len(name) else "latest"
                packages.append(Package(name=name, version=version or "latest", ecosystem="pypi"))

    # npm install packages
    for match in _NPM_INSTALL_RE.finditer(code_text):
        specs = match.group(1).strip()
        # Strip inline comments before splitting into package specs
        specs = specs.split("#")[0].strip()
        if not specs:
            continue
        for spec in re.split(r"\s+", specs):
            spec = spec.strip("'\"")
            if not spec or spec.startswith("-"):
                continue
            name, version = _parse_pkg_spec(spec, "@")
            if not name:
                continue
            key = (name.lower(), "npm")
            if key not in seen_packages:
                seen_packages.add(key)
                packages.append(Package(name=name, version=version or "latest", ecosystem="npm"))

    # MCP server JSON blocks
    for match in _MCP_JSON_RE.finditer(content):
        try:
            config = json.loads(match.group(1))
            mcp_servers = config.get("mcpServers", {})
            for name, srv_config in mcp_servers.items():
                command = srv_config.get("command", "")
                args = srv_config.get("args", [])
                env = srv_config.get("env", {})
                # Redact values — only keep keys for credential detection
                redacted_env = {k: "***REDACTED***" for k in env}
                servers.append(MCPServer(
                    name=name,
                    command=command,
                    args=args,
                    env=redacted_env,
                    transport=TransportType.STDIO,
                ))
        except (json.JSONDecodeError, AttributeError):
            logger.debug("Failed to parse MCP JSON block in %s", path)

    # Credential env var detection
    all_env_vars = set(_ENV_VAR_RE.findall(content))
    credential_vars = sorted(
        v for v in all_env_vars
        if _is_credential_name(v) and v not in _ENV_VAR_EXCLUDE
    )

    # Parse YAML frontmatter (SKILL.md format)
    metadata = _parse_frontmatter(content)

    return SkillScanResult(
        packages=packages,
        servers=servers,
        credential_env_vars=credential_vars,
        source_files=[str(path)],
        raw_content={str(path): truncated_content},
        metadata=metadata,
    )


def _parse_pkg_spec(spec: str, version_sep: str) -> tuple[str, str]:
    """Parse a package spec like '@scope/pkg@1.0.0' or 'pkg==1.0.0'.

    Returns (name, version). Version may be empty string.
    """
    spec = spec.strip("'\"")
    if not spec:
        return ("", "")

    if version_sep == "@":
        # Handle scoped npm packages: @scope/name@version
        if spec.startswith("@"):
            # Find the second @ (version separator)
            rest = spec[1:]
            if "@" in rest:
                idx = rest.index("@")
                return (spec[: idx + 1], rest[idx + 1:])
            return (spec, "")
        # Non-scoped: name@version
        if "@" in spec:
            parts = spec.split("@", 1)
            return (parts[0], parts[1])
        return (spec, "")
    else:
        # pip-style: name==version or name>=version
        if version_sep in spec:
            parts = spec.split(version_sep, 1)
            return (parts[0], parts[1])
        return (spec, "")


def _is_credential_name(name: str) -> bool:
    """Check if an env var name looks like a credential."""
    lower = name.lower()
    return any(kw in lower for kw in _CREDENTIAL_KEYWORDS)


# ─── Discovery ───────────────────────────────────────────────────────────────


def discover_skill_files(project_dir: Path) -> list[Path]:
    """Auto-discover common skill/instruction files in a project directory.

    Searches for CLAUDE.md, .cursorrules, skill.md, skills/*.md, etc.
    """
    found: list[Path] = []

    for name in SKILL_FILE_NAMES:
        candidate = project_dir / name
        if candidate.is_file():
            found.append(candidate)
        elif candidate.is_dir():
            # Scan .md files inside the directory
            for md_file in sorted(candidate.glob("*.md")):
                if md_file.is_file():
                    found.append(md_file)

    return found


# ─── Batch scanning ──────────────────────────────────────────────────────────


def scan_skill_files(paths: list[Path]) -> SkillScanResult:
    """Scan multiple skill files and merge/deduplicate results."""
    merged = SkillScanResult()
    seen_packages: set[tuple[str, str]] = set()
    seen_servers: set[str] = set()
    seen_creds: set[str] = set()

    for path in paths:
        result = parse_skill_file(path)
        merged.source_files.extend(result.source_files)
        merged.raw_content.update(result.raw_content)

        # Keep the first valid metadata (typically from SKILL.md)
        if result.metadata is not None and merged.metadata is None:
            merged.metadata = result.metadata

        for pkg in result.packages:
            key = (pkg.name.lower(), pkg.ecosystem)
            if key not in seen_packages:
                seen_packages.add(key)
                merged.packages.append(pkg)

        for srv in result.servers:
            if srv.name not in seen_servers:
                seen_servers.add(srv.name)
                merged.servers.append(srv)

        for cred in result.credential_env_vars:
            if cred not in seen_creds:
                seen_creds.add(cred)
                merged.credential_env_vars.append(cred)

    return merged
