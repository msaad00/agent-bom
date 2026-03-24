"""Core data models for AI-BOM inventory."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agent_bom.finding import Finding

# ─── Package name normalization ──────────────────────────────────────────────
# PEP 503: https://peps.python.org/pep-0503/#normalized-names
# Ensures consistent matching across parsers, scanners, and cache.
_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_package_name(name: str, ecosystem: str = "") -> str:
    """Normalize a package name for consistent matching.

    - **PyPI**: PEP 503 — lowercases and collapses ``-``, ``_``, ``.`` runs
      to a single ``-``.  (e.g. ``Requests_OAuthlib`` → ``requests-oauthlib``)
    - **npm**: lowercases only (scoped names preserved, e.g. ``@scope/Pkg`` → ``@scope/pkg``)
    - **Other ecosystems**: lowercases only.

    This is the single source of truth for name normalization across the
    entire scanner pipeline (parsers → cache → OSV queries → result matching).
    """
    if not name:
        return name
    eco = ecosystem.lower()
    if eco == "pypi":
        return _NORMALIZE_RE.sub("-", name).lower()
    return name.lower()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"  # No CVSS/severity data available — not the same as NONE (no vulnerability)


class AgentType(str, Enum):
    CLAUDE_DESKTOP = "claude-desktop"
    CLAUDE_CODE = "claude-code"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    CLINE = "cline"
    VSCODE_COPILOT = "vscode-copilot"
    CORTEX_CODE = "cortex-code"  # Snowflake Cortex Code CLI (CoCo)
    CODEX_CLI = "codex-cli"  # OpenAI Codex CLI
    GEMINI_CLI = "gemini-cli"  # Google Gemini CLI
    GOOSE = "goose"  # Block Goose AI agent
    SNOWFLAKE_CLI = "snowflake-cli"  # Snowflake CLI (snow)
    CONTINUE = "continue"  # Continue.dev
    ZED = "zed"  # Zed editor
    OPENCLAW = "openclaw"  # OpenClaw AI agent
    ROO_CODE = "roo-code"  # Roo Code (VS Code extension)
    AMAZON_Q = "amazon-q"  # Amazon Q Developer (VS Code)
    TOOLHIVE = "toolhive"  # ToolHive MCP server manager
    DOCKER_MCP = "docker-mcp"  # Docker Desktop MCP Toolkit
    JETBRAINS_AI = "jetbrains-ai"  # JetBrains AI Assistant (IntelliJ, PyCharm, etc.)
    JUNIE = "junie"  # JetBrains Junie coding agent
    COPILOT_CLI = "copilot-cli"  # GitHub Copilot CLI (standalone)
    TABNINE = "tabnine"  # Tabnine AI assistant
    SOURCEGRAPH_CODY = "sourcegraph-cody"  # Sourcegraph Cody AI assistant
    AIDER = "aider"  # Aider AI pair programming
    REPLIT_AGENT = "replit-agent"  # Replit Agent
    VOID_EDITOR = "void"  # Void editor (open-source Cursor alternative)
    AIDE = "aide"  # Aide AI IDE (VS Code fork)
    TRAE = "trae"  # Trae AI IDE (ByteDance)
    PIECES = "pieces"  # Pieces for Developers
    MCP_CLI = "mcp-cli"  # mcp-cli standalone tool
    CUSTOM = "custom"


class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


class AgentStatus(str, Enum):
    CONFIGURED = "configured"
    INSTALLED_NOT_CONFIGURED = "installed-not-configured"


@dataclass
class Vulnerability:
    """A known vulnerability in a package."""

    id: str  # CVE or OSV ID
    summary: str
    severity: Severity
    severity_source: Optional[str] = None  # "cvss", "osv_database", "osv_ecosystem", "ghsa_heuristic"
    confidence: float | None = None  # Data quality confidence score (0.0-1.0)
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    references: list[str] = field(default_factory=list)

    # Enhanced metadata
    epss_score: Optional[float] = None  # EPSS probability (0.0-1.0)
    epss_percentile: Optional[float] = None  # EPSS percentile (0.0-100.0)
    is_kev: bool = False  # CISA Known Exploited Vulnerability
    kev_date_added: Optional[str] = None  # Date added to KEV catalog
    kev_due_date: Optional[str] = None  # Remediation due date
    published_at: Optional[str] = None  # Canonical advisory publish date
    modified_at: Optional[str] = None  # Canonical advisory modified date
    nvd_published: Optional[str] = None  # NVD publish date
    nvd_modified: Optional[str] = None  # NVD last modified date
    nvd_status: Optional[str] = (
        None  # NVD review status: RECEIVED, AWAITING_ANALYSIS, UNDERGOING_ANALYSIS, ANALYZED, MODIFIED, DEFERRED, REJECTED
    )
    cwe_ids: list[str] = field(default_factory=list)  # CWE weakness types
    aliases: list[str] = field(default_factory=list)  # Cross-source aliases (e.g. GHSA↔CVE)
    exploitability: Optional[str] = None  # "HIGH", "MEDIUM", "LOW" based on EPSS
    vex_status: Optional[str] = None  # VEX status: affected, not_affected, fixed, under_investigation
    vex_justification: Optional[str] = None  # VEX justification when not_affected
    compliance_tags: dict[str, list[str]] = field(
        default_factory=dict
    )  # CVE-level framework tags, e.g. {"nist_csf": ["ID.RA-01"], "cis": ["CIS-02.3"]}

    def __post_init__(self) -> None:
        """Sanitize fixed_version — filter git SHAs and non-version strings."""
        if self.fixed_version:
            v = self.fixed_version.lstrip("v")
            # Git SHA (40 hex chars)
            if len(v) == 40 and all(c in "0123456789abcdef" for c in v):
                self.fixed_version = None
            # Short SHA (7-12 hex only, no dots/dashes)
            elif 7 <= len(v) <= 12 and all(c in "0123456789abcdef" for c in v):
                self.fixed_version = None
            # No digits at all
            elif not any(c.isdigit() for c in v):
                self.fixed_version = None

    @property
    def is_actively_exploited(self) -> bool:
        """Check if vulnerability is being actively exploited.

        True when in CISA KEV catalog or EPSS score exceeds the active
        exploitation threshold (default 0.5, configurable via
        AGENT_BOM_EPSS_ACTIVE_THRESHOLD).
        """
        from agent_bom.config import EPSS_ACTIVE_EXPLOITATION_THRESHOLD

        return self.is_kev or (self.epss_score is not None and self.epss_score > EPSS_ACTIVE_EXPLOITATION_THRESHOLD)

    @property
    def risk_level(self) -> str:
        """Calculate overall risk level using configurable EPSS thresholds."""
        from agent_bom.config import EPSS_CRITICAL_THRESHOLD, EPSS_HIGH_LIKELY_THRESHOLD

        if self.is_kev:
            return "CRITICAL - Active Exploitation"
        if self.epss_score and self.epss_score > EPSS_CRITICAL_THRESHOLD:
            return "CRITICAL - High Exploit Probability"
        if self.severity == Severity.CRITICAL:
            return "CRITICAL"
        if self.severity == Severity.HIGH and self.epss_score and self.epss_score > EPSS_HIGH_LIKELY_THRESHOLD:
            return "HIGH - Likely Exploitable"
        if self.severity == Severity.HIGH:
            return "HIGH"
        if self.severity == Severity.MEDIUM:
            return "MEDIUM"
        return "LOW"


def compute_confidence(vuln: Vulnerability) -> float:
    """Compute 0.0-1.0 data quality confidence for a vulnerability."""
    score = 0.0
    if vuln.cvss_score is not None:
        score += 0.25
    if vuln.epss_score is not None:
        score += 0.20
    if vuln.severity_source and vuln.severity_source != "unknown":
        score += 0.15
    if getattr(vuln, "cwe_ids", None):
        score += 0.15
    if vuln.fixed_version:
        score += 0.10
    if vuln.cvss_score is not None and vuln.severity_source == "cvss":
        score += 0.15  # NVD-analyzed quality
    return min(score, 1.0)


@dataclass
class Package:
    """A software package dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, go, etc.
    purl: Optional[str] = None  # Package URL
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_direct: bool = True  # vs transitive dependency
    parent_package: Optional[str] = None  # Name of parent package (for transitive deps)
    dependency_depth: int = 0  # 0 for direct, 1+ for transitive
    resolved_from_registry: bool = False  # True if resolved dynamically vs from lock file
    registry_version: Optional[str] = None  # Latest version from registry (for drift comparison)
    version_source: str = "detected"  # "detected" | "manifest" | "registry_fallback"
    is_malicious: bool = False  # True if flagged as known malicious (MAL- prefix in OSV)
    malicious_reason: Optional[str] = None  # Why this package is flagged (e.g. "MAL-2024-1234")
    license: Optional[str] = None  # SPDX license identifier (e.g. "MIT", "Apache-2.0")
    license_expression: Optional[str] = None  # Full SPDX expression (e.g. "Apache-2.0 AND MIT")
    deps_dev_resolved: bool = False  # True if resolved via deps.dev API

    # Supply chain metadata (populated by deps.dev enrichment or SBOM ingestion)
    supplier: Optional[str] = None  # Organization or individual that supplied the package
    author: Optional[str] = None  # Package author (name or email)
    description: Optional[str] = None  # Short package description
    homepage: Optional[str] = None  # Project homepage URL
    repository_url: Optional[str] = None  # Source repository URL (git, svn)
    download_url: Optional[str] = None  # Artifact download location
    copyright_text: Optional[str] = None  # Copyright notice

    # OpenSSF Scorecard enrichment (populated by --scorecard flag)
    scorecard_score: Optional[float] = None  # 0.0-10.0 overall score
    scorecard_checks: dict[str, int] = field(default_factory=dict)  # check_name -> score (-1 to 10)

    # Provenance / supply chain attestation (populated by --verify-integrity)
    integrity_verified: Optional[bool] = None  # SHA256/SRI verified against registry
    provenance_attested: Optional[bool] = None  # SLSA/PEP740/sum.golang.org attestation found
    provenance_source: Optional[str] = None  # "npm_slsa", "pypi_pep740", "go_sumdb"

    # Auto-discovery metadata (populated when not in bundled registry)
    auto_risk_level: Optional[str] = None
    auto_risk_justification: Optional[str] = None
    maintainer_count: Optional[int] = None
    source_repo: Optional[str] = None

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this package instance.

        Same ecosystem/name/version (or purl when available) always produces
        the same ID across scans — enables first-seen/last-seen tracking.
        """
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        purl = self.purl or f"pkg:{self.ecosystem}/{self.name}@{self.version}"
        fingerprint = f"package:{purl.lower().strip()}"
        return str(_uuid.uuid5(_ns, fingerprint))

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def max_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.NONE
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            if any(v.severity == sev for v in self.vulnerabilities):
                return sev
        return Severity.NONE


@dataclass
class MCPTool:
    """A tool exposed by an MCP server."""

    name: str
    description: str
    input_schema: Optional[dict] = None
    schema_findings: list[str] = field(default_factory=list)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP tool."""
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        schema = json.dumps(self.input_schema or {}, sort_keys=True, separators=(",", ":"))
        fingerprint = f"mcp_tool:{self.name.lower().strip()}:{schema}"
        return str(_uuid.uuid5(_ns, fingerprint))

    @property
    def fingerprint(self) -> str:
        return self.stable_id

    @property
    def risk_score(self) -> int:
        """Heuristic risk score for the tool based on schema findings."""
        score = 0
        for finding in self.schema_findings:
            if "shell-execution-capability" in finding:
                score += 4
            elif "network-egress-capability" in finding:
                score += 3
            elif "filesystem-capability" in finding:
                score += 2
            else:
                score += 1
        return min(score, 10)


@dataclass
class MCPResource:
    """A resource exposed by an MCP server."""

    uri: str
    name: str
    description: str = ""
    mime_type: Optional[str] = None
    content_findings: list[str] = field(default_factory=list)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP resource."""
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        fingerprint = f"mcp_resource:{self.uri.lower().strip()}:{(self.mime_type or '').lower().strip()}"
        return str(_uuid.uuid5(_ns, fingerprint))

    @property
    def fingerprint(self) -> str:
        return self.stable_id

    @property
    def risk_score(self) -> int:
        """Heuristic risk score for the resource based on content findings."""
        score = 0
        for finding in self.content_findings:
            if "hidden-instruction-surface" in finding or "prompt-bearing-resource" in finding:
                score += 3
            elif "mutable-resource" in finding:
                score += 2
            else:
                score += 1
        return min(score, 10)


@dataclass
class PermissionProfile:
    """Privilege and permission profile for an MCP server or container."""

    runs_as_root: bool = False
    container_privileged: bool = False
    tool_permissions: dict[str, str] = field(default_factory=dict)  # tool -> "read"|"write"|"execute"|"destructive"
    capabilities: list[str] = field(default_factory=list)  # Linux caps: CAP_SYS_ADMIN, etc.
    network_access: bool = False
    filesystem_write: bool = False
    shell_access: bool = False
    security_opt: list[str] = field(default_factory=list)

    @property
    def is_elevated(self) -> bool:
        """True if server has any elevated privileges."""
        return self.runs_as_root or self.container_privileged or self.shell_access or bool(self.capabilities)

    @property
    def privilege_level(self) -> str:
        """Summarize privilege level as critical/high/medium/low."""
        if self.container_privileged or "CAP_SYS_ADMIN" in self.capabilities:
            return "critical"
        if self.runs_as_root or self.shell_access:
            return "high"
        if self.filesystem_write or self.network_access or self.capabilities:
            return "medium"
        return "low"


@dataclass
class MCPServer:
    """An MCP server with its tools, resources, and dependencies."""

    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: TransportType = TransportType.STDIO
    url: Optional[str] = None  # For SSE/HTTP transports
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    config_path: Optional[str] = None  # Where this server was discovered
    working_dir: Optional[str] = None  # Server's working directory
    mcp_version: Optional[str] = None  # MCP protocol version (e.g. "2024-11-05")
    registry_verified: bool = False  # True if found in agent-bom MCP registry
    registry_id: Optional[str] = None  # Registry entry ID, e.g. "modelcontextprotocol/filesystem"
    permission_profile: Optional[PermissionProfile] = None
    security_blocked: bool = False  # True if server was rejected for security reasons
    security_warnings: list[str] = field(default_factory=list)  # Security issues found during discovery

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this MCP server.

        Uses registry_id when available (most stable identifier), otherwise
        falls back to name+command so the same server is always the same ID.
        """
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        identifier = self.registry_id or f"{self.name}:{self.command}"
        fingerprint = f"mcp_server:{identifier.lower().strip()}"
        return str(_uuid.uuid5(_ns, fingerprint))

    @property
    def auth_mode(self) -> str:
        """Best-effort auth posture classification for the server."""
        credential_names = self.credential_names
        if credential_names:
            return "env-credentials"
        if self.url and "@" in self.url:
            return "url-embedded-credentials"
        if self.url:
            return "network-no-auth-observed"
        return "local-stdio"

    @property
    def fingerprint(self) -> str:
        """Deterministic runtime/config fingerprint for the server."""
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        tool_ids = sorted(t.stable_id for t in self.tools)
        resource_ids = sorted(r.stable_id for r in self.resources)
        env_keys = sorted(self.credential_names)
        raw = json.dumps(
            {
                "registry_id": self.registry_id,
                "name": self.name,
                "command": self.command,
                "args": self.args,
                "url": self.url,
                "transport": self.transport.value,
                "auth_mode": self.auth_mode,
                "credential_refs": env_keys,
                "tool_ids": tool_ids,
                "resource_ids": resource_ids,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return str(_uuid.uuid5(_ns, f"mcp_server_fingerprint:{raw}"))

    @property
    def vulnerable_packages(self) -> list[Package]:
        return [p for p in self.packages if p.has_vulnerabilities]

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(p.vulnerabilities) for p in self.packages)

    @property
    def has_credentials(self) -> bool:
        """Check if env vars suggest credentials are present."""
        from agent_bom.constants import SENSITIVE_PATTERNS

        return any(any(pat in k.lower() for pat in SENSITIVE_PATTERNS) for k in self.env)

    @property
    def credential_names(self) -> list[str]:
        """Return names of env vars that look like credentials."""
        from agent_bom.constants import SENSITIVE_PATTERNS

        return [k for k in self.env if any(pat in k.lower() for pat in SENSITIVE_PATTERNS)]


@dataclass
class Agent:
    """An AI agent (client) that connects to MCP servers."""

    name: str
    agent_type: AgentType
    config_path: str
    mcp_servers: list[MCPServer] = field(default_factory=list)
    version: Optional[str] = None
    source: Optional[str] = None  # Inventory source (e.g. "snowflake", "aws", "local")
    status: AgentStatus = AgentStatus.CONFIGURED
    parent_agent: Optional[str] = None  # Parent agent name (for spawn tree / delegation)
    metadata: dict = field(default_factory=dict)  # Extra config data (permissions, hooks, etc.)
    automation_settings: list = field(default_factory=list)  # Risky automation settings (scheduled tasks, etc.)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this agent.

        Canonical identity: agent_type + name. Same agent configuration
        always resolves to the same ID across scans.
        """
        import uuid as _uuid

        _ns = _uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
        fingerprint = f"agent:{self.agent_type.value}:{self.name.lower().strip()}"
        return str(_uuid.uuid5(_ns, fingerprint))

    @property
    def total_packages(self) -> int:
        return sum(len(s.packages) for s in self.mcp_servers)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(s.total_vulnerabilities for s in self.mcp_servers)

    @property
    def affected_servers(self) -> list[MCPServer]:
        return [s for s in self.mcp_servers if s.vulnerable_packages]

    @property
    def servers_with_credentials(self) -> list[MCPServer]:
        return [s for s in self.mcp_servers if s.has_credentials]


@dataclass
class BlastRadius:
    """Blast radius analysis for a vulnerability."""

    vulnerability: Vulnerability
    package: Package
    affected_servers: list[MCPServer]
    affected_agents: list[Agent]
    exposed_credentials: list[str]  # Credential env var names at risk
    exposed_tools: list[MCPTool]  # Tools accessible through compromised path
    risk_score: float = 0.0  # 0-10
    ai_risk_context: Optional[str] = None  # AI-native risk explanation when relevant
    owasp_tags: list[str] = field(default_factory=list)  # OWASP LLM Top 10 codes, e.g. ["LLM05", "LLM06"]
    atlas_tags: list[str] = field(default_factory=list)  # MITRE ATLAS technique IDs (AI/ML-specific), e.g. ["AML.T0010"]
    attack_tags: list[str] = field(default_factory=list)  # MITRE ATT&CK Enterprise technique IDs, e.g. ["T1059", "T1190"]
    nist_ai_rmf_tags: list[str] = field(default_factory=list)  # NIST AI RMF subcategories, e.g. ["MAP-3.5"]
    owasp_mcp_tags: list[str] = field(default_factory=list)  # OWASP MCP Top 10 codes, e.g. ["MCP04", "MCP01"]
    owasp_agentic_tags: list[str] = field(default_factory=list)  # OWASP Agentic Top 10, e.g. ["ASI04"]
    eu_ai_act_tags: list[str] = field(default_factory=list)  # EU AI Act articles, e.g. ["ART-15"]
    nist_csf_tags: list[str] = field(default_factory=list)  # NIST CSF 2.0, e.g. ["ID.RA-01"]
    iso_27001_tags: list[str] = field(default_factory=list)  # ISO 27001:2022, e.g. ["A.8.8"]
    soc2_tags: list[str] = field(default_factory=list)  # SOC 2 TSC, e.g. ["CC7.1"]
    cis_tags: list[str] = field(default_factory=list)  # CIS Controls v8, e.g. ["CIS-07.1"]
    cmmc_tags: list[str] = field(default_factory=list)  # CMMC 2.0 Level 2, e.g. ["RA.L2-3.11.2"]
    nist_800_53_tags: list[str] = field(default_factory=list)  # NIST 800-53 Rev 5, e.g. ["RA-5", "SI-2"]
    fedramp_tags: list[str] = field(default_factory=list)  # FedRAMP Moderate baseline, e.g. ["RA-5"]
    ai_summary: Optional[str] = None  # LLM-generated contextual risk narrative

    # Multi-hop delegation fields
    hop_depth: int = 1  # How many hops from the vulnerable package (1 = direct)
    delegation_chain: list[str] = field(default_factory=list)  # e.g. ["server1→agent1→server2→agent2"]
    transitive_agents: list[dict] = field(default_factory=list)  # Agents reached via delegation
    transitive_credentials: list[str] = field(default_factory=list)  # Credentials exposed transitively
    transitive_risk_score: float = 0.0  # Risk score weighted by hop distance

    def calculate_risk_score(self) -> float:
        """Calculate contextual risk score based on blast radius.

        All weights and thresholds are configurable via ``AGENT_BOM_RISK_*``
        environment variables.  See :mod:`agent_bom.config` for defaults and
        documentation.
        """
        from agent_bom.config import (
            EPSS_CRITICAL_THRESHOLD,
            RISK_AGENT_CAP,
            RISK_AGENT_WEIGHT,
            RISK_AI_BOOST,
            RISK_BASE_CRITICAL,
            RISK_BASE_HIGH,
            RISK_BASE_LOW,
            RISK_BASE_MEDIUM,
            RISK_CRED_CAP,
            RISK_CRED_WEIGHT,
            RISK_EPSS_BOOST,
            RISK_KEV_BOOST,
            RISK_SCORECARD_TIER1_BOOST,
            RISK_SCORECARD_TIER1_THRESHOLD,
            RISK_SCORECARD_TIER2_BOOST,
            RISK_SCORECARD_TIER2_THRESHOLD,
            RISK_SCORECARD_TIER3_BOOST,
            RISK_SCORECARD_TIER3_THRESHOLD,
            RISK_TOOL_CAP,
            RISK_TOOL_WEIGHT,
        )

        severity_scores = {
            Severity.CRITICAL: RISK_BASE_CRITICAL,
            Severity.HIGH: RISK_BASE_HIGH,
            Severity.MEDIUM: RISK_BASE_MEDIUM,
            Severity.LOW: RISK_BASE_LOW,
        }
        base = severity_scores.get(self.vulnerability.severity, 0.0)

        # Reach factors — each dimension is weight × count, capped
        agent_factor = min(len(self.affected_agents) * RISK_AGENT_WEIGHT, RISK_AGENT_CAP)
        cred_factor = min(len(self.exposed_credentials) * RISK_CRED_WEIGHT, RISK_CRED_CAP)
        tool_factor = min(len(self.exposed_tools) * RISK_TOOL_WEIGHT, RISK_TOOL_CAP)

        # AI framework boost: when AI context + at least one exposure vector (creds OR tools)
        ai_signals = sum([bool(self.ai_risk_context), bool(self.exposed_credentials), bool(self.exposed_tools)])
        ai_boost = RISK_AI_BOOST if ai_signals >= 2 else 0.0

        # Actively exploited (KEV) and high exploit probability (EPSS) boosts
        kev_boost = RISK_KEV_BOOST if self.vulnerability.is_kev else 0.0
        epss_boost = RISK_EPSS_BOOST if (self.vulnerability.epss_score or 0) >= EPSS_CRITICAL_THRESHOLD else 0.0

        # Poorly-maintained package boost (low OpenSSF Scorecard)
        scorecard_boost = 0.0
        if self.package.scorecard_score is not None:
            if self.package.scorecard_score < RISK_SCORECARD_TIER1_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER1_BOOST
            elif self.package.scorecard_score < RISK_SCORECARD_TIER2_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER2_BOOST
            elif self.package.scorecard_score < RISK_SCORECARD_TIER3_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER3_BOOST

        self.risk_score = min(
            base + agent_factor + cred_factor + tool_factor + ai_boost + kev_boost + epss_boost + scorecard_boost,
            10.0,
        )
        return self.risk_score

    @property
    def reachability(self) -> str:
        """Classify how reachable this vulnerability is through the blast radius.

        Returns:
            "confirmed"  — credentials OR tools exposed + direct dependency
            "likely"     — credentials OR tools exposed OR direct dep with agents
            "unlikely"   — transitive dep, no creds, no tools, LOW severity
            "unknown"    — insufficient data to determine
        """
        has_creds = bool(self.exposed_credentials)
        has_tools = bool(self.exposed_tools)
        is_direct = self.package.is_direct
        is_high = self.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH)
        has_agents = bool(self.affected_agents)

        if (has_creds or has_tools) and is_direct:
            return "confirmed"
        if has_creds or has_tools or (is_direct and has_agents) or is_high:
            return "likely"
        if not is_direct and not has_creds and not has_tools:
            return "unlikely"
        return "unknown"

    @property
    def is_actionable(self) -> bool:
        """Whether this finding warrants user attention in default output.

        LOW/MEDIUM transitive deps with no blast radius context are noise.
        Users can still see them with --verbose.
        """
        if self.vulnerability.is_kev:
            return True  # KEV = always actionable
        if self.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH):
            return True
        if self.exposed_credentials or self.exposed_tools:
            return True
        if self.package.is_direct:
            return True
        if self.package.is_malicious:
            return True
        return False


@dataclass
class AIBOMReport:
    """Complete AI-BOM report."""

    agents: list[Agent] = field(default_factory=list)
    blast_radii: list[BlastRadius] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""  # Deterministic UUID v5 from scan inputs (set by CLI after discovery)
    tool_version: str = ""
    executive_summary: Optional[str] = None  # LLM-generated executive summary
    ai_threat_chains: list[str] = field(default_factory=list)  # LLM-generated threat chain analyses
    mcp_config_analysis: Optional[dict] = None  # LLM-powered MCP config security analysis
    skill_audit_data: Optional[dict] = None  # Serialized SkillAuditResult (set by CLI)
    trust_assessment_data: Optional[dict] = None  # Serialized TrustAssessmentResult (set by CLI)
    prompt_scan_data: Optional[dict] = None  # Serialized PromptScanResult (set by CLI)
    model_files: list[dict] = field(default_factory=list)
    model_provenance: list[dict] = field(default_factory=list)  # HuggingFace provenance results
    enforcement_data: Optional[dict] = None  # Serialized EnforcementReport (set by CLI)
    context_graph_data: Optional[dict] = None  # Serialized context graph (set by CLI)
    license_report: Optional[dict] = None  # Serialized license compliance report
    vex_data: Optional[dict] = None  # Serialized VEX document
    toxic_combinations: Optional[list] = None  # Serialized ToxicCombination list
    prioritized_findings: Optional[list] = None  # Priority-ordered findings
    sast_data: Optional[dict] = None  # Serialized SAST scan results (Semgrep)
    cis_benchmark_data: Optional[dict] = None  # Serialized CIS AWS Benchmark results
    snowflake_cis_benchmark_data: Optional[dict] = None  # Serialized CIS Snowflake Benchmark results
    azure_cis_benchmark_data: Optional[dict] = None  # Serialized CIS Azure Benchmark results
    gcp_cis_benchmark_data: Optional[dict] = None  # Serialized CIS GCP Benchmark results
    databricks_cis_benchmark_data: Optional[dict] = None  # Serialized Databricks Security Best Practices results
    aisvs_benchmark_data: Optional[dict] = None  # Serialized AISVS compliance results
    vector_db_scan_data: Optional[list] = None  # Serialized vector DB security assessments
    gpu_infra_data: Optional[dict] = None  # Serialized GPU/AI compute infra scan results
    iac_findings_data: Optional[dict] = None  # Serialized IaC misconfiguration findings (set by CLI)
    runtime_correlation: Optional[dict] = None  # Runtime ↔ scan correlation (proxy audit vs CVE findings)
    training_pipelines: Optional[dict] = None  # Serialized TrainingPipelineScanResult
    dataset_cards: Optional[dict] = None  # Serialized DatasetScanResult
    serving_configs: Optional[list] = None  # Serialized ServingConfig list
    browser_extensions: Optional[dict] = None  # Serialized browser extension scan results
    ai_inventory_data: Optional[dict] = None  # AI component source scan results (SDK imports, models, keys)
    introspection_data: Optional[dict] = None  # Runtime MCP introspection results (tools, resources, drift)
    health_check_data: Optional[dict] = None  # MCP server reachability/health results
    runtime_session_graph: Optional[dict] = None  # Structured runtime session graph/timeline evidence

    # Unified Finding stream (issue #566 — Phase 1).
    # Populated alongside blast_radii for backward compatibility.
    # Future phases will migrate cloud_reports and proxy alerts here too.
    findings: list["Finding"] = field(default_factory=list)

    # Scan context metadata — what input sources were actually processed.
    # Populated by the CLI/API after scan completes. Consumers use this to
    # determine which UI panels, compliance frameworks, and graphs apply.
    scan_sources: list[str] = field(default_factory=list)  # e.g. ["agent_discovery", "image", "sbom"]

    @property
    def has_mcp_context(self) -> bool:
        """True if scan discovered real MCP servers (not synthetic SBOM/image wrappers).

        A synthetic wrapper has ``command=""`` — real MCP servers always have a command.
        """
        return any(s.command for a in self.agents for s in a.mcp_servers)

    @property
    def has_agent_context(self) -> bool:
        """True if scan discovered real AI agents (not synthetic SBOM/image wrappers).

        Synthetic agents (SBOM ingest, image scan) use ``AgentType.CUSTOM`` with
        names prefixed by ``sbom:`` or ``image:``.  Real discovered agents have
        specific agent types (CLAUDE_DESKTOP, CURSOR, etc.).
        """
        return any(a.agent_type != AgentType.CUSTOM for a in self.agents)

    def __post_init__(self):
        if not self.tool_version:
            from agent_bom import __version__

            self.tool_version = __version__

    @property
    def total_agents(self) -> int:
        return len(self.agents)

    @property
    def total_servers(self) -> int:
        return sum(len(a.mcp_servers) for a in self.agents)

    @property
    def total_packages(self) -> int:
        return sum(a.total_packages for a in self.agents)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(a.total_vulnerabilities for a in self.agents)

    @property
    def critical_vulns(self) -> list[BlastRadius]:
        return [br for br in self.blast_radii if br.vulnerability.severity == Severity.CRITICAL]

    def to_findings(self) -> "list[Finding]":
        """Return the unified findings list, auto-populating from blast_radii if empty.

        Phase 1 shim: if ``self.findings`` is already populated (dual-write path),
        return it directly.  Otherwise convert ``blast_radii`` on the fly so callers
        can always work with the unified model.
        """
        if self.findings:
            return self.findings
        from agent_bom.finding import blast_radius_to_finding

        return [blast_radius_to_finding(br) for br in self.blast_radii]

    def cve_findings(self) -> "list[Finding]":
        """Return only CVE-type findings from the unified stream."""
        from agent_bom.finding import FindingType

        return [f for f in self.to_findings() if f.finding_type == FindingType.CVE]
