"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


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
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    references: list[str] = field(default_factory=list)

    # Enhanced metadata
    epss_score: Optional[float] = None  # EPSS probability (0.0-1.0)
    epss_percentile: Optional[float] = None  # EPSS percentile (0.0-100.0)
    is_kev: bool = False  # CISA Known Exploited Vulnerability
    kev_date_added: Optional[str] = None  # Date added to KEV catalog
    kev_due_date: Optional[str] = None  # Remediation due date
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

    # Auto-discovery metadata (populated when not in bundled registry)
    auto_risk_level: Optional[str] = None
    auto_risk_justification: Optional[str] = None
    maintainer_count: Optional[int] = None
    source_repo: Optional[str] = None

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


@dataclass
class MCPResource:
    """A resource exposed by an MCP server."""

    uri: str
    name: str
    description: str = ""
    mime_type: Optional[str] = None


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
    hipaa_tags: list[str] = field(default_factory=list)  # HIPAA Security Rule, e.g. ["164.312(a)(1)"]
    ai_summary: Optional[str] = None  # LLM-generated contextual risk narrative

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


@dataclass
class AIBOMReport:
    """Complete AI-BOM report."""

    agents: list[Agent] = field(default_factory=list)
    blast_radii: list[BlastRadius] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
    runtime_correlation: Optional[dict] = None  # Runtime ↔ scan correlation (proxy audit vs CVE findings)
    training_pipelines: Optional[dict] = None  # Serialized TrainingPipelineScanResult
    dataset_cards: Optional[dict] = None  # Serialized DatasetScanResult
    serving_configs: Optional[list] = None  # Serialized ServingConfig list
    browser_extensions: Optional[dict] = None  # Serialized browser extension scan results

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
