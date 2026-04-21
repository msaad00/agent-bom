"""Pydantic models for the agent-bom API."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ─── Enums ─────────────────────────────────────────────────────────────────


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ─── Scan Models ───────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    """Options accepted by POST /v1/scan — mirrors agent-bom scan CLI flags."""

    inventory: str | None = None
    """Path to agents.json inventory file."""

    images: list[str] = Field(default_factory=list)
    """Docker image references to scan (e.g. ['myapp:latest', 'redis:7'])."""

    k8s: bool = False
    """Scan running Kubernetes pods via kubectl."""

    k8s_namespace: str | None = None
    """Kubernetes namespace (None = all)."""

    tf_dirs: list[str] = Field(default_factory=list)
    """Terraform directories to scan."""

    gha_path: str | None = None
    """Path to a Git repo to scan GitHub Actions workflows."""

    agent_projects: list[str] = Field(default_factory=list)
    """Python project directories using AI agent frameworks."""

    jupyter_dirs: list[str] = Field(default_factory=list)
    """Directories to scan for Jupyter notebooks (.ipynb) with AI library usage."""

    sbom: str | None = None
    """Path to an existing CycloneDX / SPDX SBOM file."""

    enrich: bool = False
    """Enrich with NVD CVSS, EPSS, and CISA KEV data."""

    connectors: list[str] = Field(default_factory=list)
    """SaaS connectors to discover from (e.g. ['jira', 'servicenow', 'slack'])."""

    filesystem_paths: list[str] = Field(default_factory=list)
    """Filesystem directories or tar archives to scan via Syft."""

    format: str = "json"
    """Output format: json | cyclonedx | sarif | spdx | html | text."""

    dynamic_discovery: bool = False
    """Enable dynamic content-based MCP config discovery."""

    dynamic_max_depth: int = 4
    """Max directory depth for dynamic discovery."""

    scope_agents: list[str] = Field(default_factory=list)
    """Filter discovered agents by name (glob patterns, e.g. ['claude-*', 'cursor'])."""

    scope_servers: list[str] = Field(default_factory=list)
    """Filter discovered MCP servers by name (glob patterns)."""

    exclude_agents: list[str] = Field(default_factory=list)
    """Exclude agents matching these name patterns."""

    exclude_servers: list[str] = Field(default_factory=list)
    """Exclude MCP servers matching these name patterns."""

    min_severity: str | None = None
    """Minimum severity to include in results (low/medium/high/critical)."""


class ScanJob(BaseModel):
    """Represents a running or completed scan job."""

    job_id: str
    tenant_id: str = "default"
    source_id: str | None = None
    triggered_by: str | None = None
    status: JobStatus = JobStatus.PENDING
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    request: ScanRequest
    progress: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ─── Meta Models ───────────────────────────────────────────────────────────


class VersionInfo(BaseModel):
    version: str
    api_version: str = "v1"
    python_package: str = "agent-bom"


class TracingHealth(BaseModel):
    w3c_trace_context: bool = True
    w3c_tracestate: bool = True
    w3c_baggage: bool = True
    otlp_export: str = "disabled"
    otlp_endpoint_configured: bool = False
    otlp_headers_configured: bool = False


class AnalyticsHealth(BaseModel):
    backend: str = "disabled"
    enabled: bool = False
    buffered: bool = False
    clickhouse_url_configured: bool = False
    flush_interval_seconds: float | None = None
    max_batch: int | None = None


class StorageHealth(BaseModel):
    control_plane_backend: str = "inmemory"
    job_store: str = "inmemory"
    fleet_store: str = "inmemory"
    policy_store: str = "inmemory"
    source_store: str = "inmemory"
    schedule_store: str = "inmemory"
    exception_store: str = "inmemory"
    trend_store: str = "inmemory"
    graph_store: str = "inmemory"
    key_store: str = "inmemory"
    audit_log: str = "inmemory"


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    tracing: TracingHealth
    analytics: AnalyticsHealth
    storage: StorageHealth


class ComplianceEvidenceItem(BaseModel):
    finding_id: str
    control_tag: str
    vulnerability_id: str | None = None
    package: str | None = None
    severity: str | None = None
    scan_id: str | None = None
    fixed_version: str | None = None
    agents_at_risk: list[str] = Field(default_factory=list)


class ComplianceReportControl(BaseModel):
    control_id: str | None = None
    control_name: str | None = None
    status: str = "unknown"
    finding_count: int = 0
    evidence: list[ComplianceEvidenceItem] = Field(default_factory=list)


class ComplianceReportScope(BaseModel):
    since: str
    until: str
    control_count: int = 0
    finding_count: int = 0
    audit_event_count: int = 0


class ComplianceReportSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    passed: int = Field(alias="pass")
    warning: int = 0
    fail: int = 0
    score: float = 100.0


class ComplianceAuditIntegrity(BaseModel):
    verified: int = 0
    tampered: int = 0
    checked: int = 0


class ComplianceThreatModel(BaseModel):
    integrity: str
    confidentiality: str
    replay: str
    non_repudiation: str


class ComplianceReportBundle(BaseModel):
    schema_version: str = "v1"
    framework: str
    framework_key: str
    framework_label: str
    tenant_id: str
    generated_at: str
    expires_at: str
    nonce: str
    scope: ComplianceReportScope
    summary: ComplianceReportSummary
    controls: list[ComplianceReportControl] = Field(default_factory=list)
    audit_events: list[dict[str, Any]] = Field(default_factory=list)
    audit_log_integrity: ComplianceAuditIntegrity
    signature_algorithm: str
    threat_model: ComplianceThreatModel


# ─── Fleet Models ──────────────────────────────────────────────────────────


class StateUpdate(BaseModel):
    state: str
    reason: str = ""


class FleetAgentUpdate(BaseModel):
    owner: str | None = None
    environment: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


# ─── Gateway Models ───────────────────────────────────────────────────────


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    mode: str = "audit"
    rules: list[dict[str, Any]] = Field(default_factory=list)
    bound_agents: list[str] = Field(default_factory=list)
    bound_agent_types: list[str] = Field(default_factory=list)
    bound_environments: list[str] = Field(default_factory=list)
    enabled: bool = True


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    rules: list[dict[str, Any]] | None = None
    bound_agents: list[str] | None = None
    bound_agent_types: list[str] | None = None
    bound_environments: list[str] | None = None
    enabled: bool | None = None


class EvaluateRequest(BaseModel):
    agent_name: str = ""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProxyAuditIngestRequest(BaseModel):
    source_id: str = ""
    session_id: str = ""
    idempotency_key: str = ""
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] | None = None


class SAMLLoginRequest(BaseModel):
    saml_response: str
    relay_state: str | None = None


# ─── Scan Type Request Models ─────────────────────────────────────────────


class DatasetCardsRequest(BaseModel):
    """Request body for POST /v1/scan/dataset-cards."""

    directories: list[str]
    """Directories to scan for dataset cards (dataset_info.json, README.md, .dvc)."""


class TrainingPipelinesRequest(BaseModel):
    """Request body for POST /v1/scan/training-pipelines."""

    directories: list[str]
    """Directories to scan for ML training artifacts (MLflow, W&B, Kubeflow)."""


class BrowserExtensionsRequest(BaseModel):
    """Request body for POST /v1/scan/browser-extensions."""

    include_low_risk: bool = False
    """Include low-risk extensions (default: only medium+ risk)."""


class ModelProvenanceRequest(BaseModel):
    """Request body for POST /v1/scan/model-provenance."""

    hf_models: list[str] = Field(default_factory=list)
    """HuggingFace model IDs to check (e.g. ['meta-llama/Llama-2-7b-hf'])."""

    ollama_models: list[str] = Field(default_factory=list)
    """Ollama model names to check (e.g. ['llama2', 'codellama'])."""


class PromptScanRequest(BaseModel):
    """Request body for POST /v1/scan/prompt-scan."""

    directories: list[str] = Field(default_factory=list)
    """Directories to scan for prompt files (.prompt, prompt.yaml, etc.)."""

    files: list[str] = Field(default_factory=list)
    """Specific prompt files to scan."""


class ModelFilesRequest(BaseModel):
    """Request body for POST /v1/scan/model-files."""

    directories: list[str]
    """Directories to scan for ML model files (.pt, .pkl, .safetensors, .gguf, etc.)."""

    verify_hashes: bool = False
    """Compute SHA-256 hashes for each model file."""


# ─── Push / Schedule / Auth / Exception Models ────────────────────────────


class PushPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_id: str = ""
    idempotency_key: str = ""
    agents: list[dict[str, Any]] = Field(default_factory=list)
    blast_radii: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[dict[str, Any] | str] = Field(default_factory=list)


class ScheduleCreate(BaseModel):
    name: str
    cron_expression: str
    scan_config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    tenant_id: str = "default"


class SourceKind(str, Enum):
    SCAN_REPO = "scan.repo"
    SCAN_IMAGE = "scan.image"
    SCAN_IAC = "scan.iac"
    SCAN_CLOUD = "scan.cloud"
    SCAN_MCP_CONFIG = "scan.mcp_config"
    CONNECTOR_CLOUD_READ_ONLY = "connector.cloud_read_only"
    CONNECTOR_REGISTRY = "connector.registry"
    CONNECTOR_WAREHOUSE = "connector.warehouse"
    INGEST_FLEET_SYNC = "ingest.fleet_sync"
    INGEST_TRACE_PUSH = "ingest.trace_push"
    INGEST_RESULT_PUSH = "ingest.result_push"
    INGEST_ARTIFACT_IMPORT = "ingest.artifact_import"
    RUNTIME_PROXY = "runtime.proxy"
    RUNTIME_GATEWAY = "runtime.gateway"


class SourceStatus(str, Enum):
    CONFIGURED = "configured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISABLED = "disabled"


class SourceRecord(BaseModel):
    source_id: str
    tenant_id: str = "default"
    display_name: str
    kind: SourceKind
    description: str = ""
    owner: str = ""
    connector_name: str | None = None
    credential_mode: str = "none"
    credential_ref: str | None = None
    enabled: bool = True
    status: SourceStatus = SourceStatus.CONFIGURED
    config: dict[str, Any] = Field(default_factory=dict)
    last_tested_at: str | None = None
    last_test_status: str | None = None
    last_test_message: str | None = None
    last_run_at: str | None = None
    last_run_status: str | None = None
    last_job_id: str | None = None
    created_at: str = ""
    updated_at: str = ""


class SourceCreate(BaseModel):
    display_name: str
    kind: SourceKind
    description: str = ""
    owner: str = ""
    connector_name: str | None = None
    credential_mode: str = "none"
    credential_ref: str | None = None
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = "default"


class SourceUpdate(BaseModel):
    display_name: str | None = None
    description: str | None = None
    owner: str | None = None
    connector_name: str | None = None
    credential_mode: str | None = None
    credential_ref: str | None = None
    enabled: bool | None = None
    status: SourceStatus | None = None
    config: dict[str, Any] | None = None


class CreateKeyRequest(BaseModel):
    name: str
    role: str = "viewer"
    expires_at: str | None = None
    scopes: list[str] = Field(default_factory=list)


class RotateKeyRequest(BaseModel):
    name: str | None = None
    expires_at: str | None = None
    overlap_seconds: int | None = None


class ExceptionRequest(BaseModel):
    vuln_id: str
    package_name: str
    server_name: str = ""
    reason: str = ""
    requested_by: str = ""
    expires_at: str = ""
    tenant_id: str = "default"


class JiraTicketRequest(BaseModel):
    """Request body for POST /v1/findings/jira."""

    jira_url: str
    email: str
    project_key: str
    finding: dict[str, Any]


class FalsePositiveRequest(BaseModel):
    """Request body for POST /v1/findings/false-positive."""

    vulnerability_id: str
    package: str
    reason: str = ""
    marked_by: str = ""
