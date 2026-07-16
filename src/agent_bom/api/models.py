"""Pydantic models for the agent-bom API."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

from agent_bom.config import API_MAX_BATCH_SCAN_TARGETS

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

# Fields that fan out one child scan job per element when a request carries more
# than one explicit target. Mirrors scan_batches.BATCH_*_TARGET_FIELDS (kept
# local to avoid a models -> scan_batches import cycle).
_BATCH_LIST_TARGET_FIELDS = (
    "images",
    "tf_dirs",
    "agent_projects",
    "jupyter_dirs",
    "connectors",
    "filesystem_paths",
)
_BATCH_SINGLE_TARGET_FIELDS = ("inventory", "gha_path", "sbom", "external_scan", "vex", "repo_url")

_SCAN_PATH_MAX_LENGTH = 4096
_SCAN_IMAGE_REF_MAX_LENGTH = 512
_SCAN_CONNECTOR_MAX_LENGTH = 128
_SCAN_GLOB_MAX_LENGTH = 256

ScanPathEntry = Annotated[str, Field(max_length=_SCAN_PATH_MAX_LENGTH)]
ScanImageRef = Annotated[str, Field(max_length=_SCAN_IMAGE_REF_MAX_LENGTH)]
ScanConnectorName = Annotated[str, Field(max_length=_SCAN_CONNECTOR_MAX_LENGTH)]
ScanGlobPattern = Annotated[str, Field(max_length=_SCAN_GLOB_MAX_LENGTH)]
ScanSinglePath = Annotated[str, Field(max_length=_SCAN_PATH_MAX_LENGTH)]


class _BoundedProgress(list[str]):
    """List that keeps only the latest configured API progress events."""

    def _trim(self) -> None:
        from agent_bom.config import API_MAX_JOB_PROGRESS_EVENTS

        if API_MAX_JOB_PROGRESS_EVENTS > 0 and len(self) > API_MAX_JOB_PROGRESS_EVENTS:
            del self[: len(self) - API_MAX_JOB_PROGRESS_EVENTS]

    def append(self, item: str) -> None:
        super().append(item)
        self._trim()

    def extend(self, iterable: Iterable[str]) -> None:
        super().extend(iterable)
        self._trim()


class ScanRequest(BaseModel):
    """Options accepted by POST /v1/scan — mirrors agent-bom scan CLI flags."""

    model_config = ConfigDict(extra="forbid")

    inventory: ScanSinglePath | None = None
    """Path to agents.json inventory file."""

    images: list[ScanImageRef] = Field(default_factory=list)
    """Docker image references to scan (e.g. ['myapp:latest', 'redis:7'])."""

    k8s: bool = False
    """Scan running Kubernetes pods via kubectl."""

    k8s_namespace: str | None = None
    """Kubernetes namespace (None = all)."""

    tf_dirs: list[ScanPathEntry] = Field(default_factory=list)
    """Terraform directories to scan."""

    gha_path: ScanSinglePath | None = None
    """Path to a Git repo to scan GitHub Actions workflows."""

    repo_url: str | None = Field(default=None, max_length=2048)
    """Public ``http(s)`` git repository URL to shallow-clone and scan statically."""

    agent_projects: list[ScanPathEntry] = Field(default_factory=list)
    """Python project directories using AI agent frameworks."""

    jupyter_dirs: list[ScanPathEntry] = Field(default_factory=list)
    """Directories to scan for Jupyter notebooks (.ipynb) with AI library usage."""

    sbom: ScanSinglePath | None = None
    """Path to an existing CycloneDX / SPDX SBOM file."""

    external_scan: ScanSinglePath | None = None
    """Path to an external scanner JSON report (Trivy, Grype, Syft, SARIF)."""

    vex: ScanSinglePath | None = None
    """Path to a VEX document (OpenVEX JSON) to apply before result serialization."""

    enrich: bool = False
    """Enrich with NVD CVSS, EPSS, and CISA KEV data."""

    offline: bool = False
    """Use the local vulnerability DB only; do not perform network vulnerability lookups."""

    dry_run: bool = False
    """Validate and preview the scan request without discovery, vulnerability scanning, or result side effects."""

    no_scan: bool = False
    """Run discovery and package extraction only; skip vulnerability scanning and result side effects."""

    auto_update_db: bool = False
    """Explicitly refresh the local vulnerability DB before scanning when stale."""

    db_sources: str | None = None
    """Comma-separated vulnerability DB sources to refresh when auto_update_db is enabled."""

    connectors: list[ScanConnectorName] = Field(default_factory=list)
    """SaaS connectors to discover from (e.g. ['jira', 'servicenow', 'slack'])."""

    filesystem_paths: list[ScanPathEntry] = Field(default_factory=list)
    """Filesystem directories or tar archives to scan via Syft."""

    format: Literal["json", "cyclonedx", "sarif", "spdx", "html", "text"] = "json"
    """Output format: json | cyclonedx | sarif | spdx | html | text."""

    dynamic_discovery: bool = False
    """Enable dynamic content-based MCP config discovery."""

    dynamic_max_depth: int = 4
    """Max directory depth for dynamic discovery."""

    scope_agents: list[ScanGlobPattern] = Field(default_factory=list)
    """Filter discovered agents by name (glob patterns, e.g. ['claude-*', 'cursor'])."""

    scope_servers: list[ScanGlobPattern] = Field(default_factory=list)
    """Filter discovered MCP servers by name (glob patterns)."""

    exclude_agents: list[ScanGlobPattern] = Field(default_factory=list)
    """Exclude agents matching these name patterns."""

    exclude_servers: list[ScanGlobPattern] = Field(default_factory=list)
    """Exclude MCP servers matching these name patterns."""

    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    """Minimum severity to include in results (low/medium/high/critical)."""

    @field_validator("format", "min_severity", mode="before")
    @classmethod
    def _normalize_enum_case(cls, value: Any) -> Any:
        """Accept case/whitespace variants (e.g. ``HIGH``/``JSON``) before the
        Literal constraint validates, so tightening the field does not reject
        inputs the pipeline previously lower-cased at read time."""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _enforce_batch_target_cap(self) -> "ScanRequest":
        """Bound per-request fan-out so one request cannot enqueue unbounded work."""
        total = sum(len(getattr(self, name)) for name in _BATCH_LIST_TARGET_FIELDS)
        total += sum(1 for name in _BATCH_SINGLE_TARGET_FIELDS if getattr(self, name))
        if self.k8s:
            total += 1
        if total > API_MAX_BATCH_SCAN_TARGETS:
            raise ValueError(f"scan request expands to {total} targets; maximum is {API_MAX_BATCH_SCAN_TARGETS} per request")
        return self

    @model_validator(mode="after")
    def _validate_repo_url_exclusive(self) -> "ScanRequest":
        """``repo_url`` mirrors CLI ``--repo`` and cannot mix with local path targets."""
        repo_url = (self.repo_url or "").strip()
        if not repo_url:
            return self
        if self.offline:
            raise ValueError(
                "offline mode cannot clone a remote repo_url; drop offline or scan a local path instead"
            )
        conflicts: list[str] = []
        if self.agent_projects:
            conflicts.append("agent_projects")
        if self.gha_path:
            conflicts.append("gha_path")
        if self.tf_dirs:
            conflicts.append("tf_dirs")
        if self.inventory:
            conflicts.append("inventory")
        if self.jupyter_dirs:
            conflicts.append("jupyter_dirs")
        if self.filesystem_paths:
            conflicts.append("filesystem_paths")
        if self.sbom:
            conflicts.append("sbom")
        if self.external_scan:
            conflicts.append("external_scan")
        if self.vex:
            conflicts.append("vex")
        if conflicts:
            joined = ", ".join(conflicts)
            raise ValueError(f"repo_url is mutually exclusive with local path targets: {joined}")
        return self


class ScanJob(BaseModel):
    """Represents a running or completed scan job."""

    job_id: str
    tenant_id: str = "default"
    batch_id: str | None = None
    parent_job_id: str | None = None
    child_job_ids: list[str] = Field(default_factory=list)
    target: dict[str, Any] | None = None
    target_index: int | None = None
    target_count: int | None = None
    source_id: str | None = None
    schedule_id: str | None = None
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

    def model_post_init(self, __context: Any) -> None:
        if not isinstance(self.progress, _BoundedProgress):
            self.progress = _BoundedProgress(self.progress)

    @field_serializer("request", return_type=ScanRequest)
    def _serialize_request(self, value: ScanRequest) -> ScanRequest:
        from agent_bom.security import sanitize_sensitive_payload

        sanitized = sanitize_sensitive_payload(value.model_dump())
        payload = sanitized if isinstance(sanitized, dict) else {}
        result: ScanRequest = ScanRequest.model_validate(payload)
        return result

    @field_serializer("progress", return_type=list[str])
    def _serialize_progress(self, value: list[str]) -> list[str]:
        from agent_bom.security import sanitize_sensitive_payload

        sanitized = sanitize_sensitive_payload(value)
        return sanitized if isinstance(sanitized, list) else []


class ReportFormat(str, Enum):
    """Supported async report artifact formats."""

    NDJSON = "ndjson"


class ReportJobRequest(BaseModel):
    """Request body for ``POST /v1/reports``."""

    model_config = ConfigDict(extra="forbid")

    format: ReportFormat = ReportFormat.NDJSON
    sort: Literal["effective_reach", "cvss", "severity", "ordinal"] = "effective_reach"
    severity: str | None = Field(default=None, max_length=32)


class ReportJob(BaseModel):
    """Async findings export job backed by streamed hub reads."""

    job_id: str
    tenant_id: str = "default"
    status: JobStatus = JobStatus.PENDING
    format: ReportFormat = ReportFormat.NDJSON
    sort: str = "effective_reach"
    severity: str | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    row_count: int | None = None
    byte_count: int | None = None
    download_token: str | None = None
    artifact_backend: Literal["local", "s3"] | None = None
    artifact_uri: str | None = None
    presigned_download_url: str | None = None
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
    # Audit-event OTLP *log* export (governance chain → OTLP logs), distinct from
    # the trace-span export above.
    otlp_logs_export: str = "disabled"
    otlp_logs_endpoint_configured: bool = False
    otlp_logs_headers_configured: bool = False


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
    credential_ref_store: str = "inmemory"
    schedule_store: str = "inmemory"
    exception_store: str = "inmemory"
    trend_store: str = "inmemory"
    graph_store: str = "inmemory"
    key_store: str = "inmemory"
    audit_log: str = "inmemory"


class EntitlementHealth(BaseModel):
    status: str = "missing"
    lane: str = "oss"
    support_tier: str = "community"
    enabled_feature_count: int = 0
    metadata_only: bool = True
    current_oss_paths_gated: bool = False


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    auth_required: bool = True
    auth_configured: bool = False
    configured_auth_modes: list[str] = Field(default_factory=list)
    unauthenticated_allowed: bool = False
    tracing: TracingHealth
    analytics: AnalyticsHealth
    storage: StorageHealth
    entitlements: EntitlementHealth = Field(default_factory=EntitlementHealth)


class ComplianceEvidenceItem(BaseModel):
    finding_id: str
    control_tag: str
    vulnerability_id: str | None = None
    package: str | None = None
    severity: str | None = None
    scan_id: str | None = None
    scan_input: dict[str, Any] = Field(default_factory=dict)
    scanner_version: str | None = None
    scan_started_at: str | None = None
    scan_completed_at: str | None = None
    policy_decisions: list[dict[str, Any]] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    fixed_version: str | None = None
    agents_at_risk: list[str] = Field(default_factory=list)


class ComplianceReportControl(BaseModel):
    control_id: str | None = None
    control_name: str | None = None
    status: str = "unknown"
    source_status: str | None = None
    evidence_state: str = "not_evaluated"
    finding_count: int = 0
    evidence: list[ComplianceEvidenceItem] = Field(default_factory=list)


class ComplianceReportScope(BaseModel):
    since: str
    until: str
    control_count: int = 0
    finding_count: int = 0
    audit_event_count: int = 0
    completed_scan_count: int = 0


class ComplianceReportSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    passed: int = Field(alias="pass")
    warning: int = 0
    fail: int = 0
    incomplete: int = 0
    not_evaluated: int = 0
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
    model_config = ConfigDict(extra="forbid")
    state: str
    reason: str = ""


class FleetAgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str | None = None
    environment: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


# ─── Gateway Models ───────────────────────────────────────────────────────


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    mode: str = "audit"
    rules: list[dict[str, Any]] = Field(default_factory=list)
    bound_agents: list[str] = Field(default_factory=list)
    bound_agent_types: list[str] = Field(default_factory=list)
    bound_environments: list[str] = Field(default_factory=list)
    enabled: bool = True


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    rules: list[dict[str, Any]] | None = None
    bound_agents: list[str] | None = None
    bound_agent_types: list[str] | None = None
    bound_environments: list[str] | None = None
    enabled: bool | None = None


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_name: str = ""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProxyAuditIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = ""
    session_id: str = ""
    idempotency_key: str = ""
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] | None = None


class SAMLLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    saml_response: str
    relay_state: str | None = None


# ─── Scan Type Request Models ─────────────────────────────────────────────


class DatasetCardsRequest(BaseModel):
    """Request body for POST /v1/scan/dataset-cards."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str]
    """Directories to scan for dataset cards (dataset_info.json, README.md, .dvc)."""


class TrainingPipelinesRequest(BaseModel):
    """Request body for POST /v1/scan/training-pipelines."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str]
    """Directories to scan for ML training artifacts (MLflow, W&B, Kubeflow)."""


class BrowserExtensionsRequest(BaseModel):
    """Request body for POST /v1/scan/browser-extensions."""

    model_config = ConfigDict(extra="forbid")

    include_low_risk: bool = False
    """Include low-risk extensions (default: only medium+ risk)."""


class ModelProvenanceRequest(BaseModel):
    """Request body for POST /v1/scan/model-provenance."""

    model_config = ConfigDict(extra="forbid")

    hf_models: list[str] = Field(default_factory=list)
    """HuggingFace model IDs to check (e.g. ['meta-llama/Llama-2-7b-hf'])."""

    ollama_models: list[str] = Field(default_factory=list)
    """Ollama model names to check (e.g. ['llama2', 'codellama'])."""


class PromptScanRequest(BaseModel):
    """Request body for POST /v1/scan/prompt-scan."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str] = Field(default_factory=list)
    """Directories to scan for prompt files (.prompt, prompt.yaml, etc.)."""

    files: list[str] = Field(default_factory=list)
    """Specific prompt files to scan."""


class ModelFilesRequest(BaseModel):
    """Request body for POST /v1/scan/model-files."""

    model_config = ConfigDict(extra="forbid")

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
    model_config = ConfigDict(extra="forbid")
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


class CredentialRefStatus(str, Enum):
    CONFIGURED = "configured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISABLED = "disabled"
    RETIRED = "retired"


class CredentialRefRecord(BaseModel):
    credential_ref_id: str
    tenant_id: str = "default"
    display_name: str
    provider: str
    mode: str = "external_ref"
    external_ref: str
    description: str = ""
    owner: str = ""
    scopes: list[str] = Field(default_factory=list)
    credential_class: str = "generic"
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool = True
    status: CredentialRefStatus = CredentialRefStatus.CONFIGURED
    last_validated_at: str | None = None
    last_validation_status: str | None = None
    last_validation_message: str | None = None
    created_at: str = ""
    updated_at: str = ""


class CredentialRefCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str
    provider: str
    mode: str = "external_ref"
    external_ref: str
    description: str = ""
    owner: str = ""
    scopes: list[str] = Field(default_factory=list)
    credential_class: str = "generic"
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool = True
    tenant_id: str = "default"


class CredentialRefUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = None
    provider: str | None = None
    mode: str | None = None
    external_ref: str | None = None
    description: str | None = None
    owner: str | None = None
    scopes: list[str] | None = None
    credential_class: str | None = None
    last_rotated_at: str | None = None
    expires_at: str | None = None
    rotation_interval_days: int | None = Field(default=None, ge=1)
    max_age_days: int | None = Field(default=None, ge=1)
    expiry_warning_days: int | None = Field(default=None, ge=1)
    enabled: bool | None = None
    status: CredentialRefStatus | None = None


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
    model_config = ConfigDict(extra="forbid")
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
    model_config = ConfigDict(extra="forbid")
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
    model_config = ConfigDict(extra="forbid")
    name: str
    role: str = "viewer"
    expires_at: str | None = None
    scopes: list[str] = Field(default_factory=list)
    scim_subject_id: str | None = None
    # User this key is issued on behalf of (e.g. a SCIM user_id/user_name). Lets
    # deprovisioning revoke free-form CI keys that don't name the departing user.
    owner: str | None = None


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    expires_at: str | None = None
    overlap_seconds: int | None = None


class TenantQuotaUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_scan_jobs: int | None = Field(default=None, ge=0)
    retained_scan_jobs: int | None = Field(default=None, ge=0)
    fleet_agents: int | None = Field(default=None, ge=0)
    schedules: int | None = Field(default=None, ge=0)


class ExecScoreConfigUpdateRequest(BaseModel):
    """Body for PUT /v1/overview/score-config (issue #3940).

    Deliberately lenient: unknown keys are ignored and values are canonicalized
    / clamped server-side (see ``agent_bom.exec_score.canonicalize_config``) so
    an ad-hoc override never raises — out-of-range weights are clamped, junk
    keys dropped, an invalid display format falls back to the default.
    """

    model_config = ConfigDict(extra="ignore")
    weights: dict[str, Any] | None = None
    grade_thresholds: dict[str, Any] | None = None
    display_format: str | None = None


class ExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vuln_id: str
    package_name: str
    server_name: str = ""
    reason: str = ""
    requested_by: str = ""
    expires_at: str = ""
    tenant_id: str = "default"


class JiraTicketRequest(BaseModel):
    """Request body for POST /v1/findings/jira."""

    model_config = ConfigDict(extra="forbid")

    jira_url: str
    email: str
    project_key: str
    finding: dict[str, Any]
    target_kind: str = Field("finding", pattern="^(finding|exposure_path)$")
    target_id: str = Field("", max_length=256)


class IssueStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(..., min_length=1, max_length=64)


class FalsePositiveRequest(BaseModel):
    """Request body for POST /v1/findings/false-positive."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    package: str
    reason: str = ""
    marked_by: str = ""


FindingFeedbackState = Literal["false_positive", "accepted_risk", "not_affected", "not_applicable", "fixed_verified", "needs_review"]
FindingTriageQueueState = Literal["open", "assigned", "reviewing", "decided"]
FindingTriageDecision = Literal["not_affected", "affected", "under_investigation"]
FindingTriageJustification = Literal[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


class FindingFeedbackRequest(BaseModel):
    """Request body for POST /v1/findings/feedback."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(..., min_length=1, max_length=128)
    package: str = Field("*", min_length=1, max_length=256)
    state: FindingFeedbackState = "false_positive"
    reason: str = Field("", max_length=2000)
    server_name: str = Field("", max_length=256)
    expires_at: str = Field("", max_length=64)


class FindingTriageRequest(BaseModel):
    """Request body for POST /v1/findings/triage."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(..., min_length=1, max_length=128)
    package: str = Field("*", min_length=1, max_length=256)
    server_name: str = Field("", max_length=256)
    assignee: str = Field("", max_length=256)
    queue_state: FindingTriageQueueState = "open"
    decision: FindingTriageDecision = "under_investigation"
    justification: FindingTriageJustification | None = None
    decision_reason: str = Field("", max_length=2000)
    expires_at: str = Field("", max_length=64)


class FindingTriageVexIngestRequest(BaseModel):
    """Request body for POST /v1/findings/triage/vex/ingest.

    Accepts an OpenVEX (or CycloneDX/CSAF) VEX document and applies its
    ``not_affected`` / ``fixed`` statements as tenant-scoped triage suppressions.
    """

    model_config = ConfigDict(extra="forbid")

    vex: dict[str, Any] = Field(..., description="A decoded VEX document (OpenVEX @context + statements).")


class FindingTriageDecisionRequest(BaseModel):
    """Request body for PUT /v1/findings/triage/{triage_id}/decision."""

    model_config = ConfigDict(extra="forbid")

    decision: FindingTriageDecision
    justification: FindingTriageJustification | None = None
    decision_reason: str = Field("", max_length=2000)
    assignee: str | None = Field(None, max_length=256)
    expires_at: str | None = Field(None, max_length=64)
