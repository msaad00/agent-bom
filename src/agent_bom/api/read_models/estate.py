"""Response contracts: findings, fleet, connectors, sources, intel and runtime."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from agent_bom.api.read_models._base import (
    CountMetadata,
    CountWindow,
    Num,
    ReadModel,
    ReadResponse,
)

# ── findings ─────────────────────────────────────────────────────────────────


class EffectiveReach(ReadModel):
    agent_breadth: int
    band: str
    composite: Num
    cred_visibility: Num
    cvss: Num
    epss: Num
    is_kev: bool
    symbol_reachability: Any
    tool_capability: Num


class FindingAsset(ReadModel):
    asset_type: str
    canonical_id: str
    name: str
    stable_id: str


class FindingRow(ReadModel):
    id: str
    canonical_id: str
    cve_id: str | None
    vulnerability_id: str
    title: str
    severity: str
    source: str
    finding_class: str
    finding_type: str
    scan_id: str
    scan_sources: list[str]
    observation_status: str
    last_observed: str | None
    first_seen: str | None
    last_seen: str | None
    status: str | None
    lifecycle_status: str | None
    owner: str | None
    sla_due_at: str | None
    sla_due_at_source: str
    cvss_score: Num | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_score: Num | None
    is_kev: bool
    kev_due_date: str | None
    fixed_version: str | None
    remediation_versions: list[str]
    remediation_guidance: Any
    effective_reach: EffectiveReach
    effective_reach_band: str
    effective_reach_score: Num
    graph_reachable: bool | None
    graph_min_hop_distance: int | None
    graph_reachable_from_agents: list[str]
    affected_agents: list[str]
    affected_servers: list[str]
    occurrence_count: int | None
    provenance: Any
    package_integrity_verified: bool | None
    package_provenance_attested: bool | None
    package_provenance_source: str | None
    package_provenance_status: str | None
    applicable_frameworks: list[str] | None = None
    asset: FindingAsset | None = None
    controls_count: int | None = None
    ecosystem: str | None = None
    entity_type: str | None = None
    evidence: dict[str, Any] | None = None
    finding_id: str | None = None
    finding_node_id: str | None = None
    framework_tags: list[str] | None = None
    kev_cve_id: str | None = None
    match_confidence_tier: str | None = None
    node_id: str | None = None
    package: str | None = None
    package_version: str | None = None
    provider: str | None = None
    risk_score: Num | None = None
    schema_version: str | None = None
    suppressed: bool | None = None
    suppression_id: str | None = None


class FindingsResponse(ReadResponse):
    schema_version: str
    findings: list[FindingRow]
    count: int
    total: int
    limit: int
    offset: int
    cursor: str | None
    next_cursor: str | None
    has_more: bool
    sort: str
    scan_id: str | None
    include: list[str]
    filters: dict[str, Any]
    count_metadata: CountMetadata
    window: CountWindow
    warnings: list[str]


# ── fleet ────────────────────────────────────────────────────────────────────


class FleetAgentRow(ReadModel):
    agent_id: str
    tenant_id: str
    name: str
    agent_name: str
    agent_type: str
    canonical_id: str
    config_path: str
    device_fingerprint: str
    enrollment_name: str
    environment: str
    lifecycle_state: str
    mdm_provider: str
    notes: str
    owner: str
    source_id: str
    tags: list[str]
    trust_factors: dict[str, Any]
    trust_score: Num
    credential_count: int
    package_count: int
    server_count: int
    vuln_count: int
    created_at: str
    updated_at: str
    last_discovery: str | None
    last_scan: str | None
    last_seen: str | None


class FleetResponse(ReadResponse):
    agents: list[FleetAgentRow]
    count: int
    total: int
    limit: int
    offset: int
    has_more: bool


class FleetStatsResponse(ReadResponse):
    total: int
    avg_trust_score: Num
    low_trust_count: int
    by_environment: dict[str, int]
    by_state: dict[str, int]


# ── connectors / registry / sources ──────────────────────────────────────────


class ConnectorsResponse(ReadResponse):
    connectors: list[str]


class RegistryPackage(ReadModel):
    ecosystem: str
    name: str


class RegistryServerRow(ReadModel):
    id: str
    name: str
    publisher: str
    description: str
    category: str | None
    transport: str
    verified: bool
    risk_level: str
    risk_justification: str | None
    license: str | None
    latest_version: str | None
    source_url: str | None
    sigstore_bundle: Any
    command_patterns: list[str]
    credential_env_vars: list[str]
    known_cves: list[str]
    packages: list[RegistryPackage]
    tools: list[str]


class RegistryMeta(ReadModel):
    schema_version: str
    source_url: str
    sources: list[str]
    total_servers: int
    updated: str


class RegistryResponse(ReadResponse):
    count: int
    meta: RegistryMeta
    servers: list[RegistryServerRow]


class DataSourceRow(ReadModel):
    source_id: str
    tenant_id: str
    kind: str
    display_name: str
    description: str
    owner: str
    status: str
    enabled: bool
    config: dict[str, Any]
    connector_name: str | None
    credential_mode: str
    credential_ref: str | None
    created_at: str
    updated_at: str
    last_job_id: str | None
    last_run_at: str | None
    last_run_status: str | None
    last_test_message: str | None
    last_test_status: str | None
    last_tested_at: str | None


class SourcesResponse(ReadResponse):
    schema_version: str
    sources: list[DataSourceRow]
    count: int
    total: int
    limit: int
    offset: int


class CloudConnectionRow(ReadModel):
    id: str
    tenant_id: str
    provider: str
    display_name: str
    status: str
    status_detail: str
    auth_params: dict[str, str]
    auto_scan_on_create: bool
    capability_probe_status: str
    credential_present: bool
    has_external_id: bool
    inventory_scope: str
    regions: list[str]
    role_ref: str | None
    scan_interval_minutes: int | None
    scan_mode: str
    verified_capabilities: list[str]
    created_at: str
    updated_at: str
    last_event_at: str | None
    last_scan_at: str | None
    last_scan_id: str | None


class CloudConnectionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    connections: list[CloudConnectionRow]
    connections_scheduler_enabled: bool
    count: int
    workload_auth_modes: dict[str, list[str]]


class TicketingConnectionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    connections: list[dict[str, Any]]
    count: int


class SiemConnectorsResponse(ReadResponse):
    connectors: list[str]


class SiemFormatsResponse(ReadResponse):
    formats: list[str]


class IntelFeedRun(ReadModel):
    status: str
    sync_meta_source: str
    cap_hit: bool
    record_count: int
    parse_errors: int
    validation_failures: int
    validation_status: str
    content_hash: str | None
    etag: str | None
    fetched_at: str | None
    last_modified: str | None
    last_synced: str | None
    last_validated_at: str | None


class IntelSourceRow(ReadModel):
    source_id: str
    display_name: str
    description: str
    kind: str
    connector_type: str
    enabled: bool
    owner: str
    tier: int
    source_tier: int
    support_status: str
    validation_status: str
    license: str
    license_or_terms_url: str
    redistribution: str
    robots_policy: str
    homepage_url: str
    source_url: str
    parser_version: str
    crawl_delay_seconds: Num | None
    feed_run: IntelFeedRun


class IntelSourcesResponse(ReadResponse):
    schema_version: str
    count: int
    sources: list[IntelSourceRow]


# ── runtime / gateway / governance ───────────────────────────────────────────


class GatewayPoliciesResponse(ReadResponse):
    count: int
    policies: list[dict[str, Any]]


class GraphScenariosResponse(ReadResponse):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    count: int
    scenarios: list[dict[str, Any]]


class ActivitySource(ReadModel):
    source: str
    status: str
    event_count: int
    detail: str


class ActivityTimelineResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    status: str
    window_days: int
    event_count: int
    truncated: bool
    events: list[dict[str, Any]]
    sources: list[ActivitySource]


class AgentIdentityRow(ReadModel):
    identity_id: str
    agent_id: str
    tenant_id: str
    blueprint_id: str | None
    owner: str
    owner_type: str
    role: str
    status: str
    token_prefix: str
    allowed_tools: list[str]
    issued_at: str
    expires_at: str | None
    last_used_at: str | None
    revoked_at: str | None
    revoked_reason: str | None
    rotated_to_id: str | None
    rotation_due: bool
    rotation_due_at: str | None
    quota_window_seconds: int | None
    max_requests_per_window: int | None
    max_cost_usd_per_window: Num | None


class IdentitiesResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    identities: list[AgentIdentityRow]


class DriftViolation(ReadModel):
    type: str
    tool_name: str
    detail: str


class DriftIncidentRow(ReadModel):
    incident_id: str
    tenant_id: str
    blueprint_id: str
    status: str
    resolved: bool
    drift_score: Num
    occurrences: int
    violation_count: int
    warning_count: int
    first_detected_at: str
    last_detected_at: str
    resolved_at: str | None
    resolved_by: str | None
    resolution_note: str | None
    top_violations: list[DriftViolation]


class DriftIncidentsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    open_count: int
    incidents: list[DriftIncidentRow]


class RecentProxyAlert(ReadModel):
    detector: str
    message: str
    severity: str
    ts: str


class ProxyAlertSummary(ReadModel):
    alerts_by_detector: dict[str, int]
    alerts_by_severity: dict[str, int]
    blocked_alerts: int
    latest_alert_at: str | None
    total_alerts: int
    recent_alerts: list[RecentProxyAlert] | None = None


class ProxyHealth(ReadModel):
    state: str
    live: bool
    reason: str
    assurance_basis: str
    producer_assurance: str
    heartbeat_at: str | None
    age_seconds: Num | None
    stale_after_seconds: int


class ProxyLatency(ReadModel):
    p50_ms: Num
    p95_ms: Num


class ProxyStatusResponse(ReadResponse):
    """Latest proxy metrics; without a session only ``status`` and ``message`` explain why."""

    producer_assurance: str
    health: ProxyHealth
    status: str | None = None
    message: str | None = None
    tenant_id: str | None = None
    source_id: str | None = None
    session_id: str | None = None
    received_at: str | None = None
    ts: str | None = None
    uptime_seconds: Num | None = None
    total_tool_calls: int | None = None
    total_blocked: int | None = None
    calls_by_tool: dict[str, int] | None = None
    blocked_by_reason: dict[str, int] | None = None
    latency: ProxyLatency | None = None
    alert_summary: ProxyAlertSummary | None = None
    recent_alerts: list[RecentProxyAlert] | None = None


class ProxyAlertRow(ReadModel):
    event_id: str
    tenant_id: str
    source_id: str
    session_id: str
    agent_name: str
    tool_name: str
    detector: str
    event_type: str
    severity: str
    decision: str
    reason_code: str
    producer_assurance: str
    timestamp: str
    ts: str


class ProxyAlertFilters(ReadModel):
    detector: str | None
    severity: str | None
    limit: int


class ProxyAlertsResponse(ReadResponse):
    alerts: list[ProxyAlertRow]
    count: int
    matched_total: int
    filters: ProxyAlertFilters
    summary: ProxyAlertSummary


class SkillsScanSummary(ReadModel):
    files_scanned: int
    findings: int
    clean_files: int
    blocked_files: int
    bundled_files: int
    bundles: int
    credential_env_vars: int
    high_risk_files: int
    malicious_files: int
    malicious_status_files: int
    packages_found: int
    pending_status_files: int
    servers_found: int
    suspicious_files: int
    suspicious_status_files: int
    unavailable_status_files: int
    verified_files: int


class SkillsScanResponse(ReadResponse):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    json_schema_ref: str | None = Field(default=None, alias="$schema")
    schema_version: str | None = None
    report_type: str
    scan_type: str
    run_id: str | None
    status: str
    synthetic: bool | None = None
    note: str
    created_at: str | None
    generated_at: str | None = None
    files: list[dict[str, Any]]
    summary: SkillsScanSummary
