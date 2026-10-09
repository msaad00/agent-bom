"""Response contracts: auth, jobs, discovery, posture, overview and compliance."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import (
    Completeness,
    CountMetadata,
    IssueCounts,
    Num,
    PostureBreakdownItem,
    ReadModel,
    ReadResponse,
    SeverityCounts,
)

# ── auth ─────────────────────────────────────────────────────────────────────


class TenantMembership(ReadModel):
    active: bool
    display_name: str
    role: str
    tenant_id: str
    ui_role: str


class RoleCapability(ReadModel):
    allowed: bool
    description: str
    id: str
    label: str
    minimum_role: str
    minimum_role_label: str


class RoleSummary(ReadModel):
    can_do: list[str]
    can_see: list[str]
    cannot_do: list[str]
    capabilities: list[str]
    capability_matrix: list[RoleCapability]
    description: str
    display_name: str
    role: str
    ui_role: str


class AuthMeResponse(ReadResponse):
    auth_method: str
    auth_required: bool
    authenticated: bool
    configured_modes: list[str]
    managed_trial_envelope: dict[str, Any] | None
    managed_trial_mode: bool
    memberships: list[TenantMembership]
    recommended_ui_mode: str
    request_id: str
    role: str
    role_summary: RoleSummary
    span_id: str | None
    sso_provider: str | None
    subject: str | None
    tenant_id: str
    trace_id: str | None


# ── jobs ─────────────────────────────────────────────────────────────────────


class JobListItem(ReadModel):
    job_id: str
    tenant_id: str | None = None
    status: str | None = None
    created_at: str | None = None
    completed_at: str | None = None
    triggered_by: str | None = None
    batch_id: str | None = None
    parent_job_id: str | None = None
    child_job_ids: list[str] | None = None
    schedule_id: str | None = None
    target: str | None = None
    target_count: int | None = None
    target_index: int | None = None


class JobsResponse(ReadResponse):
    schema_version: str
    jobs: list[JobListItem]
    count: int
    total: int
    limit: int
    offset: int
    status_counts: dict[str, int]


# ── agents / discovery ───────────────────────────────────────────────────────


class DiscoveryProvenance(ReadModel):
    collector: str
    confidence: str
    observed_via: list[str]
    source: str
    source_type: str


class DiscoveredAgent(ReadModel):
    name: str
    agent_type: str
    agent_class: str
    canonical_id: str
    stable_id: str
    config_path: str | None
    status: str
    source: str | None
    source_id: str | None
    version: str | None
    parent_agent: str | None
    device_fingerprint: str | None
    discovered_at: str | None
    last_seen: str | None
    discovery_envelope: dict[str, Any] | None
    discovery_provenance: DiscoveryProvenance | None
    automation_settings: list[dict[str, Any]]
    mcp_servers: list[dict[str, Any]]
    metadata: dict[str, Any]


class AgentsResponse(ReadResponse):
    agents: list[DiscoveredAgent]
    count: int
    count_by_class: dict[str, int]
    scope: str
    source: str
    warnings: list[str]
    count_definition: str | None = None


class ProviderCapabilities(ReadModel):
    data_boundary: str
    guarantees: list[str]
    network_access: bool
    network_destinations: list[str]
    outbound_destinations: list[str]
    permissions_used: list[str]
    required_scopes: list[str]
    scan_modes: list[str]
    writes: bool


class ProviderSdkReadiness(ReadModel):
    distribution: str
    in_scope: bool | None
    installed: bool
    installed_version: str | None
    message: str
    provider: str
    recommended_floor: str | None
    status: str


class ProviderTrustContract(ReadModel):
    agentless: bool
    data_residency: str
    entrypoints_opt_in: bool
    read_only: bool
    redaction_status: str
    scope_control: str
    supports_scope_zero: bool


class DiscoveryProvider(ReadModel):
    name: str
    module: str
    discover_attr: str
    source: str
    capabilities: ProviderCapabilities
    sdk_readiness: list[ProviderSdkReadiness]
    trust_contract: ProviderTrustContract


class DiscoveryProvidersResponse(ReadResponse):
    contract_version: str
    entrypoints_enabled: bool
    provider_count: int
    providers: list[DiscoveryProvider]
    warnings: list[str]


# ── posture / overview ───────────────────────────────────────────────────────


class PostureDimension(ReadModel):
    name: str
    details: str
    score: Num
    weight: Num
    weighted_score: Num


class ScanScorecard(ReadModel):
    grade: str
    score: Num
    summary: str


class PostureResponse(ReadResponse):
    """Graded posture; with ``no_data`` true only grade, score and summary are set."""

    grade: str
    score: Num
    summary: str
    no_data: bool
    dimensions: dict[str, PostureDimension] | None = None
    basis: str | None = None
    breakdown: list[PostureBreakdownItem] | None = None
    display: str | None = None
    display_format: str | None = None
    finding_total: int | None = None
    floored: bool | None = None
    percent: int | None = None
    policy_source: str | None = None
    scan_scorecard: ScanScorecard | None = None
    severity_basis: str | None = None


class AgentCount(ReadModel):
    basis: str
    scan_id: str | None = None
    total: int


class ServiceState(ReadModel):
    count: int
    state: str
    detail: str | None = None
    requires: list[str] | None = None
    connections: int | None = None
    scanned_scopes: int | None = None
    last_scan_at: str | None = None


class PostureCountsResponse(ReadResponse):
    agents: AgentCount
    compound_issues: int
    critical: int
    high: int
    medium: int
    low: int
    unrated: int
    kev: int
    total: int
    deployment_mode: str
    has_agent_context: bool
    has_ci_cd_scan: bool
    has_cluster_scan: bool
    has_fleet_ingest: bool
    has_gateway: bool
    has_local_scan: bool
    has_mcp_context: bool
    has_mesh: bool
    has_proxy: bool
    has_registry: bool
    has_traces: bool
    issues: IssueCounts
    scan_count: int
    scan_sources: list[str]
    services: dict[str, ServiceState]


class OverviewCoverage(ReadModel):
    count: int
    count_exact: bool
    domain: str
    evidence_status: str
    href: str
    label: str
    severity: SeverityCounts


class OverviewDomain(ReadModel):
    detail: dict[str, Any]
    href: str
    label: str
    metric: Num
    metric_label: str
    status: str
    graph_href: str | None = None
    count_exact: bool | None = None
    evidence_status: str | None = None


class OverviewFindingCounts(ReadModel):
    critical: int
    high: int
    medium: int
    low: int
    unrated: int
    kev: int
    total: int


class OverviewHeadline(ReadModel):
    credential_exposed: int
    critical: int
    critical_high: int
    high: int
    hub_findings: int
    kev: int
    latest_scan_at: str | None
    scans: int


class OverviewPosture(ReadModel):
    breakdown: list[PostureBreakdownItem]
    display: str | None
    display_format: str
    finding_total: int
    floored: bool
    grade: str
    grade_thresholds: dict[str, Num]
    penalty_total: Num
    percent: int
    points: Num
    policy_source: str
    score: Num
    severity_basis: str
    summary: str
    weights: dict[str, Num]


class OverviewTopRisk(ReadModel):
    vulnerability_id: str
    package: str | None = None
    severity: str
    risk_score: Num | None = None
    cvss_score: Num | None = None
    epss_score: Num | None = None
    is_kev: bool | None = None
    fixed_version: str | None = None
    impact_category: str | None = None
    asset_id: str | None = None
    canonical_id: str | None = None
    affected_agents: list[str] | None = None
    affected_servers: list[str] | None = None


class OverviewResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    coverage: list[OverviewCoverage]
    domains: dict[str, OverviewDomain]
    finding_counts: OverviewFindingCounts
    headline: OverviewHeadline
    issue_counts: IssueCounts
    posture: OverviewPosture
    top_risks: list[OverviewTopRisk]


class TrendComparison(ReadModel):
    status: str
    reason: str
    previous_scan_id: str | None
    new_findings: int | None
    no_longer_detected: int | None
    still_open: int | None


class TrendPoint(ReadModel):
    scan_id: str
    scope_id: str | None
    timestamp: str
    measurement_version: int
    collection_coverage: str
    comparison: TrendComparison
    critical: int
    high: int
    medium: int
    low: int
    total_vulns: int
    posture_grade: str
    posture_score: Num
    age_sample_count: int
    evidence_sample_count: int
    evidence_age_days: Num | None
    open_finding_age_days: Num | None
    verified_remediation_duration_days: Num | None
    verified_remediations: int | None


class TrendsResponse(ReadResponse):
    age_statistic: str
    available_scopes: list[str]
    count: int
    data_points: list[TrendPoint]
    days: int | None
    freshness_reference: str
    history_limited: bool
    scope_id: str | None


# ── compliance ───────────────────────────────────────────────────────────────


class ControlSeverityBreakdown(ReadModel):
    critical: int
    high: int
    medium: int
    low: int


class ComplianceControl(ReadModel):
    code: str
    control_id: str
    name: str
    status: str
    findings: int
    evaluation_mode: str
    evidence_reason: str
    affected_agents: list[str]
    affected_packages: list[str]
    severity_breakdown: ControlSeverityBreakdown
    tags: list[str]


class ComplianceResponse(ReadResponse):
    overall_score: Num
    overall_status: str
    coverage_pct: Num
    evaluated_controls: int
    total_controls: int
    has_agent_context: bool
    has_mcp_context: bool
    latest_scan: str | None
    scan_count: int
    scan_sources: list[str]
    framework_kinds: dict[str, str]
    summary: dict[str, int]
    aisvs_benchmark: dict[str, Any]
    cis_foundations_benchmark: dict[str, Any]
    nist_800_53_catalog: dict[str, Any]
    cis_controls: list[ComplianceControl]
    cmmc: list[ComplianceControl]
    eu_ai_act: list[ComplianceControl]
    fedramp: list[ComplianceControl]
    iso_27001: list[ComplianceControl]
    mitre_atlas: list[ComplianceControl]
    mitre_attack: list[ComplianceControl]
    nist_800_53: list[ComplianceControl]
    nist_ai_rmf: list[ComplianceControl]
    nist_csf: list[ComplianceControl]
    owasp_agentic_top10: list[ComplianceControl]
    owasp_llm_top10: list[ComplianceControl]
    owasp_mcp_top10: list[ComplianceControl]
    pci_dss: list[ComplianceControl]
    soc2: list[ComplianceControl]


class NarrativeEvidenceSnapshot(ReadModel):
    completed_scan_count: int
    completeness: Completeness
    count_metadata: CountMetadata
    returned: int
    scan_ids: list[str]
    schema_version: str
    source: str
    tenant_id: str
    total: int
    warnings: list[str]


class NarrativeFailingControl(ReadModel):
    control_id: str
    title: str
    status: str
    narrative: str
    affected_agents: list[str]
    affected_findings: list[str]
    affected_packages: list[str]
    remediation_steps: list[str]


class FrameworkNarrative(ReadModel):
    framework: str
    slug: str
    status: str
    score: Num
    narrative: str
    recommendations: list[str]
    failing_controls: list[NarrativeFailingControl]


class RemediationImpact(ReadModel):
    package: str
    current_version: str
    fix_version: str
    narrative: str
    controls_fixed: list[str]
    frameworks_impacted: list[str]


class ComplianceNarrativeResponse(ReadResponse):
    claim_boundary: str
    evidence_snapshot: NarrativeEvidenceSnapshot | None = None
    executive_summary: str
    framework_narratives: list[FrameworkNarrative]
    generated_at: str
    remediation_impact: list[RemediationImpact]
    risk_narrative: str


class HubFrameworkCounts(ReadModel):
    combined: dict[str, int]
    hub: dict[str, int]
    native: dict[str, int]


class HubTotals(ReadModel):
    combined: int
    hub: int
    native: int


class HubPostureResponse(ReadResponse):
    framework_counts: HubFrameworkCounts
    hub_severity_breakdown: dict[str, int]
    totals: HubTotals


class FrameworkCatalogsResponse(ReadResponse):
    frameworks: dict[str, dict[str, Any]]
