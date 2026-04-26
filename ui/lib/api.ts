/**
 * agent-bom API client
 * Connects to the FastAPI backend at NEXT_PUBLIC_API_URL (default: same origin)
 */

import type { UnifiedEdge, UnifiedGraphData, UnifiedNode } from "./graph-schema";
import { getSessionAuthHeaders } from "./auth";
import { getConfiguredApiUrl } from "./runtime-config";

// ─── Types ────────────────────────────────────────────────────────────────────

export type JobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export interface ScanRequest {
  inventory?: string;
  images?: string[];
  k8s?: boolean;
  k8s_namespace?: string;
  tf_dirs?: string[];
  gha_path?: string;
  agent_projects?: string[];
  sbom?: string;
  enrich?: boolean;
  format?: string;
  dynamic_discovery?: boolean;
  dynamic_max_depth?: number;
}

// ── Scan Pipeline Step Types ────────────────────────────────────────────────

export type StepStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface StepEvent {
  type: "step";
  step_id: string;
  status: StepStatus;
  message: string;
  started_at?: string;
  completed_at?: string;
  stats?: Record<string, number>;
  sub_step?: string;
  progress_pct?: number;
}

export interface ProgressEvent {
  type: "progress";
  message: string;
}

export interface DoneEvent {
  type: "done";
  status: string;
  job_id: string;
}

export type SSEEvent = StepEvent | ProgressEvent | DoneEvent;

export const PIPELINE_STEPS = [
  { id: "discovery", label: "Discovery", icon: "Search" },
  { id: "extraction", label: "Extraction", icon: "Package" },
  { id: "scanning", label: "Scanning", icon: "Bug" },
  { id: "enrichment", label: "Enrichment", icon: "Zap" },
  { id: "analysis", label: "Analysis", icon: "Shield" },
  { id: "output", label: "Report", icon: "FileText" },
] as const;

export interface ScanJob {
  job_id: string;
  status: JobStatus;
  created_at: string;
  tenant_id?: string;
  source_id?: string;
  triggered_by?: string;
  started_at?: string;
  completed_at?: string;
  request: ScanRequest;
  progress: string[];
  result?: ScanResult;
  error?: string;
}

export interface ScanResult {
  agents: Agent[];
  blast_radius: BlastRadius[];
  remediation_plan?: RemediationItem[];
  scorecard_summary?: ScorecardSummary;
  scan_performance?: Record<string, number>;
  posture_scorecard?: PostureScorecard;
  summary?: Summary;
  warnings?: string[];
  scan_timestamp?: string;
  tool_version?: string;
  /** Context metadata — auto-detected from scan sources */
  has_mcp_context?: boolean;
  has_agent_context?: boolean;
  scan_sources?: string[];
}

export interface GraphPagination {
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  cursor?: string;
  next_cursor?: string;
}

export interface GraphSnapshot {
  scan_id: string;
  created_at: string;
  node_count: number;
  edge_count: number;
  risk_summary: Record<string, number>;
}

export interface UnifiedGraphResponse extends UnifiedGraphData {
  pagination: GraphPagination;
}

export interface GraphImpactResponse {
  node_id: string;
  affected_nodes: string[];
  affected_by_type: Record<string, number>;
  affected_count: number;
  max_depth_reached: number;
}

export interface GraphNodeDetailResponse {
  node: UnifiedNode;
  edges_out: UnifiedEdge[];
  edges_in: UnifiedEdge[];
  neighbors: string[];
  sources: string[];
  impact: GraphImpactResponse;
}

export interface GraphSearchResponse {
  query: string;
  results: UnifiedNode[];
  pagination: GraphPagination;
}

export interface GraphAgentSelectorItem {
  id: string;
  label: string;
  risk_score: number;
  severity: string;
  status: string;
  data_sources: string[];
  first_seen: string;
  last_seen: string;
}

export interface GraphAgentsResponse {
  scan_id: string;
  tenant_id: string;
  created_at: string;
  agents: GraphAgentSelectorItem[];
  pagination: GraphPagination;
}

export interface GraphDiffResponse {
  nodes_added: string[];
  nodes_removed: string[];
  nodes_changed: string[];
  edges_added: [string, string, string][];
  edges_removed: [string, string, string][];
}

export type GraphExportFormat = "json" | "dot" | "mermaid" | "graphml" | "cypher";

export type DeploymentMode = "local" | "fleet" | "cluster" | "hybrid";

export interface PostureCountsResponse {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  kev: number;
  compound_issues: number;
  deployment_mode?: DeploymentMode;
  has_mcp_context?: boolean;
  has_agent_context?: boolean;
  has_local_scan?: boolean;
  has_fleet_ingest?: boolean;
  has_cluster_scan?: boolean;
  has_ci_cd_scan?: boolean;
  has_mesh?: boolean;
  has_gateway?: boolean;
  has_proxy?: boolean;
  has_traces?: boolean;
  has_registry?: boolean;
  scan_sources?: string[];
  scan_count?: number;
}

export interface RemediationItem {
  package: string;
  ecosystem: string;
  current_version: string;
  fixed_version: string | null;
  severity: string;
  is_kev: boolean;
  /** Normalized 0-10 remediation risk derived from grouped blast-radius risk. */
  impact_score: number;
  priority?: number;
  action?: string;
  reason?: string | null;
  command?: string | null;
  verify_command?: string | null;
  vulnerabilities: string[];
  affected_agents: string[];
  agents_pct: number;
  exposed_credentials: string[];
  credentials_pct: number;
  reachable_tools: string[];
  tools_pct: number;
  owasp_tags: string[];
  atlas_tags: string[];
  nist_ai_rmf_tags?: string[];
  owasp_mcp_tags?: string[];
  owasp_agentic_tags?: string[];
  eu_ai_act_tags?: string[];
  nist_csf_tags?: string[];
  iso_27001_tags?: string[];
  soc2_tags?: string[];
  cis_tags?: string[];
  references?: string[];
  risk_narrative: string;
}

export type AgentStatus = "configured" | "installed-not-configured";

export interface Agent {
  name: string;
  agent_type: string;
  config_path?: string;
  source?: string;
  status?: AgentStatus;
  mcp_servers: MCPServer[];
  automation_settings?: string[];
}

export interface MCPServer {
  name: string;
  command?: string;
  args?: string[];
  transport?: string;
  url?: string;
  auth_mode?: string;
  config_path?: string;
  security_warnings?: string[];
  packages: Package[];
  tools?: Tool[];
  env?: Record<string, string>;
  vulnerabilities?: Vulnerability[];
  has_credentials?: boolean;
  credential_env_vars?: string[];
  security_blocked?: boolean;
  provenance?: MCPProvenance;
}

export interface MCPProvenance {
  observed_via: string[];
  observed_scopes: string[];
  scan_sources: string[];
  source_agents: string[];
  configured_locally: boolean;
  fleet_present: boolean;
  gateway_registered: boolean;
  runtime_observed: boolean;
  first_seen?: string | null;
  last_seen?: string | null;
  last_synced?: string | null;
}

export interface Package {
  name: string;
  version: string;
  ecosystem: string;
  purl?: string;
  vulnerabilities?: Vulnerability[];
}

export interface Vulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "none";
  /** API v2 field — same as description */
  summary?: string;
  description?: string;
  references?: string[];
  advisory_sources?: string[];
  aliases?: string[];
  cvss_score?: number;
  epss_score?: number;
  /** API v2 field — same as cisa_kev */
  is_kev?: boolean;
  cisa_kev?: boolean;
  fixed_version?: string;
  /** API v2 field — same as published */
  published_at?: string;
  modified_at?: string;
  nvd_published?: string;
  published?: string;
  /** Phase 2 fields */
  severity_source?: string;
  confidence?: number;
}

export interface BlastRadius {
  vulnerability_id: string;
  severity: string;
  package?: string;
  ecosystem?: string;
  affected_agents: string[];
  affected_servers?: string[];
  exposed_credentials: string[];
  /** API v2 field — same as reachable_tools */
  exposed_tools?: string[];
  reachable_tools: string[];
  /** API v2 field — same as blast_score (0-100) */
  risk_score?: number;
  blast_score: number;
  cvss_score?: number;
  epss_score?: number;
  is_kev?: boolean;
  cisa_kev?: boolean;
  fixed_version?: string;
  owasp_tags?: string[];
  atlas_tags?: string[];
  nist_ai_rmf_tags?: string[];
  owasp_mcp_tags?: string[];
  owasp_agentic_tags?: string[];
  eu_ai_act_tags?: string[];
  /** CWE-derived impact category: code-execution, credential-access, etc. */
  impact_category?: string;
  /** Full credential set before CWE filtering (for reference) */
  all_server_credentials?: string[];
  /** Human-readable attack vector description */
  attack_vector_summary?: string;
}

// ─── Attack Flow Types ───────────────────────────────────────────────────────

export interface AttackFlowNodeData {
  [key: string]: unknown;
  nodeType: "cve" | "package" | "server" | "agent" | "credential" | "tool";
  label: string;
  severity?: string;
  cvss_score?: number;
  epss_score?: number;
  is_kev?: boolean;
  risk_score?: number;
  fixed_version?: string;
  owasp_tags?: string[];
  atlas_tags?: string[];
  nist_ai_rmf_tags?: string[];
  owasp_mcp_tags?: string[];
  owasp_agentic_tags?: string[];
  eu_ai_act_tags?: string[];
  version?: string;
  ecosystem?: string;
  agent_type?: string;
  status?: string;
  description?: string;
}

export interface AttackFlowNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: AttackFlowNodeData;
}

export interface AttackFlowEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  animated?: boolean;
  style?: { stroke: string };
}

export interface AttackFlowStats {
  total_cves: number;
  total_packages: number;
  total_servers: number;
  total_agents: number;
  total_credentials: number;
  total_tools: number;
  severity_counts: Record<string, number>;
}

export interface AttackFlowResponse {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
  stats: AttackFlowStats;
}

// ─── Context Graph Types ────────────────────────────────────────────────────

export interface ContextGraphResponse {
  nodes: Array<{
    id: string;
    kind: string;
    label: string;
    metadata: Record<string, unknown>;
  }>;
  edges: Array<{
    source: string;
    target: string;
    kind: string;
    weight: number;
    metadata: Record<string, unknown>;
  }>;
  lateral_paths: Array<{
    source: string;
    target: string;
    hops: string[];
    edges: string[];
    composite_risk: number;
    summary: string;
    credential_exposure: string[];
    tool_exposure: string[];
    vuln_ids: string[];
  }>;
  interaction_risks: Array<{
    pattern: string;
    agents: string[];
    risk_score: number;
    description: string;
    owasp_agentic_tag?: string;
  }>;
  stats: {
    total_nodes: number;
    total_edges: number;
    agent_count: number;
    shared_server_count: number;
    shared_credential_count: number;
    lateral_path_count: number;
    max_lateral_depth: number;
    highest_path_risk: number;
    interaction_risk_count: number;
  };
}

export interface Tool {
  name: string;
  description?: string;
}

export interface Summary {
  total_agents: number;
  total_servers: number;
  total_packages: number;
  total_vulnerabilities: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

export interface ScorecardSummary {
  total_packages: number;
  unique_packages: number;
  eligible_packages: number;
  attempted_packages: number;
  enriched_packages: number;
  unresolved_packages: number;
  failed_packages: number;
  transient_failed_packages?: number;
  persistent_failed_packages?: number;
  failed_reasons?: Record<string, number>;
}

export interface PostureDimension {
  name: string;
  score: number;
  weight: number;
  weighted_score: number;
  details: string;
}

export interface PostureScorecard {
  grade: string;
  score: number;
  summary: string;
  dimensions: Record<string, PostureDimension>;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface VersionInfo {
  version: string;
  api_version: string;
  python_package: string;
}

export interface AuthDebugResponse {
  authenticated: boolean;
  auth_required: boolean;
  configured_modes: string[];
  recommended_ui_mode: string;
  auth_method: string | null;
  subject: string | null;
  role: string | null;
  tenant_id: string;
  oidc_issuer_suffix: string | null;
  api_key_id_prefix: string | null;
  request_id: string | null;
  trace_id: string | null;
  span_id: string | null;
}

export interface AuthRoleCapability {
  id: string;
  label: string;
  description: string;
  minimum_role: string;
  minimum_role_label: string;
  allowed: boolean;
}

export interface AuthRoleSummary {
  role: string;
  ui_role: string;
  display_name: string;
  description: string;
  capabilities: string[];
  capability_matrix: AuthRoleCapability[];
  can_see: string[];
  can_do: string[];
  cannot_do: string[];
}

export interface AuthMembership {
  tenant_id: string;
  role: string;
  ui_role: string;
  display_name: string;
  active: boolean;
}

export interface AuthMeResponse {
  authenticated: boolean;
  auth_required: boolean;
  configured_modes: string[];
  recommended_ui_mode: string;
  auth_method: string | null;
  subject: string | null;
  tenant_id: string;
  role: string | null;
  role_summary: AuthRoleSummary | null;
  memberships: AuthMembership[];
  request_id: string | null;
  trace_id: string | null;
  span_id: string | null;
}

export interface AuthPolicyResponse {
  api_key: {
    default_ttl_seconds: number;
    max_ttl_seconds: number;
    default_overlap_seconds: number;
    max_overlap_seconds: number;
    rotation_policy: string;
    rotation_endpoint: string;
  };
  rate_limit_key: {
    status: string;
    last_rotated: string | null;
    age_days: number | null;
    rotation_days?: number | null;
    max_age_days?: number | null;
    message?: string;
    fallback_source?: string | null;
    [key: string]: unknown;
  };
  audit_hmac: {
    status: string;
    configured: boolean;
    key_id_configured?: boolean;
    rotation_tracking_supported?: boolean;
    [key: string]: unknown;
  };
  ui: {
    recommended_mode: string;
    configured_modes: string[];
    browser_session: string;
    session_storage_fallback: string;
    credentials_mode: string;
    trusted_proxy_headers: string[];
    message: string;
  };
  rate_limit_runtime: {
    backend: string;
    postgres_configured: boolean;
    configured_api_replicas: number;
    shared_required: boolean;
    shared_across_replicas: boolean;
    fail_closed: boolean;
    message: string;
  };
  secret_integrity: {
    audit_hmac: {
      status: string;
      configured: boolean;
      required: boolean;
      source: string;
      persists_across_restart: boolean;
      rotation_tracking_supported: boolean;
      rotation_status: string;
      rotation_method: string;
      rotation_days: number | null;
      max_age_days: number | null;
      last_rotated: string | null;
      age_days: number | null;
      rotation_message: string;
      message: string;
    };
    compliance_signing: {
      algorithm: string;
      mode: string;
      configured: boolean;
      key_id: string | null;
      public_key_endpoint: string | null;
      auditor_distributable: boolean;
      uses_audit_hmac_secret: boolean;
      persists_across_restart: boolean;
      rotation_tracking_supported: boolean;
      rotation_status: string;
      rotation_method: string;
      rotation_days: number | null;
      max_age_days: number | null;
      last_rotated: string | null;
      age_days: number | null;
      rotation_message: string;
      message: string;
    };
  };
  tenant_quotas: {
    active_scan_jobs: number;
    retained_scan_jobs: number;
    fleet_agents: number;
    schedules: number;
  };
  tenant_quota_runtime: {
    source: string;
    per_tenant_overrides: boolean;
    active_override: boolean;
    override_endpoint: string;
    message: string;
    overrides: Partial<Record<"active_scan_jobs" | "retained_scan_jobs" | "fleet_agents" | "schedules", number>>;
    usage: Record<
      "active_scan_jobs" | "retained_scan_jobs" | "fleet_agents" | "schedules",
      {
        limit: number;
        default_limit: number;
        override_limit: number | null;
        current: number;
        remaining: number | null;
        enforced: boolean;
        source: string;
        utilization_pct: number | null;
        status: "ok" | "near_limit" | "at_limit" | "unlimited" | string;
        recommended_action: string;
      }
    >;
  };
  identity_provisioning: {
    oidc: {
      supported: boolean;
      configured: boolean;
      mode: string;
      issuer_hosts: string[];
      provider_count: number;
      audience_configured: boolean;
      role_claim: string | null;
      tenant_claim: string | null;
      require_role_claim: boolean;
      require_tenant_claim: boolean;
      allow_default_tenant: boolean;
      required_nonce: boolean;
      message: string;
    };
    saml: {
      supported: boolean;
      configured: boolean;
      metadata_endpoint: string;
      acs_path: string | null;
      idp_host: string | null;
      role_attribute: string;
      tenant_attribute: string;
      require_role_attribute: boolean;
      require_tenant_attribute: boolean;
      session_ttl_seconds: number;
      message: string;
    };
    scim: {
      supported: boolean;
      configured: boolean;
      status: string;
      base_path: string;
      token_configured: boolean;
      external_id_attribute: string;
      role_attribute: string;
      tenant_attribute: string;
      groups_required: boolean;
      verified_idp_templates?: Array<{
        idp: string;
        status: string;
        notes: string;
      }>;
      message: string;
    };
    session_revocation: {
      service_keys: string;
      session_api_key: string;
      browser_sessions: string;
    };
  };
}

export type ApiKeyLifecycleState = "active" | "rotation_overlap" | "rotated" | "revoked" | "expired";

export interface ApiKeyRecord {
  key_id: string;
  key_prefix: string;
  name: string;
  role: string;
  created_at: string;
  expires_at: string | null;
  scopes: string[];
  tenant_id: string;
  revoked_at: string | null;
  rotation_overlap_until: string | null;
  replacement_key_id: string | null;
  state: ApiKeyLifecycleState;
  overlap_seconds_remaining: number | null;
}

export interface ListKeysResponse {
  keys: ApiKeyRecord[];
}

export interface CreateApiKeyRequest {
  name: string;
  role: string;
  expires_at?: string | null;
  scopes?: string[];
}

export interface CreateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  message: string;
}

export interface RotateApiKeyRequest {
  name?: string | null;
  expires_at?: string | null;
  overlap_seconds?: number | null;
}

export interface RotateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  replaced_key_id: string;
  overlap_until: string;
  overlap_seconds: number;
  message: string;
}

export interface TenantQuotaUpdateRequest {
  active_scan_jobs?: number | null;
  retained_scan_jobs?: number | null;
  fleet_agents?: number | null;
  schedules?: number | null;
}

export interface ConnectorsResponse {
  connectors: string[];
}

export interface ConnectorHealthResponse {
  connector: string;
  state: string;
  message: string;
  api_version: string | null;
}

export type SourceKind =
  | "scan.repo"
  | "scan.image"
  | "scan.iac"
  | "scan.cloud"
  | "scan.mcp_config"
  | "connector.cloud_read_only"
  | "connector.registry"
  | "connector.warehouse"
  | "ingest.fleet_sync"
  | "ingest.trace_push"
  | "ingest.result_push"
  | "ingest.artifact_import"
  | "runtime.proxy"
  | "runtime.gateway";

export type SourceStatus = "configured" | "healthy" | "degraded" | "disabled";

export interface SourceRecord {
  source_id: string;
  tenant_id: string;
  display_name: string;
  kind: SourceKind;
  description: string;
  owner: string;
  connector_name: string | null;
  credential_mode: string;
  credential_ref: string | null;
  enabled: boolean;
  status: SourceStatus;
  config: Record<string, unknown>;
  last_tested_at: string | null;
  last_test_status: string | null;
  last_test_message: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_job_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SourcesResponse {
  sources: SourceRecord[];
  count: number;
}

export interface SourceCreateRequest {
  display_name: string;
  kind: SourceKind;
  description?: string;
  owner?: string;
  connector_name?: string | null;
  credential_mode?: string;
  credential_ref?: string | null;
  enabled?: boolean;
  config?: Record<string, unknown>;
  tenant_id?: string;
}

export interface SourceUpdateRequest {
  display_name?: string;
  description?: string;
  owner?: string;
  connector_name?: string | null;
  credential_mode?: string;
  credential_ref?: string | null;
  enabled?: boolean;
  status?: SourceStatus;
  config?: Record<string, unknown>;
}

export interface SourceCheckResponse {
  source_id: string;
  status: SourceStatus;
  message: string;
  tested_at: string;
}

export interface SourceRunResponse {
  source_id: string;
  job_id: string;
  status: JobStatus;
}

export interface SourceJobsResponse {
  source_id: string;
  jobs: ScanJob[];
  count: number;
}

export interface JobsResponse {
  jobs: JobListItem[];
  count: number;
  total?: number;
  limit?: number;
  offset?: number;
}

export interface JobListItem {
  job_id: string;
  status: JobStatus;
  created_at: string;
  completed_at?: string;
  request?: ScanRequest;
  summary?: Summary;
  scan_timestamp?: string;
  pushed?: boolean;
  error?: string;
}

export interface AgentsResponse {
  agents: Agent[];
  count: number;
  warnings: string[];
}

export interface RegistryServer {
  id: string;
  name: string;
  publisher: string;
  verified: boolean;
  transport: string;
  risk_level: "low" | "medium" | "high";
  packages: Array<{ name: string; ecosystem: string }>;
  source_url: string;
  description?: string;
  sigstore_bundle: string | null;
  tools?: string[];
  credential_env_vars?: string[];
  category?: string;
  license?: string;
  latest_version?: string;
  known_cves?: string[];
  command_patterns?: string[];
  risk_justification?: string;
}

export interface RegistryResponse {
  servers: RegistryServer[];
  count: number;
}

// ─── Compliance Narrative Types ──────────────────────────────────────────────

export interface ControlNarrative {
  control_id: string;
  title: string;
  status: "pass" | "warning" | "fail";
  narrative: string;
  affected_packages: string[];
  affected_agents: string[];
  remediation_steps: string[];
}

export interface FrameworkNarrative {
  framework: string;
  slug: string;
  status: "passing" | "at_risk" | "failing";
  score: number;
  narrative: string;
  recommendations: string[];
  failing_controls: ControlNarrative[];
}

export interface RemediationImpact {
  package: string;
  current_version: string;
  fix_version: string;
  controls_fixed: string[];
  frameworks_impacted: string[];
  narrative: string;
}

export interface ComplianceNarrativeResponse {
  executive_summary: string;
  framework_narratives: FrameworkNarrative[];
  remediation_impact: RemediationImpact[];
  risk_narrative: string;
  generated_at: string;
}

// ─── Compliance Types ─────────────────────────────────────────────────────────

export interface ComplianceControl {
  code: string;
  name: string;
  findings: number;
  status: "pass" | "warning" | "fail";
  severity_breakdown: Record<string, number>;
  affected_packages: string[];
  affected_agents: string[];
}

export interface ComplianceResponse {
  overall_score: number;
  overall_status: "pass" | "warning" | "fail";
  scan_count: number;
  latest_scan: string | null;
  has_mcp_context?: boolean;
  has_agent_context?: boolean;
  scan_sources?: string[];
  owasp_llm_top10: ComplianceControl[];
  owasp_mcp_top10: ComplianceControl[];
  mitre_atlas: ComplianceControl[];
  nist_ai_rmf: ComplianceControl[];
  owasp_agentic_top10: ComplianceControl[];
  eu_ai_act: ComplianceControl[];
  nist_csf: ComplianceControl[];
  iso_27001: ComplianceControl[];
  soc2: ComplianceControl[];
  cis_controls: ComplianceControl[];
  cmmc: ComplianceControl[];
  nist_800_53: ComplianceControl[];
  fedramp: ComplianceControl[];
  pci_dss: ComplianceControl[];
  summary: {
    owasp_pass: number; owasp_warn: number; owasp_fail: number;
    owasp_mcp_pass: number; owasp_mcp_warn: number; owasp_mcp_fail: number;
    atlas_pass: number; atlas_warn: number; atlas_fail: number;
    nist_pass: number;  nist_warn: number;  nist_fail: number;
    owasp_agentic_pass: number; owasp_agentic_warn: number; owasp_agentic_fail: number;
    eu_ai_act_pass: number; eu_ai_act_warn: number; eu_ai_act_fail: number;
    nist_csf_pass: number; nist_csf_warn: number; nist_csf_fail: number;
    iso_27001_pass: number; iso_27001_warn: number; iso_27001_fail: number;
    soc2_pass: number; soc2_warn: number; soc2_fail: number;
    cis_pass: number; cis_warn: number; cis_fail: number;
    cmmc_pass: number; cmmc_warn: number; cmmc_fail: number;
    nist_800_53_pass: number; nist_800_53_warn: number; nist_800_53_fail: number;
    fedramp_pass: number; fedramp_warn: number; fedramp_fail: number;
    pci_dss_pass: number; pci_dss_warn: number; pci_dss_fail: number;
  };
}

export interface FrameworkCatalogMetadata {
  schema_version: number;
  catalog_id: string;
  catalog_type: string;
  source: string;
  attack_version: string;
  updated_at: string;
  fetched_at: number;
  normalized_sha256: string;
  sources: Record<string, unknown>;
  technique_count: number;
  cwe_mapping_count: number;
  path?: string;
}

export interface FrameworkCatalogsResponse {
  frameworks: {
    mitre_attack: FrameworkCatalogMetadata;
  };
}

// ─── Agent Detail Types ──────────────────────────────────────────────────────

export interface AgentDetailResponse {
  agent: Agent;
  summary: {
    total_servers: number;
    total_packages: number;
    total_tools: number;
    total_credentials: number;
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
  };
  blast_radius: BlastRadius[];
  credentials: string[];
  fleet?: FleetAgent | null;
}

export interface AgentLifecycleResponse {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
  stats: Record<string, number>;
}

// ─── Fleet Types ─────────────────────────────────────────────────────────────

export type FleetLifecycleState = "discovered" | "pending_review" | "approved" | "quarantined" | "decommissioned";

export interface FleetAgent {
  agent_id: string;
  name: string;
  agent_type: string;
  config_path: string;
  lifecycle_state: FleetLifecycleState;
  owner: string | null;
  environment: string | null;
  tags: string[];
  trust_score: number;
  trust_factors: Record<string, number>;
  server_count: number;
  package_count: number;
  credential_count: number;
  vuln_count: number;
  last_discovery: string | null;
  last_scan: string | null;
  created_at: string;
  updated_at: string;
  notes: string;
}

export interface FleetResponse {
  agents: FleetAgent[];
  count: number;
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface FleetStatsResponse {
  total: number;
  by_state: Record<string, number>;
  by_environment: Record<string, number>;
  avg_trust_score: number;
  low_trust_count: number;
}

export interface FleetSyncResult {
  synced: number;
  new: number;
  updated: number;
}

export interface ScanSchedule {
  schedule_id: string;
  name: string;
  cron_expression: string;
  scan_config: Record<string, unknown>;
  enabled: boolean;
  last_run: string | null;
  next_run: string | null;
  last_job_id: string | null;
  created_at: string;
  updated_at: string;
  tenant_id: string;
}

export interface ScheduleCreateRequest {
  name: string;
  cron_expression: string;
  scan_config?: Record<string, unknown>;
  enabled?: boolean;
  tenant_id?: string;
}

// ─── Gateway types ───────────────────────────────────────────────────────────

export type PolicyMode = "audit" | "enforce";

export interface GatewayRule {
  id: string;
  description: string;
  action: string;
  block_tools: string[];
  tool_name: string | null;
  tool_name_pattern: string | null;
  arg_pattern: Record<string, string>;
  rate_limit: number | null;
  require_registry_verified: boolean;
}

export interface GatewayPolicy {
  policy_id: string;
  name: string;
  description: string;
  mode: PolicyMode;
  rules: GatewayRule[];
  bound_agents: string[];
  bound_agent_types: string[];
  bound_environments: string[];
  created_at: string;
  updated_at: string;
  enabled: boolean;
}

export interface GatewayPolicyResponse {
  policies: GatewayPolicy[];
  count: number;
}

export interface PolicyAuditEntry {
  entry_id: string;
  policy_id: string;
  policy_name: string;
  rule_id: string;
  agent_name: string;
  tool_name: string;
  arguments_preview: Record<string, unknown>;
  action_taken: string;
  reason: string;
  timestamp: string;
}

export interface GatewayAuditResponse {
  entries: PolicyAuditEntry[];
  count: number;
}

export interface GatewayStatsResponse {
  total_policies: number;
  enforce_count: number;
  audit_count: number;
  enabled_count: number;
  total_rules: number;
  audit_entries: number;
  blocked_count: number;
  alerted_count: number;
  policy_runtime: GatewayPolicyRuntimeSummary;
}

export interface GatewayPolicyRuntimeSummary {
  source: string;
  source_kind: string;
  enabled_policies: number;
  rollout_mode: "disabled" | "advisory_only" | "mixed" | "default_deny" | "blocking";
  summary: string;
  total_rules: number;
  blocking_rules: number;
  advisory_rules: number;
  allowlist_rules: number;
  default_deny_rules: number;
  read_only_rules: number;
  secret_path_rules: number;
  unknown_egress_rules: number;
  denied_tool_classes: string[];
  blocks_requests: boolean;
  advisory_only: boolean;
  default_deny: boolean;
  protects_secret_paths: boolean;
  restricts_unknown_egress: boolean;
}

export interface EvaluateResult {
  allowed: boolean;
  reason: string;
  policy_id: string | null;
  policies_evaluated: number;
}

export interface PostureResponse {
  grade: string;
  score: number;
  summary: string;
  dimensions: Record<string, { score: number; label: string; details?: string }>;
}

export interface EnrichmentSourcePosture {
  source: string;
  status: "ok" | "stale" | "degraded" | "unknown" | string;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_cache_at: string | null;
  age_seconds: number | null;
  slo_seconds: number;
  success_count: number;
  failure_count: number;
  cache_hit_count: number;
  message: string;
}

export interface EnrichmentPostureResponse {
  status: "ok" | "stale" | "degraded" | "unknown" | string;
  sources: EnrichmentSourcePosture[];
  operator_message: string;
}

// ─── Fetch helpers ────────────────────────────────────────────────────────────
//
// Closes #1956. All five wrappers below funnel through ApiError-typed throws
// (lib/api-errors.ts) and the GET wrapper is memoized + dedup'd via
// lib/api-cache.ts. Mutations (post/postVoid/put/del) invalidate cache
// prefixes so a write to /v1/scan/{id} flushes /v1/scan and any nested
// children without each call site having to remember.

import { ApiNetworkError, classifyApiResponse } from "./api-errors";
import { cachedGet, invalidate as _invalidate, type CacheOptions } from "./api-cache";

const FETCH_TIMEOUT_MS = 30_000;

function withTimeout(): AbortSignal {
  return AbortSignal.timeout(FETCH_TIMEOUT_MS);
}

async function _parseBody(res: Response): Promise<unknown> {
  // Only called on the error path; caller never reads the body again, so we
  // can consume the stream directly. Avoid `.clone()` because test mocks
  // and partial Response shims may not implement it.
  try {
    return await res.json();
  } catch {
    try {
      return await res.text();
    } catch {
      return undefined;
    }
  }
}

async function _doFetch(path: string, init: RequestInit, method: string): Promise<Response> {
  const url = `${getConfiguredApiUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new ApiNetworkError(`Network request failed: ${message}`, { url, method, cause });
  }
  if (!res.ok) {
    const body = await _parseBody(res);
    throw classifyApiResponse(res, body, method);
  }
  return res;
}

/** Cache-prefix invalidation rules for write paths. */
function _invalidationsFor(path: string): string[] {
  // Any write to /v1/<resource>[/<id>][/...] flushes /v1/<resource> entirely.
  // Coarse on purpose: getting a stale /v1/scan list right after the user
  // submits a scan is the failure mode this is here to prevent.
  const match = /^\/v1\/[^/?]+/.exec(path);
  return match ? [match[0]] : [];
}

function _runInvalidations(path: string): void {
  for (const prefix of _invalidationsFor(path)) {
    _invalidate(prefix);
  }
}

async function get<T>(path: string, cacheOptions: CacheOptions = {}): Promise<T> {
  const key = `GET ${path}`;
  return cachedGet<T>(
    key,
    async () => {
      const res = await _doFetch(path, {
        credentials: "include",
        headers: getSessionAuthHeaders(),
        signal: withTimeout(),
      }, "GET");
      return res.json() as Promise<T>;
    },
    cacheOptions,
  );
}

async function post<T>(path: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await _doFetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders(), ...headers },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "POST");
  _runInvalidations(path);
  return res.json() as Promise<T>;
}

async function postVoid(path: string, body: unknown, headers: Record<string, string> = {}): Promise<void> {
  await _doFetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders(), ...headers },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "POST");
  _runInvalidations(path);
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await _doFetch(path, {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders() },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "PUT");
  _runInvalidations(path);
  return res.json() as Promise<T>;
}

async function del(path: string): Promise<void> {
  await _doFetch(path, {
    method: "DELETE",
    credentials: "include",
    headers: getSessionAuthHeaders(),
    signal: withTimeout(),
  }, "DELETE");
  _runInvalidations(path);
}

async function getBlob(path: string): Promise<Blob> {
  const res = await _doFetch(path, {
    credentials: "include",
    headers: getSessionAuthHeaders(),
    signal: withTimeout(),
  }, "GET");
  return res.blob();
}

// Re-export the typed errors so call sites can `import { ApiAuthError } from "@/lib/api"`
// without learning a new module path.
export {
  ApiError,
  ApiAuthError,
  ApiForbiddenError,
  ApiNotFoundError,
  ApiConflictError,
  ApiRateLimitError,
  ApiServerError,
  ApiValidationError,
  ApiNetworkError,
} from "./api-errors";
export { invalidate as invalidateApiCache, clearCache as _clearApiCacheForTests } from "./api-cache";

// ─── API functions ────────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>("/health"),
  version: () => get<VersionInfo>("/version"),
  getAuthMe: () => get<AuthMeResponse>("/v1/auth/me"),
  getAuthDebug: () => get<AuthDebugResponse>("/v1/auth/debug"),
  getAuthPolicy: () => get<AuthPolicyResponse>("/v1/auth/policy"),
  getTenantQuota: () => get<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota"),
  updateTenantQuota: (body: TenantQuotaUpdateRequest) =>
    put<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota", body),
  resetTenantQuota: () => del("/v1/auth/quota"),
  createAuthSession: (apiKey: string) => postVoid("/v1/auth/session", { api_key: apiKey }),
  deleteAuthSession: () => del("/v1/auth/session"),
  reportClientError: (body: { message: string; digest?: string; path?: string; component?: string }) =>
    post<{ ok: boolean }>("/v1/ui/errors", body),
  listKeys: () => get<ListKeysResponse>("/v1/auth/keys"),
  createKey: (body: CreateApiKeyRequest) => post<CreateApiKeyResponse>("/v1/auth/keys", body),
  rotateKey: (keyId: string, body: RotateApiKeyRequest) =>
    post<RotateApiKeyResponse>(`/v1/auth/keys/${encodeURIComponent(keyId)}/rotate`, body),
  deleteKey: (keyId: string) => del(`/v1/auth/keys/${encodeURIComponent(keyId)}`),

  /** Start a scan — returns immediately with job_id */
  startScan: (req: ScanRequest) => post<ScanJob>("/v1/scan", req),

  /** Poll scan status + results */
  getScan: (jobId: string) => get<ScanJob>(`/v1/scan/${jobId}`),

  /** Export a completed scan graph in a graph-native format. */
  downloadScanGraph: (jobId: string, format: GraphExportFormat = "json") =>
    getBlob(`/v1/scan/${encodeURIComponent(jobId)}/graph-export?format=${encodeURIComponent(format)}`),

  /** Delete a job record */
  deleteScan: (jobId: string) => del(`/v1/scan/${jobId}`),

  /** List all jobs */
  listJobs: (options?: { includeDetails?: boolean; limit?: number; offset?: number }) => {
    const params = new URLSearchParams();
    if (options?.includeDetails) params.set("include_details", "true");
    if (typeof options?.limit === "number") params.set("limit", String(options.limit));
    if (typeof options?.offset === "number") params.set("offset", String(options.offset));
    const qs = params.toString();
    return get<JobsResponse>(`/v1/jobs${qs ? `?${qs}` : ""}`);
  },

  /** Quick agent discovery (no CVE scan) */
  listAgents: () => get<AgentsResponse>("/v1/agents"),

  /** Get detailed view of a single agent */
  getAgentDetail: (name: string) => get<AgentDetailResponse>(`/v1/agents/${encodeURIComponent(name)}`),

  /** Get React Flow lifecycle graph for an agent */
  getAgentLifecycle: (name: string) => get<AgentLifecycleResponse>(`/v1/agents/${encodeURIComponent(name)}/lifecycle`),

  /** MCP registry catalog */
  listRegistry: () => get<RegistryResponse>("/v1/registry"),
  getRegistryServer: (id: string) => get<RegistryServer>(`/v1/registry/${id}`),

  /** Get attack flow graph for a completed scan */
  getAttackFlow: (
    jobId: string,
    filters?: { cve?: string; severity?: string; framework?: string; agent?: string }
  ) => {
    const params = new URLSearchParams();
    if (filters?.cve) params.set("cve", filters.cve);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.framework) params.set("framework", filters.framework);
    if (filters?.agent) params.set("agent", filters.agent);
    const qs = params.toString();
    return get<AttackFlowResponse>(`/v1/scan/${jobId}/attack-flow${qs ? `?${qs}` : ""}`);
  },

  /** Get context graph with lateral movement analysis */
  getContextGraph: (jobId: string, agent?: string) => {
    const params = new URLSearchParams();
    if (agent) params.set("agent", agent);
    const qs = params.toString();
    return get<ContextGraphResponse>(`/v1/scan/${jobId}/context-graph${qs ? `?${qs}` : ""}`);
  },

  /** List persisted unified graph snapshots */
  getGraphSnapshots: (limit = 50) => get<GraphSnapshot[]>(`/v1/graph/snapshots?limit=${limit}`),

  /** Diff two persisted graph snapshots without loading either full graph */
  getGraphDiff: (oldScanId: string, newScanId: string) => {
    const params = new URLSearchParams();
    params.set("old", oldScanId);
    params.set("new", newScanId);
    return get<GraphDiffResponse>(`/v1/graph/diff?${params.toString()}`);
  },

  /** Load the unified graph for a specific snapshot or the latest persisted state */
  getGraph: (filters?: {
    scanId?: string;
    entityTypes?: string[];
    minSeverity?: string;
    relationships?: string[];
    staticOnly?: boolean;
    dynamicOnly?: boolean;
    maxDepth?: number;
    offset?: number;
    limit?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.entityTypes && filters.entityTypes.length > 0) {
      params.set("entity_types", filters.entityTypes.join(","));
    }
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    if (filters?.relationships && filters.relationships.length > 0) {
      params.set("relationships", filters.relationships.join(","));
    }
    if (filters?.staticOnly) params.set("static_only", "true");
    if (filters?.dynamicOnly) params.set("dynamic_only", "true");
    if (filters?.maxDepth != null) params.set("max_depth", String(filters.maxDepth));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<UnifiedGraphResponse>(`/v1/graph${qs ? `?${qs}` : ""}`);
  },

  /** Search graph nodes within a snapshot */
  searchGraph: (query: string, filters?: { scanId?: string; offset?: number; limit?: number }) => {
    const params = new URLSearchParams();
    params.set("q", query);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    return get<GraphSearchResponse>(`/v1/graph/search?${params.toString()}`);
  },

  /** List agent nodes for large graph selectors without loading the full graph */
  listGraphAgents: (filters?: { query?: string; scanId?: string; offset?: number; limit?: number; cursor?: string }) => {
    const params = new URLSearchParams();
    if (filters?.query) params.set("q", filters.query);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    const qs = params.toString();
    return get<GraphAgentsResponse>(`/v1/graph/agents${qs ? `?${qs}` : ""}`);
  },

  /** Load one graph node plus impact and neighbor context */
  getGraphNode: (nodeId: string, scanId?: string) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    const qs = params.toString();
    return get<GraphNodeDetailResponse>(`/v1/graph/node/${encodeURIComponent(nodeId)}${qs ? `?${qs}` : ""}`);
  },

  /** Connect to SSE stream for real-time progress */
  streamScan: (jobId: string, onMessage: (data: SSEEvent) => void, onDone: () => void) => {
    const es = new EventSource(`${getConfiguredApiUrl()}/v1/scan/${jobId}/stream`, { withCredentials: true });
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data as string);
        onMessage(data);
        if (data.type === "done") {
          es.close();
          onDone();
        }
      } catch {
        // ignore parse errors
      }
    };
    es.onerror = () => {
      es.close();
      onDone();
    };
    return () => es.close(); // cleanup fn
  },

  /** Full posture grade + dimensions */
  getPosture: () => get<PostureResponse>("/v1/posture"),

  /** Runtime health for external vulnerability enrichment sources */
  getEnrichmentPosture: () => get<EnrichmentPostureResponse>("/v1/posture/enrichment"),

  /** Lightweight aggregate counts + scan context for nav badges */
  getPostureCounts: () => get<PostureCountsResponse>("/v1/posture/counts"),

  /** Compliance posture across all completed scans */
  getCompliance: () => get<ComplianceResponse>("/v1/compliance"),

  /** Active framework catalog metadata surfaced by the API */
  getFrameworkCatalogs: () => get<FrameworkCatalogsResponse>("/v1/frameworks/catalogs"),

  /** Auditor-ready compliance narrative for all 14 frameworks */
  getComplianceNarrative: () => get<ComplianceNarrativeResponse>("/v1/compliance/narrative"),

  /** Single-framework compliance narrative */
  getComplianceNarrativeByFramework: (framework: string) =>
    get<ComplianceNarrativeResponse>(`/v1/compliance/narrative/${encodeURIComponent(framework)}`),

  /** Fleet management */
  listFleet: (filters?: {
    state?: string;
    environment?: string;
    min_trust?: number;
    search?: string;
    include_quarantined?: boolean;
    limit?: number;
    offset?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.state) params.set("state", filters.state);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.min_trust != null) params.set("min_trust", String(filters.min_trust));
    if (filters?.search) params.set("search", filters.search);
    if (filters?.include_quarantined) params.set("include_quarantined", "true");
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<FleetResponse>(`/v1/fleet${qs ? `?${qs}` : ""}`);
  },
  getFleetAgent: (agentId: string) => get<FleetAgent>(`/v1/fleet/${agentId}`),
  syncFleet: () => post<FleetSyncResult>("/v1/fleet/sync", {}),
  updateFleetState: (agentId: string, state: string, reason?: string) =>
    put<unknown>(`/v1/fleet/${agentId}/state`, { state, reason: reason ?? "" }),
  updateFleetAgent: (agentId: string, update: Partial<FleetAgent>) =>
    put<unknown>(`/v1/fleet/${agentId}`, update),
  getFleetStats: () => get<FleetStatsResponse>("/v1/fleet/stats"),

  // ── Connectors / sources ──
  listConnectors: () => get<ConnectorsResponse>("/v1/connectors"),
  getConnectorHealth: (name: string) => get<ConnectorHealthResponse>(`/v1/connectors/${encodeURIComponent(name)}/health`),
  listSources: () => get<SourcesResponse>("/v1/sources"),
  getSource: (sourceId: string) => get<SourceRecord>(`/v1/sources/${encodeURIComponent(sourceId)}`),
  createSource: (body: SourceCreateRequest) => post<SourceRecord>("/v1/sources", body),
  updateSource: (sourceId: string, body: SourceUpdateRequest) =>
    put<SourceRecord>(`/v1/sources/${encodeURIComponent(sourceId)}`, body),
  deleteSource: (sourceId: string) => del(`/v1/sources/${encodeURIComponent(sourceId)}`),
  testSource: (sourceId: string) => post<SourceCheckResponse>(`/v1/sources/${encodeURIComponent(sourceId)}/test`, {}),
  runSource: (sourceId: string) => post<SourceRunResponse>(`/v1/sources/${encodeURIComponent(sourceId)}/run`, {}),
  listSourceJobs: (sourceId: string) => get<SourceJobsResponse>(`/v1/sources/${encodeURIComponent(sourceId)}/jobs`),
  listSchedules: () => get<ScanSchedule[]>("/v1/schedules"),
  createSchedule: (body: ScheduleCreateRequest) => post<ScanSchedule>("/v1/schedules", body),
  toggleSchedule: (scheduleId: string) => put<ScanSchedule>(`/v1/schedules/${scheduleId}/toggle`, {}),
  deleteSchedule: (scheduleId: string) => del(`/v1/schedules/${scheduleId}`),

  // ── Gateway ──
  listGatewayPolicies: () => get<GatewayPolicyResponse>("/v1/gateway/policies"),
  createGatewayPolicy: (body: Partial<GatewayPolicy>) =>
    post<GatewayPolicy>("/v1/gateway/policies", body),
  getGatewayPolicy: (id: string) => get<GatewayPolicy>(`/v1/gateway/policies/${id}`),
  updateGatewayPolicy: (id: string, body: Partial<GatewayPolicy>) =>
    put<GatewayPolicy>(`/v1/gateway/policies/${id}`, body),
  deleteGatewayPolicy: (id: string) => del(`/v1/gateway/policies/${id}`),
  evaluateGateway: (body: { agent_name?: string; tool_name: string; arguments?: Record<string, unknown> }) =>
    post<EvaluateResult>("/v1/gateway/evaluate", body),
  listGatewayAudit: () => get<GatewayAuditResponse>("/v1/gateway/audit"),
  getGatewayStats: () => get<GatewayStatsResponse>("/v1/gateway/stats"),

  // Governance
  getGovernance: (days = 30) => get<GovernanceReport>(`/v1/governance?days=${days}`),
  getGovernanceFindings: (days = 30, severity?: string, category?: string) => {
    const params = new URLSearchParams({ days: String(days) });
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    return get<{ findings: GovernanceFinding[]; count: number; warnings: string[] }>(
      `/v1/governance/findings?${params}`
    );
  },

  // Activity Timeline
  getActivity: (days = 30) => get<ActivityTimeline>(`/v1/activity?days=${days}`),
  ingestTraces: (body: unknown) => post<TraceIngestResponse>("/v1/traces", body),

  // ── Proxy Runtime ──
  getProxyStatus: () => get<ProxyStatusResponse>("/v1/proxy/status"),
  getProxyAlerts: (filters?: { severity?: string; detector?: string; limit?: number }) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.detector) params.set("detector", filters.detector);
    if (filters?.limit) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<ProxyAlertsResponse>(`/v1/proxy/alerts${qs ? `?${qs}` : ""}`);
  },

  // ── Shield / Break-Glass ──
  breakGlass: async (sessionId: string, reason: string) => {
    return post<{ status: string; session_id: string }>('/v1/shield/break-glass', { session_id: sessionId, reason });
  },

  // ── Exceptions (FP suppression) ──
  createException: (body: { vulnerability_id: string; package_name: string; reason: string }) =>
    post<{ id: string; status: string }>("/v1/exceptions", body),

  // ── Jira Integration ──
  createJiraTicket: (body: {
    jira_url: string;
    email: string;
    api_token: string;
    project_key: string;
    finding: Record<string, unknown>;
  }) =>
    post<{ ticket_key: string; status: string }>(
      "/v1/findings/jira",
      {
        jira_url: body.jira_url,
        email: body.email,
        project_key: body.project_key,
        finding: body.finding,
      },
      { "X-Jira-Api-Token": body.api_token },
    ),

  // ── False Positive Management ──
  markFalsePositive: (body: {
    vulnerability_id: string;
    package: string;
    reason?: string;
    marked_by?: string;
  }) => post<{ id: string; vulnerability_id: string; package: string; status: string }>(
    "/v1/findings/false-positive",
    body,
  ),
  listFalsePositives: () =>
    get<{
      false_positives: Array<{
        id: string;
        vulnerability_id: string;
        package: string;
        reason: string;
        marked_by: string;
        status: string;
        created_at: string;
      }>;
      total: number;
    }>("/v1/findings/false-positives"),
  removeFalsePositive: (id: string) => del(`/v1/findings/false-positive/${id}`),

  // ── Remediation ──
  /** Extract remediation plan from the latest completed scan */
  getRemediation: async (jobId: string): Promise<RemediationItem[]> => {
    const job = await get<ScanJob>(`/v1/scan/${jobId}`);
    return job.result?.remediation_plan ?? [];
  },

  // ── Audit Log ──
  listAuditEntries: (filters?: { action?: string; resource?: string; since?: string; limit?: number; offset?: number }) => {
    const params = new URLSearchParams();
    if (filters?.action) params.set("action", filters.action);
    if (filters?.resource) params.set("resource", filters.resource);
    if (filters?.since) params.set("since", filters.since);
    if (filters?.limit) params.set("limit", String(filters.limit));
    if (filters?.offset) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<AuditLogResponse>(`/v1/audit${qs ? `?${qs}` : ""}`);
  },
  getAuditIntegrity: (limit = 1000) => get<AuditIntegrityResponse>(`/v1/audit/integrity?limit=${limit}`),
  getAuditLog: (limit?: number) => get<{ entries: AuditEntry[] }>(`/v1/audit?limit=${limit ?? 10}`),
};

// ─── Threat Framework Catalogs ────────────────────────────────────────────────

/** OWASP LLM Top 10 (2025) — code → human-readable name */
export const OWASP_LLM_TOP10: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Insecure Output Handling",
  LLM03: "Training Data Poisoning",
  LLM04: "Data and Model Poisoning",
  LLM05: "Supply Chain Vulnerabilities",
  LLM06: "Sensitive Information Disclosure",
  LLM07: "System Prompt Leakage",
  LLM08: "Excessive Agency",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

/** OWASP MCP Top 10 — code → human-readable name */
export const OWASP_MCP_TOP10: Record<string, string> = {
  MCP01: "Token Mismanagement & Secret Exposure",
  MCP02: "Privilege Escalation via Scope Creep",
  MCP03: "Tool Poisoning",
  MCP04: "Software Supply Chain Attacks",
  MCP05: "Command Injection & Execution",
  MCP06: "Intent Flow Subversion",
  MCP07: "Insufficient Auth & Authorization",
  MCP08: "Lack of Audit & Telemetry",
  MCP09: "Shadow MCP Servers",
  MCP10: "Context Injection & Over-Sharing",
};

/** MITRE ATLAS — technique ID → human-readable name */
export const MITRE_ATLAS: Record<string, string> = {
  "AML.T0010": "ML Supply Chain Compromise",
  "AML.T0020": "Poison Training Data",
  "AML.T0024": "Exfiltration via ML Inference API",
  "AML.T0043": "Craft Adversarial Data",
  "AML.T0051": "LLM Prompt Injection",
  "AML.T0052": "Phishing via AI",
  "AML.T0054": "LLM Jailbreak",
  "AML.T0056": "LLM Meta Prompt Extraction",
  "AML.T0058": "AI Agent Context Poisoning",
  "AML.T0059": "Activation Triggers",
  "AML.T0060": "Data from AI Services",
  "AML.T0061": "AI Agent Tools",
  "AML.T0062": "Exfiltration via AI Agent Tool Invocation",
};

/** OWASP Agentic Top 10 (2026) — code → human-readable name */
export const OWASP_AGENTIC_TOP10: Record<string, string> = {
  ASI01: "Excessive Agency & Autonomy",
  ASI02: "Tool Misuse & Exploitation",
  ASI03: "Identity & Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities",
  ASI05: "Unexpected Code Execution",
  ASI06: "Memory & Context Poisoning",
  ASI07: "Insecure Inter-Agent Communication",
  ASI08: "Cascading Hallucination Failures",
  ASI09: "Human-Agent Trust Exploitation",
  ASI10: "Rogue Agent Persistence",
};

/** EU AI Act — article code → human-readable name */
export const EU_AI_ACT: Record<string, string> = {
  "ART-5": "Prohibited AI Practices",
  "ART-6": "High-Risk AI System Classification",
  "ART-9": "Risk Management System",
  "ART-10": "Data & Data Governance",
  "ART-15": "Accuracy, Robustness & Cybersecurity",
  "ART-17": "Quality Management System",
};

/** NIST AI RMF 1.0 — subcategory ID → human-readable name */
export const NIST_AI_RMF: Record<string, string> = {
  "GOVERN-1.5": "Ongoing monitoring mechanisms for AI risk",
  "GOVERN-1.7": "Third-party AI component risk processes",
  "GOVERN-6.1": "Assessment policies for third-party AI entities",
  "GOVERN-6.2": "Contingency plans for third-party AI failures",
  "MAP-1.6": "System dependencies and external interfaces mapped",
  "MAP-3.5": "AI supply chain risks assessed",
  "MAP-5.2": "AI deployment impact practices identified",
  "MEASURE-2.5": "AI system security testing conducted",
  "MEASURE-2.6": "AI system results validated",
  "MEASURE-2.9": "Effectiveness of risk mitigations assessed",
  "MANAGE-1.3": "Responses to identified AI risks documented",
  "MANAGE-2.2": "Anomalous event detection and response",
  "MANAGE-2.4": "Risk treatments including remediation applied",
  "MANAGE-4.1": "Post-deployment monitoring plans implemented",
};

/** NIST CSF 2.0 — category ID → human-readable name */
export const NIST_CSF: Record<string, string> = {
  "GV.SC-05": "Cyber supply chain risk management requirements established",
  "GV.SC-07": "Supplier risks identified, recorded, and mitigated",
  "ID.AM-05": "Assets prioritized based on classification and criticality",
  "ID.RA-01": "Vulnerabilities in assets are identified",
  "ID.RA-02": "Cyber threat intelligence received from information sharing forums",
  "ID.RA-05": "Threats, vulnerabilities, likelihoods, and impacts used to determine risk",
  "PR.AA-01": "Identities and credentials managed for authorized users and services",
  "PR.AA-03": "Users, services, and hardware are authenticated",
  "PR.DS-01": "Data-at-rest is protected",
  "PR.DS-02": "Data-in-transit is protected",
  "DE.CM-01": "Networks and network services are monitored",
  "DE.CM-09": "Computing hardware and software are monitored for vulnerabilities",
  "RS.AN-03": "Analysis is performed to determine what has taken place",
  "RS.MI-02": "Incidents are contained and mitigated",
};

/** ISO/IEC 27001:2022 Annex A — control ID → human-readable name */
export const ISO_27001: Record<string, string> = {
  "A.5.19": "Information security in supplier relationships",
  "A.5.20": "Addressing information security within supplier agreements",
  "A.5.21": "Managing information security in the ICT supply chain",
  "A.5.23": "Information security for use of cloud services",
  "A.5.28": "Collection of evidence",
  "A.8.8": "Management of technical vulnerabilities",
  "A.8.9": "Configuration management",
  "A.8.24": "Use of cryptography",
  "A.8.28": "Secure coding",
};

/** SOC 2 Trust Services Criteria — code → human-readable name */
export const SOC2_TSC: Record<string, string> = {
  "CC6.1": "Logical and physical access controls implemented",
  "CC6.6": "Security boundaries and system access restricted",
  "CC6.8": "Unauthorized or malicious software prevented or detected",
  "CC7.1": "Detection and monitoring of anomalies and events",
  "CC7.2": "Monitoring of system components for anomalies",
  "CC7.4": "Incident response activities executed",
  "CC8.1": "Change management processes authorized and implemented",
  "CC9.1": "Risk mitigation activities identified and applied",
  "CC9.2": "Vendor and business partner risk is managed",
};

/** CIS Controls v8 — safeguard ID → human-readable name */
export const CIS_CONTROLS: Record<string, string> = {
  "CIS-02.1": "Establish and maintain a software inventory",
  "CIS-02.3": "Address unauthorized software",
  "CIS-02.7": "Allowlist authorized libraries",
  "CIS-07.1": "Establish and maintain a vulnerability management process",
  "CIS-07.4": "Perform automated patch management",
  "CIS-07.5": "Perform automated vulnerability scans of internal assets",
  "CIS-07.6": "Perform automated vulnerability scans of public-facing assets",
  "CIS-16.1": "Establish and maintain a secure application development process",
  "CIS-16.11": "Use standard hardening configuration templates",
  "CIS-16.12": "Implement code-level security checks",
};

/** CMMC 2.0 Level 2 — practice ID → human-readable name */
export const CMMC_PRACTICES: Record<string, string> = {
  "RA.L2-3.11.2": "Vulnerability scanning",
  "RA.L2-3.11.3": "Remediate vulnerabilities",
  "SI.L2-3.14.1": "Flaw remediation",
  "SI.L2-3.14.2": "Malicious code protection",
  "SI.L2-3.14.3": "Security alerts, advisories, and directives",
  "SI.L2-3.14.6": "Monitor communications for attacks",
  "SI.L2-3.14.7": "Identify unauthorized use",
  "SC.L2-3.13.1": "Monitor communications at boundaries",
  "SC.L2-3.13.2": "Employ architectural designs and techniques for security",
  "SC.L2-3.13.5": "Implement subnetworks for publicly accessible components",
  "CM.L2-3.4.1": "Establish and maintain baseline configurations",
  "CM.L2-3.4.2": "Establish and enforce security configuration settings",
  "CM.L2-3.4.3": "Track, review, and control changes",
  "AC.L2-3.1.1": "Limit system access to authorized users",
  "AC.L2-3.1.2": "Limit system access to authorized transactions and functions",
  "AC.L2-3.1.7": "Prevent non-privileged users from executing privileged functions",
  "IA.L2-3.5.3": "Use multi-factor authentication for local and network access",
};

// ─── Governance types ────────────────────────────────────────────────────────

export interface GovernanceFinding {
  category: string;
  severity: string;
  title: string;
  description: string;
  agent_or_role: string;
  object_name: string;
  details: Record<string, unknown>;
}

export interface GovernanceReport {
  account: string;
  discovered_at: string;
  summary: {
    access_records: number;
    privilege_grants: number;
    data_classifications: number;
    agent_usage_records: number;
    findings: number;
    critical_findings: number;
    high_findings: number;
  };
  findings: GovernanceFinding[];
  access_records: Array<{
    query_id: string;
    user_name: string;
    role_name: string;
    query_start: string;
    object_name: string;
    object_type: string;
    columns: string[];
    operation: string;
    is_write: boolean;
  }>;
  privilege_grants: Array<{
    grantee: string;
    grantee_type: string;
    privilege: string;
    granted_on: string;
    object_name: string;
    is_elevated: boolean;
  }>;
  data_classifications: Array<{
    object_name: string;
    object_type: string;
    column_name: string | null;
    tag_name: string;
    tag_value: string;
  }>;
  agent_usage: Array<{
    agent_name: string;
    user_name: string;
    role_name: string;
    start_time: string;
    total_tokens: number;
    credits_used: number;
    model_name: string;
    tool_calls: number;
    status: string;
  }>;
  warnings: string[];
}

export interface ActivityTimeline {
  account: string;
  discovered_at: string;
  summary: {
    total_queries: number;
    agent_queries: number;
    observability_events: number;
    unique_agents: number;
    tool_calls: number;
  };
  query_history: Array<{
    query_id: string;
    query_text: string;
    user_name: string;
    role_name: string;
    start_time: string;
    execution_status: string;
    query_type: string;
    is_agent_query: boolean;
    agent_pattern: string;
    execution_time_ms: number;
  }>;
  observability_events: Array<{
    event_id: string;
    event_type: string;
    agent_name: string;
    timestamp: string;
    duration_ms: number;
    status: string;
    model_name: string;
    tool_name: string;
    trace_id: string;
    input_tokens: number;
    output_tokens: number;
  }>;
  warnings: string[];
}

export interface TraceFlaggedCall {
  tool_name: string;
  server: string;
  package_name?: string;
  cve_ids: string[];
  severity: string;
  reason: string;
  span_id: string;
}

export interface TraceIngestResponse {
  traces: number;
  flagged: TraceFlaggedCall[];
  message?: string;
}

// ─── Proxy Runtime types ─────────────────────────────────────────────────────

export interface ProxyStatusResponse {
  status: string;
  message?: string;
  total_tool_calls?: number;
  total_blocked?: number;
  uptime_seconds?: number;
  calls_by_tool?: Record<string, number>;
  blocked_by_reason?: Record<string, number>;
  latency?: { p50_ms?: number; p95_ms?: number; p99_ms?: number };
  detectors_active?: string[];
  proxy_pid?: number;
}

export interface ProxyAlert {
  ts: number;
  severity: string;
  detector: string;
  tool_name: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ProxyAlertsResponse {
  alerts: ProxyAlert[];
  count: number;
  filters: { severity: string | null; detector: string | null; limit: number };
}

// ─── Audit Log types ─────────────────────────────────────────────────────────

export interface AuditEntry {
  entry_id: string;
  timestamp: string;
  action: string;
  actor: string;
  resource: string;
  details: Record<string, unknown>;
  hmac_signature: string;
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
}

export interface AuditIntegrityResponse {
  verified: number;
  tampered: number;
  checked: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

export function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical": return "text-red-400 bg-red-950 border-red-800";
    case "high":     return "text-orange-400 bg-orange-950 border-orange-800";
    case "medium":   return "text-yellow-400 bg-yellow-950 border-yellow-800";
    case "low":      return "text-blue-400 bg-blue-950 border-blue-800";
    default:         return "text-zinc-400 bg-zinc-800 border-zinc-700";
  }
}

export function severityDot(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical": return "bg-red-500";
    case "high":     return "bg-orange-500";
    case "medium":   return "bg-yellow-500";
    case "low":      return "bg-blue-500";
    default:         return "bg-zinc-500";
  }
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function isConfigured(agent: Agent): boolean {
  return agent.status !== "installed-not-configured";
}
