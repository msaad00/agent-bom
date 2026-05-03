/** Shared API response and request contracts. */

import type { UnifiedEdge, UnifiedGraphData, UnifiedNode } from "./graph-schema";

export type JobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export interface ScanRequest {
  inventory?: string | undefined;
  images?: string[] | undefined;
  k8s?: boolean | undefined;
  k8s_namespace?: string | undefined;
  tf_dirs?: string[] | undefined;
  gha_path?: string | undefined;
  agent_projects?: string[] | undefined;
  sbom?: string | undefined;
  enrich?: boolean | undefined;
  format?: string | undefined;
  dynamic_discovery?: boolean | undefined;
  dynamic_max_depth?: number | undefined;
}

export type StepStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface StepEvent {
  type: "step";
  step_id: string;
  status: StepStatus;
  message: string;
  started_at?: string | undefined;
  completed_at?: string | undefined;
  stats?: Record<string, number> | undefined;
  sub_step?: string | undefined;
  progress_pct?: number | undefined;
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

export interface ScanJob {
  job_id: string;
  status: JobStatus;
  created_at: string;
  tenant_id?: string | undefined;
  source_id?: string | undefined;
  triggered_by?: string | undefined;
  started_at?: string | undefined;
  completed_at?: string | undefined;
  request: ScanRequest;
  progress: string[];
  result?: ScanResult | undefined;
  error?: string | undefined;
}

export interface ScanResult {
  agents: Agent[];
  blast_radius: BlastRadius[];
  remediation_plan?: RemediationItem[] | undefined;
  scorecard_summary?: ScorecardSummary | undefined;
  scan_performance?: Record<string, number> | undefined;
  posture_scorecard?: PostureScorecard | undefined;
  summary?: Summary | undefined;
  warnings?: string[] | undefined;
  scan_timestamp?: string | undefined;
  tool_version?: string | undefined;
  /** Context metadata — auto-detected from scan sources */
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  scan_sources?: string[] | undefined;
}

export interface GraphPagination {
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  cursor?: string | undefined;
  next_cursor?: string | undefined;
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
  deployment_mode?: DeploymentMode | undefined;
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  has_local_scan?: boolean | undefined;
  has_fleet_ingest?: boolean | undefined;
  has_cluster_scan?: boolean | undefined;
  has_ci_cd_scan?: boolean | undefined;
  has_mesh?: boolean | undefined;
  has_gateway?: boolean | undefined;
  has_proxy?: boolean | undefined;
  has_traces?: boolean | undefined;
  has_registry?: boolean | undefined;
  scan_sources?: string[] | undefined;
  scan_count?: number | undefined;
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
  priority?: number | undefined;
  action?: string | undefined;
  reason?: string | null | undefined;
  command?: string | null | undefined;
  verify_command?: string | null | undefined;
  vulnerabilities: string[];
  affected_agents: string[];
  agents_pct: number;
  exposed_credentials: string[];
  credentials_pct: number;
  reachable_tools: string[];
  tools_pct: number;
  owasp_tags: string[];
  atlas_tags: string[];
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  nist_csf_tags?: string[] | undefined;
  iso_27001_tags?: string[] | undefined;
  soc2_tags?: string[] | undefined;
  cis_tags?: string[] | undefined;
  references?: string[] | undefined;
  risk_narrative: string;
}

export type AgentStatus = "configured" | "installed-not-configured";

export interface Agent {
  name: string;
  agent_type: string;
  config_path?: string | undefined;
  source?: string | undefined;
  source_id?: string | undefined;
  enrollment_name?: string | undefined;
  owner?: string | undefined;
  environment?: string | undefined;
  mdm_provider?: string | undefined;
  tags?: string[] | undefined;
  status?: AgentStatus | undefined;
  discovered_at?: string | undefined;
  last_seen?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
  // Per-run discovery envelope (#2083). Trust contract for the scan run that
  // produced this Agent record: scan_mode, discovery_scope, permissions_used,
  // redaction_status. Optional because legacy records pre-envelope don't carry it.
  discovery_envelope?: DiscoveryEnvelope | null | undefined;
  mcp_servers: MCPServer[];
  automation_settings?: string[] | undefined;
}

export interface DiscoveryEnvelope {
  envelope_version: number;
  scan_mode: string;
  discovery_scope: string[];
  permissions_used: string[];
  redaction_status: string;
  captured_at: string;
}

export interface MCPServer {
  name: string;
  command?: string | undefined;
  args?: string[] | undefined;
  transport?: string | undefined;
  url?: string | undefined;
  auth_mode?: string | undefined;
  config_path?: string | undefined;
  security_warnings?: string[] | undefined;
  security_intelligence?: SecurityIntelligenceEntry[] | undefined;
  packages: Package[];
  tools?: Tool[] | undefined;
  env?: Record<string, string> | undefined;
  vulnerabilities?: Vulnerability[] | undefined;
  has_credentials?: boolean | undefined;
  credential_env_vars?: string[] | undefined;
  security_blocked?: boolean | undefined;
  provenance?: MCPProvenance | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
}

export interface DiscoveryProvenance {
  source_type?: string | undefined;
  observed_via?: string | string[] | undefined;
  source?: string | undefined;
  collector?: string | undefined;
  provider?: string | undefined;
  service?: string | undefined;
  resource_type?: string | undefined;
  resource_id?: string | undefined;
  resource_name?: string | undefined;
  location?: string | undefined;
  mapping_method?: string | undefined;
  version_source?: string | undefined;
  version_provenance?: VersionProvenance | undefined;
  confidence?: string | number | undefined;
  discovered_via?: string | undefined;
  resolved_from_registry?: boolean | undefined;
}

export interface VersionProvenance {
  declared_name?: string | undefined;
  declared_version?: string | undefined;
  resolved_version?: string | undefined;
  version_source?: string | undefined;
  confidence?: string | undefined;
  observed_at?: string | undefined;
  version_resolved_at?: string | undefined;
  resolved_from_registry?: boolean | undefined;
  floating_reference?: boolean | undefined;
  floating_reference_reason?: string | undefined;
  evidence?: Record<string, unknown>[] | undefined;
  version_conflicts?: Record<string, unknown>[] | undefined;
}

export interface SecurityIntelligenceEntry {
  entry_id: string;
  title: string;
  severity?: string | undefined;
  confidence: string;
  default_recommendation: string;
  source_type?: string | undefined;
  source?: string | undefined;
  match_type?: string | undefined;
  matched_value?: string | undefined;
  ecosystem?: string | undefined;
  package?: string | undefined;
  affected_versions?: string | undefined;
  first_seen?: string | undefined;
  references?: string[] | undefined;
  last_verified?: string | undefined;
  remediation_actions?: string[] | undefined;
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
  first_seen?: string | null | undefined;
  last_seen?: string | null | undefined;
  last_synced?: string | null | undefined;
}

export interface Package {
  name: string;
  version: string;
  ecosystem: string;
  purl?: string | undefined;
  version_source?: string | undefined;
  version_confidence?: string | undefined;
  version_provenance?: VersionProvenance | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
  vulnerabilities?: Vulnerability[] | undefined;
}

export interface Vulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "none";
  /** API v2 field — same as description */
  summary?: string | undefined;
  description?: string | undefined;
  references?: string[] | undefined;
  advisory_sources?: string[] | undefined;
  aliases?: string[] | undefined;
  cvss_score?: number | undefined;
  epss_score?: number | undefined;
  /** API v2 field — same as cisa_kev */
  is_kev?: boolean | undefined;
  cisa_kev?: boolean | undefined;
  fixed_version?: string | undefined;
  /** API v2 field — same as published */
  published_at?: string | undefined;
  modified_at?: string | undefined;
  nvd_published?: string | undefined;
  published?: string | undefined;
  /** Phase 2 fields */
  severity_source?: string | undefined;
  confidence?: number | undefined;
}

export interface BlastRadius {
  vulnerability_id: string;
  severity: string;
  package?: string | undefined;
  ecosystem?: string | undefined;
  affected_agents: string[];
  affected_servers?: string[] | undefined;
  exposed_credentials: string[];
  /** API v2 field — same as reachable_tools */
  exposed_tools?: string[] | undefined;
  reachable_tools: string[];
  /** API v2 field — same as blast_score (0-100) */
  risk_score?: number | undefined;
  blast_score: number;
  cvss_score?: number | undefined;
  epss_score?: number | undefined;
  is_kev?: boolean | undefined;
  cisa_kev?: boolean | undefined;
  fixed_version?: string | undefined;
  owasp_tags?: string[] | undefined;
  atlas_tags?: string[] | undefined;
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  /** CWE-derived impact category: code-execution, credential-access, etc. */
  impact_category?: string | undefined;
  /** Full credential set before CWE filtering (for reference) */
  all_server_credentials?: string[] | undefined;
  /** Human-readable attack vector description */
  attack_vector_summary?: string | undefined;
  /** Graph-walk reachability (populated by the unified-graph dependency
   *  reach engine). `true` when an agent's USES/DEPENDS_ON closure
   *  reaches the vulnerable package; `false` when the package is in
   *  inventory but no agent traversal reaches it; `undefined` when the
   *  engine did not run for this scan. */
  graph_reachable?: boolean | null | undefined;
  /** Smallest hop count from any reaching agent. `null` / `undefined`
   *  when graph_reachable is not `true`. */
  graph_min_hop_distance?: number | null | undefined;
  /** Agent node ids whose dependency closure reaches the vulnerable
   *  package (e.g. ["agent:cursor", "agent:claude-desktop"]). */
  graph_reachable_from_agents?: string[] | undefined;
}

export interface AttackFlowNodeData {
  [key: string]: unknown;
  nodeType: "cve" | "package" | "server" | "agent" | "credential" | "tool";
  label: string;
  severity?: string | undefined;
  cvss_score?: number | undefined;
  epss_score?: number | undefined;
  is_kev?: boolean | undefined;
  risk_score?: number | undefined;
  fixed_version?: string | undefined;
  owasp_tags?: string[] | undefined;
  atlas_tags?: string[] | undefined;
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  version?: string | undefined;
  ecosystem?: string | undefined;
  agent_type?: string | undefined;
  status?: string | undefined;
  description?: string | undefined;
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
  animated?: boolean | undefined;
  style?: { stroke: string } | undefined;
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
    owasp_agentic_tag?: string | undefined;
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
  description?: string | undefined;
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
  transient_failed_packages?: number | undefined;
  persistent_failed_packages?: number | undefined;
  failed_reasons?: Record<string, number> | undefined;
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

export interface DataAccessBoundaryMode {
  mode: string;
  reads: string[];
  evidence?: string[] | undefined;
  required_identity?: string | undefined;
  controls?: string[] | undefined;
  operator_controls?: string[] | undefined;
  does_not_read?: string[] | undefined;
  does_not_store?: string[] | undefined;
  does_not_do?: string[] | undefined;
}

export interface DataAccessBoundaries {
  default_posture: {
    self_hosted_first: boolean;
    mandatory_hosted_control_plane: boolean;
    hidden_telemetry: boolean;
    default_network_mode: string;
    credential_values_stored: boolean;
    credential_values_transmitted: boolean;
    credential_values_validated_by_default: boolean;
    support_access_default: string;
  };
  modes: DataAccessBoundaryMode[];
  network_boundaries: {
    telemetry: string;
    vulnerability_enrichment: string;
    cloud_provider_api_calls: string;
    outbound_exports: string;
    proxy_gateway_egress: string;
    disable_controls: string[];
  };
  storage_boundaries: {
    local_default: string;
    control_plane_default: string;
    secret_values: string;
    secret_previews: string;
    raw_artifact_exports: string;
    support_bundle_default: string;
  };
  auth_boundaries: {
    api: string[];
    authorization: string[];
    scim: {
      provisioning_authority: string;
      runtime_auth_overlay: string;
      tenant_source: string;
      payload_tenant_attributes_ignored: boolean;
    };
    does_not_do: string[];
  };
  deployment_boundaries: Record<string, string[]>;
  extension_boundaries: {
    connectors: {
      default_posture: string;
      credential_scope: string;
      does_not_do: string[];
      stronger_actions_require: string[];
    };
    plugins_and_skills: {
      default_posture: string;
      execution_boundary: string;
      does_not_do: string[];
      controls: string[];
    };
    roles: {
      viewer: string[];
      analyst: string[];
      admin: string[];
      principle: string;
    };
  };
  posture_vocabulary: {
    capability_flags: string[];
    enforcement_flags: string[];
    intentional_boundary_flags: string[];
  };
  operator_controls: {
    scope_preview: string;
    inventory_only: string;
    project_scope: string;
    config_scope: string;
    disable_vulnerability_network: string;
    disable_scan_network_and_vuln_lookup: string;
    disable_skill_scan: string;
    isolate_skill_scan: string;
    api_access_control: string[];
    optional_exports: string[];
  };
  credential_evidence: {
    config_env_vars: string;
    project_secret_scan: string;
    stores_matched_value: boolean;
    stores_matched_prefix: boolean;
    validates_live_secret: boolean;
  };
  redacted_evidence_context: {
    allowed_context: string[];
    never_show: string[];
    display_model: string;
  };
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
    rotation_days?: number | null | undefined;
    max_age_days?: number | null | undefined;
    message?: string | undefined;
    fallback_source?: string | null | undefined;
    [key: string]: unknown;
  };
  audit_hmac: {
    status: string;
    configured: boolean;
    key_id_configured?: boolean | undefined;
    rotation_tracking_supported?: boolean | undefined;
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
      default_role: string;
      role_values: string[];
      tenant_attribute: string;
      tenant_assignment: {
        source: string;
        payload_tenant_attributes_ignored: boolean;
      };
      provisioning_authority: string;
      auth_authority: string;
      runtime_auth_enforced: boolean;
      deprovisioning_boundary: string;
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
  data_access_boundaries: DataAccessBoundaries;
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
  expires_at?: string | null | undefined;
  scopes?: string[] | undefined;
}

export interface CreateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  message: string;
}

export interface RotateApiKeyRequest {
  name?: string | null | undefined;
  expires_at?: string | null | undefined;
  overlap_seconds?: number | null | undefined;
}

export interface RotateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  replaced_key_id: string;
  overlap_until: string;
  overlap_seconds: number;
  message: string;
}

export interface TenantQuotaUpdateRequest {
  active_scan_jobs?: number | null | undefined;
  retained_scan_jobs?: number | null | undefined;
  fleet_agents?: number | null | undefined;
  schedules?: number | null | undefined;
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

export interface DiscoveryProviderCapabilities {
  scan_modes: string[];
  required_scopes: string[];
  permissions_used: string[];
  outbound_destinations: string[];
  network_destinations?: string[] | undefined;
  data_boundary: string;
  writes: boolean;
  network_access: boolean;
  guarantees: string[];
}

export interface DiscoveryProviderTrustContract {
  read_only: boolean;
  agentless: boolean;
  entrypoints_opt_in: boolean;
  redaction_status: string;
  scope_control: string;
  data_residency: string;
  supports_scope_zero: boolean;
}

export interface DiscoveryProviderContract {
  name: string;
  module: string;
  source: string;
  discover_attr: string;
  capabilities: DiscoveryProviderCapabilities;
  trust_contract: DiscoveryProviderTrustContract;
}

export interface DiscoveryProvidersResponse {
  contract_version: string;
  entrypoints_enabled: boolean;
  provider_count: number;
  providers: DiscoveryProviderContract[];
  warnings: string[];
}

export interface SourceCreateRequest {
  display_name: string;
  kind: SourceKind;
  description?: string | undefined;
  owner?: string | undefined;
  connector_name?: string | null | undefined;
  credential_mode?: string | undefined;
  credential_ref?: string | null | undefined;
  enabled?: boolean | undefined;
  config?: Record<string, unknown> | undefined;
  tenant_id?: string | undefined;
}

export interface SourceUpdateRequest {
  display_name?: string | undefined;
  description?: string | undefined;
  owner?: string | undefined;
  connector_name?: string | null | undefined;
  credential_mode?: string | undefined;
  credential_ref?: string | null | undefined;
  enabled?: boolean | undefined;
  status?: SourceStatus | undefined;
  config?: Record<string, unknown> | undefined;
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
  total?: number | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

export interface JobListItem {
  job_id: string;
  status: JobStatus;
  created_at: string;
  tenant_id?: string | undefined;
  completed_at?: string | undefined;
  request?: ScanRequest | undefined;
  summary?: Summary | undefined;
  scan_timestamp?: string | undefined;
  pushed?: boolean | undefined;
  error?: string | undefined;
}

export type ScanJobStatus = JobListItem;

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
  description?: string | undefined;
  sigstore_bundle: string | null;
  tools?: string[] | undefined;
  credential_env_vars?: string[] | undefined;
  category?: string | undefined;
  license?: string | undefined;
  latest_version?: string | undefined;
  known_cves?: string[] | undefined;
  command_patterns?: string[] | undefined;
  risk_justification?: string | undefined;
}

export interface RegistryResponse {
  servers: RegistryServer[];
  count: number;
}

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

export interface ComplianceControl {
  code: string;
  name: string;
  findings: number;
  status: "pass" | "warning" | "fail";
  severity_breakdown: Record<string, number>;
  affected_packages: string[];
  affected_agents: string[];
}

export interface AISVSCheck {
  check_id: string;
  title?: string | undefined;
  status: "pass" | "fail" | "error" | "not_applicable";
  severity: string;
  evidence?: string | undefined;
  recommendation?: string | undefined;
  cis_section?: string | undefined;
  maestro_layer?: string | undefined;
}

export interface AISVSBenchmark {
  benchmark: string;
  benchmark_version: string;
  passed: number;
  failed: number;
  total: number;
  pass_rate: number;
  checks: AISVSCheck[];
  metadata: Record<string, unknown>;
}

export interface AISVSComplianceResponse {
  framework: "aisvs";
  framework_key: "aisvs_benchmark";
  framework_label: string;
  source: "scan_jobs";
  scan_id: string | null;
  measured_at: string | null;
  representation: "benchmark";
  score: number;
  summary: {
    pass: number;
    fail: number;
    error: number;
    not_applicable: number;
    total: number;
    score: number;
  };
  benchmark: AISVSBenchmark;
}

export interface ComplianceResponse {
  overall_score: number;
  overall_status: "pass" | "warning" | "fail";
  scan_count: number;
  latest_scan: string | null;
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  scan_sources?: string[] | undefined;
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
  aisvs_benchmark: AISVSComplianceResponse;
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
    aisvs_pass: number; aisvs_fail: number; aisvs_error: number; aisvs_not_applicable: number;
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
  path?: string | undefined;
}

export interface FrameworkCatalogsResponse {
  frameworks: {
    mitre_attack: FrameworkCatalogMetadata;
  };
}

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
  fleet?: FleetAgent | null | undefined;
}

export interface AgentLifecycleResponse {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
  stats: Record<string, number>;
}

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
  scan_config?: Record<string, unknown> | undefined;
  enabled?: boolean | undefined;
  tenant_id?: string | undefined;
}

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
  firewall_runtime: FirewallRuntimeStats;
}

// ─── Inter-agent firewall (#982) ────────────────────────────────────────

export interface FirewallPairTally {
  source_agent: string;
  target_agent: string;
  allow: number;
  warn: number;
  deny: number;
}

export interface FirewallDecisionRecord {
  timestamp: number;
  source_agent: string;
  target_agent: string;
  decision: "allow" | "deny" | "warn";
  effective_decision: "allow" | "deny" | "warn";
  matched_rule: {
    source: string;
    target: string;
    decision: "allow" | "deny" | "warn";
    description: string;
  } | null;
  enforcement_mode: "enforce" | "dry_run" | null;
}

export interface FirewallRuntimeStats {
  total_decisions: number;
  allow: number;
  warn: number;
  deny: number;
  last_seen_ts: number | null;
  top_pairs: FirewallPairTally[];
  recent: FirewallDecisionRecord[];
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
  package_name?: string | undefined;
  cve_ids: string[];
  severity: string;
  reason: string;
  span_id: string;
}

export interface TraceIngestResponse {
  traces: number;
  flagged: TraceFlaggedCall[];
  message?: string | undefined;
}

export interface ProxyStatusResponse {
  status: string;
  message?: string | undefined;
  total_tool_calls?: number | undefined;
  total_blocked?: number | undefined;
  uptime_seconds?: number | undefined;
  calls_by_tool?: Record<string, number> | undefined;
  blocked_by_reason?: Record<string, number> | undefined;
  latency?: { p50_ms?: number; p95_ms?: number; p99_ms?: number };
  detectors_active?: string[] | undefined;
  proxy_pid?: number | undefined;
}

export interface ProxyAlert {
  ts: number;
  severity: string;
  detector: string;
  tool_name: string;
  message: string;
  details?: Record<string, unknown> | undefined;
}

export interface ProxyAlertsResponse {
  alerts: ProxyAlert[];
  count: number;
  filters: { severity: string | null; detector: string | null; limit: number };
}

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

// ─── Compliance Hub (#1044) ─────────────────────────────────────────────────

export interface HubPostureResponse {
  totals: {
    native: number;
    hub: number;
    combined: number;
  };
  framework_counts: {
    native: Record<string, number>;
    hub: Record<string, number>;
    combined: Record<string, number>;
  };
  hub_severity_breakdown: Record<string, number>;
}
