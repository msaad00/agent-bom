/**
 * agent-bom API client
 * Connects to the FastAPI backend at NEXT_PUBLIC_API_URL (default: same origin)
 */

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

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
  summary?: Summary;
  warnings?: string[];
  scan_timestamp?: string;
  tool_version?: string;
  /** Context metadata — auto-detected from scan sources */
  has_mcp_context?: boolean;
  has_agent_context?: boolean;
  scan_sources?: string[];
}

export interface RemediationItem {
  package: string;
  ecosystem: string;
  current_version: string;
  fixed_version: string | null;
  severity: string;
  is_kev: boolean;
  impact_score: number;
  vulnerabilities: string[];
  affected_agents: string[];
  agents_pct: number;
  exposed_credentials: string[];
  credentials_pct: number;
  reachable_tools: string[];
  tools_pct: number;
  owasp_tags: string[];
  atlas_tags: string[];
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
  transport?: string;
  packages: Package[];
  tools?: Tool[];
  env?: Record<string, string>;
  vulnerabilities?: Vulnerability[];
  has_credentials?: boolean;
  credential_env_vars?: string[];
  security_blocked?: boolean;
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
  cvss_score?: number;
  epss_score?: number;
  /** API v2 field — same as cisa_kev */
  is_kev?: boolean;
  cisa_kev?: boolean;
  fixed_version?: string;
  /** API v2 field — same as published */
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

export interface HealthResponse {
  status: string;
  version: string;
}

export interface VersionInfo {
  version: string;
  api_version: string;
  python_package: string;
}

export interface JobsResponse {
  jobs: Array<{
    job_id: string;
    status: JobStatus;
    created_at: string;
    completed_at?: string;
  }>;
  count: number;
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

// ─── Fetch helpers ────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 30_000;

function withTimeout(): AbortSignal {
  return AbortSignal.timeout(FETCH_TIMEOUT_MS);
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { signal: withTimeout() });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: withTimeout(),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: withTimeout(),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function del(path: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, { method: "DELETE", signal: withTimeout() });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
}

// ─── API functions ────────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>("/health"),
  version: () => get<VersionInfo>("/version"),

  /** Start a scan — returns immediately with job_id */
  startScan: (req: ScanRequest) => post<ScanJob>("/v1/scan", req),

  /** Poll scan status + results */
  getScan: (jobId: string) => get<ScanJob>(`/v1/scan/${jobId}`),

  /** Delete a job record */
  deleteScan: (jobId: string) => del(`/v1/scan/${jobId}`),

  /** List all jobs */
  listJobs: () => get<JobsResponse>("/v1/jobs"),

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

  /** Connect to SSE stream for real-time progress */
  streamScan: (jobId: string, onMessage: (data: SSEEvent) => void, onDone: () => void) => {
    const es = new EventSource(`${BASE}/v1/scan/${jobId}/stream`);
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

  /** Lightweight aggregate counts + scan context for nav badges */
  getPostureCounts: () =>
    get<{
      critical: number;
      high: number;
      medium: number;
      low: number;
      total: number;
      kev: number;
      compound_issues: number;
      has_mcp_context?: boolean;
      has_agent_context?: boolean;
      scan_sources?: string[];
      scan_count?: number;
    }>("/v1/posture/counts"),

  /** Compliance posture across all completed scans */
  getCompliance: () => get<ComplianceResponse>("/v1/compliance"),

  /** Auditor-ready compliance narrative for all 14 frameworks */
  getComplianceNarrative: () => get<ComplianceNarrativeResponse>("/v1/compliance/narrative"),

  /** Single-framework compliance narrative */
  getComplianceNarrativeByFramework: (framework: string) =>
    get<ComplianceNarrativeResponse>(`/v1/compliance/narrative/${encodeURIComponent(framework)}`),

  /** Fleet management */
  listFleet: (filters?: { state?: string; environment?: string; min_trust?: number }) => {
    const params = new URLSearchParams();
    if (filters?.state) params.set("state", filters.state);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.min_trust != null) params.set("min_trust", String(filters.min_trust));
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
  }) => post<{ ticket_key: string; status: string }>("/v1/findings/jira", body),

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
