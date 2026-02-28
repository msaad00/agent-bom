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
}

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
}

export interface MCPServer {
  name: string;
  command?: string;
  transport?: string;
  packages: Package[];
  tools?: Tool[];
  env?: Record<string, string>;
  vulnerabilities?: Vulnerability[];
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
  description?: string;
  cvss_score?: number;
  epss_score?: number;
  cisa_kev?: boolean;
  fixed_version?: string;
  published?: string;
}

export interface BlastRadius {
  vulnerability_id: string;
  severity: string;
  package?: string;
  ecosystem?: string;
  affected_agents: string[];
  affected_servers?: string[];
  exposed_credentials: string[];
  reachable_tools: string[];
  blast_score: number;
  cvss_score?: number;
  epss_score?: number;
  is_kev?: boolean;
  cisa_kev?: boolean;
  risk_score?: number;
  fixed_version?: string;
  owasp_tags?: string[];
  atlas_tags?: string[];
  nist_ai_rmf_tags?: string[];
  owasp_mcp_tags?: string[];
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
  owasp_llm_top10: ComplianceControl[];
  owasp_mcp_top10: ComplianceControl[];
  mitre_atlas: ComplianceControl[];
  nist_ai_rmf: ComplianceControl[];
  summary: {
    owasp_pass: number; owasp_warn: number; owasp_fail: number;
    owasp_mcp_pass: number; owasp_mcp_warn: number; owasp_mcp_fail: number;
    atlas_pass: number; atlas_warn: number; atlas_fail: number;
    nist_pass: number;  nist_warn: number;  nist_fail: number;
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

export interface AgentMeshResponse {
  nodes: Array<{
    id: string;
    type: string;
    position: { x: number; y: number };
    data: Record<string, unknown>;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    type: string;
    animated?: boolean;
    style?: Record<string, string>;
    label?: string;
  }>;
  stats: {
    total_agents: number;
    total_servers: number;
    total_packages: number;
    total_tools: number;
    total_credentials: number;
    total_vulnerabilities: number;
  };
}

// ─── Fetch helpers ────────────────────────────────────────────────────────────

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { next: { revalidate: 0 } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function del(path: string): Promise<void> {
  await fetch(`${BASE}${path}`, { method: "DELETE" });
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

  /** Get agent mesh topology graph */
  getAgentMesh: () => get<AgentMeshResponse>("/v1/agents/mesh"),

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

  /** Connect to SSE stream for real-time progress */
  streamScan: (jobId: string, onMessage: (data: unknown) => void, onDone: () => void) => {
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

  /** Compliance posture across all completed scans */
  getCompliance: () => get<ComplianceResponse>("/v1/compliance"),

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
    fetch(`${BASE}/v1/fleet/${agentId}/state`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state, reason: reason ?? "" }),
    }).then((r) => r.json()),
  updateFleetAgent: (agentId: string, update: Partial<FleetAgent>) =>
    fetch(`${BASE}/v1/fleet/${agentId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(update),
    }).then((r) => r.json()),
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
