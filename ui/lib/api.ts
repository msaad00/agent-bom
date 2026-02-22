/**
 * agent-bom API client
 * Connects to the FastAPI backend at NEXT_PUBLIC_API_URL (default: http://localhost:8422)
 */

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8422";

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
}

// ─── Attack Flow Types ───────────────────────────────────────────────────────

export interface AttackFlowNodeData {
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
  version?: string;
  ecosystem?: string;
  agent_type?: string;
  status?: string;
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
  mitre_atlas: ComplianceControl[];
  nist_ai_rmf: ComplianceControl[];
  summary: {
    owasp_pass: number; owasp_warn: number; owasp_fail: number;
    atlas_pass: number; atlas_warn: number; atlas_fail: number;
    nist_pass: number;  nist_warn: number;  nist_fail: number;
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
