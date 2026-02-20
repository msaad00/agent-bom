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
  summary?: Summary;
  warnings?: string[];
  scan_timestamp?: string;
  tool_version?: string;
}

export interface Agent {
  name: string;
  agent_type: string;
  config_path?: string;
  source?: string;
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
  affected_agents: string[];
  exposed_credentials: string[];
  reachable_tools: string[];
  blast_score: number;
  cvss_score?: number;
  epss_score?: number;
  cisa_kev?: boolean;
  owasp_tags?: string[];
  atlas_tags?: string[];
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
}

export interface RegistryResponse {
  servers: RegistryServer[];
  count: number;
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
