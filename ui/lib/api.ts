/**
 * agent-bom API client
 * Connects to the FastAPI backend at NEXT_PUBLIC_API_URL (default: same origin)
 */

import { getSessionAuthHeaders } from "./auth";
import { getConfiguredApiUrl } from "./runtime-config";
import type {
  ScanRequest,
  SSEEvent,
  ScanJob,
  ScanJobStatus,
  GraphSnapshot,
  UnifiedGraphResponse,
  GraphNodeDetailResponse,
  GraphSearchResponse,
  GraphAgentsResponse,
  GraphDiffResponse,
  GraphExportFormat,
  PostureCountsResponse,
  RemediationItem,
  AttackFlowResponse,
  ContextGraphResponse,
  HealthResponse,
  VersionInfo,
  AuthDebugResponse,
  AuthMeResponse,
  AuthPolicyResponse,
  ListKeysResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  RotateApiKeyRequest,
  RotateApiKeyResponse,
  TenantQuotaUpdateRequest,
  ConnectorsResponse,
  ConnectorHealthResponse,
  DiscoveryProvidersResponse,
  SourceRecord,
  SourcesResponse,
  SourceCreateRequest,
  SourceUpdateRequest,
  SourceCheckResponse,
  SourceRunResponse,
  SourceJobsResponse,
  JobsResponse,
  AgentsResponse,
  RegistryServer,
  RegistryResponse,
  ComplianceNarrativeResponse,
  AISVSComplianceResponse,
  ComplianceResponse,
  FrameworkCatalogsResponse,
  MitreAtlasCatalogMetadata,
  AgentDetailResponse,
  AgentLifecycleResponse,
  FleetAgent,
  FleetResponse,
  FleetStatsResponse,
  FleetSyncResult,
  ScanSchedule,
  ScheduleCreateRequest,
  GatewayPolicy,
  GatewayPolicyResponse,
  GatewayAuditResponse,
  GatewayStatsResponse,
  FirewallRuntimeStats,
  EvaluateResult,
  PostureResponse,
  EnrichmentPostureResponse,
  GovernanceFinding,
  GovernanceReport,
  ActivityTimeline,
  TraceIngestResponse,
  ProxyStatusResponse,
  ProxyAlertsResponse,
  AuditEntry,
  AuditLogResponse,
  AuditIntegrityResponse,
  HubPostureResponse
} from "./api-types";
export type {
  JobStatus,
  ScanRequest,
  StepStatus,
  StepEvent,
  ProgressEvent,
  DoneEvent,
  SSEEvent,
  ScanJob,
  ScanJobStatus,
  ScanResult,
  GraphPagination,
  GraphSnapshot,
  UnifiedGraphResponse,
  GraphImpactResponse,
  GraphNodeDetailResponse,
  GraphSearchResponse,
  GraphAgentSelectorItem,
  GraphAgentsResponse,
  GraphDiffResponse,
  GraphExportFormat,
  DeploymentMode,
  PostureCountsResponse,
  RemediationItem,
  AgentStatus,
  Agent,
  MCPServer,
  MCPProvenance,
  DiscoveryProvenance,
  DiscoveryEnvelope,
  Package,
  Vulnerability,
  BlastRadius,
  AttackFlowNodeData,
  AttackFlowNode,
  AttackFlowEdge,
  AttackFlowStats,
  AttackFlowResponse,
  ContextGraphResponse,
  Tool,
  Summary,
  ScorecardSummary,
  PostureDimension,
  PostureScorecard,
  HealthResponse,
  VersionInfo,
  AuthDebugResponse,
  AuthRoleCapability,
  AuthRoleSummary,
  AuthMembership,
  AuthMeResponse,
  AuthPolicyResponse,
  ApiKeyLifecycleState,
  ApiKeyRecord,
  ListKeysResponse,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  RotateApiKeyRequest,
  RotateApiKeyResponse,
  TenantQuotaUpdateRequest,
  ConnectorsResponse,
  ConnectorHealthResponse,
  DiscoveryProviderCapabilities,
  DiscoveryProviderTrustContract,
  DiscoveryProviderContract,
  DiscoveryProvidersResponse,
  SourceKind,
  SourceStatus,
  SourceRecord,
  SourcesResponse,
  SourceCreateRequest,
  SourceUpdateRequest,
  SourceCheckResponse,
  SourceRunResponse,
  SourceJobsResponse,
  JobsResponse,
  JobListItem,
  AgentsResponse,
  RegistryServer,
  RegistryResponse,
  ControlNarrative,
  FrameworkNarrative,
  RemediationImpact,
  ComplianceNarrativeResponse,
  ComplianceControl,
  AISVSCheck,
  AISVSBenchmark,
  AISVSComplianceResponse,
  ComplianceResponse,
  FrameworkCatalogMetadata,
  FrameworkCatalogsResponse,
  MitreAtlasCatalogMetadata,
  AgentDetailResponse,
  AgentLifecycleResponse,
  FleetLifecycleState,
  FleetAgent,
  FleetResponse,
  FleetStatsResponse,
  FleetSyncResult,
  ScanSchedule,
  ScheduleCreateRequest,
  PolicyMode,
  GatewayRule,
  GatewayPolicy,
  GatewayPolicyResponse,
  PolicyAuditEntry,
  GatewayAuditResponse,
  GatewayStatsResponse,
  GatewayPolicyRuntimeSummary,
  FirewallRuntimeStats,
  FirewallPairTally,
  FirewallDecisionRecord,
  EvaluateResult,
  PostureResponse,
  EnrichmentSourcePosture,
  EnrichmentPostureResponse,
  GovernanceFinding,
  GovernanceReport,
  ActivityTimeline,
  TraceFlaggedCall,
  TraceIngestResponse,
  ProxyStatusResponse,
  ProxyAlert,
  ProxyAlertsResponse,
  AuditEntry,
  AuditLogResponse,
  AuditIntegrityResponse,
  HubPostureResponse
} from "./api-types";

// ── Scan Pipeline Step Types ────────────────────────────────────────────────

export const PIPELINE_STEPS = [
  { id: "discovery", label: "Discovery", icon: "Search" },
  { id: "extraction", label: "Extraction", icon: "Package" },
  { id: "scanning", label: "Scanning", icon: "Bug" },
  { id: "enrichment", label: "Enrichment", icon: "Zap" },
  { id: "analysis", label: "Analysis", icon: "Shield" },
  { id: "output", label: "Report", icon: "FileText" },
] as const;

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
  reportClientError: (body: { message: string; digest?: string | undefined; path?: string | undefined; component?: string | undefined }) =>
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

  /** Poll scan status without loading large result payloads */
  getScanStatus: (jobId: string) => get<ScanJobStatus>(`/v1/scan/${jobId}/status`),

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
    scanId?: string | undefined;
    entityTypes?: string[] | undefined;
    minSeverity?: string | undefined;
    relationships?: string[] | undefined;
    staticOnly?: boolean | undefined;
    dynamicOnly?: boolean | undefined;
    maxDepth?: number | undefined;
    offset?: number | undefined;
    limit?: number | undefined;
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

  /** Latest tenant-scoped OWASP AISVS benchmark posture */
  getAISVSCompliance: () => get<AISVSComplianceResponse>("/v1/compliance/aisvs"),

  /** Active framework catalog metadata surfaced by the API */
  getFrameworkCatalogs: () => get<FrameworkCatalogsResponse>("/v1/frameworks/catalogs"),

  /** Auditor-ready compliance narrative for all tag-mapped frameworks */
  getComplianceNarrative: () => get<ComplianceNarrativeResponse>("/v1/compliance/narrative"),

  /** Single-framework compliance narrative */
  getComplianceNarrativeByFramework: (framework: string) =>
    get<ComplianceNarrativeResponse>(`/v1/compliance/narrative/${encodeURIComponent(framework)}`),

  /** Compliance Hub: aggregate posture across native + ingested findings (#1044) */
  getHubPosture: () => get<HubPostureResponse>("/v1/compliance/hub/posture"),

  /** Fleet management */
  listFleet: (filters?: {
    state?: string | undefined;
    environment?: string | undefined;
    min_trust?: number | undefined;
    search?: string | undefined;
    include_quarantined?: boolean | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
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
  listDiscoveryProviders: () => get<DiscoveryProvidersResponse>("/v1/discovery/providers"),
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
  getFirewallStats: () => get<FirewallRuntimeStats>("/v1/firewall/stats"),

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
    reason?: string | undefined;
    marked_by?: string | undefined;
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
  listAuditEntries: (filters?: { action?: string | undefined; resource?: string | undefined; since?: string | undefined; limit?: number | undefined; offset?: number | undefined }) => {
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

// ─── Proxy Runtime types ─────────────────────────────────────────────────────

// ─── Audit Log types ─────────────────────────────────────────────────────────

// ─── Helpers ──────────────────────────────────────────────────────────────────
//
// Implementations moved to ./api-format as the first incremental step
// toward the broader ui/lib/api.ts decomposition tracked in #1965. These
// re-exports keep every existing `import { severityColor } from "@/lib/api"`
// working unchanged so callers don't need to migrate in one big bang.

export { severityColor, severityDot, formatDate, isConfigured } from "./api-format";
