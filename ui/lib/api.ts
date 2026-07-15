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
  FixFirstGraphViewResponse,
  GraphQueryRequest,
  GraphQueryResponse,
  GraphNodeDetailResponse,
  GraphNodeNeighborsResponse,
  GraphNeighborDirection,
  GraphImpactResponse,
  GraphRollupResponse,
  GraphSearchResponse,
  GraphSemanticClustersResponse,
  GraphAgentsResponse,
  GraphDiffResponse,
  GraphEdgeChangesResponse,
  GraphExportFormat,
  AgentBomManifestResponse,
  PostureCountsResponse,
  OverviewResponse,
  AccountSummaryResponse,
  ScoreConfigRuntime,
  ScoreConfigUpdate,
  RemediationItem,
  FindingsResponse,
  FindingListEnvelope,
  FindingTriageRequest,
  FindingTriageDecisionRequest,
  FindingTriageResponse,
  FindingTriageVexResponse,
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
  CISBenchmarkChecksResponse,
  FrameworkCatalogsResponse,
  AgentDetailResponse,
  AgentLifecycleResponse,
  FleetAgent,
  FleetResponse,
  FleetQuarantineResult,
  FleetStatsResponse,
  FleetSyncResult,
  ScanSchedule,
  ScheduleCreateRequest,
  GatewayPolicy,
  GatewayPolicyResponse,
  GatewayAuditResponse,
  GatewayStatsResponse,
  GatewayFeedResponse,
  GatewayFeedKpis,
  FirewallRuntimeStats,
  EvaluateResult,
  PostureResponse,
  EnrichmentPostureResponse,
  GovernanceFinding,
  GovernanceReport,
  ActivityTimeline,
  TraceIngestResponse,
  TraceExplorerResponse,
  HitlApprovalQueueResponse,
  ProxyStatusResponse,
  ProxyAlertsResponse,
  AuditEntry,
  AuditLogResponse,
  AuditIntegrityResponse,
  HubPostureResponse,
  CostReport,
  AnomaliesReport,
  CostBudgetStatus,
  IdentitiesResponse,
  JITGrantsResponse,
  ConditionalAccessResponse,
  DriftIncidentsResponse,
  CostForecast,
  CredentialExpiryReport,
  AccessReviewsResponse,
  NhiDiscoveryResponse,
  CloudConnectionRecord,
  CloudConnectionsResponse,
  CloudConnectionCreateRequest,
  CloudConnectionUpdateRequest,
  CloudConnectionTestResponse,
  CloudConnectionScanResponse,
  BlueprintListResponse,
  BlueprintDetailResponse,
  BlueprintVersionResponse,
  BlueprintSeedResponse,
  BlueprintCreateRequest,
  WebhookSubscriptionsResponse,
  WebhookCreateRequest,
  WebhookCreateResponse,
  WebhookMutationResponse,
  WebhookOutboxResponse,
  SiemConnectorsResponse,
  SiemFormatsResponse,
  SiemTestResponse,
  IntelSourcesResponse,
  IntelAdvisoryResponse,
  IntelMatchPackageInput,
  IntelMatchResponse,
  IntelDailyBriefResponse,
  ReportJobRecord,
  ReportCreateRequest
} from "./api-types";
export type {
  AccountSummaryResponse,
  AccountSummaryDomain,
  AccountSummaryBenchmark,
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
  GraphAttackPath,
  GraphSnapshot,
  UnifiedGraphResponse,
  FixFirstGraphViewResponse,
  FixFirstPathCard,
  GraphQueryRequest,
  GraphQueryResponse,
  GraphImpactResponse,
  GraphNodeDetailResponse,
  GraphNodeNeighborsResponse,
  GraphNeighborDirection,
  GraphSearchResponse,
  GraphSemanticClusterKind,
  GraphSemanticClusterExpansion,
  GraphSemanticCluster,
  GraphSemanticClustersResponse,
  GraphAgentSelectorItem,
  GraphAgentsResponse,
  GraphDiffResponse,
  GraphEdgeChangesResponse,
  GraphExportFormat,
  AgentBomManifestResponse,
  AgentBomManifestNode,
  AgentBomManifestEdge,
  DeploymentMode,
  PostureCountsResponse,
  OverviewResponse,
  OverviewPosture,
  ExecScoreDriver,
  ExecScoreDisplayFormat,
  ScoreConfigRuntime,
  ScoreConfigUpdate,
  OverviewDomain,
  OverviewTopRisk,
  RemediationItem,
  FindingsResponse,
  UnifiedFinding,
  FindingTriageQueueState,
  FindingTriageDecision,
  FindingTriageJustification,
  FindingTriageRequest,
  FindingTriageDecisionRequest,
  FindingTriageItem,
  FindingTriageResponse,
  FindingTriageVexResponse,
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
  CISBenchmarkCheck,
  CISBenchmarkRemediation,
  CISBenchmarkChecksResponse,
  FrameworkCatalogMetadata,
  FrameworkCatalogsResponse,
  AgentDetailResponse,
  AgentLifecycleResponse,
  FleetLifecycleState,
  FleetAgent,
  FleetResponse,
  FleetQuarantineResult,
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
  GatewayFeedResponse,
  GatewayFeedKpis,
  GatewayFeedEvent,
  GatewayFeedActionType,
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
  TraceExplorerResponse,
  HitlApprovalQueueResponse,
  ProxyStatusResponse,
  ProxyAlert,
  ProxyAlertsResponse,
  AuditEntry,
  AuditLogResponse,
  AuditIntegrityResponse,
  HubPostureResponse,
  CostReport,
  AnomaliesReport,
  CostBudgetStatus,
  IdentitiesResponse,
  JITGrantsResponse,
  ConditionalAccessResponse,
  DriftIncidentsResponse,
  CostForecast,
  CostForecastStatus,
  CostTagRollup,
  CredentialExpiryState,
  CredentialExpiryItem,
  CredentialExpiryReport,
  AccessReviewStatus,
  AccessReviewCampaign,
  AccessReviewsResponse,
  NhiDiscoveryProvider,
  DiscoveredNonHumanIdentity,
  NhiDiscoveryResponse,
  CloudConnectionProvider,
  CloudConnectionStatus,
  CloudConnectionRecord,
  CloudConnectionsResponse,
  CloudConnectionCreateRequest,
  CloudConnectionUpdateRequest,
  CloudConnectionScanInventory,
  CloudConnectionScanCis,
  CloudConnectionTestResponse,
  CloudConnectionScanResponse,
  BlueprintRecord,
  BlueprintVersion,
  BlueprintComposition,
  BlueprintListResponse,
  BlueprintDetailResponse,
  BlueprintVersionResponse,
  BlueprintSeedResponse,
  BlueprintCreateRequest,
  WebhookSubscription,
  WebhookSubscriptionsResponse,
  WebhookCreateRequest,
  WebhookCreateResponse,
  WebhookMutationResponse,
  WebhookOutboxResponse,
  SiemConnectorsResponse,
  SiemFormatsResponse,
  SiemTestResponse,
  IntelFeedRun,
  IntelSource,
  IntelSourcesResponse,
  IntelAdvisory,
  IntelAdvisoryResponse,
  IntelMatchPackageInput,
  IntelMatchItem,
  IntelMatchResponse,
  IntelDailyBriefResponse,
  ReportSort,
  ReportJobRecord,
  ReportCreateRequest,
} from "./api-types";
export type { MitreAtlasCatalogMetadata } from "./api-types";

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
import type {
  DatasetCardsRequest,
  DatasetCardsResponse,
  TrainingPipelinesRequest,
  TrainingPipelinesResponse,
  BrowserExtensionsRequest,
  BrowserExtensionsResponse,
  ModelProvenanceRequest,
  ModelProvenanceResponse,
  PromptScanRequest,
  PromptScanResponse,
  ModelFilesRequest,
  ModelFilesResponse,
} from "./ai-scan";

const FETCH_TIMEOUT_MS = 30_000;
const BOOTSTRAP_TIMEOUT_MS = 5_000;

function withTimeout(timeoutMs: number = FETCH_TIMEOUT_MS): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

type GetOptions = CacheOptions & { timeoutMs?: number };

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

async function get<T>(path: string, options: GetOptions = {}): Promise<T> {
  const { timeoutMs, ...cacheOptions } = options;
  const key = `GET ${path}`;
  return cachedGet<T>(
    key,
    async () => {
      const res = await _doFetch(path, {
        credentials: "include",
        headers: getSessionAuthHeaders(),
        signal: withTimeout(timeoutMs ?? FETCH_TIMEOUT_MS),
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

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await _doFetch(path, {
    method: "PATCH",
    credentials: "include",
    headers: { "Content-Type": "application/json", ...getSessionAuthHeaders() },
    body: JSON.stringify(body),
    signal: withTimeout(),
  }, "PATCH");
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

async function getBlob(path: string, headers: Record<string, string> = {}): Promise<Blob> {
  const res = await _doFetch(path, {
    credentials: "include",
    headers: { ...getSessionAuthHeaders(), ...headers },
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

// ─── Surface-parity types (#4014) ─────────────────────────────────────────────
// Human UIs for three flagship API/MCP-only surfaces: signed audit export/verify
// (P1-2), the "should I deploy" gate, and the ExposurePath lens (P1-3). Response
// shapes mirror the backend contracts in api/routes/enterprise.py + routes/graph.py.

/** Signed audit evidence packet: JSON body + its detached HMAC signature header. */
export interface AuditExportPacket {
  /** The export body returned by GET /v1/audit/export. */
  payload: unknown;
  /** X-Agent-Bom-Audit-Export-Signature header value (empty if the server omitted it). */
  signature: string;
}

/** Result of POST /v1/audit/export/verify — tamper-evident PASS/FAIL, no key material. */
export interface AuditExportVerifyResult {
  valid: boolean;
  payload_bytes: number;
}

export interface GraphExposureEntityRef {
  id: string;
  label: string;
  role: string;
  severity?: string | undefined;
  riskScore?: number | undefined;
}

export interface GraphExposureRelationshipRef {
  id: string;
  source: string;
  target: string;
  relationship: string;
  confidence?: number | undefined;
}

/** One ranked ExposurePath as returned by the MCP-compatible REST surface. */
export interface GraphExposurePath {
  id: string;
  rank?: number | undefined;
  label: string;
  summary?: string | undefined;
  riskScore: number;
  severity: string;
  source: GraphExposureEntityRef;
  target: GraphExposureEntityRef;
  hops: GraphExposureEntityRef[];
  relationships: GraphExposureRelationshipRef[];
  nodeIds: string[];
  edgeIds: string[];
  findings: string[];
  reachableTools: string[];
  exposedCredentials: string[];
  provenance?: { source: string; scanId?: string | undefined } | undefined;
}

export interface GraphExposurePathsResponse {
  schema_version: string;
  tool: string;
  tenant_id: string;
  scan_id: string;
  created_at?: string | null | undefined;
  count: number;
  total: number;
  filters: { limit: number; min_risk: number };
  paths: GraphExposurePath[];
  message?: string | undefined;
}

export type DeployDecision = "allow" | "warn" | "block";

/** allow/warn/block deploy gate decision from POST /v1/graph/should-i-deploy. */
export interface GraphDeployDecisionResponse {
  schema_version: string;
  tool: string;
  tenant_id: string;
  scan_id: string;
  candidate: { value: string };
  decision: DeployDecision;
  maxRisk: number;
  thresholds: { warnRisk: number; blockRisk: number };
  reasons: string[];
  matchedPathCount: number;
  matchedPaths: GraphExposurePath[];
  provenance?: { source: string; basis: string } | undefined;
}

// ─── API functions ────────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>("/health", { ttlMs: 0, timeoutMs: BOOTSTRAP_TIMEOUT_MS }),
  version: () => get<VersionInfo>("/version", { timeoutMs: BOOTSTRAP_TIMEOUT_MS }),
  getAuthMe: () => get<AuthMeResponse>("/v1/auth/me", { ttlMs: 0, timeoutMs: BOOTSTRAP_TIMEOUT_MS }),
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

  // ── AI / ML supply-chain scans (synchronous; results returned inline) ──
  /** Scan directories for HuggingFace dataset cards, DVC files, and lineage. */
  scanDatasetCards: (body: DatasetCardsRequest) =>
    post<DatasetCardsResponse>("/v1/scan/dataset-cards", body),
  /** Scan directories for MLflow / W&B / Kubeflow training + serving artifacts. */
  scanTrainingPipelines: (body: TrainingPipelinesRequest) =>
    post<TrainingPipelinesResponse>("/v1/scan/training-pipelines", body),
  /** Scan installed browser extensions for dangerous permissions + AI host access. */
  scanBrowserExtensions: (body: BrowserExtensionsRequest) =>
    post<BrowserExtensionsResponse>("/v1/scan/browser-extensions", body),
  /** Check HuggingFace / Ollama model provenance (format, digest, gating, card). */
  scanModelProvenance: (body: ModelProvenanceRequest) =>
    post<ModelProvenanceResponse>("/v1/scan/model-provenance", body),
  /** Scan prompt files for injection, hardcoded secrets, and unsafe instructions. */
  scanPrompts: (body: PromptScanRequest) =>
    post<PromptScanResponse>("/v1/scan/prompt-scan", body),
  /** Scan directories for model files and assess serialization safety. */
  scanModelFiles: (body: ModelFilesRequest) =>
    post<ModelFilesResponse>("/v1/scan/model-files", body),

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

  /** Canonical Agent BOM manifest for humans and agent callers. */
  getAgentBomManifest: () => get<AgentBomManifestResponse>("/v1/agent-bom/manifest"),

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

  /** Rich edge lifecycle changes between two snapshots (added/removed/changed). */
  getGraphEdgeChanges: (oldScanId: string, newScanId: string) => {
    const params = new URLSearchParams();
    params.set("old", oldScanId);
    params.set("new", newScanId);
    return get<GraphEdgeChangesResponse>(`/v1/graph/edges/changes?${params.toString()}`);
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

  /** Load the ranked fix-first security graph view model */
  getFixFirstGraphView: (filters?: {
    scanId?: string | undefined;
    cve?: string | undefined;
    packageName?: string | undefined;
    agentName?: string | undefined;
    limit?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.cve) params.set("cve", filters.cve);
    if (filters?.packageName) params.set("package", filters.packageName);
    if (filters?.agentName) params.set("agent", filters.agentName);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<FixFirstGraphViewResponse>(`/v1/graph/views/fix-first${qs ? `?${qs}` : ""}`);
  },

  /** Load the global risk-sorted attack path queue without node-page coupling */
  getGraphAttackPaths: (filters?: {
    scanId?: string | undefined;
    offset?: number | undefined;
    limit?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<UnifiedGraphResponse>(`/v1/graph/attack-paths${qs ? `?${qs}` : ""}`);
  },

  /** Ranked ExposurePath queue (agent-native lens) over REST — GET /v1/graph/exposure-paths */
  getGraphExposurePaths: (filters?: {
    scanId?: string | undefined;
    limit?: number | undefined;
    minRisk?: number | undefined;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.minRisk != null) params.set("min_risk", String(filters.minRisk));
    const qs = params.toString();
    return get<GraphExposurePathsResponse>(`/v1/graph/exposure-paths${qs ? `?${qs}` : ""}`);
  },

  /** "Should I deploy" gate — POST /v1/graph/should-i-deploy → GO/REVIEW/BLOCK decision */
  graphShouldIDeploy: (body: {
    candidate: string;
    scanId?: string | undefined;
    limit?: number | undefined;
    warnRisk?: number | undefined;
    blockRisk?: number | undefined;
  }) => {
    const payload: Record<string, unknown> = { candidate: body.candidate };
    if (body.scanId) payload.scan_id = body.scanId;
    if (body.limit != null) payload.limit = body.limit;
    if (body.warnRisk != null) payload.warnRisk = body.warnRisk;
    if (body.blockRisk != null) payload.blockRisk = body.blockRisk;
    return post<GraphDeployDecisionResponse>("/v1/graph/should-i-deploy", payload);
  },

  /** Run a bounded root-centered graph traversal */
  queryGraph: (body: GraphQueryRequest) =>
    post<GraphQueryResponse>("/v1/graph/query", body),

  /** Search graph nodes within a snapshot */
  searchGraph: (
    query: string,
    filters?: {
      scanId?: string;
      entityTypes?: string[];
      minSeverity?: string;
      compliancePrefixes?: string[];
      dataSources?: string[];
      offset?: number;
      limit?: number;
      cursor?: string;
    },
  ) => {
    const params = new URLSearchParams();
    params.set("q", query);
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.entityTypes && filters.entityTypes.length > 0) {
      params.set("entity_types", filters.entityTypes.join(","));
    }
    if (filters?.minSeverity) params.set("min_severity", filters.minSeverity);
    if (filters?.compliancePrefixes && filters.compliancePrefixes.length > 0) {
      params.set("compliance_prefixes", filters.compliancePrefixes.join(","));
    }
    if (filters?.dataSources && filters.dataSources.length > 0) {
      params.set("data_sources", filters.dataSources.join(","));
    }
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.cursor) params.set("cursor", filters.cursor);
    return get<GraphSearchResponse>(`/v1/graph/search?${params.toString()}`);
  },

  /** Load API-backed semantic graph clusters without client-only inference */
  getGraphClusters: (filters?: {
    scanId?: string;
    kinds?: string[];
    minMembers?: number;
    limit?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.kinds && filters.kinds.length > 0) params.set("kinds", filters.kinds.join(","));
    if (filters?.minMembers != null) params.set("min_members", String(filters.minMembers));
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    const qs = params.toString();
    return get<GraphSemanticClustersResponse>(`/v1/graph/clusters${qs ? `?${qs}` : ""}`);
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

  /** Lazily load a bounded set of one node's direct graph neighbors for inline expand */
  getGraphNodeNeighbors: (
    nodeId: string,
    options?: { scanId?: string | undefined; limit?: number | undefined; direction?: GraphNeighborDirection | undefined },
  ) => {
    const params = new URLSearchParams();
    if (options?.scanId) params.set("scan_id", options.scanId);
    if (options?.limit != null) params.set("limit", String(options.limit));
    if (options?.direction) params.set("direction", options.direction);
    const qs = params.toString();
    return get<GraphNodeNeighborsResponse>(
      `/v1/graph/node/${encodeURIComponent(nodeId)}/neighbors${qs ? `?${qs}` : ""}`,
    );
  },

  /** Compute the blast radius (reverse-BFS impact) of a node */
  getGraphImpact: (nodeId: string, scanId?: string, maxDepth?: number) => {
    const params = new URLSearchParams();
    params.set("node", nodeId);
    if (scanId) params.set("scan_id", scanId);
    if (maxDepth != null) params.set("max_depth", String(maxDepth));
    return get<GraphImpactResponse>(`/v1/graph/impact?${params.toString()}`);
  },

  /** Estate-scale CONTAINS roll-up with optional one-level drill-down */
  getGraphRollup: (
    scanId?: string,
    options?: {
      node?: string;
      minSeverity?: string;
      exposed?: boolean;
      toxic?: boolean;
      mode?: "rollup" | "attack_path";
    },
  ) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan_id", scanId);
    if (options?.node) params.set("node", options.node);
    if (options?.minSeverity) params.set("min_severity", options.minSeverity);
    if (options?.exposed) params.set("exposed", "true");
    if (options?.toxic) params.set("toxic", "true");
    if (options?.mode) params.set("mode", options.mode);
    const qs = params.toString();
    return get<GraphRollupResponse>(`/v1/graph/rollup${qs ? `?${qs}` : ""}`);
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

  /** Cross-domain posture snapshot for the unified overview landing page */
  getOverview: () => get<OverviewResponse>("/v1/overview"),

  /** Per-account, end-to-end posture drill for one cloud account (#3931) */
  getCloudAccountSummary: (accountRef: string) =>
    get<AccountSummaryResponse>(`/v1/cloud/accounts/${encodeURIComponent(accountRef)}/summary`),

  /** Configurable exec risk-score model + display config for this tenant (#3940) */
  getScoreConfig: () => get<ScoreConfigRuntime>("/v1/overview/score-config"),

  /** Update the exec risk-score weights, thresholds, or display format (admin) */
  updateScoreConfig: (body: ScoreConfigUpdate) =>
    put<ScoreConfigRuntime>("/v1/overview/score-config", body),

  /** Runtime health for external vulnerability enrichment sources */
  getEnrichmentPosture: () => get<EnrichmentPostureResponse>("/v1/posture/enrichment"),

  /** Lightweight aggregate counts + scan context for nav badges */
  getPostureCounts: () => get<PostureCountsResponse>("/v1/posture/counts"),

  /** Compliance posture across all completed scans */
  getCompliance: () => get<ComplianceResponse>("/v1/compliance"),

  /** Latest tenant-scoped OWASP AISVS benchmark posture */
  getAISVSCompliance: () => get<AISVSComplianceResponse>("/v1/compliance/aisvs"),

  /**
   * Tenant-scoped cloud CIS benchmark checks with structured remediation.
   * Server-side filters (cloud/status/priority) are optional; callers that
   * also need a guardrails filter fetch a page and filter client-side.
   */
  listCisBenchmarkChecks: (filters?: {
    cloud?: string;
    status?: string;
    priority?: number;
    limit?: number;
    offset?: number;
  }) => {
    const params = new URLSearchParams();
    if (filters?.cloud) params.set("cloud", filters.cloud);
    if (filters?.status) params.set("status", filters.status);
    if (filters?.priority !== undefined) params.set("priority", String(filters.priority));
    if (filters?.limit !== undefined) params.set("limit", String(filters.limit));
    if (filters?.offset !== undefined) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<CISBenchmarkChecksResponse>(`/v1/cis/checks${qs ? `?${qs}` : ""}`);
  },

  /** Active framework catalog metadata surfaced by the API */
  getFrameworkCatalogs: () => get<FrameworkCatalogsResponse>("/v1/frameworks/catalogs"),

  /** Auditor-ready compliance narrative for all tag-mapped frameworks */
  getComplianceNarrative: () => get<ComplianceNarrativeResponse>("/v1/compliance/narrative"),

  /** Single-framework compliance narrative */
  getComplianceNarrativeByFramework: (framework: string) =>
    get<ComplianceNarrativeResponse>(`/v1/compliance/narrative/${encodeURIComponent(framework)}`),

  /** Compliance Hub: aggregate posture across native + ingested findings (#1044) */
  getHubPosture: () => get<HubPostureResponse>("/v1/compliance/hub/posture"),

  /**
   * Download one signed evidence pack covering every tag-mapped framework.
   * Returns the raw bundle Blob (JSON) so the caller can save it to disk; the
   * tamper-evident signature travels in the response headers.
   */
  downloadCompliancePack: () => getBlob("/v1/compliance/report/pack"),

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
  /**
   * One-click containment: quarantine the agent AND mint an enforce-mode
   * gateway deny policy bound to its identity (fail closed, idempotent).
   */
  quarantineFleetAgent: (agentId: string) =>
    post<FleetQuarantineResult>(`/v1/fleet/${encodeURIComponent(agentId)}/quarantine`, {}),
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
  getGatewayFeed: (limit = 100) => get<GatewayFeedResponse>(`/v1/gateway/feed?limit=${limit}`),
  getGatewayFeedKpis: () => get<GatewayFeedKpis>("/v1/gateway/feed/kpis"),
  getFirewallStats: () => get<FirewallRuntimeStats>("/v1/firewall/stats"),

  // Governance
  getGovernance: (days = 30) => get<GovernanceReport>(`/v1/governance?days=${days}`),
  getGovernanceFindings: (days = 30, severity?: string, category?: string) => {
    const params = new URLSearchParams({ days: String(days) });
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    return get<FindingListEnvelope<GovernanceFinding>>(
      `/v1/governance/findings?${params}`
    );
  },

  // Governance blueprints (persisted AI-system blueprints + versioning + approval)
  listBlueprints: (limit = 50, offset = 0) =>
    get<BlueprintListResponse>(`/v1/governance/blueprints?limit=${limit}&offset=${offset}`),
  getBlueprint: (blueprintId: string) =>
    get<BlueprintDetailResponse>(`/v1/governance/blueprints/${encodeURIComponent(blueprintId)}`),
  createBlueprint: (body: BlueprintCreateRequest) =>
    post<BlueprintVersionResponse>("/v1/governance/blueprints", body),
  seedBlueprints: () => post<BlueprintSeedResponse>("/v1/governance/blueprints/seed", {}),
  submitBlueprintVersion: (blueprintId: string, version: number) =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/submit`,
      {}
    ),
  approveBlueprintVersion: (blueprintId: string, version: number, note = "") =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/approve`,
      { note }
    ),
  rejectBlueprintVersion: (blueprintId: string, version: number, note = "") =>
    post<BlueprintVersionResponse>(
      `/v1/governance/blueprints/${encodeURIComponent(blueprintId)}/versions/${version}/reject`,
      { note }
    ),

  // Activity Timeline
  getActivity: (days = 30) => get<ActivityTimeline>(`/v1/activity?days=${days}`),
  ingestTraces: (body: unknown) => post<TraceIngestResponse>("/v1/traces", body),
  getTraceExplorer: (limit = 100) => get<TraceExplorerResponse>(`/v1/runtime/trace-explorer?limit=${limit}`),
  getHitlApprovalQueue: (status?: string, limit = 100) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) params.set("status", status);
    return get<HitlApprovalQueueResponse>(`/v1/runtime/approval-queue?${params}`);
  },
  decideHitlApproval: (itemId: string, decision: "approve" | "deny", note = "") =>
    post<{ schema_version: string; item: HitlApprovalQueueResponse["items"][number] }>(
      `/v1/runtime/approval-queue/${encodeURIComponent(itemId)}/decision`,
      { decision, note },
    ),

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

  // ── Unified findings ──
  listFindings: (filters?: {
    scanId?: string;
    severity?: string;
    sort?: string;
    limit?: number;
    offset?: number;
    approximateTotal?: boolean;
    // First-class scope + taxonomy filters (issue #3946). All optional +
    // backward compatible; the server canonicalizes and never rejects them.
    provider?: string;
    account?: string;
    environment?: string;
    domain?: string;
  }) => {
    const params = new URLSearchParams();
    if (filters?.scanId) params.set("scan_id", filters.scanId);
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.sort) params.set("sort", filters.sort);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    if (filters?.approximateTotal) params.set("approximate_total", "true");
    if (filters?.provider) params.set("provider", filters.provider);
    if (filters?.account) params.set("account", filters.account);
    if (filters?.environment) params.set("environment", filters.environment);
    if (filters?.domain) params.set("domain", filters.domain);
    const qs = params.toString();
    return get<FindingsResponse>(`/v1/findings${qs ? `?${qs}` : ""}`);
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

  // ── Finding triage and signed VEX ──
  createFindingTriage: (body: FindingTriageRequest) =>
    post<FindingTriageResponse["triage"][number]>("/v1/findings/triage", body),
  listFindingTriage: (filters?: { queueState?: string; decision?: string; limit?: number; offset?: number }) => {
    const params = new URLSearchParams();
    if (filters?.queueState) params.set("queue_state", filters.queueState);
    if (filters?.decision) params.set("decision", filters.decision);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const qs = params.toString();
    return get<FindingTriageResponse>(`/v1/findings/triage${qs ? `?${qs}` : ""}`);
  },
  updateFindingTriageDecision: (triageId: string, body: FindingTriageDecisionRequest) =>
    put<FindingTriageResponse["triage"][number]>(`/v1/findings/triage/${encodeURIComponent(triageId)}/decision`, body),
  exportFindingTriageVex: () => get<FindingTriageVexResponse>("/v1/findings/triage/vex"),

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

  /**
   * Download a signed audit evidence packet (GET /v1/audit/export). Returns the
   * JSON body together with its detached HMAC signature (response header) so the
   * caller can persist a self-contained, tamper-evident evidence file.
   */
  exportAuditPacket: async (filters?: {
    action?: string | undefined;
    resource?: string | undefined;
    since?: string | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
  }): Promise<AuditExportPacket> => {
    const params = new URLSearchParams();
    params.set("format", "json");
    if (filters?.action) params.set("action", filters.action);
    if (filters?.resource) params.set("resource", filters.resource);
    if (filters?.since) params.set("since", filters.since);
    if (filters?.limit != null) params.set("limit", String(filters.limit));
    if (filters?.offset != null) params.set("offset", String(filters.offset));
    const res = await _doFetch(
      `/v1/audit/export?${params.toString()}`,
      { credentials: "include", headers: getSessionAuthHeaders(), signal: withTimeout() },
      "GET",
    );
    const signature = res.headers.get("X-Agent-Bom-Audit-Export-Signature") ?? "";
    const payload = (await res.json()) as unknown;
    return { payload, signature };
  },

  /** Verify a signed audit export packet without returning HMAC key material. */
  verifyAuditPacket: (payload: unknown, signature: string) =>
    post<AuditExportVerifyResult>("/v1/audit/export/verify", { payload, signature }),

  // ── Cost / FinOps cockpit ──
  getCostReport: (filters?: { agent?: string; costCenter?: string; tag?: string }) => {
    const params = new URLSearchParams();
    if (filters?.agent) params.set("agent", filters.agent);
    if (filters?.costCenter) params.set("cost_center", filters.costCenter);
    if (filters?.tag) params.set("tag", filters.tag);
    const qs = params.toString();
    return get<CostReport>(`/v1/observability/costs${qs ? `?${qs}` : ""}`);
  },
  getCostBudget: (agent?: string) =>
    get<CostBudgetStatus>(`/v1/observability/costs/budget${agent ? `?agent=${encodeURIComponent(agent)}` : ""}`),
  /** Forward-looking burn-rate + budget-runway projection (reference only) */
  getCostForecast: (agent?: string) =>
    get<CostForecast>(`/v1/observability/costs/forecast${agent ? `?agent=${encodeURIComponent(agent)}` : ""}`),
  getCostAnomalies: (zThreshold?: number) =>
    get<AnomaliesReport>(`/v1/observability/anomalies${zThreshold ? `?z_threshold=${zThreshold}` : ""}`),

  // ── Identity / access-governance cockpit ──
  listIdentities: (includeInactive = false, limit = 200) =>
    get<IdentitiesResponse>(`/v1/identities?include_inactive=${includeInactive}&limit=${limit}`),
  listJitGrants: (includeInactive = false, limit = 200) =>
    get<JITGrantsResponse>(`/v1/identity-jit-grants?include_inactive=${includeInactive}&limit=${limit}`),
  listConditionalAccessPolicies: (includeDisabled = false, limit = 200) =>
    get<ConditionalAccessResponse>(`/v1/conditional-access-policies?include_disabled=${includeDisabled}&limit=${limit}`),

  // ── NHI / identity governance: credential expiry, access reviews, discovery ──
  /** Non-secret credential expiry / rotation governance posture */
  getCredentialExpiry: () =>
    get<CredentialExpiryReport>("/v1/auth/secrets/credential-expiry"),
  /** Access-review / recertification campaigns over discovered NHIs */
  listAccessReviews: (limit = 200) =>
    get<AccessReviewsResponse>(`/v1/identities/access-reviews?limit=${limit}`),
  /** Read-only NHI discovery summary (gated by *_DISCOVERY env flags) */
  discoverNonHumanIdentities: (providers?: string[]) =>
    post<NhiDiscoveryResponse>("/v1/identities/discover", providers ? { providers } : {}),

  // ── Cloud connections plane (#3175) ──
  /** List this tenant's read-only cloud connections (non-secret metadata only). */
  listCloudConnections: () => get<CloudConnectionsResponse>("/v1/cloud/connections"),
  /** One connection's non-secret metadata. */
  getCloudConnection: (id: string) =>
    get<CloudConnectionRecord>(`/v1/cloud/connections/${encodeURIComponent(id)}`),
  /**
   * Create a read-only cloud connection. `external_id` is write-only: it is
   * encrypted at rest server-side and never returned in any response.
   */
  createCloudConnection: (body: CloudConnectionCreateRequest) =>
    post<CloudConnectionRecord>("/v1/cloud/connections", body),
  /** Update non-secret connection controls such as recurring scan cadence. */
  updateCloudConnection: (id: string, body: CloudConnectionUpdateRequest) =>
    patch<CloudConnectionRecord>(`/v1/cloud/connections/${encodeURIComponent(id)}`, body),
  /** Delete a connection owned by this tenant. */
  deleteCloudConnection: (id: string) => del(`/v1/cloud/connections/${encodeURIComponent(id)}`),
  /** Validate the stored read-only credential without running inventory/CIS. */
  testCloudConnection: (id: string) =>
    post<CloudConnectionTestResponse>(`/v1/cloud/connections/${encodeURIComponent(id)}/test`, {}),
  /** Launch a read-only scan via the credential broker (AWS, Azure, GCP, Snowflake). */
  scanCloudConnection: (id: string) =>
    post<CloudConnectionScanResponse>(`/v1/cloud/connections/${encodeURIComponent(id)}/scan`, {}),

  // ── Drift / behavior-incident cockpit ──
  listDriftIncidents: (includeResolved = false, limit = 200) =>
    get<DriftIncidentsResponse>(`/v1/runtime/drift/incidents?include_resolved=${includeResolved}&limit=${limit}`),
  resolveDriftIncident: (incidentId: string, note?: string) =>
    post<{ resolved: boolean }>(`/v1/runtime/drift/incidents/${encodeURIComponent(incidentId)}/resolve`, { note: note ?? "" }),

  // ── Operations & Integrations: webhook subscriptions ──
  /** List governance webhook subscriptions for the active tenant. */
  listWebhookSubscriptions: (includeDisabled = true, limit = 200) =>
    get<WebhookSubscriptionsResponse>(
      `/v1/webhooks?include_disabled=${includeDisabled}&limit=${limit}`,
      { ttlMs: 0 },
    ),
  /** Register a governance webhook destination. Returns the signing secret once. */
  createWebhookSubscription: (body: WebhookCreateRequest) =>
    post<WebhookCreateResponse>("/v1/webhooks", body),
  /** Enable a disabled subscription. */
  enableWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/enable`, {}),
  /** Disable a subscription without deleting it. */
  disableWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/disable`, {}),
  /** Delete a subscription. */
  deleteWebhookSubscription: (id: string) => del(`/v1/webhooks/${encodeURIComponent(id)}`),
  /** Enqueue a synthetic test delivery to this destination. */
  testWebhookSubscription: (id: string) =>
    post<WebhookMutationResponse>(`/v1/webhooks/${encodeURIComponent(id)}/test`, {}),
  /** Recent webhook outbox deliveries (observability of the shipped outbox). */
  listWebhookOutbox: (status?: "pending" | "delivered" | "dead_letter", limit = 50) =>
    get<WebhookOutboxResponse>(
      `/v1/posture/webhooks/outbox?limit=${limit}${status ? `&status=${status}` : ""}`,
      { ttlMs: 0 },
    ),

  // ── Operations & Integrations: SIEM connectors ──
  /** List available SIEM connector types. */
  listSiemConnectors: () => get<SiemConnectorsResponse>("/v1/siem/connectors"),
  /** List supported SIEM event formats. */
  listSiemFormats: () => get<SiemFormatsResponse>("/v1/siem/formats"),
  /** Test SIEM connectivity. The token (if any) is sent via header, never persisted. */
  testSiemConnection: (siemType: string, url: string, token?: string) =>
    post<SiemTestResponse>(
      `/v1/siem/test?siem_type=${encodeURIComponent(siemType)}&url=${encodeURIComponent(url)}`,
      {},
      token ? { "X-Siem-Token": token } : {},
    ),

  // ── Operations & Integrations: threat intel ──
  /** Canonical threat-intel source and feed-run metadata. */
  getIntelSources: () => get<IntelSourcesResponse>("/v1/intel/sources", { ttlMs: 0 }),
  /** Look up one CVE/GHSA/OSV advisory from local intel. */
  getIntelAdvisory: (advisoryId: string) =>
    get<IntelAdvisoryResponse>(`/v1/intel/advisories/${encodeURIComponent(advisoryId)}`, { ttlMs: 0 }),
  /** Match inventory package coordinates to local advisory intel. */
  matchIntelPackages: (packages: IntelMatchPackageInput[], limit = 100) =>
    post<IntelMatchResponse>("/v1/intel/match", { packages, limit }),
  /** Local analyst threat brief from governed intel sources. */
  getIntelDailyBrief: (body: Record<string, unknown> = {}) =>
    post<IntelDailyBriefResponse>("/v1/intel/daily-brief", body),

  // ── Operations & Integrations: async reports ──
  /** Enqueue an async findings export (gzipped NDJSON). */
  createReportJob: (body: ReportCreateRequest = {}) =>
    post<ReportJobRecord>("/v1/reports", body),
  /** Poll async report job status and download metadata. */
  getReportJob: (jobId: string) =>
    get<ReportJobRecord>(`/v1/reports/${encodeURIComponent(jobId)}`, { ttlMs: 0 }),
  /** Download a completed report artifact. The job-scoped token is sent via
   *  header (kept out of logs/history), never in the URL. */
  downloadReportArtifact: (jobId: string, token: string) =>
    getBlob(`/v1/reports/${encodeURIComponent(jobId)}/download`, {
      "X-Agent-Bom-Download-Token": token,
    }),
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

export { severityColor, severityDot, formatDate, isConfigured, agentClass, agentClassCounts } from "./api-format";
