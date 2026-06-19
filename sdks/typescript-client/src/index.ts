export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface AgentBomClientOptions {
  baseUrl: string;
  apiKey?: string;
  bearerToken?: string;
  tenantId?: string;
  fetch?: FetchLike;
  defaultHeaders?: Record<string, string>;
}

export interface HealthResponse {
  status?: string;
  version?: string;
  storage?: Record<string, JsonValue>;
  [key: string]: JsonValue | undefined;
}

export interface ExposurePathQuery {
  tenantId?: string;
  limit?: number;
  minRisk?: number;
}

export interface FindingsQuery {
  severity?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export interface ExposurePathEnvelope {
  paths: JsonValue[];
  nodes?: JsonValue[];
  edges?: JsonValue[];
  stats?: Record<string, JsonValue>;
  [key: string]: JsonValue | undefined;
}

export interface DeployDecisionRequest {
  candidate: string | Record<string, JsonValue>;
  tenantId?: string;
  blockRisk?: number;
  context?: Record<string, JsonValue>;
}

export interface DeployDecision {
  decision: "allow" | "warn" | "block" | string;
  reasons?: string[];
  matchedPaths?: JsonValue[];
  matchedPathCount?: number;
  maxRisk?: number;
  thresholds?: Record<string, JsonValue>;
  [key: string]: JsonValue | undefined;
}

export interface BulkFindingIngestRequest {
  findings: Record<string, JsonValue>[];
  source?: string;
  schemaVersion?: string;
  metadata?: Record<string, JsonValue>;
  tenantId?: string;
}

export interface DatasetVersionCreateRequest {
  datasetId: string;
  versionId?: string;
  artifactUri?: string;
  digest?: string;
  digestAlgorithm?: string;
  source?: string;
  metadata?: Record<string, JsonValue>;
  tenantId?: string;
}

export interface EvaluationRunCreateRequest {
  evaluationId?: string;
  name?: string;
  status?: string;
  datasetId?: string;
  datasetVersionId?: string;
  traceId?: string;
  model?: string;
  promptHash?: string;
  source?: string;
  scores?: Record<string, number>;
  summary?: Record<string, JsonValue>;
  cases?: Record<string, JsonValue>[];
  metadata?: Record<string, JsonValue>;
  tenantId?: string;
}

export interface BulkFindingIngestResponse {
  schema_version: string;
  batch_id: string;
  ingested: number;
  tenant_total: number;
  tenant_id: string;
  source: string;
  warnings?: string[];
  [key: string]: JsonValue | undefined;
}

export interface DatasetVersionRecord {
  tenant_id: string;
  dataset_id: string;
  version_id: string;
  created_at: string;
  source: string;
  artifact_uri?: string | null;
  digest?: string | null;
  digest_algorithm?: string;
  metadata?: Record<string, JsonValue>;
}

export interface DatasetVersionResponse {
  schema_version: string;
  dataset: DatasetVersionRecord;
  warnings?: string[];
}

export interface DatasetVersionsResponse {
  schema_version: string;
  tenant_id: string;
  dataset_id: string;
  versions: DatasetVersionRecord[];
  count: number;
}

export interface EvaluationRunRecord {
  tenant_id: string;
  evaluation_id: string;
  created_at: string;
  updated_at: string;
  name?: string | null;
  status: string;
  dataset_id?: string | null;
  dataset_version_id?: string | null;
  trace_id?: string | null;
  model?: string | null;
  prompt_hash?: string | null;
  source: string;
  scores?: Record<string, number>;
  summary?: Record<string, JsonValue>;
  cases?: Record<string, JsonValue>[];
  metadata?: Record<string, JsonValue>;
}

export interface EvaluationRunResponse {
  schema_version: string;
  evaluation: EvaluationRunRecord;
  warnings?: string[];
}

export interface EvaluationRunsResponse {
  schema_version: string;
  tenant_id: string;
  evaluations: EvaluationRunRecord[];
  count: number;
  limit: number;
  offset: number;
}

export interface EvaluationRunsQuery {
  datasetId?: string;
  limit?: number;
  offset?: number;
}

export interface IngestRuntimeEventsRequest {
  events: Record<string, JsonValue>[];
}

export interface RuntimeSessionsQuery {
  limit?: number;
  offset?: number;
}

export interface RuntimeObservationsQuery {
  sessionId?: string;
  limit?: number;
  offset?: number;
}

export interface RuntimeSessionObservationsQuery {
  limit?: number;
  offset?: number;
}

export interface IntelMatchRequest {
  packages?: Record<string, JsonValue>[];
  purl?: string;
  ecosystem?: string;
  name?: string;
  version?: string;
  limit?: number;
}

export class AgentBomApiError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(message: string, status: number, body: string) {
    super(message);
    this.name = "AgentBomApiError";
    this.status = status;
    this.body = body;
  }
}

export class AgentBomClient {
  readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly bearerToken: string | undefined;
  private readonly tenantId: string | undefined;
  private readonly fetchImpl: FetchLike;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: AgentBomClientOptions) {
    if (!options.baseUrl.trim()) {
      throw new Error("baseUrl is required");
    }
    if (options.apiKey && options.bearerToken) {
      throw new Error("Configure either apiKey or bearerToken, not both");
    }

    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (!fetchImpl) {
      throw new Error("No fetch implementation available");
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.bearerToken = options.bearerToken;
    this.tenantId = options.tenantId;
    this.fetchImpl = fetchImpl.bind(globalThis) as FetchLike;
    this.defaultHeaders = options.defaultHeaders ?? {};
  }

  health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/health");
  }

  exposurePaths(query: ExposurePathQuery = {}): Promise<ExposurePathEnvelope> {
    const search = new URLSearchParams();
    const tenantId = query.tenantId ?? this.tenantId;
    if (tenantId) {
      search.set("tenant_id", tenantId);
    }
    if (query.limit !== undefined) {
      search.set("limit", String(query.limit));
    }
    if (query.minRisk !== undefined) {
      search.set("min_risk", String(query.minRisk));
    }
    return this.request<ExposurePathEnvelope>(
      "GET",
      `/v1/graph/exposure-paths${formatSearch(search)}`,
    );
  }

  listFindings(query: FindingsQuery = {}): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    search.set("sort", query.sort ?? "effective_reach");
    search.set("limit", String(query.limit ?? 500));
    search.set("offset", String(query.offset ?? 0));
    if (query.severity) {
      search.set("severity", query.severity);
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/findings${formatSearch(search)}`,
    );
  }

  shouldIDeploy(request: DeployDecisionRequest): Promise<DeployDecision> {
    return this.request<DeployDecision>("POST", "/v1/graph/should-i-deploy", {
      candidate: request.candidate,
      tenant_id: request.tenantId ?? this.tenantId,
      block_risk: request.blockRisk,
      context: request.context,
    });
  }

  ingestFindings(
    request: BulkFindingIngestRequest,
  ): Promise<BulkFindingIngestResponse> {
    return this.request<BulkFindingIngestResponse>("POST", "/v1/findings/bulk", {
      findings: request.findings,
      source: request.source,
      schema_version: request.schemaVersion,
      metadata: request.metadata,
      tenant_id: request.tenantId ?? this.tenantId,
    });
  }

  registerDatasetVersion(
    request: DatasetVersionCreateRequest,
  ): Promise<DatasetVersionResponse> {
    return this.request<DatasetVersionResponse>(
      "POST",
      `/v1/datasets/${encodeURIComponent(request.datasetId)}/versions`,
      {
        version_id: request.versionId,
        artifact_uri: request.artifactUri,
        digest: request.digest,
        digest_algorithm: request.digestAlgorithm,
        source: request.source,
        metadata: request.metadata,
        tenant_id: request.tenantId ?? this.tenantId,
      },
    );
  }

  datasetVersions(datasetId: string): Promise<DatasetVersionsResponse> {
    return this.request<DatasetVersionsResponse>(
      "GET",
      `/v1/datasets/${encodeURIComponent(datasetId)}/versions`,
    );
  }

  datasetVersion(
    datasetId: string,
    versionId: string,
  ): Promise<DatasetVersionResponse> {
    return this.request<DatasetVersionResponse>(
      "GET",
      `/v1/datasets/${encodeURIComponent(datasetId)}/versions/${encodeURIComponent(versionId)}`,
    );
  }

  registerEvaluationRun(
    request: EvaluationRunCreateRequest,
  ): Promise<EvaluationRunResponse> {
    return this.request<EvaluationRunResponse>("POST", "/v1/evaluations", {
      evaluation_id: request.evaluationId,
      name: request.name,
      status: request.status,
      dataset_id: request.datasetId,
      dataset_version_id: request.datasetVersionId,
      trace_id: request.traceId,
      model: request.model,
      prompt_hash: request.promptHash,
      source: request.source,
      scores: request.scores,
      summary: request.summary,
      cases: request.cases,
      metadata: request.metadata,
      tenant_id: request.tenantId ?? this.tenantId,
    });
  }

  evaluationRuns(query: EvaluationRunsQuery = {}): Promise<EvaluationRunsResponse> {
    const search = new URLSearchParams();
    if (query.datasetId) {
      search.set("dataset_id", query.datasetId);
    }
    if (query.limit !== undefined) {
      search.set("limit", String(query.limit));
    }
    if (query.offset !== undefined) {
      search.set("offset", String(query.offset));
    }
    return this.request<EvaluationRunsResponse>(
      "GET",
      `/v1/evaluations${formatSearch(search)}`,
    );
  }

  evaluationRun(evaluationId: string): Promise<EvaluationRunResponse> {
    return this.request<EvaluationRunResponse>(
      "GET",
      `/v1/evaluations/${encodeURIComponent(evaluationId)}`,
    );
  }

  agentManifest(): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    if (this.tenantId) {
      search.set("tenant_id", this.tenantId);
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/agent-bom/manifest${formatSearch(search)}`,
    );
  }

  runtimeProductionIndex(): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    if (this.tenantId) {
      search.set("tenant_id", this.tenantId);
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/runtime/production-index${formatSearch(search)}`,
    );
  }

  ingestRuntimeEvents(
    request: IngestRuntimeEventsRequest,
  ): Promise<Record<string, JsonValue>> {
    return this.request<Record<string, JsonValue>>(
      "POST",
      "/v1/runtime/events",
      {
        events: request.events,
        tenant_id: this.tenantId,
      },
    );
  }

  runtimeSessions(
    query: RuntimeSessionsQuery = {},
  ): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    if (this.tenantId) {
      search.set("tenant_id", this.tenantId);
    }
    if (query.limit !== undefined) {
      search.set("limit", String(query.limit));
    }
    if (query.offset !== undefined) {
      search.set("offset", String(query.offset));
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/runtime/sessions${formatSearch(search)}`,
    );
  }

  runtimeObservations(
    query: RuntimeObservationsQuery = {},
  ): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    if (this.tenantId) {
      search.set("tenant_id", this.tenantId);
    }
    if (query.sessionId) {
      search.set("session_id", query.sessionId);
    }
    if (query.limit !== undefined) {
      search.set("limit", String(query.limit));
    }
    if (query.offset !== undefined) {
      search.set("offset", String(query.offset));
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/runtime/observations${formatSearch(search)}`,
    );
  }

  runtimeSessionObservations(
    sessionId: string,
    query: RuntimeSessionObservationsQuery = {},
  ): Promise<Record<string, JsonValue>> {
    const search = new URLSearchParams();
    if (this.tenantId) {
      search.set("tenant_id", this.tenantId);
    }
    if (query.limit !== undefined) {
      search.set("limit", String(query.limit));
    }
    if (query.offset !== undefined) {
      search.set("offset", String(query.offset));
    }
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/runtime/sessions/${encodeURIComponent(sessionId)}/observations${formatSearch(search)}`,
    );
  }

  intelLookup(advisoryId: string): Promise<Record<string, JsonValue>> {
    return this.request<Record<string, JsonValue>>(
      "GET",
      `/v1/intel/advisories/${encodeURIComponent(advisoryId)}`,
    );
  }

  intelMatch(request: IntelMatchRequest): Promise<Record<string, JsonValue>> {
    return this.request<Record<string, JsonValue>>("POST", "/v1/intel/match", {
      packages: request.packages,
      purl: request.purl,
      ecosystem: request.ecosystem,
      name: request.name,
      version: request.version,
      limit: request.limit,
    });
  }

  intelSources(): Promise<Record<string, JsonValue>> {
    return this.request<Record<string, JsonValue>>("GET", "/v1/intel/sources");
  }

  async request<T>(
    method: string,
    path: string,
    body?: Record<string, JsonValue | undefined>,
  ): Promise<T> {
    const init: RequestInit = {
      method,
      headers: this.headers(body !== undefined),
    };
    if (body !== undefined) {
      init.body = JSON.stringify(stripUndefined(body));
    }

    const response = await this.fetchImpl(this.url(path), init);

    const text = await response.text();
    if (!response.ok) {
      throw new AgentBomApiError(
        `agent-bom request failed: ${response.status}`,
        response.status,
        text,
      );
    }

    if (!text) {
      return undefined as T;
    }
    return JSON.parse(text) as T;
  }

  private url(path: string): string {
    if (/^https?:\/\//.test(path)) {
      return path;
    }
    return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  }

  private headers(hasBody: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.defaultHeaders,
    };
    if (hasBody) {
      headers["content-type"] = "application/json";
    }
    if (this.apiKey) {
      headers["x-api-key"] = this.apiKey;
    }
    if (this.bearerToken) {
      headers.authorization = `Bearer ${this.bearerToken}`;
    }
    if (this.tenantId) {
      headers["x-agent-bom-tenant-id"] = this.tenantId;
    }
    return headers;
  }
}

function formatSearch(search: URLSearchParams): string {
  const value = search.toString();
  return value ? `?${value}` : "";
}

function stripUndefined(
  value: Record<string, JsonValue | undefined>,
): Record<string, JsonValue> {
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, JsonValue] => {
      return entry[1] !== undefined;
    }),
  );
}
