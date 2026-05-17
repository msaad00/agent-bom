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
  verdict: "allow" | "warn" | "block" | string;
  reasons?: string[];
  paths?: JsonValue[];
  [key: string]: JsonValue | undefined;
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

  shouldIDeploy(request: DeployDecisionRequest): Promise<DeployDecision> {
    return this.request<DeployDecision>("POST", "/v1/graph/should-i-deploy", {
      candidate: request.candidate,
      tenant_id: request.tenantId ?? this.tenantId,
      block_risk: request.blockRisk,
      context: request.context,
    });
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
