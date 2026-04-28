// Typed API error taxonomy for the dashboard.
//
// Closes the "typed error taxonomy" half of #1956. Before this module the
// fetch helpers in `api.ts` threw raw `Error(string)` instances, so every
// call site that wanted to branch on auth vs validation vs server failure
// had to substring-match the message — fragile, and meaningless once a
// backend message changed.
//
// Now every helper throws an `ApiError` subclass. Callers can branch on
// the class (instanceof ApiAuthError) or the `status` field directly,
// and `requestId`/`traceId` flow through so support tickets are
// traceable end to end.
//
// ── Branching pattern ───────────────────────────────────────────────────
//   try {
//     await api.scanList();
//   } catch (err) {
//     if (err instanceof ApiAuthError) router.push("/login");
//     else if (err instanceof ApiRateLimitError) toast(`Try again in ${err.retryAfterSeconds}s`);
//     else if (err instanceof ApiValidationError) showFieldErrors(err.details);
//     else if (err instanceof ApiNetworkError) toast("Network unreachable");
//     else throw err; // genuine bug — bubble to the error boundary
//   }

export interface ApiErrorContext {
  status: number;
  statusText: string;
  url: string;
  method: string;
  body?: unknown | undefined;
  details?: Record<string, unknown> | undefined;
  requestId?: string | undefined;
  traceId?: string | undefined;
}

export class ApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  readonly method: string;
  readonly body?: unknown | undefined;
  readonly details?: Record<string, unknown> | undefined;
  readonly requestId?: string | undefined;
  readonly traceId?: string | undefined;

  constructor(message: string, ctx: ApiErrorContext) {
    super(message);
    this.name = "ApiError";
    this.status = ctx.status;
    this.statusText = ctx.statusText;
    this.url = ctx.url;
    this.method = ctx.method;
    this.body = ctx.body;
    this.details = ctx.details;
    this.requestId = ctx.requestId;
    this.traceId = ctx.traceId;
  }
}

export class ApiValidationError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiValidationError";
  }
}

export class ApiAuthError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiAuthError";
  }
}

export class ApiForbiddenError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiForbiddenError";
  }
}

export class ApiNotFoundError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiNotFoundError";
  }
}

export class ApiConflictError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiConflictError";
  }
}

export class ApiRateLimitError extends ApiError {
  readonly retryAfterSeconds?: number | undefined;

  constructor(message: string, ctx: ApiErrorContext, retryAfterSeconds?: number) {
    super(message, ctx);
    this.name = "ApiRateLimitError";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class ApiServerError extends ApiError {
  constructor(message: string, ctx: ApiErrorContext) {
    super(message, ctx);
    this.name = "ApiServerError";
  }
}

export class ApiNetworkError extends ApiError {
  constructor(message: string, ctx: Omit<ApiErrorContext, "status" | "statusText"> & { cause?: unknown }) {
    super(message, { ...ctx, status: 0, statusText: "network_error" });
    this.name = "ApiNetworkError";
    if (ctx.cause !== undefined) {
      // Preserve the underlying fetch failure (TypeError, AbortError, etc.)
      // so debugging and Sentry-style reporting can keep the original stack.
      (this as { cause?: unknown }).cause = ctx.cause;
    }
  }
}

export function classifyApiResponse(
  res: Response,
  parsedBody: unknown,
  method: string,
): ApiError {
  // Guard against test mocks and partial Response shims that omit headers.
  const requestId = res.headers?.get?.("x-request-id") ?? undefined;
  const traceId = res.headers?.get?.("x-trace-id") ?? undefined;
  const ctx: ApiErrorContext = {
    status: res.status,
    statusText: res.statusText,
    url: res.url,
    method,
    body: parsedBody,
    requestId,
    traceId,
  };

  // Backend convention is `{detail|message|error: string|object, ...}`. Pull
  // the operator-readable message and any structured details up to the top
  // level so callers don't have to re-walk the shape.
  let message = `${res.status} ${res.statusText}`;
  let details: Record<string, unknown> | undefined;
  if (parsedBody && typeof parsedBody === "object") {
    const record = parsedBody as Record<string, unknown>;
    const candidate = record.detail ?? record.message ?? record.error;
    if (typeof candidate === "string" && candidate.trim()) {
      message = candidate;
    } else if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      const nested = candidate as Record<string, unknown>;
      if (typeof nested.message === "string") message = nested.message;
      details = nested;
    }
    if (!details && record.details && typeof record.details === "object") {
      details = record.details as Record<string, unknown>;
    }
  }
  ctx.details = details;

  if (res.status === 400 || res.status === 422) return new ApiValidationError(message, ctx);
  if (res.status === 401) return new ApiAuthError(message, ctx);
  if (res.status === 403) return new ApiForbiddenError(message, ctx);
  if (res.status === 404) return new ApiNotFoundError(message, ctx);
  if (res.status === 409) return new ApiConflictError(message, ctx);
  if (res.status === 429) {
    const headerValue = res.headers?.get?.("retry-after") ?? null;
    const retryAfter = headerValue ? Number(headerValue) : undefined;
    return new ApiRateLimitError(
      message,
      ctx,
      Number.isFinite(retryAfter) ? (retryAfter as number) : undefined,
    );
  }
  if (res.status >= 500) return new ApiServerError(message, ctx);
  return new ApiError(message, ctx);
}
