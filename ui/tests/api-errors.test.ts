// Pin the typed-error contract for #1956. Call sites branch on these
// classes (instanceof) AND on the `status` field; both surfaces must stay
// stable, and the Response → error classification must be deterministic.

import { describe, expect, it } from "vitest";

import {
  ApiAuthError,
  ApiConflictError,
  ApiError,
  ApiForbiddenError,
  ApiNotFoundError,
  ApiNetworkError,
  ApiRateLimitError,
  ApiServerError,
  ApiValidationError,
  classifyApiResponse,
} from "../lib/api-errors";

function _resp(status: number, body: unknown, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 429 ? "Too Many Requests" : "Status",
    headers: {
      "content-type": "application/json",
      "x-request-id": "req-test",
      "x-trace-id": "trace-test",
      ...extraHeaders,
    },
  });
}

describe("classifyApiResponse", () => {
  it("400/422 → ApiValidationError with details preserved", () => {
    const err = classifyApiResponse(_resp(422, { detail: "bad", details: { field: "name" } }), { detail: "bad", details: { field: "name" } }, "POST");
    expect(err).toBeInstanceOf(ApiValidationError);
    expect(err.status).toBe(422);
    expect(err.message).toBe("bad");
    expect(err.details).toEqual({ field: "name" });
    expect(err.requestId).toBe("req-test");
    expect(err.traceId).toBe("trace-test");
    expect(err.method).toBe("POST");
  });

  it("401 → ApiAuthError, 403 → ApiForbiddenError", () => {
    expect(classifyApiResponse(_resp(401, {}), {}, "GET")).toBeInstanceOf(ApiAuthError);
    expect(classifyApiResponse(_resp(403, {}), {}, "GET")).toBeInstanceOf(ApiForbiddenError);
  });

  it("404 → ApiNotFoundError, 409 → ApiConflictError", () => {
    expect(classifyApiResponse(_resp(404, { detail: "missing" }), { detail: "missing" }, "GET")).toBeInstanceOf(ApiNotFoundError);
    expect(classifyApiResponse(_resp(409, { detail: "conflict" }), { detail: "conflict" }, "POST")).toBeInstanceOf(ApiConflictError);
  });

  it("429 → ApiRateLimitError with retry-after seconds parsed", () => {
    const err = classifyApiResponse(_resp(429, { detail: "rate" }, { "retry-after": "12" }), { detail: "rate" }, "POST") as ApiRateLimitError;
    expect(err).toBeInstanceOf(ApiRateLimitError);
    expect(err.retryAfterSeconds).toBe(12);
  });

  it("429 with no retry-after header → retryAfterSeconds undefined", () => {
    const err = classifyApiResponse(_resp(429, {}), {}, "POST") as ApiRateLimitError;
    expect(err).toBeInstanceOf(ApiRateLimitError);
    expect(err.retryAfterSeconds).toBeUndefined();
  });

  it("5xx → ApiServerError", () => {
    expect(classifyApiResponse(_resp(500, {}), {}, "GET")).toBeInstanceOf(ApiServerError);
    expect(classifyApiResponse(_resp(503, {}), {}, "GET")).toBeInstanceOf(ApiServerError);
  });

  it("falls back to ApiError for codes outside the named set", () => {
    const err = classifyApiResponse(_resp(418, { detail: "teapot" }), { detail: "teapot" }, "GET");
    expect(err).toBeInstanceOf(ApiError);
    expect(err).not.toBeInstanceOf(ApiValidationError);
    expect(err).not.toBeInstanceOf(ApiServerError);
  });

  it("falls back to '<status> <statusText>' when body has no detail/message/error", () => {
    const err = classifyApiResponse(_resp(500, {}), {}, "GET");
    expect(err.message).toMatch(/^500 /);
  });

  it("ApiNetworkError carries cause and synthesises status=0", () => {
    const cause = new TypeError("fetch failed");
    const err = new ApiNetworkError("offline", { url: "/v1/scan", method: "GET", cause });
    expect(err.status).toBe(0);
    expect(err.statusText).toBe("network_error");
    expect((err as { cause?: unknown }).cause).toBe(cause);
  });
});
