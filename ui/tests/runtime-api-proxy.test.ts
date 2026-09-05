import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { proxyApiRequest, runtimeApiOrigin } from "@/server/runtime-api-proxy";

afterEach(() => vi.unstubAllEnvs());

describe("runtime API routing", () => {
  it("uses the runtime server destination without changing browser origin", () => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend-a:8422");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://legacy:8422");
    const req = new NextRequest("http://ui:3000/v1/auth/me?scope=one", { headers: { cookie: "session=opaque", authorization: "Bearer opaque" } });
    expect(proxyApiRequest(req).headers.get("x-middleware-rewrite")).toBe("http://backend-a:8422/v1/auth/me?scope=one");
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend-b:8423");
    expect(proxyApiRequest(req).headers.get("x-middleware-rewrite")).toBe("http://backend-b:8423/v1/auth/me?scope=one");
  });
  it("preserves the legacy runtime variable and local default", () => {
    vi.stubEnv("AGENT_BOM_API_URL", "");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "http://legacy:8422/");
    expect(runtimeApiOrigin()).toBe("http://legacy:8422");
    vi.stubEnv("NEXT_PUBLIC_API_URL", "");
    expect(runtimeApiOrigin()).toBe("http://localhost:8422");
  });
  it.each(["file:///etc/passwd", "http://user:secret@host", "http://host/path", "http://host?url=evil", "http://host/#fragment"])("rejects invalid destination %s", (value) => {
    vi.stubEnv("AGENT_BOM_API_URL", value);
    expect(() => runtimeApiOrigin()).toThrow("Invalid server API origin");
    const response = proxyApiRequest(new NextRequest("http://ui:3000/health"));
    expect(response.status).toBe(503);
  });
  it.each(["/v1/auth/me", "/health", "/version", "/ws/live"])("routes %s only to the configured backend", (path) => {
    vi.stubEnv("AGENT_BOM_API_URL", "http://backend:8422");
    const response = proxyApiRequest(new NextRequest(`http://ui:3000${path}?next=https://other.example`));
    expect(response.headers.get("x-middleware-rewrite")).toBe(`http://backend:8422${path}?next=https://other.example`);
  });
  it.each(["/", "/v10/private", "/health-extra", "/_next/static/app.js"])("does not route unrelated %s", (path) => {
    expect(proxyApiRequest(new NextRequest(`http://ui:3000${path}`)).headers.has("x-middleware-rewrite")).toBe(false);
  });
});
