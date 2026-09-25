import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, _clearApiCacheForTests } from "@/lib/api";
import { _cacheSizeForTests } from "@/lib/api-cache";

type Principal = "alice" | "bob";

function stubApi(state: { principal: Principal; failSession?: number }) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://localhost").pathname;
    const method = init?.method ?? "GET";
    if (path.startsWith("/v1/auth/")) {
      if (state.failSession) return new Response("{}", { status: state.failSession });
      if (method === "POST") state.principal = "bob";
      return new Response(null, { status: 204 });
    }
    if (method === "DELETE") return new Response(null, { status: 204 });
    return new Response(JSON.stringify({ job_id: path.split("/").pop(), status: state.principal }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  const scanReads = () => fetchMock.mock.calls.filter(([url, init]) => (init?.method ?? "GET") === "GET" && String(url).includes("/v1/scan/")).length;
  return { fetchMock, scanReads };
}

beforeEach(() => _clearApiCacheForTests());
afterEach(() => {
  vi.unstubAllGlobals();
  _clearApiCacheForTests();
});

describe("API response cache invalidation", () => {
  it("serves a repeated read from cache until a write to the same resource", async () => {
    const { scanReads } = stubApi({ principal: "alice" });
    await api.getScan("job-1");
    await api.getScan("job-1");
    expect(scanReads()).toBe(1);

    await api.deleteScan("job-1");
    await api.getScan("job-1");
    expect(scanReads()).toBe(2);
  });

  it("does not flush unrelated resources on a write", async () => {
    const state = { principal: "alice" as Principal };
    const { fetchMock } = stubApi(state);
    await api.getScan("job-1");
    await api.deleteKey("key-1").catch(() => undefined);
    expect(_cacheSizeForTests().entries).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("drops every cached response when a different principal signs in", async () => {
    const state = { principal: "alice" as Principal };
    stubApi(state);
    expect((await api.getScan("job-1")).status).toBe("alice");
    expect(_cacheSizeForTests().entries).toBe(1);

    await api.createAuthSession("bob-key");
    expect(_cacheSizeForTests()).toEqual({ entries: 0, inflight: 0 });
    expect((await api.getScan("job-1")).status).toBe("bob");
  });

  it("drops cached responses on sign-out, even when the session endpoint fails", async () => {
    const state = { principal: "alice" as Principal, failSession: 404 };
    stubApi(state);
    await api.getScan("job-1");
    await expect(api.deleteAuthSession()).rejects.toThrow();
    expect(_cacheSizeForTests()).toEqual({ entries: 0, inflight: 0 });
  });

  it("drops cached responses after a rejected sign-in attempt", async () => {
    const state = { principal: "alice" as Principal, failSession: 401 };
    stubApi(state);
    await api.getScan("job-1");
    await expect(api.createAuthSession("wrong-key")).rejects.toThrow();
    expect(_cacheSizeForTests().entries).toBe(0);
  });

  it("drops cached responses when a development session starts", async () => {
    stubApi({ principal: "alice" });
    await api.getScan("job-1");
    await api.createDevAuthSession();
    expect(_cacheSizeForTests().entries).toBe(0);
  });
});
