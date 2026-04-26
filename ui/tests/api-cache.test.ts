// Pin the cache + dedup contract for #1956. Each behaviour the dashboard
// relies on lives here so a future refactor can't quietly drop one.

import { afterEach, describe, expect, it } from "vitest";

import { _cacheSizeForTests, cachedGet, clearCache, invalidate } from "../lib/api-cache";

afterEach(() => {
  clearCache();
});

describe("cachedGet", () => {
  it("returns the cached value within ttl without re-invoking the fetcher", async () => {
    let calls = 0;
    const fetcher = async () => {
      calls++;
      return { value: calls };
    };
    const a = await cachedGet("k", fetcher, { ttlMs: 10_000 });
    const b = await cachedGet("k", fetcher, { ttlMs: 10_000 });
    expect(a).toEqual({ value: 1 });
    expect(b).toEqual({ value: 1 });
    expect(calls).toBe(1);
  });

  it("re-fetches once the ttl expires", async () => {
    let calls = 0;
    const fetcher = async () => ++calls;
    await cachedGet("k", fetcher, { ttlMs: 5 });
    await new Promise((r) => setTimeout(r, 25));
    await cachedGet("k", fetcher, { ttlMs: 5 });
    expect(calls).toBe(2);
  });

  it("dedupes concurrent in-flight calls to the same key", async () => {
    let calls = 0;
    const fetcher = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 20));
      return calls;
    };
    const [a, b, c] = await Promise.all([
      cachedGet("k", fetcher),
      cachedGet("k", fetcher),
      cachedGet("k", fetcher),
    ]);
    expect(a).toBe(1);
    expect(b).toBe(1);
    expect(c).toBe(1);
    expect(calls).toBe(1);
  });

  it("noStore skips cache lookup but still populates", async () => {
    let calls = 0;
    const fetcher = async () => ++calls;
    await cachedGet("k", fetcher, { ttlMs: 10_000 });
    await cachedGet("k", fetcher, { ttlMs: 10_000, noStore: true });
    await cachedGet("k", fetcher, { ttlMs: 10_000 });
    // 1st call populates, 2nd ignores cache and re-fetches, 3rd reads what
    // the 2nd just wrote → 2 fetcher invocations total.
    expect(calls).toBe(2);
  });

  it("ttlMs=0 disables the cache layer (only inflight dedup remains)", async () => {
    let calls = 0;
    const fetcher = async () => ++calls;
    await cachedGet("k", fetcher, { ttlMs: 0 });
    await cachedGet("k", fetcher, { ttlMs: 0 });
    expect(calls).toBe(2);
    expect(_cacheSizeForTests().entries).toBe(0);
  });

  it("rejects in-flight callers with the same error when the fetcher throws", async () => {
    let attempts = 0;
    const fetcher = async () => {
      attempts++;
      await new Promise((r) => setTimeout(r, 5));
      throw new Error("upstream down");
    };
    const a = cachedGet("k", fetcher);
    const b = cachedGet("k", fetcher);
    await expect(a).rejects.toThrow("upstream down");
    await expect(b).rejects.toThrow("upstream down");
    expect(attempts).toBe(1);
  });
});

describe("invalidate", () => {
  it("drops every entry whose key starts with the prefix", async () => {
    await cachedGet("GET /v1/scan", async () => "list", { ttlMs: 10_000 });
    await cachedGet("GET /v1/scan/abc", async () => "single", { ttlMs: 10_000 });
    await cachedGet("GET /v1/agents", async () => "agents", { ttlMs: 10_000 });
    expect(invalidate("GET /v1/scan")).toBe(2);
    expect(_cacheSizeForTests().entries).toBe(1);
  });

  it("returns 0 when no entries match", () => {
    expect(invalidate("GET /v1/nothing-here")).toBe(0);
  });
});
