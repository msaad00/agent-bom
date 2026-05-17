import assert from "node:assert/strict";
import test from "node:test";

import { AgentBomApiError, AgentBomClient } from "../dist/index.js";

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    status: 200,
    ...init,
  });
}

test("adds auth and tenant headers", async () => {
  let seen;
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com/",
    apiKey: "test-key",
    tenantId: "tenant-a",
    fetch: async (url, init) => {
      seen = { url, init };
      return jsonResponse({ status: "ok" });
    },
  });

  const response = await client.health();

  assert.equal(response.status, "ok");
  assert.equal(seen.url, "https://agent-bom.example.com/health");
  assert.equal(seen.init.headers["x-api-key"], "test-key");
  assert.equal(seen.init.headers["x-agent-bom-tenant-id"], "tenant-a");
});

test("builds exposure path query params", async () => {
  let seenUrl = "";
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async (url) => {
      seenUrl = String(url);
      return jsonResponse({ paths: [], stats: { count: 0 } });
    },
  });

  await client.exposurePaths({ tenantId: "tenant-b", limit: 5, minRisk: 70 });

  assert.equal(
    seenUrl,
    "https://agent-bom.example.com/v1/graph/exposure-paths?tenant_id=tenant-b&limit=5&min_risk=70",
  );
});

test("posts deploy decision payload without undefined fields", async () => {
  let payload;
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    bearerToken: "token",
    tenantId: "tenant-c",
    fetch: async (_url, init) => {
      payload = JSON.parse(init.body);
      return jsonResponse({ decision: "allow", reasons: [] });
    },
  });

  const decision = await client.shouldIDeploy({ candidate: "flask@2.0.0" });

  assert.equal(decision.decision, "allow");
  assert.deepEqual(payload, {
    candidate: "flask@2.0.0",
    tenant_id: "tenant-c",
  });
});

test("posts normalized bulk findings", async () => {
  let seenUrl = "";
  let payload;
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    tenantId: "tenant-d",
    fetch: async (url, init) => {
      seenUrl = String(url);
      payload = JSON.parse(init.body);
      return jsonResponse({
        schema_version: "v1",
        batch_id: "batch-1",
        ingested: 1,
        tenant_total: 1,
        tenant_id: "tenant-d",
        source: "agent-runtime",
      });
    },
  });

  const response = await client.ingestFindings({
    source: "agent-runtime",
    findings: [{ id: "finding-1", severity: "high" }],
  });

  assert.equal(seenUrl, "https://agent-bom.example.com/v1/findings/bulk");
  assert.equal(response.ingested, 1);
  assert.deepEqual(payload, {
    findings: [{ id: "finding-1", severity: "high" }],
    source: "agent-runtime",
    tenant_id: "tenant-d",
  });
});

test("throws typed errors for non-2xx responses", async () => {
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async () => jsonResponse({ detail: "blocked" }, { status: 403 }),
  });

  await assert.rejects(client.health(), (error) => {
    assert.ok(error instanceof AgentBomApiError);
    assert.equal(error.status, 403);
    assert.match(error.body, /blocked/);
    return true;
  });
});
