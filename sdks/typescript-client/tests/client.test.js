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

test("posts bulk findings with lifecycle fields and idempotency header", async () => {
  let payload;
  let headers;
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    tenantId: "tenant-d",
    fetch: async (_url, init) => {
      payload = JSON.parse(init.body);
      headers = init.headers;
      return jsonResponse({
        schema_version: "v1",
        batch_id: "batch-1",
        ingested: 1,
        tenant_total: 1,
        tenant_id: "tenant-d",
        source: "agent-runtime",
        observed_at: "2026-07-08T12:00:00Z",
        reconciled: 2,
      });
    },
  });

  const response = await client.ingestFindings({
    source: "agent-runtime",
    findings: [{ id: "finding-1", severity: "high" }],
    observedAt: "2026-07-08T12:00:00Z",
    reconcileAbsent: true,
    idempotencyKey: "scan-batch-42",
  });

  assert.equal(response.reconciled, 2);
  assert.equal(headers["Idempotency-Key"], "scan-batch-42");
  assert.deepEqual(payload, {
    findings: [{ id: "finding-1", severity: "high" }],
    source: "agent-runtime",
    tenant_id: "tenant-d",
    observed_at: "2026-07-08T12:00:00Z",
    reconcile_absent: true,
  });
});

test("registers dataset versions", async () => {
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
        dataset: {
          tenant_id: "tenant-d",
          dataset_id: "hf-corpus",
          version_id: "v1",
          created_at: "2026-05-17T00:00:00Z",
          source: "ci",
        },
      });
    },
  });

  const response = await client.registerDatasetVersion({
    datasetId: "hf-corpus",
    versionId: "v1",
    source: "ci",
  });

  assert.equal(seenUrl, "https://agent-bom.example.com/v1/datasets/hf-corpus/versions");
  assert.equal(response.dataset.version_id, "v1");
  assert.deepEqual(payload, {
    version_id: "v1",
    source: "ci",
    tenant_id: "tenant-d",
  });
});

test("lists dataset versions", async () => {
  let seenUrl = "";
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async (url) => {
      seenUrl = String(url);
      return jsonResponse({
        schema_version: "v1",
        tenant_id: "tenant-d",
        dataset_id: "hf-corpus",
        versions: [],
        count: 0,
      });
    },
  });

  const response = await client.datasetVersions("hf-corpus");

  assert.equal(seenUrl, "https://agent-bom.example.com/v1/datasets/hf-corpus/versions");
  assert.equal(response.count, 0);
});

test("lists findings with default query params", async () => {
  let seenUrl = "";
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async (url) => {
      seenUrl = String(url);
      return jsonResponse({ findings: [], count: 0 });
    },
  });

  const response = await client.listFindings({ severity: "high" });

  assert.equal(
    seenUrl,
    "https://agent-bom.example.com/v1/findings?sort=effective_reach&limit=500&offset=0&severity=high",
  );
  assert.equal(response.count, 0);
});

test("gets a single dataset version", async () => {
  let seenUrl = "";
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async (url) => {
      seenUrl = String(url);
      return jsonResponse({
        schema_version: "v1",
        dataset: {
          tenant_id: "tenant-d",
          dataset_id: "hf/corpus",
          version_id: "2026/05/25",
          created_at: "2026-05-25T00:00:00Z",
          source: "ci",
        },
      });
    },
  });

  const response = await client.datasetVersion("hf/corpus", "2026/05/25");

  assert.equal(
    seenUrl,
    "https://agent-bom.example.com/v1/datasets/hf%2Fcorpus/versions/2026%2F05%2F25",
  );
  assert.equal(response.dataset.version_id, "2026/05/25");
});

test("registers and reads evaluation runs", async () => {
  const seen = [];
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    tenantId: "tenant-f",
    fetch: async (url, init = {}) => {
      seen.push({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined });
      return jsonResponse({
        schema_version: "evals.runs.v1",
        evaluation: {
          tenant_id: "tenant-f",
          evaluation_id: "eval-a",
          created_at: "2026-05-25T00:00:00Z",
          updated_at: "2026-05-25T00:00:00Z",
          status: "completed",
          source: "ci",
        },
        evaluations: [],
        count: 0,
        limit: 10,
        offset: 0,
      });
    },
  });

  await client.registerEvaluationRun({
    evaluationId: "eval-a",
    datasetId: "dataset-a",
    datasetVersionId: "v1",
    scores: { safety: 1 },
    source: "ci",
  });
  await client.evaluationRuns({ datasetId: "dataset-a", limit: 10 });
  await client.evaluationRun("eval-a");

  assert.deepEqual(seen, [
    {
      url: "https://agent-bom.example.com/v1/evaluations",
      body: {
        evaluation_id: "eval-a",
        dataset_id: "dataset-a",
        dataset_version_id: "v1",
        source: "ci",
        scores: { safety: 1 },
        tenant_id: "tenant-f",
      },
    },
    {
      url: "https://agent-bom.example.com/v1/evaluations?dataset_id=dataset-a&limit=10",
      body: undefined,
    },
    {
      url: "https://agent-bom.example.com/v1/evaluations/eval-a",
      body: undefined,
    },
  ]);
});

test("reads manifest and runtime index with tenant query", async () => {
  const seenUrls = [];
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    tenantId: "tenant-e",
    fetch: async (url) => {
      seenUrls.push(String(url));
      return jsonResponse({ schema_version: "v1" });
    },
  });

  await client.agentManifest();
  await client.runtimeProductionIndex();

  assert.deepEqual(seenUrls, [
    "https://agent-bom.example.com/v1/agent-bom/manifest?tenant_id=tenant-e",
    "https://agent-bom.example.com/v1/runtime/production-index?tenant_id=tenant-e",
  ]);
});

test("ingests events and reads runtime sessions and observations", async () => {
  const seen = [];
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    tenantId: "tenant-r",
    fetch: async (url, init = {}) => {
      seen.push({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined });
      return jsonResponse({ schema_version: "runtime.v1" });
    },
  });

  await client.ingestRuntimeEvents({ events: [{ kind: "tool_call" }] });
  await client.runtimeSessions({ limit: 10, offset: 0 });
  await client.runtimeObservations({ sessionId: "sess-1", limit: 5 });
  await client.runtimeSessionObservations("sess/1", { limit: 5 });

  assert.deepEqual(seen, [
    {
      url: "https://agent-bom.example.com/v1/runtime/events",
      body: { events: [{ kind: "tool_call" }], tenant_id: "tenant-r" },
    },
    {
      url: "https://agent-bom.example.com/v1/runtime/sessions?tenant_id=tenant-r&limit=10&offset=0",
      body: undefined,
    },
    {
      url: "https://agent-bom.example.com/v1/runtime/observations?tenant_id=tenant-r&session_id=sess-1&limit=5",
      body: undefined,
    },
    {
      url: "https://agent-bom.example.com/v1/runtime/sessions/sess%2F1/observations?tenant_id=tenant-r&limit=5",
      body: undefined,
    },
  ]);
});

test("wraps intel lookup match and sources", async () => {
  const seen = [];
  const client = new AgentBomClient({
    baseUrl: "https://agent-bom.example.com",
    fetch: async (url, init = {}) => {
      seen.push({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined });
      return jsonResponse({ schema_version: "intel.lookup.v1", matches: [] });
    },
  });

  await client.intelLookup("CVE-2026-0001");
  await client.intelMatch({ ecosystem: "npm", name: "demo", version: "1.0.0", limit: 3 });
  await client.intelSources();

  assert.deepEqual(seen, [
    {
      url: "https://agent-bom.example.com/v1/intel/advisories/CVE-2026-0001",
      body: undefined,
    },
    {
      url: "https://agent-bom.example.com/v1/intel/match",
      body: { ecosystem: "npm", name: "demo", version: "1.0.0", limit: 3 },
    },
    {
      url: "https://agent-bom.example.com/v1/intel/sources",
      body: undefined,
    },
  ]);
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
