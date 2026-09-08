import assert from "node:assert/strict";
import test from "node:test";
import { AgentBomClient } from "../dist/index.js";

const wire = (id = "cursor-1") => `event: activity\r\nid: ${id}\r\ndata: ${JSON.stringify({ schema_version: "gateway.activity.stream.v1", next_cursor: id, events: [{ event_id: "caf\u00e9" }] })}\r\n\r\n`;

test("managed profiles forward credentials, tenant, revision and simulation context", async () => {
  const requests = [];
  const client = new AgentBomClient({ baseUrl: "https://api.example", bearerToken: "secret", tenantId: "a", fetch: async (url, init) => {
    requests.push({ url, init });
    return new Response("{}", { headers: { "content-type": "application/json" } });
  }});
  await client.runtimeProfiles();
  await client.createRuntimeProfile({ identity_id: "id", environment: "prod" });
  await client.getRuntimeProfile("a/b");
  await client.updateRuntimeProfile("id", { expected_revision: 3 });
  await client.revokeRuntimeProfile("id");
  await client.validateRuntimeProfile("id", { issuer: "agent-bom", environment: "prod" });
  await client.testRuntimeProfile("id", { issuer: "agent-bom", environment: "prod", upstream: "fs", tool: "read" });
  assert.throws(() => client.createRuntimeProfile({}), /require/);
  assert.equal(requests.length, 7);
  assert.ok(requests[2].url.endsWith("a%2Fb"));
  assert.equal(JSON.parse(requests[3].init.body).expected_revision, 3);
  assert.equal(JSON.parse(requests[6].init.body).tool, "read");
  assert.ok(requests.every(({ init }) => init.headers.authorization === "Bearer secret" && init.headers["x-agent-bom-tenant-id"] === "a"));
});

test("fragmented UTF-8 frames resume with cursor and cancel after terminal gap", async () => {
  let cancelled = false;
  const bytes = new TextEncoder().encode(wire() + 'event: gap\ndata: {"reason":"cursor_expired"}\n\n');
  let offset = 0;
  const client = new AgentBomClient({ baseUrl: "https://api.example", fetch: async (_url, init) => {
    assert.equal(init.headers["Last-Event-ID"], "old");
    return new Response(new ReadableStream({
      pull(controller) { if (offset < bytes.length) controller.enqueue(bytes.slice(offset, ++offset)); },
      cancel() { cancelled = true; },
    }), { headers: { "content-type": "text/event-stream" } });
  }});
  const frames = [];
  for await (const frame of client.gatewayActivity({ cursor: "old" })) frames.push(frame);
  assert.deepEqual(frames.map(f => f.event), ["activity", "gap"]);
  assert.equal(frames[0].data.events[0].event_id, "caf\u00e9");
  assert.equal(cancelled, true);
});

test("partial disconnect does not fabricate a checkpoint", async () => {
  const client = new AgentBomClient({ baseUrl: "https://api.example", fetch: async () => new Response(wire() + "event: activity\nid: incomplete", { headers: { "content-type": "text/event-stream" } }) });
  const frames = [];
  for await (const frame of client.gatewayActivity()) frames.push(frame);
  assert.equal(frames.length, 1);
});

test("malformed and expired streams fail without returning raw server errors", async () => {
  const expired = new AgentBomClient({ baseUrl: "https://api.example", fetch: async () => new Response("secret", { status: 410 }) });
  await assert.rejects(async () => { for await (const _ of expired.gatewayActivity()) {} }, err => err.status === 410 && !String(err).includes("secret"));
  const malformed = new AgentBomClient({ baseUrl: "https://api.example", fetch: async () => new Response("event: activity\nid: a\ndata: {}\n\n", { headers: { "content-type": "text/event-stream" } }) });
  await assert.rejects(async () => { for await (const _ of malformed.gatewayActivity()) {} }, /Invalid activity stream checkpoint/);
});
