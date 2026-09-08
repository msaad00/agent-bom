import { afterEach, describe, expect, it, vi } from "vitest";
import { ActivityStreamError, gatewayActivityPage, mergeActivity, streamGatewayActivity, type GatewayActivity } from "@/lib/gateway-activity";

import { activity } from "./fixtures/gateway-activity";

const wire = (cursor: string, events: GatewayActivity[]) => `event: activity\r\nid: ${cursor}\r\ndata: ${JSON.stringify({ schema_version: "gateway.activity.stream.v1", tenant_id: "tenant-a", events, next_cursor: cursor, has_more: false, latest_ordinal: events.length, retention_floor_ordinal: 1 })}\r\n\r\n`;
const response = (body: string) => new Response(body, { headers: { "content-type": "text/event-stream" } });
afterEach(() => vi.unstubAllGlobals());

describe("canonical browser activity transport", () => {
  it("sends cookies, CSRF and the resume cursor without a metrics socket", async () => {
    document.cookie = "agent_bom_csrf=csrf-fixture";
    const fetcher = vi.fn(async () => response(wire("next", [activity(1)])));
    vi.stubGlobal("fetch", fetcher);
    const page = await gatewayActivityPage("old", new AbortController().signal);
    expect(page.events[0]?.event_id).toBe("event-1");
    expect(fetcher).toHaveBeenCalledWith(expect.stringContaining("/v1/gateway/feed/stream"), expect.objectContaining({ credentials: "include", headers: expect.objectContaining({ "Last-Event-ID": "old", "X-Agent-Bom-CSRF": "csrf-fixture" }) }));
  });
  it("decodes fragmented UTF-8, cancels a one-page read, and discards partial frames", async () => {
    const text = wire("next", [{ ...activity(1), agent_id: "café" }]);
    const encoded = new TextEncoder().encode(text);
    let i = 0;
    const cancel = vi.fn();
    vi.stubGlobal("fetch", async () => new Response(new ReadableStream({ pull(controller) { if (i < encoded.length) controller.enqueue(encoded.slice(i, ++i)); }, cancel }), { headers: { "content-type": "text/event-stream" } }));
    expect((await gatewayActivityPage(undefined, new AbortController().signal)).events[0]?.agent_id).toBe("café");
    expect(cancel).toHaveBeenCalled();
    vi.stubGlobal("fetch", async () => response(text + "event: activity\nid: partial\ndata: {"));
    const pages = [];
    for await (const page of streamGatewayActivity(undefined, new AbortController().signal)) pages.push(page);
    expect(pages).toHaveLength(1);
  });
  it.each([[410, "gap"], [400, "gap"], [401, "auth"], [403, "auth"], [503, "unavailable"]])("fails closed on HTTP %s", async (status, kind) => {
    vi.stubGlobal("fetch", async () => new Response("private backend exception", { status: Number(status) }));
    await expect(gatewayActivityPage("old", new AbortController().signal)).rejects.toMatchObject({ kind });
  });
  it("surfaces a midstream gap and rejects cross-tenant or malformed records", async () => {
    vi.stubGlobal("fetch", async () => response(wire("one", [activity(1)]) + 'event: gap\ndata: {"reason":"cursor_expired"}\n\n'));
    const iterator = streamGatewayActivity(undefined, new AbortController().signal);
    expect((await iterator.next()).value?.next_cursor).toBe("one");
    await expect(iterator.next()).rejects.toMatchObject({ kind: "gap" });
    for (const row of [{ ...activity(2), tenant_id: "foreign" }, { ...activity(2), event_type: {} }]) {
      vi.stubGlobal("fetch", async () => response(wire("bad", [row as GatewayActivity])));
      await expect(gatewayActivityPage(undefined, new AbortController().signal)).rejects.toBeInstanceOf(ActivityStreamError);
    }
  });
  it("keeps a bounded recent window while preserving server order and deduplication", () => {
    expect(mergeActivity([activity(1)], Array.from({ length: 1200 }, (_, i) => activity(i + 1)))).toHaveLength(1000);
    expect(mergeActivity([activity(1)], [activity(2), activity(1)]).map(row => row.event_id)).toEqual(["event-2", "event-1"]);
  });
});

it("rejects a complete batch from a different authenticated tenant", async () => {
  vi.stubGlobal("fetch", async () => response(wire("next", [activity(1)])));
  await expect(gatewayActivityPage(undefined, new AbortController().signal, "another-tenant")).rejects.toMatchObject({ kind: "auth" });
});
