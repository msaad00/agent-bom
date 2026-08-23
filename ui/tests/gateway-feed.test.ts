import { describe, expect, it } from "vitest";

import type { GatewayFeedEvent } from "@/lib/api-types";
import { mergeGatewayEvents } from "@/lib/gateway-feed";

function event(id: string, ordinal: number): GatewayFeedEvent {
  return {
    event_id: id,
    ingest_ordinal: ordinal,
    ts: `2026-08-23T00:00:${String(ordinal).padStart(2, "0")}Z`,
    agent: "operator",
    action_type: "tool_call_authorized",
    target: "scan",
    detail: "allowed",
    tenant: "default",
    shadow: false,
    source: "gateway",
  };
}

describe("mergeGatewayEvents", () => {
  it("deduplicates websocket refreshes and preserves durable server order", () => {
    expect(mergeGatewayEvents([event("2", 2), event("1", 1)], [event("3", 3), event("2", 2)]).map((row) => row.event_id))
      .toEqual(["3", "2", "1"]);
  });

  it("bounds retained client history", () => {
    expect(mergeGatewayEvents([], [event("3", 3), event("2", 2), event("1", 1)], 2)).toHaveLength(2);
  });
});
