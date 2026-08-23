import type { GatewayFeedEvent } from "./api-types";

export function gatewayEventKey(event: GatewayFeedEvent): string {
  return event.event_id?.trim() || [event.ts, event.agent, event.action_type, event.target, event.trace_id ?? ""].join("|");
}

/** Merge server-ordered activity pages without duplicating websocket refreshes. */
export function mergeGatewayEvents(
  current: GatewayFeedEvent[],
  incoming: GatewayFeedEvent[],
  maxEvents = 1_000,
): GatewayFeedEvent[] {
  const deduped = new Map<string, GatewayFeedEvent>();
  for (const event of [...current, ...incoming]) deduped.set(gatewayEventKey(event), event);
  return [...deduped.values()]
    .sort((a, b) => {
      const ordinalDelta = (b.ingest_ordinal ?? 0) - (a.ingest_ordinal ?? 0);
      return ordinalDelta || Date.parse(b.ts) - Date.parse(a.ts);
    })
    .slice(0, maxEvents);
}
