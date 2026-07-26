import { describe, expect, it } from "vitest";

import { gatewayFeedDisplayState } from "@/lib/gateway-feed-health";
import type { GatewayFeedHealth } from "@/lib/api-types";

function health(
  state: GatewayFeedHealth["state"],
  live = state === "live",
): GatewayFeedHealth {
  return {
    state,
    live,
    heartbeat_at: null,
    age_seconds: null,
    stale_after_seconds: 120,
    reason: "synthetic-test",
  };
}

describe("gatewayFeedDisplayState", () => {
  it("shows live only for fresh health over a connected transport", () => {
    expect(gatewayFeedDisplayState(health("live"), true)).toEqual({
      state: "live",
      label: "Live",
      live: true,
    });
    expect(gatewayFeedDisplayState(health("live"), false)).toEqual({
      state: "unavailable",
      label: "Disconnected",
      live: false,
    });
  });

  it.each(["stale", "unavailable", "sample"] as const)(
    "never promotes %s health to live",
    (state) => {
      expect(gatewayFeedDisplayState(health(state), true).live).toBe(false);
    },
  );
});
