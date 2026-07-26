import type { GatewayFeedHealth, GatewayFeedHealthState } from "./api-types";

export interface GatewayFeedDisplayState {
  state: GatewayFeedHealthState;
  label: string;
  live: boolean;
}

export function gatewayFeedDisplayState(
  health: GatewayFeedHealth | null | undefined,
  transportConnected = true,
): GatewayFeedDisplayState {
  if (!health) {
    return { state: "unavailable", label: "Unavailable", live: false };
  }
  if (health.live && transportConnected) {
    return { state: "live", label: "Live", live: true };
  }
  if (!transportConnected && health.state === "live") {
    return { state: "unavailable", label: "Disconnected", live: false };
  }
  const labels: Record<Exclude<GatewayFeedHealthState, "live">, string> = {
    sample: "Sample",
    stale: "Stale",
    unavailable: "Unavailable",
  };
  const state = health.state === "live" ? "unavailable" : health.state;
  return { state, label: labels[state], live: false };
}
