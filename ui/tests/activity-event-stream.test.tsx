import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ActivityEventStream } from "@/components/activity-event-stream";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getGatewayFeed: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

describe("ActivityEventStream", () => {
  beforeEach(() => {
    apiMock.getGatewayFeed.mockReset();
  });

  it("merges runtime and observability events and opens truthful details", async () => {
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [
        {
          event_id: "gateway-1",
          ts: "2026-07-26T17:00:00Z",
          agent: "build-agent",
          action_type: "tool_call_blocked",
          target: "filesystem.write_file",
          decision: "deny",
          policy_source: "runtime-policy",
          trace_id: "trace-gateway",
          detail: "blocked by gateway policy",
          tenant: "synthetic",
          shadow: false,
          source: "gateway",
        },
      ],
      health: {
        state: "live",
        live: true,
        heartbeat_at: "2026-07-26T17:00:01Z",
        age_seconds: 1,
        stale_after_seconds: 120,
        reason: "recent_transport_heartbeat",
      },
    });

    render(
      <ActivityEventStream
        observabilityEvents={[
          {
            event_id: "observation-1",
            event_type: "TOOL_CALL",
            agent_name: "review-agent",
            timestamp: "2026-07-26T16:59:00Z",
            duration_ms: 42,
            status: "SUCCESS",
            model_name: "",
            tool_name: "repository.read",
            trace_id: "trace-observation",
            input_tokens: 12,
            output_tokens: 8,
          },
        ]}
      />,
    );

    await waitFor(() =>
      expect(screen.getByText("build-agent → filesystem.write_file")).toBeInTheDocument(),
    );
    expect(screen.getByText("review-agent → repository.read")).toBeInTheDocument();
    expect(screen.getByText("Live gateway")).toBeInTheDocument();

    fireEvent.click(screen.getByText("build-agent → filesystem.write_file"));

    expect(screen.getByRole("dialog", { name: "Activity event details" })).toBeInTheDocument();
    expect(screen.getByText("runtime-policy")).toBeInTheDocument();
    expect(screen.getByText("trace-gateway")).toBeInTheDocument();
    expect(screen.getAllByText("Unavailable").length).toBeGreaterThanOrEqual(3);
  });

  it("never labels stale retained events as live", async () => {
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [
        {
          event_id: "gateway-stale",
          ts: "2026-07-25T17:00:00Z",
          agent: "stale-agent",
          action_type: "tool_call_authorized",
          target: "repository.read",
          detail: "retained event",
          tenant: "synthetic",
          shadow: false,
          source: "gateway",
        },
      ],
      health: {
        state: "stale",
        live: false,
        heartbeat_at: "2026-07-25T17:00:01Z",
        age_seconds: 86400,
        stale_after_seconds: 120,
        reason: "transport_heartbeat_stale",
      },
    });

    render(<ActivityEventStream observabilityEvents={[]} />);

    await waitFor(() => expect(screen.getByText("Stale gateway")).toBeInTheDocument());
    expect(screen.queryByText("Live gateway")).not.toBeInTheDocument();
  });
});
