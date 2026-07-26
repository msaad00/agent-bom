import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GatewayLiveFeedCard } from "@/components/gateway-live-feed-card";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getGatewayFeed: vi.fn(),
    getGatewayFeedKpis: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

describe("GatewayLiveFeedCard", () => {
  beforeEach(() => {
    apiMock.getGatewayFeed.mockReset();
    apiMock.getGatewayFeedKpis.mockReset();
    apiMock.getGatewayFeedKpis.mockResolvedValue({
      calls_today: 0,
      blocked_today: 0,
      shadow_ai_blocked: 0,
      data_filters_applied: 0,
      uptime_seconds: null,
      by_action_type: {},
      by_source: {},
    });
  });

  it("keeps an empty unavailable feed empty instead of fabricating activity", async () => {
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [],
      count: 0,
      health: {
        state: "unavailable",
        live: false,
        heartbeat_at: null,
        age_seconds: null,
        stale_after_seconds: 120,
        reason: "transport_or_heartbeat_unavailable",
      },
    });

    render(<GatewayLiveFeedCard />);

    await waitFor(() =>
      expect(screen.getByText("No gateway activity yet.")).toBeInTheDocument(),
    );
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.queryByText("sample data")).not.toBeInTheDocument();
    expect(screen.queryByText("payroll-agent")).not.toBeInTheDocument();
  });

  it("labels server-declared sample data without promoting it to live", async () => {
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [
        {
          ts: "2026-06-26T14:31:07Z",
          agent: "sample-agent",
          action_type: "tool_call_authorized",
          target: "sample-tool.read",
          detail: "sample",
          tenant: "sample",
          shadow: false,
          source: "sample",
        },
      ],
      count: 1,
      health: {
        state: "sample",
        live: false,
        heartbeat_at: null,
        age_seconds: null,
        stale_after_seconds: 120,
        reason: "synthetic_sample",
      },
    });

    render(<GatewayLiveFeedCard />);

    await waitFor(() =>
      expect(screen.getByText("sample-agent → sample-tool.read")).toBeInTheDocument(),
    );
    expect(screen.getByText("sample data")).toBeInTheDocument();
    expect(screen.queryByText("live")).not.toBeInTheDocument();
  });
});
