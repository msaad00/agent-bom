import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

  it("shows structured token and cost evidence for an LLM gateway event", async () => {
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [
        {
          event_id: "llm-1",
          ts: "2026-07-26T17:00:00Z",
          agent: "review-agent",
          action_type: "llm_call",
          target: "openai/gpt-5",
          decision: "allow",
          policy_source: "observability",
          trace_id: "trace-llm",
          detail: "$4.8200 · 140400 tokens",
          tenant: "synthetic",
          shadow: false,
          source: "observability",
          input_tokens: 100_000,
          output_tokens: 40_400,
          cost_usd: 4.82,
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

    render(<ActivityEventStream observabilityEvents={[]} />);
    await waitFor(() =>
      expect(screen.getByText("review-agent → openai/gpt-5")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByText("review-agent → openai/gpt-5"));

    const drawer = screen.getByRole("dialog", { name: "Activity event details" });
    expect(within(drawer).getByText("140,400 total")).toBeInTheDocument();
    expect(within(drawer).getByText("$4.8200")).toBeInTheDocument();
  });

  it("falls back to a stable row key when normalized events have blank IDs", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    apiMock.getGatewayFeed.mockResolvedValue({
      events: [
        {
          event_id: "",
          ts: "2026-07-26T17:00:00Z",
          agent: "agent-a",
          action_type: "llm_call",
          target: "openai/gpt-5",
          detail: "10 tokens",
          tenant: "synthetic",
          shadow: false,
          source: "observability",
        },
        {
          event_id: "",
          ts: "2026-07-26T16:59:00Z",
          agent: "agent-b",
          action_type: "llm_call",
          target: "anthropic/claude",
          detail: "20 tokens",
          tenant: "synthetic",
          shadow: false,
          source: "observability",
        },
      ],
      health: {
        state: "sample",
        live: false,
        heartbeat_at: null,
        age_seconds: null,
        stale_after_seconds: 120,
        reason: "synthetic_sample",
      },
    });

    render(<ActivityEventStream observabilityEvents={[]} />);
    await waitFor(() => expect(screen.getByText("agent-b → anthropic/claude")).toBeInTheDocument());

    expect(consoleError.mock.calls.flat().join(" ")).not.toMatch(/same key/i);
    consoleError.mockRestore();
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
