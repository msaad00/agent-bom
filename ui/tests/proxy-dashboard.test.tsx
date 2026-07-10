import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import ProxyDashboard from "@/app/proxy/ProxyDashboard";
import { proxyAlertSummary } from "@/lib/proxy-alerts";

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: { has_proxy: true } }),
}));

vi.mock("@/components/runtime-embed-context", () => ({
  useRuntimeEmbedded: () => true,
}));

vi.mock("@/lib/runtime-config", () => ({
  getConfiguredApiUrl: () => "http://localhost:8080",
}));

vi.mock("@/lib/auth", () => ({
  getSessionWebSocketToken: () => "",
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      getProxyStatus: vi.fn().mockResolvedValue({
        status: "active",
        total_tool_calls: 42,
        total_blocked: 3,
        uptime_seconds: 120,
        calls_by_tool: { "github-server.push_files": 4 },
        blocked_by_reason: { replay_blocked: 1 },
        detectors_active: ["replay", "shadow_mcp"],
      }),
      getProxyAlerts: vi.fn().mockResolvedValue({
        alerts: [
          {
            ts: "2026-07-06T15:10:00+00:00",
            severity: "high",
            detector: "replay",
            tool_name: "github-server.push_files",
            message: "",
            agent_name: "shadow-agent (unregistered)",
            event_type: "tool_call_blocked",
            decision: "deny",
            reason_code: "replay_blocked",
            event_id: "demo:20:github-server.push_files",
            session_id: "demo-estate",
            source_id: "demo-estate-gateway",
          },
        ],
        count: 1,
        filters: { severity: null, detector: null, limit: 200 },
      }),
    },
  };
});

describe("proxyAlertSummary", () => {
  it("derives a readable summary from reason_code and decision when message is empty", () => {
    expect(
      proxyAlertSummary({
        ts: "2026-07-06T15:10:00+00:00",
        severity: "high",
        detector: "replay",
        tool_name: "github-server.push_files",
        message: "",
        reason_code: "replay_blocked",
        decision: "deny",
        event_type: "tool_call_blocked",
        agent_name: "shadow-agent (unregistered)",
      }),
    ).toContain("replay blocked");
  });
});

describe("ProxyDashboard alerts", () => {
  it("opens a detail drawer when an alert row is clicked", async () => {
    render(<ProxyDashboard />);

    const row = await screen.findByRole("button", { name: /github-server\.push_files/i });
    fireEvent.click(row);

    expect(
      await screen.findByRole("dialog", { name: /proxy alert details/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("replay blocked")).toBeInTheDocument();
    expect(screen.getByText("shadow-agent (unregistered)")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Close proxy alert drawer" }));
    expect(screen.queryByRole("dialog", { name: /proxy alert details/i })).not.toBeInTheDocument();
  });
});
