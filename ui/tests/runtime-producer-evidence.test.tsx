import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GatewayFeedPanel } from "@/app/gateway/GatewayFeedPanel";
import { GatewayFeedKpiBar } from "@/components/gateway-feed-kpi-bar";
import { producerEvidenceLabel } from "@/lib/gateway-feed";
import ProxyDashboard from "@/app/proxy/ProxyDashboard";

const presentation = vi.hoisted(() => ({ embedded: false }));
const stream = vi.hoisted(() => ({ rows: [] as unknown[] }));
vi.mock("@/lib/gateway-activity", async () => ({ ...await vi.importActual("@/lib/gateway-activity"), streamGatewayActivity: async function* (_cursor: unknown, signal: AbortSignal) {
  yield { schema_version: "gateway.activity.stream.v1", tenant_id: "t", events: stream.rows, next_cursor: "one", latest_ordinal: 1, has_more: false, retention_floor_ordinal: 1 };
  await new Promise<void>(resolve => signal.addEventListener("abort", () => resolve(), { once: true }));
} }));
const apiMock = vi.hoisted(() => ({ getGatewayFeed: vi.fn(), getGatewayFeedKpis: vi.fn(), getProxyStatus: vi.fn(), getProxyAlerts: vi.fn() }));
vi.mock("@/lib/api", async () => ({ ...await vi.importActual("@/lib/api"), api: apiMock }));
vi.mock("@/lib/auth", () => ({ getSessionWebSocketToken: () => "" }));
vi.mock("@/lib/runtime-config", () => ({ getConfiguredApiUrl: () => "http://localhost:8080" }));
vi.mock("@/hooks/use-deployment-context", () => ({ useDeploymentContext: () => ({ counts: { has_proxy: true } }) }));
vi.mock("@/components/runtime-embed-context", () => ({ useRuntimeEmbedded: () => presentation.embedded }));
class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  constructor() { Socket.instances.push(this); }
  send() {}
  close() {}
}
const health = { state: "live", live: true, heartbeat_at: "2026-09-07T03:00:00Z", age_seconds: 0, stale_after_seconds: 120, reason: "recent_transport_heartbeat", assurance_basis: "transport_receipt", producer_assurance: "caller_asserted" };
const event = { event_id: "receipt", ts: "2026-09-07T03:00:00Z", agent: "assistant", action_type: "tool_call_blocked", target: "read_file", detail: "policy denied", tenant: "t", shadow: false, source: "gateway_activity_ledger", producer_assurance: "caller_asserted" };
const kpis = { calls_today: 8, blocked_today: 2, shadow_ai_blocked: 0, data_filters_applied: 1, uptime_seconds: 120, producer_assurance: "caller_asserted", producer_assurance_counts: { unknown: 0, caller_asserted: 8 }, completeness: { status: "partial", reasons: ["retention_floor_advanced"] }, window: { start: "2026-09-07T00:00:00Z", end: "2026-09-07T03:00:00Z", timezone: "UTC", exact: false } };
beforeEach(() => {
  presentation.embedded = false;
  stream.rows = [{ tenant_id: "t", event_id: "receipt", ingest_ordinal: 1, event_type: "gateway.tool_call.blocked", decision: "deny", agent_id: "assistant", upstream: "filesystem", tool: "read_file", profile_id: "profile-a", profile_revision: 1, blueprint_id: "finance", blueprint_revision: 1, policy_ids: [], ingested_at: new Date().toISOString(), submission_provenance: { producer_assurance: "caller_asserted" } }];
  Socket.instances = []; vi.stubGlobal("WebSocket", Socket);
  Object.values(apiMock).forEach(fn => fn.mockReset());
  apiMock.getGatewayFeed.mockResolvedValue({ events: [event], health, completeness: { status: "complete" }, source: "gateway_activity_ledger" });
  apiMock.getGatewayFeedKpis.mockResolvedValue(kpis);
  apiMock.getProxyStatus.mockResolvedValue({ status: "active", total_tool_calls: 8, producer_assurance: "caller_asserted" });
  apiMock.getProxyAlerts.mockResolvedValue({ alerts: [], count: 0 });
});
afterEach(() => vi.unstubAllGlobals());
async function connect() { await waitFor(() => expect(Socket.instances.length).toBeGreaterThan(0)); act(() => Socket.instances.forEach(socket => socket.onopen?.())); }

describe("runtime receipt assurance", () => {
  it("never promotes an unsupported assurance string to verified identity", () => {
    for (const assurance of [undefined, null, "verified", "authenticated", {}]) {
      expect(producerEvidenceLabel(assurance)).toBe("Producer unknown");
    }
    expect(producerEvidenceLabel("caller_asserted")).toBe("Reported producer");
  });
  it("separates fresh live transport from reported producer evidence", async () => {
    render(<GatewayFeedPanel />); await screen.findByText(/filesystem \/ read_file/);
    expect(screen.getByText("Connected to durable activity")).toBeInTheDocument();
    expect(screen.getAllByText("Reported producer").length).toBeGreaterThan(0);
    expect(screen.queryByText(/^Live$|Verified/i)).not.toBeInTheDocument();
  });
  it("keeps legacy producer identity unknown despite durable storage and fresh transport", async () => {
    stream.rows = [( { ...stream.rows[0] as object, submission_provenance: undefined } )];
    render(<GatewayFeedPanel />); await screen.findByText(/filesystem \/ read_file/);
    expect(screen.getAllByText("Producer unknown").length).toBeGreaterThan(0);
    expect(screen.queryByText("Reported producer")).not.toBeInTheDocument();
  });
  it("retains stale receipt state independently of producer assurance", async () => {
    stream.rows = [{ ...stream.rows[0] as object, ingested_at: "2020-01-01T00:00:00Z" }];
    render(<GatewayFeedPanel />); await screen.findByText(/filesystem \/ read_file/);
    expect(screen.getByText(/Latest receipt is older than 2 minutes/)).toBeInTheDocument();
    expect(screen.queryByText("Live transport")).not.toBeInTheDocument();
    expect(screen.getAllByText("Reported producer").length).toBeGreaterThan(0);
  });
  it("keeps KPI counts while exposing reported evidence and partial UTC window", async () => {
    render(<GatewayFeedKpiBar />); await screen.findByText("8");
    expect(screen.getByText("Reported producer")).toBeInTheDocument();
    expect(screen.getByText(/Partial retained window/)).toHaveTextContent("UTC");
    expect(screen.getByText("Reported uptime")).toBeInTheDocument();
  });
  it("marks unavailable KPI metadata separately from zero", async () => {
    apiMock.getGatewayFeedKpis.mockRejectedValue(new Error("offline")); render(<GatewayFeedKpiBar />);
    expect(await screen.findByText("Activity summary unavailable")).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
  it("preserves a last KPI snapshot on refresh failure without relabeling it current", async () => {
    const { rerender } = render(<GatewayFeedKpiBar />); await screen.findByText("8");
    apiMock.getGatewayFeedKpis.mockRejectedValue(new Error("offline")); rerender(<GatewayFeedKpiBar refreshKey={1} />);
    expect(await screen.findByText("Activity refresh unavailable; showing last summary")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
  });
  it("keeps legacy KPI scope unknown rather than complete", async () => {
    apiMock.getGatewayFeedKpis.mockResolvedValue({ calls_today: 0 }); render(<GatewayFeedKpiBar />);
    expect(await screen.findByText("Producer unknown")).toBeInTheDocument();
    expect(screen.getByText("Window scope unavailable")).toBeInTheDocument();
    expect(screen.queryByText(/Complete retained window/)).not.toBeInTheDocument();
  });
  it("qualifies the embedded runtime proxy with receipt freshness and separate assurance", async () => {
    presentation.embedded = true;
    apiMock.getProxyStatus.mockResolvedValue({ status: "active", total_tool_calls: 8, health, producer_assurance: "caller_asserted" });
    render(<ProxyDashboard />); await screen.findByText("8"); await connect();
    expect(screen.getByText("Live transport")).toBeInTheDocument();
    expect(screen.getByText("Reported producer")).toBeInTheDocument();
    act(() => Socket.instances[0]?.onmessage?.({ data: JSON.stringify({ total_tool_calls: 9 }) }));
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Producer unknown")).toBeInTheDocument();
    expect(screen.queryByText("Live transport")).not.toBeInTheDocument();
  });
  it("does not infer live producer status from an open proxy WebSocket", async () => {
    render(<ProxyDashboard />); await screen.findByText("8"); await connect();
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Reported producer")).toBeInTheDocument();
    expect(screen.queryByText(/^Live$|Live transport/)).not.toBeInTheDocument();
  });
});
