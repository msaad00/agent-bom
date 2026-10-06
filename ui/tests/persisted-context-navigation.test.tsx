import { render, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { PersistedContextView } from "@/components/persisted-context-view";

const state = vi.hoisted(() => ({ params: new URLSearchParams(), incident: vi.fn(), jobs: vi.fn(), summary: vi.fn() }));
vi.mock("next/navigation", () => ({ useSearchParams: () => state.params }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: { tenant_id: "fixture" } }) }));
vi.mock("@/components/graph-lens-switcher", () => ({ GraphLensSwitcher: () => null }));
vi.mock("@/lib/api", () => ({ api: {
  listJobs: state.jobs,
  getInventorySummary: state.summary,
  listGraphAgents: vi.fn().mockResolvedValue({ scan_id: "snapshot", agents: [{ id: "agent:first", label: "First" }], pagination: { total: 1 } }),
} }));
vi.mock("@/hooks/use-incident-neighborhood", () => ({ useIncidentNeighborhood: (...args: unknown[]) => {
  state.incident(...args);
  return { nodes: [], edges: [], pages: [], busy: false, capped: false, stale: false, error: null };
} }));
vi.mock("@/lib/use-context-layout", () => ({ useContextLayout: () => ({ nodes: [], edges: [], direction: "LR", mode: "auto", selectMode: vi.fn(), canvasRef: { current: null } }) }));

beforeEach(() => {
  vi.clearAllMocks();
  state.jobs.mockResolvedValue({ jobs: [], total: 0 });
  state.summary.mockResolvedValue({scan_id: "current-estate:fixture"});
});

it.each(["root", "node", "agent"])("honors an exact %s deep link without substituting the first agent", async (parameter) => {
  const root = "server:with spaces/+&?";
  state.params = new URLSearchParams({ scan: "snapshot", [parameter]: root });
  render(<PersistedContextView />);
  await waitFor(() => expect(state.incident).toHaveBeenCalledWith("snapshot", root, "both", expect.any(String)));
  expect(state.incident.mock.calls.some((call) => call[1] === "agent:first")).toBe(false);
});

it("opens an exact snapshot even when the completed-job list is unavailable", async () => {
  state.jobs.mockRejectedValue(new Error("unavailable"));
  state.params = new URLSearchParams({ scan: "snapshot", root: "server:exact" });
  render(<PersistedContextView />);
  await waitFor(() => expect(state.incident).toHaveBeenCalledWith("snapshot", "server:exact", "both", expect.any(String)));
});

it("remounts the neighborhood when only the canonical root changes", async () => {
  state.params = new URLSearchParams({ scan: "snapshot", root: "server:a", agent: "display-name" });
  const view = render(<PersistedContextView />);
  await waitFor(() => expect(state.incident).toHaveBeenCalledWith("snapshot", "server:a", "both", expect.any(String)));
  state.params = new URLSearchParams({ scan: "snapshot", root: "server:b", agent: "display-name" });
  view.rerender(<PersistedContextView />);
  await waitFor(() => expect(state.incident).toHaveBeenLastCalledWith("snapshot", "server:b", "both", expect.any(String)));
});


it("opens the current tenant estate when scan scope is omitted", async () => {
  state.params = new URLSearchParams({root: "server:retained"});
  render(<PersistedContextView />);
  await waitFor(() => expect(state.incident).toHaveBeenCalledWith("current-estate:fixture", "server:retained", "both", expect.any(String)));
});
