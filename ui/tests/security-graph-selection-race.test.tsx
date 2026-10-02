import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

const mocks = vi.hoisted(() => ({
  neighbors: vi.fn(),
  detail: vi.fn(),
  impact: vi.fn(),
  nodes: ["A", "B"].map(id => ({
    id,
    position: { x: 0, y: 0 },
    data: { label: id, nodeType: "agent", attributes: { node_id: id } },
  })),
}));
vi.mock("@/lib/api", () => ({ api: {
  getGraphNodeNeighbors: mocks.neighbors,
  getGraphNode: mocks.detail,
  getGraphImpact: mocks.impact,
} }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: null, loading: false }) }));
vi.mock("@/lib/graph-renderer-switch", () => ({ decideGraphRenderer: () => ({ kind: "webgl" }) }));
vi.mock("@/lib/unified-graph-flow", () => ({ buildUnifiedFlowGraph: () => ({ nodes: mocks.nodes, edges: [], legend: [] }) }));
vi.mock("@/lib/use-graph-layout", () => ({ useGraphLayout: () => ({ nodes: mocks.nodes, edges: [], pending: false }) }));
vi.mock("@/components/sigma-graph-overview", () => ({
  SigmaGraphOverview: ({ onNodeSelect }: { onNodeSelect: (id: string) => void }) => (
    <>{["A", "B"].map(id => <button key={id} onClick={() => onNodeSelect(id)}>Select {id}</button>)}</>
  ),
}));
vi.mock("@/components/graph-entity-drawer", () => ({
  GraphEntityDrawer: ({ data, onExpandNeighbors, onShowImpact, onClose }: {
    data: unknown;
    onExpandNeighbors: () => void;
    onShowImpact: () => void;
    onClose: () => void;
  }) => (
    <>
      <output data-testid="drawer">{JSON.stringify(data)}</output>
      <button onClick={onExpandNeighbors}>Expand</button>
      <button onClick={onShowImpact}>Impact</button>
      <button onClick={onClose}>Close</button>
    </>
  ),
}));
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";

const graph = { scan_id: "scan-1", nodes: [], edges: [], attack_paths: [] } as unknown as UnifiedGraphData;
const props = { graph, attackPath: null, focusMode: false, onFocusModeChange: vi.fn(), fullGraphHref: "/graph", scanId: "scan-1" };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
const neighbors = { node_id: "A", scan_id: "scan-1", neighbors: [], edges: [], total_neighbors: 99, truncated: false };
const detail = { node: { id: "A", entity_type: "agent", attributes: { receipt: "A-only" } }, edges_in: [], edges_out: [], sources: [], neighbors: [], impact: { affected_count: 99, affected_by_type: { agent: 99 }, max_depth_reached: 4 } };

describe("investigation response ownership", () => {
  beforeEach(() => vi.clearAllMocks());

  it.each(["Expand", "Impact"])("does not apply late %s evidence to another selection", async action => {
    const pending = deferred<typeof neighbors>();
    const pendingImpact = deferred<{ affected_count: number; affected_by_type: Record<string, number>; max_depth_reached: number }>();
    mocks.neighbors.mockReturnValue(pending.promise);
    mocks.detail.mockResolvedValue(detail);
    mocks.impact.mockReturnValue(pendingImpact.promise);
    render(<SecurityGraphInvestigation {...props} />);
    fireEvent.click(screen.getByText("Select A"));
    fireEvent.click(screen.getByText(action));
    fireEvent.click(screen.getByText("Select B"));
    await act(async () => {
      pending.resolve(neighbors);
      pendingImpact.resolve({ affected_count: 99, affected_by_type: { agent: 99 }, max_depth_reached: 4 });
    });
    const drawer = JSON.parse(screen.getByTestId("drawer").textContent!);
    expect(drawer.attributes.node_id).toBe("B");
    expect(drawer.impactCount).toBeUndefined();
    expect(drawer.neighborCount).toBeUndefined();
  });

  it.each(["snapshot", "generation"])("rejects an old %s response even when the selected ID stays the same", async change => {
    const pending = deferred<typeof neighbors>();
    mocks.neighbors.mockReturnValue(pending.promise);
    const view = render(<SecurityGraphInvestigation {...props} />);
    fireEvent.click(screen.getByText("Select A"));
    fireEvent.click(screen.getByText("Expand"));
    view.rerender(<SecurityGraphInvestigation {...props}
      scanId={change === "snapshot" ? "scan-2" : "scan-1"}
      graph={{ ...graph, ...(change === "snapshot" ? { scan_id: "scan-2" } : { snapshot_generation: "new-generation" }) }}
    />);
    await act(async () => pending.resolve(neighbors));
    expect(JSON.parse(screen.getByTestId("drawer").textContent!).neighborCount).toBeUndefined();
  });

  it("rejects a late response after leaving and reselecting the same node", async () => {
    const pending = deferred<typeof neighbors>();
    mocks.neighbors.mockReturnValue(pending.promise);
    render(<SecurityGraphInvestigation {...props} />);
    fireEvent.click(screen.getByText("Select A"));
    fireEvent.click(screen.getByText("Expand"));
    fireEvent.click(screen.getByText("Close"));
    fireEvent.click(screen.getByText("Select A"));
    await act(async () => pending.resolve(neighbors));
    expect(JSON.parse(screen.getByTestId("drawer").textContent!).neighborCount).toBeUndefined();
  });
  it.each([
    ["focus", "Expand"], ["path", "Expand"],
    ["focus", "Impact"], ["path", "Impact"],
  ])("rejects a pending %s-scope %s response with the same selected node", async (change, action) => {
    const pending = deferred<typeof neighbors>();
    const pendingImpact = deferred<{ affected_count: number; affected_by_type: Record<string, number>; max_depth_reached: number }>();
    mocks.neighbors.mockReturnValue(pending.promise);
    mocks.detail.mockResolvedValue(detail);
    mocks.impact.mockReturnValue(pendingImpact.promise);
    const path: AttackPath = {
      source: "A", target: "B", hops: ["A", "B"], edges: [], composite_risk: 1,
      summary: "Recorded path", credential_exposure: [], tool_exposure: [], vuln_ids: [],
    };
    const view = render(<SecurityGraphInvestigation {...props} attackPath={path} />);
    fireEvent.click(screen.getByText("Select A"));
    fireEvent.click(screen.getByText(action));
    view.rerender(<SecurityGraphInvestigation {...props}
      focusMode={change === "focus"}
      attackPath={change === "path" ? { ...path, target: "C", hops: ["A", "C"] } : path}
    />);
    await act(async () => {
      pending.resolve(neighbors);
      pendingImpact.resolve({ affected_count: 99, affected_by_type: { agent: 99 }, max_depth_reached: 4 });
    });
    const drawer = JSON.parse(screen.getByTestId("drawer").textContent!);
    expect(drawer.attributes.node_id).toBe("A");
    expect(drawer.neighborCount).toBeUndefined();
    expect(drawer.impactCount).toBeUndefined();
  });

});
