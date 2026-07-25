import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  autoLayout: vi.fn(),
  fitView: vi.fn(),
  reset: vi.fn(),
}));

vi.mock("@xyflow/react", () => ({
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  ReactFlow: ({ onInit }: { onInit?: (instance: unknown) => void }) => {
    useLayoutEffect(() => {
      onInit?.({ fitView: mocks.fitView, getNode: vi.fn() });
    }, [onInit]);
    return <div data-testid="react-flow" />;
  },
}));
vi.mock("@/lib/use-graph-layout", () => ({
  useGraphLayout: (_layout: string, nodes: unknown[], edges: unknown[]) => ({ nodes, edges }),
}));
vi.mock("@/lib/api", () => ({
  api: { getScan: vi.fn().mockResolvedValue({ job_id: "scan-1", result: {}, created_at: "2026-07-25T00:00:00Z" }) },
}));
vi.mock("@/lib/mesh-graph", () => ({
  buildMeshGraph: () => ({
    nodes: [{ id: "agent", position: { x: 0, y: 0 }, data: { label: "Agent", nodeType: "agent" } }],
    edges: [],
    stats: {},
  }),
  getConnectedIds: () => null,
}));
vi.mock("@/hooks/use-graph-presentation", () => ({
  useGraphPresentation: ({ nodes }: { nodes: unknown[] }) => ({
    storageKey: "opaque",
    enabled: true,
    nodes,
    editing: false,
    hasSavedState: false,
    viewport: { x: 0, y: 0, zoom: 1 },
    autoLayout: mocks.autoLayout,
    reset: mocks.reset,
    toggleEditing: vi.fn(),
    onNodesChange: vi.fn(),
    onNodeDragStop: vi.fn(),
    onMoveEnd: vi.fn(),
  }),
}));
vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: { tenant_id: "local", subject: null, auth_method: null, recommended_ui_mode: "no_auth" },
    loading: false,
  }),
}));
vi.mock("@/components/graph-chrome", () => ({
  GraphLegend: () => null,
  GraphInteractionToolbar: ({ onAutoLayout, onReset }: { onAutoLayout: () => void; onReset: () => void }) => (
    <div>
      <button onClick={onAutoLayout}>Auto layout</button>
      <button onClick={onReset}>Reset layout</button>
    </div>
  ),
}));
vi.mock("@/components/mesh-stats", () => ({ MeshStats: () => null }));
vi.mock("@/components/graph-entity-drawer", () => ({ GraphEntityDrawer: () => null }));

import { ScanMeshView } from "@/components/scan-mesh";

describe("ScanMesh presentation controls", () => {
  beforeEach(() => {
    mocks.autoLayout.mockClear();
    mocks.fitView.mockClear();
    mocks.reset.mockClear();
  });

  it("refits visible nodes after auto-layout and reset", async () => {
    render(<ScanMeshView id="scan-1" />);
    await waitFor(() => expect(screen.getByTestId("react-flow")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Auto layout" }));
    expect(mocks.autoLayout).toHaveBeenCalledOnce();
    await waitFor(() => expect(mocks.fitView).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole("button", { name: "Reset layout" }));
    expect(mocks.reset).toHaveBeenCalledOnce();
    await waitFor(() => expect(mocks.fitView).toHaveBeenCalledTimes(2));
  });
});
