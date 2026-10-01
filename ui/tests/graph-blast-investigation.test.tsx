import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { loadBlastInvestigation } from "@/lib/graph-blast-investigation";
import { BlastRadiusPanel } from "@/components/graph-blast-radius-panel";

const identity = { scan_id: "resolved-scan", tenant_id: "tenant-a", snapshot_generation: "a".repeat(32) };
const impact = { ...identity, node_id: "asset", affected_nodes: ["account"], affected_count: 1, affected_by_type: { account: 1 }, max_depth_reached: 1 };
const client = (context = identity) => ({ getGraphImpact: vi.fn().mockResolvedValue(impact), queryGraph: vi.fn().mockResolvedValue(context) });

describe("blast-radius investigation", () => {
  it("pins the resolved snapshot and includes recorded context relationships", async () => {
    const api = client();
    await loadBlastInvestigation(api, "asset", undefined);
    expect(api.queryGraph).toHaveBeenCalledWith(expect.objectContaining({
      roots: ["asset"], scan_id: identity.scan_id, snapshot_generation: identity.snapshot_generation,
      direction: "reverse", traversable_only: false, max_nodes: 4,
    }), undefined);
  });
  it.each(["scan_id", "tenant_id", "snapshot_generation"] as const)("rejects a different %s", async key => {
    await expect(loadBlastInvestigation(client({ ...identity, [key]: "different" }), "asset", undefined)).rejects.toThrow("Restart");
  });
  it("does not query when the backend cannot pin evidence", async () => {
    const api = client();
    api.getGraphImpact.mockResolvedValue({ ...impact, snapshot_generation: null });
    await expect(loadBlastInvestigation(api, "asset", undefined)).rejects.toThrow("cannot pin");
    expect(api.queryGraph).not.toHaveBeenCalled();
  });
  it("preserves stale-revision failure without publishing a partial result", async () => {
    const api = client();
    api.queryGraph.mockRejectedValue(new Error("409: restart"));
    await expect(loadBlastInvestigation(api, "asset", undefined)).rejects.toThrow("409");
  });
  it("labels incomplete counts and separates the small canvas from impact scope", () => {
    render(<BlastRadiusPanel summary={{ rootId: "asset", rootLabel: "Asset", nodeIds: new Set(), countsByType: {}, affectedCount: 50, maxDepthReached: 4, visibleRelatedCount: 3 }} loading={false} error={null} onClear={() => {}} />);
    expect(screen.getByText("At least 50 upstream related nodes connected to Asset")).toBeTruthy();
    expect(screen.getByText(/3 related nodes shown.*Collection coverage is unknown/)).toBeTruthy();
    expect(screen.getByText(/lower bound/)).toBeTruthy();
  });
});
