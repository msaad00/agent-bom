import { describe, expect, it } from "vitest";

import { graphFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";

describe("graph viewport framing", () => {
  it("zooms small operator-scoped graphs instead of leaving empty canvas", () => {
    const small = graphFitViewOptions({ nodeCount: 6, edgeCount: 5, mode: "lineage" });
    const dense = graphFitViewOptions({ nodeCount: 120, edgeCount: 520, mode: "lineage" });

    expect(small.maxZoom).toBeGreaterThan(1.6);
    expect(small.padding).toBeLessThan(0.1);
    expect(dense.maxZoom).toBeLessThan(1);
    expect(dense.padding).toBeGreaterThan(0.18);
  });

  it("keeps selected-node investigations tighter than the same unfocused graph", () => {
    const unfocused = graphFitViewOptions({ nodeCount: 12, edgeCount: 14, mode: "context" });
    const selected = graphFitViewOptions({
      nodeCount: 12,
      edgeCount: 14,
      selectedNode: true,
      mode: "context",
    });

    expect(selected.maxZoom).toBeGreaterThan(unfocused.maxZoom);
  });

  it("hides the minimap for readable focused captures and keeps it for dense topology", () => {
    expect(shouldShowGraphMiniMap({ nodeCount: 10, edgeCount: 12 })).toBe(false);
    expect(shouldShowGraphMiniMap({ nodeCount: 24, edgeCount: 40, selectedNode: true })).toBe(false);
    expect(shouldShowGraphMiniMap({ nodeCount: 90, edgeCount: 160 })).toBe(true);
  });
});
