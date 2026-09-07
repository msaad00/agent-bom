import { describe, expect, it } from "vitest";

import { graphFitViewOptions, graphInitialFitViewOptions, shouldShowGraphMiniMap } from "@/lib/graph-viewport";

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

  it("frames small context paths as the canvas hero instead of under-zooming", () => {
    const context = graphFitViewOptions({ nodeCount: 6, edgeCount: 5, mode: "context" });
    const lineage = graphFitViewOptions({ nodeCount: 6, edgeCount: 5, mode: "lineage" });
    const capture = graphFitViewOptions({
      nodeCount: 6,
      edgeCount: 5,
      mode: "context",
      captureMode: true,
    });

    expect(context.maxZoom).toBeGreaterThan(lineage.maxZoom);
    expect(context.padding).toBeLessThanOrEqual(0.06);
    expect(capture.maxZoom).toBeGreaterThan(context.maxZoom);
    expect(capture.padding).toBeLessThanOrEqual(context.padding);
  });

  it("hides the minimap for readable focused captures and keeps it for dense topology", () => {
    expect(shouldShowGraphMiniMap({ nodeCount: 10, edgeCount: 12 })).toBe(false);
    expect(shouldShowGraphMiniMap({ nodeCount: 24, edgeCount: 40, selectedNode: true })).toBe(false);
    expect(shouldShowGraphMiniMap({ nodeCount: 90, edgeCount: 160 })).toBe(true);
  });

  it("keeps published mesh captures inside a bounded proof frame", () => {
    const interactive = graphFitViewOptions({ nodeCount: 18, edgeCount: 24, mode: "mesh" });
    const capture = graphFitViewOptions({ nodeCount: 18, edgeCount: 24, mode: "mesh", captureMode: true });

    expect(capture.maxZoom).toBeGreaterThan(interactive.maxZoom);
    expect(capture.maxZoom).toBeLessThanOrEqual(2.25);
    expect(capture.padding).toBeGreaterThan(interactive.padding);
    expect(capture.duration).toBe(0);
  });
});


describe("readable initial graph focus", () => {
  const nodes = Array.from({ length: 30 }, (_, index) => ({ id: `node:${index}`, data: { nodeType: index === 20 ? "agent" : "package" } }));
  const options = graphFitViewOptions({ nodeCount: nodes.length });
  it("uses deterministic context without mutating the complete graph", () => {
    const before = structuredClone(nodes);
    const fit = graphInitialFitViewOptions(nodes, options);
    expect(fit.nodes).toEqual([{ id: "node:20" }]);
    expect(fit.minZoom! * 11).toBeGreaterThanOrEqual(12);
    expect(graphInitialFitViewOptions([...nodes].reverse(), options)).toEqual(fit);
    expect(nodes).toEqual(before);
    expect(options).not.toHaveProperty("nodes"); // Explicit Fit all is unchanged.
  });
  it("prefers selection, then existing proposed changes, and ignores absent IDs", () => {
    expect(graphInitialFitViewOptions(nodes, options, "node:4", ["node:3"]).nodes).toEqual([{ id: "node:4" }]);
    expect(graphInitialFitViewOptions(nodes, options, "absent", ["absent", "node:3"]).nodes).toEqual([{ id: "node:3" }]);
  });
  it("retains full-fit framing for compact unselected graphs", () => {
    expect(graphInitialFitViewOptions(nodes.slice(0, 3), options)).toBe(options);
    expect(graphInitialFitViewOptions([], options)).toBe(options);
  });
});
