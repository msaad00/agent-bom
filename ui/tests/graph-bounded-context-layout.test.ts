import { describe, expect, it } from "vitest";
import { getViewportForBounds, type Edge, type Node } from "@xyflow/react";
import { graphFitViewOptions } from "@/lib/graph-viewport";
import { applyDagreLayout } from "@/lib/dagre-layout";
import { compactInvestigationLayout, READABLE_LINEAGE_DAGRE_LR } from "@/lib/graph-node-dimensions";

function contextGraph() {
  const layers = [["asset"], ["bucket", "table"], ["role", "user", "service"], ["agent", "tool", "repo", "workload", "package"], ["finding"]];
  const nodes: Node[] = layers.flat().map((id) => ({ id, data: {}, position: { x: 0, y: 0 } }));
  const links = [["asset", "bucket"], ["asset", "table"], ["bucket", "role"], ["bucket", "user"], ["table", "service"],
    ["role", "agent"], ["role", "tool"], ["user", "repo"], ["service", "workload"], ["service", "package"],
    ["agent", "finding"], ["tool", "finding"], ["repo", "finding"], ["workload", "finding"], ["package", "finding"], ["bucket", "service"]];
  const edges: Edge[] = links.map(([source, target], index) => ({ id: String(index), source: source!, target: target! }));
  return { nodes, edges };
}

function fit(nodes: Node[], width: number, height: number) {
  const xs = nodes.map((n) => n.position.x), ys = nodes.map((n) => n.position.y);
  const options = graphFitViewOptions({ nodeCount: nodes.length, edgeCount: 16, selectedNode: false, mode: "lineage" });
  return getViewportForBounds({ x: Math.min(...xs), y: Math.min(...ys),
    width: Math.max(...xs) - Math.min(...xs) + width,
    height: Math.max(...ys) - Math.min(...ys) + height }, 1322, 610, 0.16, options.maxZoom, options.padding).zoom;
}

describe("bounded investigation layout", () => {
  it("uses compact readable cards only for an explicit bounded investigation", () => {
    expect(compactInvestigationLayout(false, 12)).toBeUndefined();
    expect(compactInvestigationLayout(true, 0)).toBeUndefined();
    expect(compactInvestigationLayout(true, 17)).toBeUndefined();
    expect(compactInvestigationLayout(true, 12)).toBeDefined();
  });

  it("keeps every node and directed edge in a branching 12-node context without card overlap", () => {
    const graph = contextGraph();
    const options = compactInvestigationLayout(true, graph.nodes.length)!;
    const compact = applyDagreLayout(graph.nodes, graph.edges, { ...options, direction: "LR" });
    const previous = applyDagreLayout(graph.nodes, graph.edges, { ...READABLE_LINEAGE_DAGRE_LR, direction: "LR" });
    expect(compact.nodes.map((n) => n.id)).toEqual(graph.nodes.map((n) => n.id));
    expect(compact.edges).toEqual(graph.edges);
    const footprint = options.minSeparation!;
    for (let i = 0; i < compact.nodes.length; i++) for (let j = i + 1; j < compact.nodes.length; j++) {
      const a = compact.nodes[i]!, b = compact.nodes[j]!;
      expect(Math.abs(a.position.x - b.position.x) >= footprint.width + footprint.gap - 0.001 ||
        Math.abs(a.position.y - b.position.y) >= footprint.height + footprint.gap - 0.001).toBe(true);
    }
    const zoom = fit(compact.nodes, footprint.width, footprint.height);
    // Full-card 18px labels remain readable in the complete desktop fit;
    // previous summary labels were 11px before the viewport scale.
    expect(zoom * 18).toBeGreaterThan(11);
    expect(zoom * 18).toBeGreaterThan(fit(previous.nodes, 300, 140) * 11 * 1.5);
  });
});
