import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import { chooseContextDirection, contextFitScore, contextLayoutCandidates, contextLayoutOptions } from "@/lib/context-layout";

function graph(count: number, hub = false) {
  const nodes: Node[] = Array.from({ length: count }, (_, i) => ({ id: String(i), data: {}, position: { x: 0, y: 0 } }));
  const edges: Edge[] = nodes.slice(1).map((node, i) => ({ id: `e${i}`, source: hub ? "0" : String(i), target: node.id }));
  return { nodes, edges };
}

describe("Context layout fit", () => {
  it("fits a short chain horizontally on a wide canvas and vertically on a narrow one", () => {
    const { nodes, edges } = graph(3);
    const candidates = contextLayoutCandidates(nodes, edges, false);
    const choose = (width: number, height: number) => chooseContextDirection(
      contextFitScore(candidates.LR.nodes, { width, height }, false),
      contextFitScore(candidates.TB.nodes, { width, height }, false),
    );
    expect(choose(1100, 250)).toBe("LR");
    expect(choose(340, 650)).toBe("TB");
  });
  it("keeps a near-tie stable and changes only for a material fit gain", () => {
    expect(chooseContextDirection(0.8, 0.85, "LR")).toBe("LR");
    expect(chooseContextDirection(0.85, 0.8, "TB")).toBe("TB");
    expect(chooseContextDirection(0.6, 0.9, "LR")).toBe("TB");
  });
  for (const focused of [false, true]) it(`preserves every real node/edge without overlap for 24-node hub focused=${focused}`, () => {
    const { nodes, edges } = graph(24, true);
    for (const [direction, candidate] of Object.entries(contextLayoutCandidates(nodes, edges, focused))) {
      const gap = contextLayoutOptions(focused, direction as "LR" | "TB").minSeparation!.gap;
      expect(candidate.nodes.map(node => node.id)).toEqual(nodes.map(node => node.id));
      expect(candidate.edges).toEqual(edges);
      for (let i = 0; i < candidate.nodes.length; i++) for (let j = i + 1; j < candidate.nodes.length; j++) {
        const a = candidate.nodes[i]!.position, b = candidate.nodes[j]!.position;
        expect(Math.abs(a.x - b.x) >= (focused ? 260 : 208) + gap - 0.01 || Math.abs(a.y - b.y) >= (focused ? 130 : 80) + gap - 0.01).toBe(true);
      }
    }
  });
  it("does not infer a fit from an unmeasured canvas", () => {
    expect(contextFitScore(graph(1).nodes, { width: 0, height: 0 }, false)).toBe(0);
  });
});
