/**
 * The raw lineage graph must not build a tower that no canvas can fit.
 *
 * `graph-rollup-layout-fits-the-canvas.test.ts` fixed the same defect for the
 * roll-up grid, but the roll-up never calls dagre — it emits its own grid. The
 * raw lineage branch goes through `applyDagreLayout`, which has no notion of
 * the canvas it lands on, so a shallow-but-wide DAG (one agent fanning out to
 * 40 servers is the common shape) puts every sibling in one rank and stacks
 * them vertically forever.
 *
 * Measured on this layout before the fix, on the same ~1322 x 610 canvas:
 *
 *     one agent -> 40 servers   776 x 7784  (aspect 0.10)  fit 0.064
 *     one agent -> 80 servers   776 x 15624 (aspect 0.05)  fit 0.032
 *     3 x 12 x 4 fan-out       1728 x 28168 (aspect 0.06)  fit 0.018
 *
 * React Flow floors `/graph` at `minZoom={0.16}`, so every one of those opens
 * clamped at 0.16 with the graph running far off the bottom of the canvas. A
 * 300x140 card at 0.16 is 48x22px and its label is unreadable.
 *
 * The fix reflows over-tall ranks into sub-columns so the laid-out box is
 * shaped like the landscape canvas it is dropped into. Rank order (the
 * left-to-right blast-radius flow) is preserved: every rank still sits
 * entirely to the right of the rank before it.
 */
import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { applyDagreLayout } from "@/lib/dagre-layout";
import {
  LINEAGE_MIN_SEPARATION,
  LINEAGE_NODE_HEIGHT,
  LINEAGE_NODE_WIDTH,
  READABLE_LINEAGE_DAGRE_LR,
} from "@/lib/graph-node-dimensions";

/** The `/graph` canvas measured in the browser at a 1440px-wide viewport. */
const CANVAS_WIDTH = 1322;
const CANVAS_HEIGHT = 610;
/** `graphFitViewOptions` padding for a dense (>80 node) lineage graph. */
const FIT_PADDING = 0.18;

function boundingBox(nodes: Node[]) {
  const xs = nodes.map((n) => n.position.x);
  const ys = nodes.map((n) => n.position.y);
  return {
    width: Math.max(...xs) - Math.min(...xs) + LINEAGE_NODE_WIDTH,
    height: Math.max(...ys) - Math.min(...ys) + LINEAGE_NODE_HEIGHT,
  };
}

/** The scale `fitView` resolves to for a laid-out graph on the real canvas. */
function fitScale(nodes: Node[]): number {
  const { width, height } = boundingBox(nodes);
  return Math.min(
    (CANVAS_WIDTH * (1 - FIT_PADDING)) / width,
    (CANVAS_HEIGHT * (1 - FIT_PADDING)) / height,
  );
}

/** agent -> servers -> packages -> findings, the real lineage fan-out shape. */
function fanout(levels: number[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [{ id: "root", position: { x: 0, y: 0 }, data: {} }];
  const edges: Edge[] = [];
  let previous = ["root"];
  levels.forEach((count, depth) => {
    const layer: string[] = [];
    previous.forEach((parent, parentIndex) => {
      for (let i = 0; i < count; i += 1) {
        const id = `n${depth}-${parentIndex}-${i}`;
        layer.push(id);
        nodes.push({ id, position: { x: 0, y: 0 }, data: {} });
        edges.push({ id: `e-${parent}-${id}`, source: parent, target: id });
      }
    });
    previous = layer;
  });
  return { nodes, edges };
}

function layout(levels: number[]): { nodes: Node[]; edges: Edge[] } {
  const key = levels.join("x");
  const cached = layoutCache.get(key);
  if (cached) return cached;
  const { nodes, edges } = fanout(levels);
  const result = applyDagreLayout(nodes, edges, {
    ...READABLE_LINEAGE_DAGRE_LR,
    direction: "LR",
  });
  layoutCache.set(key, result);
  return result;
}

function everyPairClear(nodes: Node[]): boolean {
  const { width, height, gap } = LINEAGE_MIN_SEPARATION;
  const eps = 1e-6;
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const dx = Math.abs(nodes[i]!.position.x - nodes[j]!.position.x);
      const dy = Math.abs(nodes[i]!.position.y - nodes[j]!.position.y);
      if (dx + eps < width + gap && dy + eps < height + gap) return false;
    }
  }
  return true;
}

const DENSE_SHAPES: Array<[string, number[]]> = [
  ["one agent -> 40 servers", [40]],
  ["one agent -> 80 servers", [80]],
  ["3 servers x 12 packages x 4 findings", [3, 12, 4]],
  ["4 x 8", [4, 8]],
  ["6 x 10", [6, 10]],
  ["2 x 5 x 6", [2, 5, 6]],
  ["12 x 3", [12, 3]],
];

/** Each shape is laid out repeatedly across this file; dagre is deterministic. */
const layoutCache = new Map<string, { nodes: Node[]; edges: Edge[] }>();

describe("the raw lineage layout is shaped like the canvas it lands on", () => {
  it("opens a 40-sibling fan-out at a legible zoom", () => {
    // 0.064 was the measured defect. A 300x140 card at 0.35 is 105x49 — small,
    // but the label reads and the severity border is unmistakable.
    expect(fitScale(layout([40]).nodes)).toBeGreaterThan(0.35);
  });

  it("never builds a portrait tower, at any dense shape", () => {
    for (const [name, levels] of DENSE_SHAPES) {
      const { width, height } = boundingBox(layout(levels).nodes);
      // The canvas is landscape; a taller-than-wide layout wastes horizontal
      // room and pays for it in zoom.
      expect(width, name).toBeGreaterThan(height);
    }
  });

  it("clears React Flow's 0.16 zoom floor instead of being clamped by it", () => {
    // Below `minZoom` the graph is not merely small, it runs off the canvas:
    // fitView cannot honour the requested scale, so nodes sit past the fold.
    for (const [name, levels] of DENSE_SHAPES) {
      expect(fitScale(layout(levels).nodes), name).toBeGreaterThan(0.16);
    }
  });

  it("lands within reach of the best fit any target aspect could achieve", () => {
    // The real invariant: the layout's job is to sit near the geometric
    // ceiling at every shape, which is a property worth asserting where a
    // magic constant is not. Kept to a few shapes and probes — each probe is
    // a full dagre run, and this suite shares a worker pool.
    for (const levels of [[40], [4, 8], [6, 10]]) {
      const chosen = fitScale(layout(levels).nodes);
      const { nodes, edges } = fanout(levels);
      const best = Math.max(
        ...[0.5, 1, 2.2, 4, 8].map((aspect) =>
          fitScale(
            applyDagreLayout(nodes, edges, {
              ...READABLE_LINEAGE_DAGRE_LR,
              direction: "LR",
              fitAspect: aspect,
            }).nodes,
          ),
        ),
      );
      expect(chosen, levels.join("x")).toBeGreaterThan(best * 0.75);
    }
  });

  it("keeps the left-to-right rank order every edge is drawn against", () => {
    for (const [name, levels] of DENSE_SHAPES) {
      const { nodes, edges } = layout(levels);
      const x = new Map(nodes.map((n) => [n.id, n.position.x]));
      for (const edge of edges) {
        expect(x.get(edge.source)!, `${name} ${edge.id}`).toBeLessThan(
          x.get(edge.target)!,
        );
      }
    }
  });

  it("still keeps every pair of cards clear of each other", () => {
    for (const [name, levels] of DENSE_SHAPES) {
      expect(everyPairClear(layout(levels).nodes), name).toBe(true);
    }
  });

  it("leaves a graph that already fits exactly as dagre laid it out", () => {
    // A 4-node chain and a 3-sibling fan already fit; reflowing them would
    // churn the layout for no gain and break the one-node-per-rank reading.
    for (const levels of [[1, 1, 1], [3]]) {
      const withFit = layout(levels).nodes.map((n) => n.position);
      const { nodes, edges } = fanout(levels);
      const plain = applyDagreLayout(nodes, edges, {
        ...READABLE_LINEAGE_DAGRE_LR,
        direction: "LR",
        fitAspect: undefined,
      }).nodes.map((n) => n.position);
      expect(withFit).toEqual(plain);
    }
  });

  it("is deterministic for identical input", () => {
    const run = () => {
      const { nodes, edges } = fanout([6, 10]);
      return applyDagreLayout(nodes, edges, {
        ...READABLE_LINEAGE_DAGRE_LR,
        direction: "LR",
      }).nodes.map((n) => n.position);
    };
    expect(run()).toEqual(run());
  });
});
