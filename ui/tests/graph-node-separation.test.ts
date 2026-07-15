import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  applyDagreLayout,
  enforceMinNodeSeparation,
  type MinSeparationOptions,
} from "@/lib/dagre-layout";
import {
  GRAPH_NODE_MIN_GAP,
  LINEAGE_MIN_SEPARATION,
  LINEAGE_NODE_HEIGHT,
  LINEAGE_NODE_WIDTH,
  READABLE_LINEAGE_DAGRE_LR,
  readableLineageDagreLr,
} from "@/lib/graph-node-dimensions";

function node(id: string, x = 0, y = 0): Node {
  return { id, position: { x, y }, data: {} };
}

function chain(ids: string[]): { nodes: Node[]; edges: Edge[] } {
  const nodes = ids.map((id) => node(id));
  const edges: Edge[] = ids.slice(0, -1).map((id, index) => ({
    id: `${id}->${ids[index + 1]}`,
    source: id,
    target: ids[index + 1]!,
  }));
  return { nodes, edges };
}

/**
 * Two `width x height` node footprints separated by at least `gap` never
 * overlap: on at least one axis the top-left distance clears the box + gap.
 */
function pairIsClear(a: Node, b: Node, opts: MinSeparationOptions): boolean {
  const dx = Math.abs(a.position.x - b.position.x);
  const dy = Math.abs(a.position.y - b.position.y);
  // Small epsilon so exact-touch (distance === box+gap) counts as clear.
  const eps = 1e-6;
  return dx + eps >= opts.width + opts.gap || dy + eps >= opts.height + opts.gap;
}

function everyPairClear(nodes: Node[], opts: MinSeparationOptions): boolean {
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      if (!pairIsClear(nodes[i]!, nodes[j]!, opts)) return false;
    }
  }
  return true;
}

describe("readable lineage layout options", () => {
  it("declares a box at least as large as the real lineage card footprint", () => {
    // The card is min-w-[208px] max-w-[300px] with a variable-height body; the
    // declared box must cover the worst case so dagre's own spacing already
    // guarantees a gap for every card it draws.
    expect(READABLE_LINEAGE_DAGRE_LR.nodeWidth).toBeGreaterThanOrEqual(300);
    expect(READABLE_LINEAGE_DAGRE_LR.nodeHeight).toBeGreaterThanOrEqual(140);
    expect(READABLE_LINEAGE_DAGRE_LR.minSeparation).toEqual(LINEAGE_MIN_SEPARATION);
  });

  it("always keeps the separation guarantee even when overrides are applied", () => {
    const tightened = readableLineageDagreLr({ rankSep: 100, nodeSep: 24 });
    expect(tightened.rankSep).toBe(100);
    expect(tightened.nodeSep).toBe(24);
    expect(tightened.minSeparation).toEqual(LINEAGE_MIN_SEPARATION);
  });
});

describe("enforceMinNodeSeparation", () => {
  const opts: MinSeparationOptions = { width: 300, height: 140, gap: 48 };

  it("separates fully-overlapping nodes so no pair touches", () => {
    const stacked = ["a", "b", "c", "d", "e"].map((id) => node(id, 0, 0));
    const out = enforceMinNodeSeparation(stacked, opts);
    expect(everyPairClear(out, opts)).toBe(true);
  });

  it("is a no-op (identical references) when nodes are already clear", () => {
    const spread = [
      node("a", 0, 0),
      node("b", 400, 0),
      node("c", 800, 0),
    ];
    const out = enforceMinNodeSeparation(spread, opts);
    expect(out[0]).toBe(spread[0]);
    expect(out[1]).toBe(spread[1]);
    expect(out[2]).toBe(spread[2]);
  });

  it("is deterministic for identical input", () => {
    const build = () =>
      ["n1", "n2", "n3", "n4", "n5", "n6"].map((id, i) => node(id, i % 2, i % 3));
    const a = enforceMinNodeSeparation(build(), opts);
    const b = enforceMinNodeSeparation(build(), opts);
    expect(a.map((n) => n.position)).toEqual(b.map((n) => n.position));
  });

  it("skips the O(n^2) relaxation above the node cap (returns input)", () => {
    const many = Array.from({ length: 700 }, (_, i) => node(`n${i}`, 0, 0));
    const out = enforceMinNodeSeparation(many, opts);
    expect(out).toBe(many);
  });
});

describe("applyDagreLayout with the lineage separation guarantee", () => {
  it("keeps a 4-node chain from touching (the top dogfooding complaint)", () => {
    const { nodes, edges } = chain(["agent", "server", "package", "cve"]);
    const { nodes: laidOut } = applyDagreLayout(nodes, edges, {
      ...READABLE_LINEAGE_DAGRE_LR,
      direction: "LR",
    });
    expect(everyPairClear(laidOut, LINEAGE_MIN_SEPARATION)).toBe(true);
  });

  it("lays the chain out left-to-right (blast-radius flow direction)", () => {
    const { nodes, edges } = chain(["agent", "server", "package", "cve"]);
    const { nodes: laidOut } = applyDagreLayout(nodes, edges, {
      ...READABLE_LINEAGE_DAGRE_LR,
      direction: "LR",
    });
    const byId = new Map(laidOut.map((n) => [n.id, n.position.x]));
    expect(byId.get("agent")!).toBeLessThan(byId.get("server")!);
    expect(byId.get("server")!).toBeLessThan(byId.get("package")!);
    expect(byId.get("package")!).toBeLessThan(byId.get("cve")!);
  });

  it("keeps many stacked siblings clear (readable at larger scale)", () => {
    // One agent fanning out to 40 sibling servers — the case that used to
    // collapse into a cramped vertical stack of touching cards.
    const nodes: Node[] = [node("agent")];
    const edges: Edge[] = [];
    for (let i = 0; i < 40; i += 1) {
      nodes.push(node(`server-${i}`));
      edges.push({ id: `e-${i}`, source: "agent", target: `server-${i}` });
    }
    const { nodes: laidOut } = applyDagreLayout(nodes, edges, {
      ...READABLE_LINEAGE_DAGRE_LR,
      direction: "LR",
    });
    expect(everyPairClear(laidOut, LINEAGE_MIN_SEPARATION)).toBe(true);
  });

  it("uses the shared minimum gap constant", () => {
    expect(LINEAGE_MIN_SEPARATION.gap).toBe(GRAPH_NODE_MIN_GAP);
    expect(LINEAGE_MIN_SEPARATION.width).toBe(LINEAGE_NODE_WIDTH);
    expect(LINEAGE_MIN_SEPARATION.height).toBe(LINEAGE_NODE_HEIGHT);
  });
});
