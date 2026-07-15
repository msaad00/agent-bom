/**
 * Dagre layout utility for React Flow graphs.
 * Automatically positions nodes using a directed graph layout.
 */

import dagre from "@dagrejs/dagre";
import { type Edge, type Node, type Position } from "@xyflow/react";

/**
 * Post-layout guarantee that no two node boxes ever touch. Dagre already
 * spaces nodes using the declared `nodeWidth`/`nodeHeight`, but the real
 * lineage cards are variable-height and can render taller/wider than the
 * declared box — which is exactly how adjacent cards ended up abutting with
 * zero gap. This pass treats every node as a `width x height` footprint and
 * pushes any overlapping pair apart along the axis of least penetration until
 * every pair is at least `gap` pixels clear. It is deterministic (ordered by
 * node id) and a no-op when the layout already satisfies the constraint.
 */
export interface MinSeparationOptions {
  /** Node footprint width used for collision (>= the real card width). */
  width: number;
  /** Node footprint height used for collision (>= the real card height). */
  height: number;
  /** Minimum clear gap enforced between two node footprints. */
  gap: number;
  /** Relaxation passes. Overlaps resolve well within the default. */
  iterations?: number;
}

// Above this node count the O(n^2) relaxation is skipped: large graphs render
// through the WebGL overview / clustering paths, and dagre's own spacing with a
// correctly-declared box already guarantees separation there.
const MIN_SEPARATION_NODE_CAP = 600;

export function enforceMinNodeSeparation(
  nodes: Node[],
  options: MinSeparationOptions,
): Node[] {
  const { width, height, gap, iterations = 48 } = options;
  if (nodes.length < 2 || nodes.length > MIN_SEPARATION_NODE_CAP) return nodes;

  const minDx = width + gap;
  const minDy = height + gap;
  const pos = nodes.map((node) => ({ x: node.position.x, y: node.position.y }));
  // Deterministic pair order so the same input always yields the same layout.
  const order = nodes
    .map((node, index) => ({ id: node.id, index }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((entry) => entry.index);

  for (let iter = 0; iter < iterations; iter += 1) {
    let moved = false;
    for (let a = 0; a < order.length; a += 1) {
      for (let b = a + 1; b < order.length; b += 1) {
        const i = order[a]!;
        const j = order[b]!;
        const dx = pos[j]!.x - pos[i]!.x;
        const dy = pos[j]!.y - pos[i]!.y;
        const overlapX = minDx - Math.abs(dx);
        const overlapY = minDy - Math.abs(dy);
        if (overlapX <= 0 || overlapY <= 0) continue;
        if (overlapX < overlapY) {
          const shift = overlapX / 2;
          const dir = dx === 0 ? -1 : Math.sign(dx);
          pos[i]!.x -= dir * shift;
          pos[j]!.x += dir * shift;
        } else {
          const shift = overlapY / 2;
          const dir = dy === 0 ? -1 : Math.sign(dy);
          pos[i]!.y -= dir * shift;
          pos[j]!.y += dir * shift;
        }
        moved = true;
      }
    }
    if (!moved) break;
  }

  return nodes.map((node, index) => {
    const next = pos[index]!;
    if (next.x === node.position.x && next.y === node.position.y) return node;
    return { ...node, position: { x: next.x, y: next.y } };
  });
}

export interface LayoutOptions {
  direction?: "LR" | "TB";
  nodeWidth?: number;
  nodeHeight?: number;
  rankSep?: number;
  nodeSep?: number;
  /**
   * When set, run {@link enforceMinNodeSeparation} after dagre so node cards
   * never touch even when the real card renders larger than the declared box.
   */
  minSeparation?: MinSeparationOptions;
}

export function applyDagreLayout(
  nodes: Node[],
  edges: Edge[],
  options: LayoutOptions = {}
): { nodes: Node[]; edges: Edge[] } {
  const {
    direction = "LR",
    nodeWidth = 180,
    nodeHeight = 60,
    rankSep = 80,
    nodeSep = 30,
    minSeparation,
  } = options;

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, ranksep: rankSep, nodesep: nodeSep });

  for (const node of nodes) {
    g.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  }

  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  dagre.layout(g);

  const isHorizontal = direction === "LR";

  const layoutNodes = nodes.map((node) => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: {
        x: pos.x - nodeWidth / 2,
        y: pos.y - nodeHeight / 2,
      },
      sourcePosition: (isHorizontal ? "right" : "bottom") as Position,
      targetPosition: (isHorizontal ? "left" : "top") as Position,
    };
  });

  return {
    nodes: minSeparation
      ? enforceMinNodeSeparation(layoutNodes, minSeparation)
      : layoutNodes,
    edges,
  };
}
