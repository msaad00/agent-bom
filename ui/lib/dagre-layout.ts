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
  /**
   * Width:height ratio of the canvas this layout is dropped into. When set,
   * {@link fitRanksToAspect} reflows over-tall ranks so the result is shaped
   * like that canvas instead of a tower `fitView` can only answer with a
   * 2px-label zoom. LR layouts only — see the function docs.
   */
  fitAspect?: number | undefined;
}

/**
 * Reflow an LR dagre layout so its bounding box is shaped like the canvas.
 *
 * Dagre gives every node in a rank the same x and stacks the rank downwards,
 * with no notion of the viewport. A shallow, wide DAG — one agent fanning out
 * to 40 servers — therefore becomes a ~776 x 7784 tower dropped into a ~1322 x
 * 610 landscape canvas, and `fitView`, working exactly as designed, resolves to
 * a scale where nothing is readable.
 *
 * This pass wraps each rank's nodes into sub-columns, picking the single row
 * count (shared by every rank, so ranks stay visually aligned) that maximises
 * the fit scale on a canvas of ratio `aspect`. Ranks are then laid out
 * left-to-right in their original order, so every node of rank *r* still sits
 * entirely left of every node of rank *r+1* and edges keep reading as flow.
 * Within a rank the dagre y-order — which is crossing-minimised — is preserved
 * down each sub-column in turn.
 *
 * It is a no-op when dagre's own layout already fits at least as well, so
 * small graphs keep the exact one-node-per-rank reading they have today.
 */
const MIN_ASPECT_FIT_GAIN = 1.25;

export function fitRanksToAspect(
  nodes: Node[],
  options: {
    aspect: number;
    nodeWidth: number;
    nodeHeight: number;
    rankSep: number;
    nodeSep: number;
  },
): Node[] {
  const { aspect, nodeWidth, nodeHeight, rankSep, nodeSep } = options;
  if (nodes.length < 3 || !(aspect > 0)) return nodes;

  // Dagre assigns one x per rank for equal-width boxes; round away float noise.
  const ranks = new Map<number, Node[]>();
  for (const node of nodes) {
    const key = Math.round(node.position.x);
    const bucket = ranks.get(key);
    if (bucket) bucket.push(node);
    else ranks.set(key, [node]);
  }
  const rankKeys = [...ranks.keys()].sort((a, b) => a - b);
  const rankSizes = rankKeys.map((key) => ranks.get(key)!.length);
  const tallestRank = Math.max(...rankSizes);
  if (tallestRank < 2) return nodes;

  const columnStep = nodeWidth + nodeSep;
  const rowStep = nodeHeight + nodeSep;

  const measure = (rows: number) => {
    let width = 0;
    rankSizes.forEach((size, index) => {
      width += Math.ceil(size / rows) * columnStep - nodeSep;
      if (index < rankSizes.length - 1) width += rankSep;
    });
    return { width, height: Math.min(rows, tallestRank) * rowStep - nodeSep };
  };

  // Scale on a canvas of `aspect` x 1. Ties keep the taller layout, which is
  // the one closest to what dagre already produced.
  let bestRows = tallestRank;
  let bestScale = -Infinity;
  for (let rows = 1; rows <= tallestRank; rows += 1) {
    const { width, height } = measure(rows);
    const scale = Math.min(aspect / width, 1 / height);
    if (scale > bestScale + 1e-9) {
      bestScale = scale;
      bestRows = rows;
    }
  }
  if (bestRows >= tallestRank) return nodes;

  // Wrapping costs the reader the one-column-per-rank reading, so it has to
  // buy a materially better fit — not the few percent a nearly-square graph
  // would gain. Compared against dagre's real box, not a model of it.
  const xs = nodes.map((node) => node.position.x);
  const ys = nodes.map((node) => node.position.y);
  const dagreScale = Math.min(
    aspect / (Math.max(...xs) - Math.min(...xs) + nodeWidth),
    1 / (Math.max(...ys) - Math.min(...ys) + nodeHeight),
  );
  if (bestScale < dagreScale * MIN_ASPECT_FIT_GAIN) return nodes;

  const totalHeight = measure(bestRows).height;
  const positions = new Map<string, { x: number; y: number }>();
  let cursorX = 0;
  for (const key of rankKeys) {
    const rank = [...ranks.get(key)!].sort(
      (a, b) =>
        a.position.y - b.position.y || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    );
    const columns = Math.ceil(rank.length / bestRows);
    const rowsUsed = Math.min(bestRows, rank.length);
    // Centre each rank block so short ranks sit beside the middle of their
    // neighbours instead of hugging the top edge.
    const offsetY = (totalHeight - (rowsUsed * rowStep - nodeSep)) / 2;
    rank.forEach((node, index) => {
      positions.set(node.id, {
        x: cursorX + Math.floor(index / bestRows) * columnStep,
        y: offsetY + (index % bestRows) * rowStep,
      });
    });
    cursorX += columns * columnStep - nodeSep + rankSep;
  }

  return nodes.map((node) => {
    const next = positions.get(node.id);
    if (!next || (next.x === node.position.x && next.y === node.position.y)) {
      return node;
    }
    return { ...node, position: next };
  });
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
    fitAspect,
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

  const fittedNodes =
    isHorizontal && fitAspect
      ? fitRanksToAspect(layoutNodes, {
          aspect: fitAspect,
          nodeWidth,
          nodeHeight,
          rankSep,
          nodeSep,
        })
      : layoutNodes;

  return {
    nodes: minSeparation
      ? enforceMinNodeSeparation(fittedNodes, minSeparation)
      : fittedNodes,
    edges,
  };
}
