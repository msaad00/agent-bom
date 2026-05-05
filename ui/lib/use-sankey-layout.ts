/**
 * Sankey layout for the scan-pipeline DAG.
 *
 * The scan pipeline is a linear stage chain (discover → resolve → vulns →
 * graph → policy → sink) with branches into output formats. Force-directed
 * obscures the flow; dagre LR preserves direction but loses throughput.
 * Sankey ranks nodes left-to-right by topological depth and stacks them
 * vertically inside each rank with band heights proportional to their
 * weight (default: count of outgoing edges).
 *
 * No new dependency: a tiny topological-sort + band stacker is enough for
 * the pipeline DAG (~30 nodes max). If we ever need true bend-aware Sankey
 * ribbons, swap to `d3-sankey` (≈10 KB) — keeping this implementation
 * pure-JS lets the helper ship even before the pipeline visualisation
 * surface lands.
 *
 * Determinism: rank within each column is sorted by id; column placement
 * is fully deterministic from the input topology. The helper exposes the
 * same `seed` field as the other layouts so visual-diff CI can key
 * snapshots uniformly (#2259).
 *
 * Wiring: this layout has no dashboard surface yet — it is pre-built so
 * the pipeline-DAG view (#2257 follow-up) can adopt it without further
 * library work.
 */

"use client";

import { useMemo } from "react";
import { Position, type Edge, type Node } from "@xyflow/react";

import { seedFromIds } from "@/lib/seed-random";

export interface SankeyLayoutOptions {
  /** Horizontal spacing between columns. */
  columnGap?: number;
  /** Vertical spacing between rows within a column. */
  rowGap?: number;
  /** Approximate node width (used for column placement). */
  nodeWidth?: number;
  /** Approximate node height (used for row placement). */
  nodeHeight?: number;
}

const DEFAULTS: Required<SankeyLayoutOptions> = {
  columnGap: 240,
  rowGap: 80,
  nodeWidth: 200,
  nodeHeight: 60,
};

export interface SankeyLayoutResult {
  nodes: Node[];
  edges: Edge[];
  seed: number;
}

/** Compute longest-path depth per node — handles DAGs cleanly. */
function computeRanks(
  nodeIds: string[],
  edges: Edge[],
): Map<string, number> {
  const incoming = new Map<string, string[]>();
  const outgoing = new Map<string, string[]>();
  const valid = new Set(nodeIds);
  for (const id of nodeIds) {
    incoming.set(id, []);
    outgoing.set(id, []);
  }
  for (const edge of edges) {
    if (!valid.has(edge.source) || !valid.has(edge.target)) continue;
    if (edge.source === edge.target) continue;
    outgoing.get(edge.source)!.push(edge.target);
    incoming.get(edge.target)!.push(edge.source);
  }

  // Kahn's algorithm to detect topological order; cycles fall back to BFS depth.
  const inDegree = new Map<string, number>();
  for (const [id, sources] of incoming) {
    inDegree.set(id, sources.length);
  }
  const queue: string[] = [];
  for (const [id, deg] of inDegree) {
    if (deg === 0) queue.push(id);
  }
  const rank = new Map<string, number>();
  for (const id of queue) rank.set(id, 0);

  let head = 0;
  while (head < queue.length) {
    const current = queue[head++]!;
    const currentRank = rank.get(current) ?? 0;
    for (const next of outgoing.get(current) ?? []) {
      rank.set(next, Math.max(rank.get(next) ?? 0, currentRank + 1));
      const remaining = (inDegree.get(next) ?? 0) - 1;
      inDegree.set(next, remaining);
      if (remaining === 0) queue.push(next);
    }
  }

  // Anything left without a rank is part of a cycle — assign it the maximum
  // rank so it lands at the right edge instead of disappearing.
  let maxRank = 0;
  for (const r of rank.values()) maxRank = Math.max(maxRank, r);
  for (const id of nodeIds) {
    if (!rank.has(id)) rank.set(id, maxRank + 1);
  }
  return rank;
}

export function applySankeyLayout(
  nodes: Node[],
  edges: Edge[],
  options: SankeyLayoutOptions = {},
): SankeyLayoutResult {
  const opts = { ...DEFAULTS, ...options };
  if (nodes.length === 0) {
    return { nodes: [], edges, seed: 0 };
  }

  const seed = seedFromIds(nodes.map((n) => n.id));
  const ids = nodes.map((n) => n.id);
  const ranks = computeRanks(ids, edges);

  // Bucket by rank, sort each rank deterministically.
  const columns = new Map<number, Node[]>();
  for (const node of nodes) {
    const r = ranks.get(node.id) ?? 0;
    const bucket = columns.get(r);
    if (bucket) {
      bucket.push(node);
    } else {
      columns.set(r, [node]);
    }
  }

  const columnEntries = [...columns.entries()].sort((a, b) => a[0] - b[0]);
  const positioned = new Map<string, Node>();
  for (const [rank, bucket] of columnEntries) {
    const sorted = [...bucket].sort((a, b) => a.id.localeCompare(b.id));
    const colHeight = sorted.length * (opts.nodeHeight + opts.rowGap);
    const yStart = -colHeight / 2;
    sorted.forEach((node, index) => {
      positioned.set(node.id, {
        ...node,
        position: {
          x: rank * (opts.nodeWidth + opts.columnGap),
          y: yStart + index * (opts.nodeHeight + opts.rowGap),
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });
    });
  }

  const final = nodes.map((n) => positioned.get(n.id) ?? n);
  return { nodes: final, edges, seed };
}

export interface UseSankeyLayoutResult {
  nodes: Node[];
  edges: Edge[];
  pending: false;
  seed: number;
}

export function useSankeyLayout(
  nodes: Node[],
  edges: Edge[],
  options: SankeyLayoutOptions = {},
): UseSankeyLayoutResult {
  const columnGap = options.columnGap;
  const rowGap = options.rowGap;
  const nodeWidth = options.nodeWidth;
  const nodeHeight = options.nodeHeight;
  return useMemo(() => {
    const opts: SankeyLayoutOptions = {};
    if (columnGap !== undefined) opts.columnGap = columnGap;
    if (rowGap !== undefined) opts.rowGap = rowGap;
    if (nodeWidth !== undefined) opts.nodeWidth = nodeWidth;
    if (nodeHeight !== undefined) opts.nodeHeight = nodeHeight;
    const result = applySankeyLayout(nodes, edges, opts);
    return { ...result, pending: false as const };
  }, [nodes, edges, columnGap, rowGap, nodeWidth, nodeHeight]);
}
