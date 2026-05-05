/**
 * Left-to-right dagre layout wrapper.
 *
 * The default `useDagreLayout` covers both LR and TB via its `direction`
 * option, but the existing call sites pass `direction` dynamically and the
 * lineage / supply-chain surfaces want a hard-coded LR direction with no
 * caller-side knob. This wrapper pins `direction: "LR"` and keeps every
 * other option (worker-vs-sync, node sizing, rank/node sep) identical.
 *
 * Determinism: dagre is deterministic given identical inputs. The wrapper
 * also exposes a `seed` derived from the node IDs so visual-diff snapshots
 * can be keyed exactly like the radial / force / sankey layouts.
 */

"use client";

import { useMemo } from "react";
import { type Edge, type Node } from "@xyflow/react";

import { type LayoutOptions } from "@/lib/dagre-layout";
import { seedFromIds } from "@/lib/seed-random";
import { useDagreLayout } from "@/lib/use-dagre-layout";

export type DagreLrOptions = Omit<LayoutOptions, "direction">;

export interface UseDagreLrResult {
  nodes: Node[];
  edges: Edge[];
  pending: boolean;
  seed: number;
}

export function useDagreLrLayout(
  nodes: Node[],
  edges: Edge[],
  options: DagreLrOptions = {},
): UseDagreLrResult {
  const layout = useDagreLayout(nodes, edges, { ...options, direction: "LR" });
  const seed = useMemo(() => seedFromIds(nodes.map((n) => n.id)), [nodes]);
  return { ...layout, seed };
}
