"use client";

import { useMemo } from "react";
import { type Edge, type Node } from "@xyflow/react";

import { GraphLayout } from "@/lib/graph-schema";
import { type LayoutOptions } from "@/lib/dagre-layout";
import { type DagreLrOptions, useDagreLrLayout } from "@/lib/use-dagre-lr";
import { type ForceLayoutOptions, useForceLayout } from "@/lib/use-force-layout";
import { type RadialLayoutOptions, useRadialLayout } from "@/lib/use-radial-layout";
import { type SankeyLayoutOptions, useSankeyLayout } from "@/lib/use-sankey-layout";
import { useDagreLayout } from "@/lib/use-dagre-layout";

const EMPTY_NODES: Node[] = [];
const EMPTY_EDGES: Edge[] = [];

export type GraphLayoutKind =
  | GraphLayout
  | "force"
  | "radial"
  | "dagre"
  | "sankey"
  | "dagre-lr"
  | "dagre_lr"
  | "lr"
  | "topology"
  | "spawn-tree"
  | "spawn_tree";

export type ResolvedGraphLayoutKind =
  | "force"
  | "radial"
  | "dagre"
  | "dagre-lr"
  | "sankey";

export interface GraphLayoutOptions {
  force?: ForceLayoutOptions;
  radial?: RadialLayoutOptions;
  dagre?: LayoutOptions;
  dagreLr?: DagreLrOptions;
  sankey?: SankeyLayoutOptions;
}

export interface GraphLayoutState {
  nodes: Node[];
  edges: Edge[];
  pending: boolean;
  seed?: number;
  kind: ResolvedGraphLayoutKind;
}

export function resolveGraphLayoutKind(kind: GraphLayoutKind): ResolvedGraphLayoutKind {
  switch (kind) {
    case GraphLayout.FORCE:
    case "force":
      return "force";
    case GraphLayout.RADIAL:
    case "radial":
      return "radial";
    case GraphLayout.SANKEY:
    case "sankey":
      return "sankey";
    case GraphLayout.DAGRE:
    case "dagre":
    case GraphLayout.HIERARCHICAL:
    case GraphLayout.GRID:
    case "topology":
    case "spawn-tree":
    case "spawn_tree":
      return "dagre";
    case "dagre-lr":
    case "dagre_lr":
    case "lr":
      return "dagre-lr";
  }
}

export function useGraphLayout(
  kind: GraphLayoutKind,
  nodes: Node[],
  edges: Edge[],
  options: GraphLayoutOptions = {},
): GraphLayoutState {
  const resolvedKind = resolveGraphLayoutKind(kind);
  const dagreOptions = useMemo<LayoutOptions>(() => {
    const requested = options.dagre ?? {};
    if (requested.direction !== undefined) return requested;
    if (kind === "spawn-tree" || kind === "spawn_tree") {
      return { ...requested, direction: "TB" };
    }
    if (kind === "topology") {
      return { ...requested, direction: "LR" };
    }
    return requested;
  }, [kind, options.dagre]);
  const force = useForceLayout(
    resolvedKind === "force" ? nodes : EMPTY_NODES,
    resolvedKind === "force" ? edges : EMPTY_EDGES,
    options.force,
  );
  const radial = useRadialLayout(
    resolvedKind === "radial" ? nodes : EMPTY_NODES,
    resolvedKind === "radial" ? edges : EMPTY_EDGES,
    options.radial,
  );
  const dagre = useDagreLayout(
    resolvedKind === "dagre" ? nodes : EMPTY_NODES,
    resolvedKind === "dagre" ? edges : EMPTY_EDGES,
    dagreOptions,
  );
  const dagreLr = useDagreLrLayout(
    resolvedKind === "dagre-lr" ? nodes : EMPTY_NODES,
    resolvedKind === "dagre-lr" ? edges : EMPTY_EDGES,
    options.dagreLr,
  );
  const sankey = useSankeyLayout(
    resolvedKind === "sankey" ? nodes : EMPTY_NODES,
    resolvedKind === "sankey" ? edges : EMPTY_EDGES,
    options.sankey,
  );

  return useMemo(() => {
    switch (resolvedKind) {
      case "force":
        return { ...force, kind: resolvedKind };
      case "radial":
        return { ...radial, kind: resolvedKind };
      case "dagre":
        return { ...dagre, kind: resolvedKind };
      case "dagre-lr":
        return { ...dagreLr, kind: resolvedKind };
      case "sankey":
        return { ...sankey, kind: resolvedKind };
    }
  }, [dagre, dagreLr, force, radial, resolvedKind, sankey]);
}
