import Graph from "graphology";
import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import {
  buildLargeGraphOverviewModel,
  summarizeLargeGraphOverview,
  type LargeGraphOverviewModel,
  type LargeGraphOverviewSummary,
} from "@/lib/large-graph-overview";

export type SigmaNodeAttributes = {
  label: string;
  x: number;
  y: number;
  size: number;
  color: string;
  nodeType: LineageNodeType;
  severity?: string | undefined;
  hidden: boolean;
  highlighted: boolean;
  forceLabel: boolean;
  dimmed: boolean;
  zIndex: number;
} & Record<string, unknown>;

export type SigmaEdgeAttributes = {
  label: string;
  relationship: string;
  color: string;
  size: number;
  hidden: boolean;
  highlighted: boolean;
  zIndex: number;
} & Record<string, unknown>;

export interface SigmaGraphOverviewModel {
  graph: Graph<SigmaNodeAttributes, SigmaEdgeAttributes>;
  overview: LargeGraphOverviewModel;
  summary: LargeGraphOverviewSummary;
}

function edgeIsHighlighted(
  source: { highlighted: boolean; forceLabel: boolean } | undefined,
  target: { highlighted: boolean; forceLabel: boolean } | undefined,
): boolean {
  return Boolean(source?.highlighted || target?.highlighted || source?.forceLabel || target?.forceLabel);
}

export function buildSigmaGraphOverviewModel(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
): SigmaGraphOverviewModel {
  const overview = buildLargeGraphOverviewModel(nodes, edges);
  const graph = new Graph<SigmaNodeAttributes, SigmaEdgeAttributes>({
    allowSelfLoops: true,
    multi: true,
    type: "directed",
  });

  for (const node of overview.nodes) {
    graph.addNode(node.id, {
      label: node.label,
      x: node.x,
      y: node.y,
      size: node.size,
      color: node.color,
      nodeType: node.nodeType,
      severity: node.severity,
      hidden: node.hidden,
      highlighted: node.highlighted,
      forceLabel: node.forceLabel,
      dimmed: node.hidden,
      zIndex: node.highlighted || node.forceLabel ? 2 : 1,
    });
  }

  overview.edges.forEach((edge, index) => {
    const source = overview.nodeById.get(edge.source);
    const target = overview.nodeById.get(edge.target);
    const highlighted = edgeIsHighlighted(source, target);
    graph.addDirectedEdgeWithKey(edge.id, edge.source, edge.target, {
      label: edge.relationship.replace(/_/g, " "),
      relationship: edge.relationship,
      color: edge.color,
      size: edge.size,
      hidden: edge.hidden || source?.hidden === true || target?.hidden === true,
      highlighted,
      zIndex: highlighted ? 2 : 1 - index / 100_000,
    });
  });

  return {
    graph,
    overview,
    summary: summarizeLargeGraphOverview(nodes, edges),
  };
}
