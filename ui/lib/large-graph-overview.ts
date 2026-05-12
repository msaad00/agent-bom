import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import { NODE_COLOR_MAP } from "@/lib/graph-utils";
import { RELATIONSHIP_COLOR_MAP } from "@/lib/graph-schema";

export const LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD = 500;
export const LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD = 1200;

export interface LargeGraphOverviewDecision {
  nodeCount: number;
  edgeCount: number;
  captureMode?: boolean;
  selectedAttackPath?: boolean;
  reachabilityActive?: boolean;
  graphOnlyFindings?: boolean;
}

export interface LargeGraphNode {
  id: string;
  x: number;
  y: number;
  label: string;
  color: string;
  size: number;
  nodeType: LineageNodeType;
  severity?: string | undefined;
  highlighted: boolean;
  hidden: boolean;
  forceLabel: boolean;
}

export interface LargeGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  color: string;
  size: number;
  hidden: boolean;
}

export interface LargeGraphOverviewModel {
  nodes: LargeGraphNode[];
  edges: LargeGraphEdge[];
  nodeById: Map<string, LargeGraphNode>;
}

export interface LargeGraphOverviewSummary {
  nodes: number;
  edges: number;
  findings: number;
  criticalFindings: number;
  credentials: number;
  tools: number;
  topRelationships: Array<{ relationship: string; count: number }>;
}

export function shouldUseLargeGraphOverview({
  nodeCount,
  edgeCount,
  captureMode = false,
  selectedAttackPath = false,
  reachabilityActive = false,
  graphOnlyFindings = false,
}: LargeGraphOverviewDecision): boolean {
  if (captureMode || selectedAttackPath || reachabilityActive || graphOnlyFindings) {
    return false;
  }
  return nodeCount >= LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD || edgeCount >= LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD;
}

function severityRank(severity?: string): number {
  switch (severity?.toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function nodeSize(data: LineageNodeData): number {
  const severity = severityRank(data.severity);
  if (data.nodeType === "vulnerability" || data.nodeType === "misconfiguration") {
    return 3.8 + severity * 1.4;
  }
  if (data.nodeType === "credential") return 6.6;
  if (data.nodeType === "tool") return 6.2;
  if (typeof data.riskScore === "number" && data.riskScore >= 80) return 7.4;
  if (data.nodeType === "agent" || data.nodeType === "server" || data.nodeType === "sharedServer") return 5.8;
  return 4.6;
}

function fallbackPosition(index: number, total: number): { x: number; y: number } {
  const ring = Math.floor(Math.sqrt(index));
  const angle = index * 2.399963229728653;
  const radius = 130 + Math.max(1, ring) * Math.max(26, Math.min(74, total / 180));
  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  };
}

function numericPosition(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function edgeRelationship(edge: Edge): string {
  const relationship = (edge.data as { relationship?: unknown } | undefined)?.relationship;
  return typeof relationship === "string" && relationship.length > 0 ? relationship : "related_to";
}

function edgeSize(edge: Edge): number {
  const strokeWidth = edge.style?.strokeWidth;
  if (typeof strokeWidth === "number" && Number.isFinite(strokeWidth)) {
    return Math.max(0.7, Math.min(2.4, strokeWidth * 0.74));
  }
  return edgeRelationship(edge) === "vulnerable_to" ? 1.4 : 0.8;
}

export function summarizeLargeGraphOverview(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
): LargeGraphOverviewSummary {
  const relationshipCounts = new Map<string, number>();
  for (const edge of edges) {
    const relationship = edgeRelationship(edge);
    relationshipCounts.set(relationship, (relationshipCounts.get(relationship) ?? 0) + 1);
  }

  return {
    nodes: nodes.length,
    edges: edges.length,
    findings: nodes.filter((node) => {
      const type = node.data.nodeType;
      return type === "vulnerability" || type === "misconfiguration";
    }).length,
    criticalFindings: nodes.filter((node) => severityRank(node.data.severity) >= 4).length,
    credentials: nodes.filter((node) => node.data.nodeType === "credential").length,
    tools: nodes.filter((node) => node.data.nodeType === "tool").length,
    topRelationships: [...relationshipCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 4)
      .map(([relationship, count]) => ({ relationship, count })),
  };
}

export function buildLargeGraphOverviewModel(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
): LargeGraphOverviewModel {
  const total = Math.max(nodes.length, 1);
  const overviewNodes: LargeGraphNode[] = nodes.map((node, index) => {
    const fallback = fallbackPosition(index, total);
    const data = node.data;
    const x = numericPosition(node.position?.x) ?? fallback.x;
    const y = numericPosition(node.position?.y) ?? fallback.y;
    const severity = severityRank(data.severity);
    return {
      id: node.id,
      x,
      y,
      label: data.label,
      color: NODE_COLOR_MAP[data.nodeType] ?? "#71717a",
      size: nodeSize(data),
      nodeType: data.nodeType,
      severity: data.severity,
      highlighted: data.highlighted === true,
      hidden: data.dimmed === true,
      forceLabel:
        data.highlighted === true ||
        severity >= 4 ||
        data.nodeType === "agent" ||
        data.nodeType === "server" ||
        data.nodeType === "sharedServer",
    };
  });
  const nodeById = new Map(overviewNodes.map((node) => [node.id, node]));
  const overviewEdges: LargeGraphEdge[] = edges.flatMap((edge, index) => {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) return [];
    const relationship = edgeRelationship(edge);
    return [
      {
        id: edge.id || `${edge.source}:${edge.target}:${relationship}:${index}`,
        source: edge.source,
        target: edge.target,
        relationship,
        color: RELATIONSHIP_COLOR_MAP[relationship] ?? "#52525b",
        size: edgeSize(edge),
        hidden: edge.hidden === true,
      },
    ];
  });

  return {
    nodes: overviewNodes,
    edges: overviewEdges,
    nodeById,
  };
}
