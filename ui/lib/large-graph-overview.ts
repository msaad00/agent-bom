import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import { NODE_COLOR_MAP } from "@/lib/graph-utils";
import { RELATIONSHIP_COLOR_MAP } from "@/lib/graph-schema";

export const LARGE_GRAPH_OVERVIEW_NODE_THRESHOLD = 200;
export const LARGE_GRAPH_OVERVIEW_EDGE_THRESHOLD = 500;
export const LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES = 3000;
export const LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES = 6000;

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
  sourceNodeCount: number;
  sourceEdgeCount: number;
  omittedNodeCount: number;
  omittedEdgeCount: number;
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

const CLUSTER_ORDER: LineageNodeType[] = [
  "provider",
  "org",
  "account",
  "environment",
  "fleet",
  "cluster",
  "cloudResource",
  "container",
  "agent",
  "server",
  "sharedServer",
  "tool",
  "credential",
  "vulnerability",
  "misconfiguration",
  "package",
  "model",
  "framework",
  "dataset",
  "dataStore",
  "directory",
  "sourceFile",
  "configFile",
  "user",
  "group",
  "role",
  "policy",
  "serviceAccount",
  "servicePrincipal",
  "federatedIdentity",
  "managedIdentity",
  "accessGrant",
  "accessPolicy",
  "driftIncident",
];

function clusterRank(nodeType: LineageNodeType): number {
  const index = CLUSTER_ORDER.indexOf(nodeType);
  return index === -1 ? CLUSTER_ORDER.length : index;
}

function clusterLabel(nodeType: LineageNodeType): string {
  if (nodeType === "org" || nodeType === "account" || nodeType === "provider") return "cloud";
  if (nodeType === "cloudResource" || nodeType === "container" || nodeType === "cluster") return "asset";
  if (nodeType === "sharedServer") return "server";
  if (nodeType === "vulnerability" || nodeType === "misconfiguration") return "finding";
  if (nodeType === "dataset" || nodeType === "dataStore") return "data";
  if (nodeType === "directory" || nodeType === "sourceFile" || nodeType === "configFile") return "source";
  if (
    nodeType === "user" ||
    nodeType === "group" ||
    nodeType === "role" ||
    nodeType === "policy" ||
    nodeType === "serviceAccount" ||
    nodeType === "servicePrincipal" ||
    nodeType === "federatedIdentity" ||
    nodeType === "managedIdentity" ||
    nodeType === "accessGrant" ||
    nodeType === "accessPolicy"
  ) {
    return "identity";
  }
  return nodeType;
}

function buildClusteredOverviewPositions(
  rankedNodes: Array<{ node: Node<LineageNodeData>; index: number; score: number }>,
): Map<string, { x: number; y: number }> {
  const groups = new Map<string, Array<{ node: Node<LineageNodeData>; index: number; score: number }>>();
  for (const item of rankedNodes) {
    const key = clusterLabel(item.node.data.nodeType);
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }

  const orderedGroups = [...groups.entries()].sort((left, right) => {
    const leftType = left[1][0]?.node.data.nodeType ?? "agent";
    const rightType = right[1][0]?.node.data.nodeType ?? "agent";
    return clusterRank(leftType) - clusterRank(rightType) || left[0].localeCompare(right[0]);
  });

  const positions = new Map<string, { x: number; y: number }>();
  if (orderedGroups.length === 0) return positions;

  const ringRadius = Math.max(360, Math.min(920, 280 + rankedNodes.length * 0.32));
  const coreTypes = new Set(["agent", "server", "sharedServer", "tool", "credential", "vulnerability", "misconfiguration"]);
  const coreGroups = orderedGroups.filter(([, items]) => coreTypes.has(items[0]?.node.data.nodeType ?? ""));
  const outerGroups = orderedGroups.filter(([, items]) => !coreTypes.has(items[0]?.node.data.nodeType ?? ""));
  const allGroups = [...coreGroups, ...outerGroups];

  allGroups.forEach(([, items], groupIndex) => {
    const inCore = coreTypes.has(items[0]?.node.data.nodeType ?? "");
    const totalGroups = Math.max(1, inCore ? coreGroups.length : outerGroups.length);
    const relativeIndex = inCore ? groupIndex : groupIndex - coreGroups.length;
    const angleOffset = inCore ? -Math.PI / 2 : -Math.PI / 2 + Math.PI / Math.max(outerGroups.length, 1);
    const radius = inCore ? ringRadius * 0.48 : ringRadius;
    const angle = angleOffset + (relativeIndex / totalGroups) * Math.PI * 2;
    const center = {
      x: Math.cos(angle) * radius,
      y: Math.sin(angle) * radius,
    };
    const sortedItems = [...items].sort((left, right) => right.score - left.score || left.index - right.index);
    const columns = Math.max(1, Math.ceil(Math.sqrt(sortedItems.length)));
    const spacing = Math.max(22, Math.min(42, 34 - Math.log10(Math.max(sortedItems.length, 1)) * 4));
    sortedItems.forEach((item, itemIndex) => {
      const column = itemIndex % columns;
      const row = Math.floor(itemIndex / columns);
      const rowCount = Math.ceil(sortedItems.length / columns);
      positions.set(item.node.id, {
        x: center.x + (column - (columns - 1) / 2) * spacing,
        y: center.y + (row - (rowCount - 1) / 2) * spacing,
      });
    });
  });

  return positions;
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

function nodeSignalScore(node: Node<LineageNodeData>, index: number): number {
  const data = node.data;
  let score = 0;
  const severity = severityRank(data.severity);
  if (data.highlighted === true) score += 1_000_000;
  if (data.nodeType === "agent" || data.nodeType === "server" || data.nodeType === "sharedServer") score += 800_000;
  if (data.nodeType === "credential" || data.nodeType === "tool") score += 500_000;
  if (data.nodeType === "vulnerability" || data.nodeType === "misconfiguration") score += 350_000 + severity * 20_000;
  if (typeof data.riskScore === "number" && Number.isFinite(data.riskScore)) score += Math.min(100, Math.max(0, data.riskScore)) * 100;
  return score - index / 10_000;
}

function edgeSignalScore(edge: Edge, nodeById: Map<string, LargeGraphNode>, index: number): number {
  const relationship = edgeRelationship(edge);
  let score = 0;
  if (relationship === "vulnerable_to") score += 500_000;
  if (relationship === "exposes_cred" || relationship === "reaches_tool") score += 450_000;
  if (relationship === "uses" || relationship === "depends_on") score += 150_000;
  const source = nodeById.get(edge.source);
  const target = nodeById.get(edge.target);
  if (source?.highlighted || target?.highlighted) score += 750_000;
  if (source?.forceLabel || target?.forceLabel) score += 200_000;
  return score - index / 10_000;
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
  const rankedNodes = nodes
    .map((node, index) => ({ node, index, score: nodeSignalScore(node, index) }))
    .sort((left, right) => right.score - left.score)
    .slice(0, LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES)
    .sort((left, right) => left.index - right.index);
  const clusteredPositions = buildClusteredOverviewPositions(rankedNodes);
  const overviewNodes: LargeGraphNode[] = rankedNodes.map(({ node, index }) => {
    const fallback = fallbackPosition(index, total);
    const data = node.data;
    const position = clusteredPositions.get(node.id) ?? fallback;
    return {
      id: node.id,
      x: position.x,
      y: position.y,
      label: data.label,
      color: NODE_COLOR_MAP[data.nodeType] ?? "#71717a",
      size: nodeSize(data),
      nodeType: data.nodeType,
      severity: data.severity,
      highlighted: data.highlighted === true,
      hidden: data.dimmed === true,
      forceLabel:
        data.highlighted === true ||
        data.nodeType === "agent" ||
        data.nodeType === "server" ||
        data.nodeType === "sharedServer" ||
        data.nodeType === "credential" ||
        data.nodeType === "tool",
    };
  });
  const nodeById = new Map(overviewNodes.map((node) => [node.id, node]));
  const drawableEdges = edges
    .map((edge, index) => ({ edge, index, score: edgeSignalScore(edge, nodeById, index) }))
    .filter(({ edge }) => nodeById.has(edge.source) && nodeById.has(edge.target))
    .sort((left, right) => right.score - left.score)
    .slice(0, LARGE_GRAPH_OVERVIEW_MAX_RENDERED_EDGES)
    .sort((left, right) => left.index - right.index);
  const overviewEdges: LargeGraphEdge[] = drawableEdges.map(({ edge, index }) => {
    const relationship = edgeRelationship(edge);
    return {
      id: edge.id || `${edge.source}:${edge.target}:${relationship}:${index}`,
      source: edge.source,
      target: edge.target,
      relationship,
      color: RELATIONSHIP_COLOR_MAP[relationship] ?? "#52525b",
      size: edgeSize(edge),
      hidden: edge.hidden === true,
    };
  });

  return {
    nodes: overviewNodes,
    edges: overviewEdges,
    nodeById,
    sourceNodeCount: nodes.length,
    sourceEdgeCount: edges.length,
    omittedNodeCount: Math.max(0, nodes.length - overviewNodes.length),
    omittedEdgeCount: Math.max(0, edges.length - overviewEdges.length),
  };
}
