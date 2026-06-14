import type { Edge, Node } from "@xyflow/react";

import type { UnifiedGraphResponse } from "@/lib/api";

export type GraphUxGrade = "excellent" | "strong" | "usable" | "weak" | "failing";

export interface GraphUxDimension {
  id: "entities" | "relationships" | "paths" | "evidence" | "readability";
  label: string;
  score: number;
  detail: string;
}

export interface GraphUxEvaluation {
  score: number;
  grade: GraphUxGrade;
  dimensions: GraphUxDimension[];
  warnings: string[];
  stats: {
    sourceNodes: number;
    sourceEdges: number;
    renderedNodes: number;
    renderedEdges: number;
    entityTypes: number;
    relationshipTypes: number;
    attackPaths: number;
    edgeEvidenceRatio: number;
    nodeSourceRatio: number;
    edgeToNodeRatio: number;
  };
}

export function gradeGraphUxScore(score: number): GraphUxGrade {
  if (score >= 92) return "excellent";
  if (score >= 82) return "strong";
  if (score >= 68) return "usable";
  if (score >= 50) return "weak";
  return "failing";
}

export function evaluateGraphUx(
  graph: UnifiedGraphResponse | null,
  renderedNodes: Node[] = [],
  renderedEdges: Edge[] = [],
): GraphUxEvaluation {
  const sourceNodes = graph?.nodes ?? [];
  const sourceEdges = graph?.edges ?? [];
  const attackPaths = graph?.attack_paths ?? [];
  const nodeCount = sourceNodes.length;
  const edgeCount = sourceEdges.length;
  const renderedNodeCount = renderedNodes.length;
  const renderedEdgeCount = renderedEdges.length;
  const entityTypeCount = new Set(sourceNodes.map((node) => String(node.entity_type))).size;
  const relationshipTypeCount = new Set(sourceEdges.map((edge) => String(edge.relationship))).size;
  const edgeEvidenceCount = sourceEdges.filter((edge) => Object.keys(edge.evidence ?? {}).length > 0).length;
  const sourcedNodeCount = sourceNodes.filter((node) => (node.data_sources ?? []).length > 0).length;
  const edgeEvidenceRatio = edgeCount > 0 ? edgeEvidenceCount / edgeCount : 0;
  const nodeSourceRatio = nodeCount > 0 ? sourcedNodeCount / nodeCount : 0;
  const edgeToNodeRatio = nodeCount > 0 ? edgeCount / nodeCount : 0;

  const entityScore = clamp01(entityTypeCount / 7) * 100;
  const relationshipScore = clamp01(relationshipTypeCount / 8) * 100;
  const pathScore = attackPaths.length > 0 ? clamp01(0.65 + attackPaths.length / 10) * 100 : 35;
  const evidenceScore = clamp01((edgeEvidenceRatio * 0.65) + (nodeSourceRatio * 0.35)) * 100;
  const readabilityScore = scoreReadability({
    sourceNodes: nodeCount,
    sourceEdges: edgeCount,
    renderedNodes: renderedNodeCount,
    renderedEdges: renderedEdgeCount,
    edgeToNodeRatio,
  });

  const dimensions: GraphUxDimension[] = [
    {
      id: "entities",
      label: "Entities",
      score: entityScore,
      detail: `${entityTypeCount} types`,
    },
    {
      id: "relationships",
      label: "Relationships",
      score: relationshipScore,
      detail: `${relationshipTypeCount} types`,
    },
    {
      id: "paths",
      label: "Paths",
      score: pathScore,
      detail: `${attackPaths.length} ranked`,
    },
    {
      id: "evidence",
      label: "Evidence",
      score: evidenceScore,
      detail: `${Math.round(edgeEvidenceRatio * 100)}% edge evidence`,
    },
    {
      id: "readability",
      label: "Readability",
      score: readabilityScore,
      detail: `${renderedNodeCount}/${Math.max(nodeCount, renderedNodeCount)} nodes visible`,
    },
  ];

  const score =
    dimensions[0]!.score * 0.16 +
    dimensions[1]!.score * 0.18 +
    dimensions[2]!.score * 0.22 +
    dimensions[3]!.score * 0.22 +
    dimensions[4]!.score * 0.22;

  const warnings: string[] = [];
  if (nodeCount === 0) warnings.push("No graph entities are loaded.");
  if (nodeCount > 0 && edgeCount === 0) warnings.push("Entities are present but relationships are missing.");
  if (attackPaths.length === 0) warnings.push("No ranked attack paths are available for this view.");
  if (edgeEvidenceRatio < 0.15 && edgeCount > 0) warnings.push("Few relationships carry evidence metadata.");
  if (renderedNodeCount > 120) warnings.push("The visible canvas is dense; use filters or search for review.");

  return {
    score,
    grade: gradeGraphUxScore(score),
    dimensions,
    warnings,
    stats: {
      sourceNodes: nodeCount,
      sourceEdges: edgeCount,
      renderedNodes: renderedNodeCount,
      renderedEdges: renderedEdgeCount,
      entityTypes: entityTypeCount,
      relationshipTypes: relationshipTypeCount,
      attackPaths: attackPaths.length,
      edgeEvidenceRatio,
      nodeSourceRatio,
      edgeToNodeRatio,
    },
  };
}

function scoreReadability(input: {
  sourceNodes: number;
  sourceEdges: number;
  renderedNodes: number;
  renderedEdges: number;
  edgeToNodeRatio: number;
}): number {
  if (input.sourceNodes === 0) return 0;
  const visibleRatio = input.sourceNodes > 0 ? input.renderedNodes / input.sourceNodes : 1;
  const densityPenalty = input.edgeToNodeRatio <= 3 ? 1 : Math.max(0.35, 1 - (input.edgeToNodeRatio - 3) * 0.12);
  const canvasPenalty = input.renderedNodes <= 80 ? 1 : Math.max(0.45, 1 - (input.renderedNodes - 80) * 0.005);
  const coverageSignal = input.sourceNodes > 500 ? Math.min(1, visibleRatio + 0.25) : Math.min(1, visibleRatio + 0.1);
  return clamp01(0.45 * densityPenalty + 0.35 * canvasPenalty + 0.2 * coverageSignal) * 100;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}
