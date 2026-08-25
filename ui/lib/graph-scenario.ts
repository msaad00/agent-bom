import type {
  GraphScenarioComparisonResponse,
  GraphScenarioDifference,
} from "@/lib/api-types";
import type { UnifiedGraphResponse } from "@/lib/api";
import type { UnifiedEdge, UnifiedNode } from "@/lib/graph-schema";

export type GraphScenarioViewState = "current" | "proposed" | "difference";

export function parseGraphScenarioViewState(
  value: string | null | undefined,
): GraphScenarioViewState {
  return value === "proposed" || value === "difference" ? value : "current";
}

function cloneNode(node: UnifiedNode): UnifiedNode {
  return {
    ...node,
    attributes: { ...node.attributes },
    compliance_tags: [...node.compliance_tags],
    data_sources: [...node.data_sources],
    dimensions: { ...node.dimensions },
  };
}

function cloneEdge(edge: UnifiedEdge): UnifiedEdge {
  return { ...edge, evidence: { ...edge.evidence } };
}

/**
 * Builds the proposed canvas from the server-authored full proposed graph.
 * The observed graph is used only for response metadata and is never mutated.
 * Sorting makes equivalent comparison payloads render identically regardless
 * of storage or network ordering.
 */
export function proposedGraphFromComparison(
  observed: UnifiedGraphResponse,
  comparison: GraphScenarioComparisonResponse | null,
): UnifiedGraphResponse | null {
  if (!comparison?.available) return null;
  const nodes = comparison.proposed.nodes
    .map(cloneNode)
    .sort((left, right) => left.id.localeCompare(right.id));
  const edges = comparison.proposed.edges
    .map(cloneEdge)
    .sort((left, right) => left.id.localeCompare(right.id));
  const nodeTypes: Record<string, number> = {};
  const severityCounts: Record<string, number> = {};
  const relationshipTypes: Record<string, number> = {};
  for (const node of nodes) {
    nodeTypes[node.entity_type] = (nodeTypes[node.entity_type] ?? 0) + 1;
    severityCounts[node.severity] = (severityCounts[node.severity] ?? 0) + 1;
  }
  for (const edge of edges) {
    relationshipTypes[edge.relationship] =
      (relationshipTypes[edge.relationship] ?? 0) + 1;
  }
  return {
    ...observed,
    nodes,
    edges,
    // Attack paths remain observed evidence. A proposal may touch one, but it
    // cannot create a detected path until a later scan observes that state.
    attack_paths: [],
    interaction_risks: [],
    stats: {
      ...observed.stats,
      total_nodes: comparison.proposed.node_count,
      total_edges: comparison.proposed.edge_count,
      node_types: nodeTypes,
      severity_counts: severityCounts,
      relationship_types: relationshipTypes,
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: {
      total:
        comparison.proposed.completeness?.total ??
        comparison.proposed.node_count,
      offset: 0,
      limit: nodes.length,
      has_more:
        comparison.proposed.completeness?.truncated ??
        nodes.length < comparison.proposed.node_count,
    },
    ...(comparison.proposed.completeness
      ? { completeness: { ...comparison.proposed.completeness } }
      : {}),
  };
}

function differenceItemLabel(item: unknown): string {
  if (typeof item === "string") return item;
  if (Array.isArray(item)) return item.map(differenceItemLabel).join(" → ");
  if (item && typeof item === "object") {
    const record = item as Record<string, unknown>;
    for (const key of ["label", "id", "node_id", "edge_id", "relationship"]) {
      if (typeof record[key] === "string" && record[key]) return record[key];
    }
  }
  return "Unnamed change";
}

export interface GraphScenarioDifferenceGroup {
  id: keyof Pick<
    GraphScenarioDifference,
    | "nodes_added"
    | "nodes_removed"
    | "nodes_changed"
    | "edges_added"
    | "edges_removed"
  >;
  label: string;
  items: string[];
}

export function graphScenarioDifferenceGroups(
  difference: GraphScenarioDifference,
): GraphScenarioDifferenceGroup[] {
  const definitions: Array<
    readonly [GraphScenarioDifferenceGroup["id"], string]
  > = [
    ["nodes_added", "Nodes added"],
    ["nodes_removed", "Nodes removed"],
    ["nodes_changed", "Nodes changed"],
    ["edges_added", "Relationships added"],
    ["edges_removed", "Relationships removed"],
  ];
  return definitions.map(([id, label]) => ({
    id,
    label,
    items: difference[id].map(differenceItemLabel),
  }));
}
