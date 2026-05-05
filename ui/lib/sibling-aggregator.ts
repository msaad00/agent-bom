/**
 * Sibling aggregation for the unified graph (#2257).
 *
 * Detects fan-outs in the rendered graph — a parent node with N or more
 * children of the same node type connected by the same edge kind — and
 * collapses those N children into a single "+N tools" / "+N packages"
 * cluster pill node. Click the pill to restore the children in place.
 *
 * The aggregation runs on the layout-ready node/edge arrays that
 * `buildUnifiedFlowGraph` produces. It is purely structural — it does not
 * touch the schema or the Python side. The cluster pill is rendered by
 * `clusterPillNode` in `lineage-nodes.tsx`.
 *
 * Threshold N is tunable per filter preset:
 *   focused mode  → 5
 *   expanded mode → 20
 */

import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

export const CLUSTER_PILL_NODE_TYPE = "clusterPillNode";
export const CLUSTER_ID_PREFIX = "cluster:";

export type ClusterPillData = LineageNodeData & {
  /** Total siblings collapsed under this pill. */
  count: number;
  /** Original child node IDs the pill currently hides. */
  members: string[];
  /** The parent the cluster sits under (display + expand provenance). */
  parentId: string;
  /** The node type the children share (drives icon + label). */
  childType: LineageNodeType;
  /** Edge kind shared by every collapsed parent→child link (for restore). */
  edgeKey: string;
  /** True when xyflow should render this as a pulsing "click to expand" pill. */
  isCluster: true;
};

export interface SiblingAggregateOptions {
  /** Minimum sibling count before a fan-out collapses. Defaults to 5. */
  thresholdN?: number;
  /** IDs that must remain expanded (e.g. user clicked-through clusters). */
  expandedClusterIds?: ReadonlySet<string>;
}

export interface SiblingAggregateResult {
  /**
   * Mixed list of original `LineageNodeData` nodes plus synthetic
   * cluster-pill nodes whose `data` carries `ClusterPillData` fields.
   * Use `isClusterPillNode()` to discriminate at the consumer.
   */
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  /**
   * Map of cluster id → member node IDs. Useful for the consumer's
   * "expand pill" callback — pop the id, add the members back to
   * `expandedClusterIds`, and re-run the aggregator.
   */
  clusters: Map<string, { parentId: string; childType: LineageNodeType; members: string[] }>;
}

/**
 * Threshold for the "focused" filter preset — operator triage view.
 * Five visible siblings is enough context, more is noise.
 */
export const FOCUSED_AGGREGATION_THRESHOLD = 5;

/**
 * Threshold for the "expanded" filter preset — topology review view.
 * Twenty visible siblings is plenty before the canvas gets unreadable.
 */
export const EXPANDED_AGGREGATION_THRESHOLD = 20;

interface SiblingGroupKey {
  parentId: string;
  edgeKind: string;
  childType: LineageNodeType;
}

function siblingGroupKey(key: SiblingGroupKey): string {
  return `${key.parentId}::${key.edgeKind}::${key.childType}`;
}

function clusterId(parentId: string, childType: LineageNodeType, edgeKind: string): string {
  return `${CLUSTER_ID_PREFIX}${parentId}:${childType}:${edgeKind}`;
}

/**
 * Walk parent→child fan-outs and replace siblings with a cluster pill.
 *
 * The function is total: when no parent fans out beyond the threshold the
 * input nodes/edges pass through unchanged and `clusters` is empty. The
 * threshold is read per-call so callers can swap it on filter-preset change
 * without rebuilding the function.
 */
export function aggregateSiblings(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
  options: SiblingAggregateOptions = {},
): SiblingAggregateResult {
  const thresholdN = Math.max(2, options.thresholdN ?? FOCUSED_AGGREGATION_THRESHOLD);
  const expanded = options.expandedClusterIds ?? new Set<string>();

  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  // Group children by (parent, edge-kind, child-type). The edge kind is
  // pulled from the edge's `data.relationship` (set by buildUnifiedFlowGraph)
  // and falls back to the edge id so unknown shapes still cluster sensibly.
  const groups = new Map<
    string,
    {
      parentId: string;
      edgeKind: string;
      childType: LineageNodeType;
      childIds: string[];
      edgeIds: Set<string>;
    }
  >();

  for (const edge of edges) {
    const parent = nodeById.get(edge.source);
    const child = nodeById.get(edge.target);
    if (!parent || !child) continue;
    const childType = (child.data as LineageNodeData).nodeType;
    if (!childType) continue;
    const edgeKind = readEdgeKind(edge);
    const key = siblingGroupKey({ parentId: parent.id, edgeKind, childType });
    const bucket = groups.get(key);
    if (bucket) {
      bucket.childIds.push(child.id);
      bucket.edgeIds.add(edge.id);
    } else {
      groups.set(key, {
        parentId: parent.id,
        edgeKind,
        childType,
        childIds: [child.id],
        edgeIds: new Set([edge.id]),
      });
    }
  }

  // Track which children + parent→child edges to drop, plus the cluster
  // nodes/edges to add. A child is only collapsed when it has exactly one
  // parent in the visible graph — multi-parent children would lose context
  // if hidden under one cluster, so we leave them on the canvas.
  const childParentCount = new Map<string, number>();
  for (const edge of edges) {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) continue;
    childParentCount.set(edge.target, (childParentCount.get(edge.target) ?? 0) + 1);
  }

  const dropNodeIds = new Set<string>();
  const dropEdgeIds = new Set<string>();
  const addNodes: Node<LineageNodeData>[] = [];
  const addEdges: Edge[] = [];
  const clusters: SiblingAggregateResult["clusters"] = new Map();

  for (const group of groups.values()) {
    if (group.childIds.length < thresholdN) continue;

    // Skip children that have multiple parents — collapsing them under one
    // cluster would silently drop edges to other parents, which is exactly
    // the kind of context loss the focus / readability features must avoid.
    const collapsible = group.childIds.filter(
      (id) => (childParentCount.get(id) ?? 0) === 1,
    );
    if (collapsible.length < thresholdN) continue;

    const id = clusterId(group.parentId, group.childType, group.edgeKind);

    // Operator already clicked the pill once — leave the children in place
    // and skip emitting a cluster node. The expand-state lives outside this
    // pure function so the consumer can re-aggregate without losing state.
    if (expanded.has(id)) continue;

    for (const childId of collapsible) dropNodeIds.add(childId);
    // Drop every visible parent→child edge that touched a collapsed child.
    for (const edge of edges) {
      if (
        edge.source === group.parentId &&
        dropNodeIds.has(edge.target) &&
        readEdgeKind(edge) === group.edgeKind
      ) {
        dropEdgeIds.add(edge.id);
      }
    }

    const data: ClusterPillData = {
      label: clusterLabel(group.childType, collapsible.length),
      nodeType: group.childType,
      count: collapsible.length,
      members: collapsible,
      parentId: group.parentId,
      childType: group.childType,
      edgeKey: group.edgeKind,
      isCluster: true,
    };

    addNodes.push({
      id,
      type: CLUSTER_PILL_NODE_TYPE,
      position: { x: 0, y: 0 },
      // ClusterPillData is a structural superset of LineageNodeData so
      // the cast keeps the canvas's typed renderers happy without
      // widening every consumer's Node generic.
      data: data as unknown as LineageNodeData,
    });

    addEdges.push({
      id: `${id}=>edge`,
      source: group.parentId,
      target: id,
      type: "smoothstep",
      // Carry the original relationship so colour mapping / legend stays
      // consistent — the cluster pill represents the same edge kind as the
      // ones it absorbed.
      data: { relationship: group.edgeKind, isClusterEdge: true },
      style: { strokeDasharray: "4 4", opacity: 0.85 },
      markerEnd: { type: "arrowclosed" as never },
    });

    clusters.set(id, {
      parentId: group.parentId,
      childType: group.childType,
      members: collapsible,
    });
  }

  const filteredNodes = nodes.filter((node) => !dropNodeIds.has(node.id));
  const filteredEdges = edges.filter((edge) => !dropEdgeIds.has(edge.id));

  return {
    nodes: [...filteredNodes, ...addNodes],
    edges: [...filteredEdges, ...addEdges],
    clusters,
  };
}

/** Operator-friendly cluster pill copy. Singular vs plural matters here. */
function clusterLabel(childType: LineageNodeType, count: number): string {
  const noun = CHILD_TYPE_NOUNS[childType] ?? childType;
  return `+${count} ${noun}${count === 1 ? "" : "s"}`;
}

const CHILD_TYPE_NOUNS: Partial<Record<LineageNodeType, string>> = {
  agent: "agent",
  server: "server",
  package: "package",
  vulnerability: "CVE",
  misconfiguration: "misconfig",
  credential: "credential",
  tool: "tool",
  model: "model",
  dataset: "dataset",
  container: "container",
  cloudResource: "cloud resource",
  user: "user",
  group: "group",
  serviceAccount: "service account",
  provider: "provider",
  environment: "environment",
  fleet: "fleet",
  cluster: "cluster",
  sharedServer: "shared server",
};

function readEdgeKind(edge: Edge): string {
  const data = edge.data as Record<string, unknown> | undefined;
  if (data && typeof data["relationship"] === "string") return data["relationship"];
  if (typeof edge.label === "string" && edge.label.trim().length > 0) return edge.label;
  return edge.type ?? "edge";
}

/**
 * Type-guard: true when the node is a cluster pill emitted by
 * `aggregateSiblings`. Useful for click handlers that need to branch
 * between regular node selection and "expand cluster" behaviour.
 */
export function isClusterPillNode(node: Node<LineageNodeData>): boolean {
  return (node.data as unknown as ClusterPillData | undefined)?.isCluster === true;
}
