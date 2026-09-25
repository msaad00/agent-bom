import Graph from "graphology";
import type { Edge, Node } from "@xyflow/react";

import type {
  LineageNodeData,
  LineageNodeType,
} from "@/components/lineage-nodes";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import {
  buildLargeGraphOverviewModel,
  summarizeLargeGraphOverview,
  type LargeGraphOverviewModel,
  type LargeGraphOverviewSummary,
} from "@/lib/large-graph-overview";
import {
  buildUnifiedFlowGraph,
  type UnifiedGraphFlowFilters,
} from "@/lib/unified-graph-flow";

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
  groups: Array<{ key: string; label: string; x: number; y: number; count: number; loadedCount: number; centerY: number }>;
  connections: Array<{ source: string; target: string; count: number }>;
  scopes: Array<{ key: string; label: string; count: number }>;
}

const SIGMA_DEFAULT_LAYERS: Record<LineageNodeType, boolean> = {
  provider: true,
  agent: true,
  org: true,
  account: true,
  user: true,
  group: true,
  role: true,
  policy: true,
  serviceAccount: true,
  servicePrincipal: true,
  federatedIdentity: true,
  environment: true,
  fleet: true,
  cluster: true,
  server: true,
  sharedServer: true,
  package: true,
  vulnerability: true,
  credential: true,
  tool: true,
  model: true,
  framework: true,
  dataset: true,
  container: true,
  cloudResource: true,
  misconfiguration: true,
  managedIdentity: true,
  accessGrant: true,
  accessPolicy: true,
  driftIncident: true,
  dataStore: true,
  directory: true,
  sourceFile: true,
  configFile: true,
  codeModule: true,
  ciJob: true,
  apiGateway: true,
  toolCall: true,
  blueprint: true,
};

const SIGMA_DEFAULT_FILTERS: UnifiedGraphFlowFilters = {
  layers: SIGMA_DEFAULT_LAYERS,
  severity: null,
  agentName: null,
  vulnOnly: false,
  maxDepth: 8,
};

function edgeIsHighlighted(
  source: { highlighted: boolean; forceLabel: boolean } | undefined,
  target: { highlighted: boolean; forceLabel: boolean } | undefined,
): boolean {
  return Boolean(
    source?.highlighted ||
    target?.highlighted ||
    source?.forceLabel ||
    target?.forceLabel,
  );
}

function scopeParts(node: Node<LineageNodeData>, grouping: "type" | "environment"): string[] {
  if (grouping === "type") return [node.data.nodeType];
  const { dimensions, attributes: attrs = {} } = node.data;
  const text = (value: unknown) => typeof value === "string" ? value.trim() : "";
  return [
    text(dimensions?.cloud_provider) || text(attrs.provider) || text(attrs.cloud_provider) || "Provider unknown",
    text(attrs.account_scope) || text(attrs.account_id) || text(attrs.project_id) || text(attrs.subscription_id) || "Account unknown",
    text(dimensions?.environment) || text(attrs.environment) || "Environment unknown",
  ];
}

export function buildSigmaGraphOverviewModel(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
  grouping: "type" | "environment" = "type",
  scopeKey: string | null = null,
): SigmaGraphOverviewModel {
  const scopeMap = new Map<string, { key: string; label: string; count: number }>();
  const nodeScopes = new Map<string, string>();
  for (const node of nodes) {
    const parts = scopeParts(node, grouping);
    const key = JSON.stringify(parts);
    nodeScopes.set(node.id, key);
    const scope = scopeMap.get(key) ?? { key, label: parts.join(" / "), count: 0 };
    scope.count++;
    scopeMap.set(key, scope);
  }
  const connections = new Map<string, { source: string; target: string; count: number }>();
  if (!scopeKey) for (const edge of edges) {
    const source = nodeScopes.get(edge.source), target = nodeScopes.get(edge.target);
    if (!source || !target || source === target) continue;
    const key = JSON.stringify([source, target]);
    const connection = connections.get(key) ?? { source, target, count: 0 };
    connection.count++;
    connections.set(key, connection);
  }
  if (scopeKey) {
    nodes = nodes.filter(node => nodeScopes.get(node.id) === scopeKey);
    const ids = new Set(nodes.map(node => node.id));
    edges = edges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
  }
  const overview = buildLargeGraphOverviewModel(nodes, edges);
  const groups: SigmaGraphOverviewModel["groups"] = [];
  {
    const scopes = new Map<string, { label: string; nodes: typeof overview.nodes }>();
    for (const node of overview.nodes) {
      const key = nodeScopes.get(node.id)!;
      const parts = JSON.parse(key) as string[];
      const scope = scopes.get(key) ?? { label: parts.join(" / "), nodes: [] };
      scope.nodes.push(node);
      scopes.set(key, scope);
    }
    // Layout groups are visual only: no synthetic assets, edges, or access claims.
    // A golden-angle disk avoids aligned rows; diameter-aware spacing prevents
    // large finding markers from colliding with their smaller neighbors.
    const clusters = [...scopes].map(([key, scope]) => {
      const size = Math.max(...scope.nodes.map(node => node.size));
      const spacing = size * 2 + 18;
      return { key, ...scope, spacing, radius: spacing * Math.sqrt(scope.nodes.length) + size };
    }).sort((a, b) => b.radius - a.radius || a.key.localeCompare(b.key));
    const place = (cluster: typeof clusters[number], x: number, y: number) => {
      cluster.nodes.sort((a, b) => a.id.localeCompare(b.id)).forEach((node, index) => {
        const radius = cluster.spacing * Math.sqrt(index);
        const angle = index * Math.PI * (3 - Math.sqrt(5));
        node.x = x + radius * Math.cos(angle);
        node.y = y + radius * Math.sin(angle);
      });
      groups.push({ key: cluster.key, label: cluster.label, x, y: y + cluster.radius + 36, count: cluster.nodes.length, loadedCount: scopeMap.get(cluster.key)!.count, centerY: y });
    };
    // Pack circles in size-aware rings. Each ring's chord spacing and radial
    // gap protect every cluster's bounding disk, including very uneven estates.
    const gap = 100;
    let index = 0;
    let outerRadius = 0;
    const center = clusters[index++];
    if (center) { place(center, 0, 0); outerRadius = center.radius; }
    while (index < clusters.length) {
      const largest = clusters[index]!.radius;
      const radius = outerRadius + gap + largest;
      const capacity = Math.floor(Math.PI / Math.asin((largest + gap / 2) / radius));
      const count = Math.min(capacity, clusters.length - index);
      for (let slot = 0; slot < count; slot++) {
        const angle = slot * 2 * Math.PI / count + Math.PI / 6;
        place(clusters[index++]!, radius * Math.cos(angle), radius * Math.sin(angle));
      }
      outerRadius = radius + largest;
    }
  }

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
      size: grouping === "environment" ? Math.min(3, node.size / 2) : node.size,
      color: node.color,
      nodeType: node.nodeType,
      severity: node.severity,
      hidden: node.hidden,
      highlighted: node.highlighted,
      // Sigma always draws a `forceLabel` node's label, bypassing both the
      // rendered-size threshold and the label-grid declutter. The overview
      // model force-labels every agent/server/credential/tool, which on a
      // broad estate is hundreds of nodes and paints an unreadable smear. Only
      // force the label for genuinely highlighted nodes here; every other label
      // is governed by the size threshold + grid declutter and appears on zoom
      // or hover. The model's `forceLabel` still drives z-ordering below so
      // high-signal nodes keep drawing on top.
      forceLabel: node.highlighted,
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
    groups,
    connections: [...connections.values()].sort((a, b) => b.count - a.count || a.source.localeCompare(b.source) || a.target.localeCompare(b.target)),
    scopes: [...scopeMap.values()].sort((a, b) => a.label.localeCompare(b.label)),
    overview,
    summary: summarizeLargeGraphOverview(nodes, edges),
  };
}

export function buildSigmaGraphOverviewModelFromUnifiedGraph(
  graph: UnifiedGraphData,
  filters: UnifiedGraphFlowFilters = SIGMA_DEFAULT_FILTERS,
  grouping: "type" | "environment" = "type",
  scopeKey: string | null = null,
): SigmaGraphOverviewModel {
  const flow = buildUnifiedFlowGraph(graph, filters);
  return buildSigmaGraphOverviewModel(flow.nodes, flow.edges, grouping, scopeKey);
}
