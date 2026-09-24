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
  groups: Array<{ key: string; label: string; x: number; y: number; count: number }>;
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

export function buildSigmaGraphOverviewModel(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
  grouping: "type" | "environment" = "type",
): SigmaGraphOverviewModel {
  const overview = buildLargeGraphOverviewModel(nodes, edges);
  const groups: SigmaGraphOverviewModel["groups"] = [];
  if (grouping === "environment") {
    const source = new Map(nodes.map((node) => [node.id, node.data]));
    const scopes = new Map<string, { label: string; nodes: typeof overview.nodes }>();
    for (const node of overview.nodes) {
      const data = source.get(node.id);
      const attrs = data?.attributes ?? {};
      const text = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : "";
      const provider = text(data?.dimensions?.cloud_provider) || text(attrs.provider) || text(attrs.cloud_provider);
      const account = text(attrs.account_scope) || text(attrs.account_id) || text(attrs.project_id) || text(attrs.subscription_id);
      const environment = text(data?.dimensions?.environment) || text(attrs.environment);
      const parts = [provider || "Provider unknown", account || "Account unknown", environment || "Environment unknown"];
      const key = JSON.stringify(parts);
      const scope = scopes.get(key) ?? { label: parts.join(" / "), nodes: [] };
      scope.nodes.push(node);
      scopes.set(key, scope);
    }
    // Presentational groups never introduce synthetic assets or relationships.
    const cellSize = Math.max(240, ...[...scopes.values()].map((scope) => Math.ceil(Math.sqrt(scope.nodes.length)) * 40 + 140));
    const groupColumns = Math.max(1, Math.ceil(Math.sqrt(scopes.size)));
    let groupIndex = 0;
    for (const [key, scope] of [...scopes].sort(([a], [b]) => a.localeCompare(b))) {
      const left = (groupIndex % groupColumns) * cellSize;
      const top = -Math.floor(groupIndex / groupColumns) * cellSize;
      const columns = Math.max(1, Math.ceil(Math.sqrt(scope.nodes.length)));
      scope.nodes.sort((a, b) => a.id.localeCompare(b.id)).forEach((node, index) => {
        node.x = left + (index % columns) * 40;
        node.y = top - Math.floor(index / columns) * 40;
      });
      groups.push({ key, label: scope.label, x: left + (columns - 1) * 20, y: top + 40, count: scope.nodes.length });
      groupIndex += 1;
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
    overview,
    summary: summarizeLargeGraphOverview(nodes, edges),
  };
}

export function buildSigmaGraphOverviewModelFromUnifiedGraph(
  graph: UnifiedGraphData,
  filters: UnifiedGraphFlowFilters = SIGMA_DEFAULT_FILTERS,
  grouping: "type" | "environment" = "type",
): SigmaGraphOverviewModel {
  const flow = buildUnifiedFlowGraph(graph, filters);
  return buildSigmaGraphOverviewModel(flow.nodes, flow.edges, grouping);
}
