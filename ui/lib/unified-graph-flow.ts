import { MarkerType, type Edge, type Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { LegendItem } from "@/lib/graph-utils";
import {
  EntityType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
  RELATIONSHIP_COLOR_MAP,
  RelationshipType,
} from "@/lib/graph-schema";

export interface UnifiedGraphFlowFilters {
  layers: Record<LineageNodeType, boolean>;
  severity: string | null;
  agentName: string | null;
  vulnOnly: boolean;
  maxDepth: number;
}

export interface UnifiedGraphFlowSummary {
  agents: number;
  servers: number;
  findings: number;
  critical: number;
  attackPaths: number;
  runtimeEdges: number;
}

export interface UnifiedGraphFlowResult {
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  agentNames: string[];
  legend: LegendItem[];
  summary: UnifiedGraphFlowSummary;
}

const ENTITY_TO_NODE_TYPE: Partial<Record<EntityType | string, LineageNodeType>> = {
  [EntityType.PROVIDER]: "provider",
  [EntityType.AGENT]: "agent",
  [EntityType.USER]: "user",
  [EntityType.GROUP]: "group",
  [EntityType.SERVICE_ACCOUNT]: "serviceAccount",
  [EntityType.ENVIRONMENT]: "environment",
  [EntityType.FLEET]: "fleet",
  [EntityType.CLUSTER]: "cluster",
  [EntityType.SERVER]: "server",
  [EntityType.PACKAGE]: "package",
  [EntityType.TOOL]: "tool",
  [EntityType.CREDENTIAL]: "credential",
  [EntityType.VULNERABILITY]: "vulnerability",
  [EntityType.MISCONFIGURATION]: "misconfiguration",
  [EntityType.MODEL]: "model",
  [EntityType.DATASET]: "dataset",
  [EntityType.CONTAINER]: "container",
  [EntityType.CLOUD_RESOURCE]: "cloudResource",
};

const FLOW_NODE_TYPES: Record<LineageNodeType, string> = {
  provider: "providerNode",
  agent: "agentNode",
  user: "userNode",
  group: "groupNode",
  serviceAccount: "serviceAccountNode",
  environment: "environmentNode",
  fleet: "fleetNode",
  cluster: "clusterNode",
  server: "serverNode",
  sharedServer: "sharedServerNode",
  package: "packageNode",
  vulnerability: "vulnNode",
  credential: "credentialNode",
  tool: "toolNode",
  model: "modelNode",
  dataset: "datasetNode",
  container: "containerNode",
  cloudResource: "cloudResourceNode",
  misconfiguration: "misconfigNode",
};

const NODE_LABELS: Record<LineageNodeType, string> = {
  provider: "Provider",
  agent: "Agent",
  user: "User",
  group: "Group",
  serviceAccount: "Service Account",
  environment: "Environment",
  fleet: "Fleet",
  cluster: "Cluster",
  server: "Server",
  sharedServer: "Shared Server",
  package: "Package",
  vulnerability: "Vulnerability",
  credential: "Credential",
  tool: "Tool",
  model: "Model",
  dataset: "Dataset",
  container: "Container",
  cloudResource: "Cloud Resource",
  misconfiguration: "Misconfiguration",
};

const NODE_COLORS: Record<LineageNodeType, string> = {
  provider: "#71717a",
  agent: "#10b981",
  user: "#34d399",
  group: "#d946ef",
  serviceAccount: "#fbbf24",
  environment: "#14b8a6",
  fleet: "#22d3ee",
  cluster: "#38bdf8",
  server: "#3b82f6",
  sharedServer: "#22d3ee",
  package: "#52525b",
  vulnerability: "#ef4444",
  credential: "#f59e0b",
  tool: "#a855f7",
  model: "#8b5cf6",
  dataset: "#06b6d4",
  container: "#6366f1",
  cloudResource: "#0ea5e9",
  misconfiguration: "#f97316",
};

const FINDING_NODE_TYPES = new Set<LineageNodeType>(["vulnerability", "misconfiguration"]);
const RUNTIME_RELATIONSHIPS = new Set<string>([
  RelationshipType.INVOKED,
  RelationshipType.ACCESSED,
  RelationshipType.DELEGATED_TO,
]);
const ANIMATED_RELATIONSHIPS = new Set<string>([
  RelationshipType.VULNERABLE_TO,
  RelationshipType.EXPLOITABLE_VIA,
  RelationshipType.LATERAL_PATH,
  RelationshipType.SHARES_SERVER,
  RelationshipType.SHARES_CRED,
  ...RUNTIME_RELATIONSHIPS,
]);
const DASHED_RELATIONSHIPS = new Set<string>([
  RelationshipType.EXPOSES_CRED,
  RelationshipType.SHARES_SERVER,
  RelationshipType.SHARES_CRED,
  RelationshipType.LATERAL_PATH,
  ...RUNTIME_RELATIONSHIPS,
]);

export function buildUnifiedFlowGraph(
  graph: UnifiedGraphData,
  filters: UnifiedGraphFlowFilters,
): UnifiedGraphFlowResult {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const outgoing = buildAdjacency(graph.edges, "source");
  const incoming = buildAdjacency(graph.edges, "target");
  const undirected = buildUndirectedAdjacency(graph.edges);

  const agentNames = graph.nodes
    .filter((node) => node.entity_type === EntityType.AGENT)
    .map((node) => node.label)
    .sort((a, b) => a.localeCompare(b));

  const visibleIds = deriveVisibleNodeIds(graph, filters, undirected);

  const nodes: Node<LineageNodeData>[] = [];
  for (const node of graph.nodes) {
    if (!visibleIds.has(node.id)) continue;
    const nodeType = mapNodeType(node);
    if (!nodeType || !filters.layers[nodeType]) continue;
    nodes.push({
      id: node.id,
      type: FLOW_NODE_TYPES[nodeType],
      position: { x: 0, y: 0 },
      data: toLineageData(node, nodeType, outgoing, incoming, nodeById),
      className: isCriticalNode(node) ? "node-critical-pulse" : undefined,
    });
  }

  const prePrunedNodeIds = new Set(nodes.map((node) => node.id));
  const prePrunedEdges: Edge[] = graph.edges
    .filter((edge) => prePrunedNodeIds.has(edge.source) && prePrunedNodeIds.has(edge.target))
    .map((edge) => toFlowEdge(edge));

  const connectedNodeIds = new Set<string>();
  for (const edge of prePrunedEdges) {
    connectedNodeIds.add(edge.source);
    connectedNodeIds.add(edge.target);
  }
  const anchorNodeIds = new Set(
    nodes
      .filter((node) => node.data.nodeType === "agent" || FINDING_NODE_TYPES.has(node.data.nodeType))
      .map((node) => node.id),
  );
  const prunedNodes = nodes.filter((node) => connectedNodeIds.has(node.id) || anchorNodeIds.has(node.id));
  const visibleNodeIds = new Set(prunedNodes.map((node) => node.id));
  const edges = prePrunedEdges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target));

  const visibleNodeTypes = new Set(prunedNodes.map((node) => node.data.nodeType));
  const summary = buildSummary(prunedNodes, graph);
  const legend = legendForNodeTypes(visibleNodeTypes);

  return { nodes: prunedNodes, edges, agentNames, legend, summary };
}

function deriveVisibleNodeIds(
  graph: UnifiedGraphData,
  filters: UnifiedGraphFlowFilters,
  undirected: Map<string, Set<string>>,
): Set<string> {
  let visible = new Set(graph.nodes.map((node) => node.id));

  if (filters.agentName) {
    const seeds = graph.nodes
      .filter((node) => node.entity_type === EntityType.AGENT && node.label === filters.agentName)
      .map((node) => node.id);
    if (seeds.length > 0) {
      visible = intersectSets(visible, collectNeighborhood(seeds, undirected, Math.max(filters.maxDepth, 2)));
    }
  }

  if (filters.vulnOnly || filters.severity) {
    const findingSeeds = graph.nodes
      .filter((node) => {
        const nodeType = mapNodeType(node);
        if (!nodeType || !FINDING_NODE_TYPES.has(nodeType)) return false;
        if (!filters.severity) return true;
        return meetsSeverityThreshold(node.severity, filters.severity);
      })
      .sort((left, right) => {
        const severityDiff = severityRank(right.severity) - severityRank(left.severity);
        if (severityDiff !== 0) return severityDiff;
        return (right.risk_score ?? 0) - (left.risk_score ?? 0);
      })
      .slice(0, filters.agentName ? 14 : 18)
      .map((node) => node.id);
    visible = intersectSets(visible, collectNeighborhood(findingSeeds, undirected, Math.max(2, filters.maxDepth - 1)));
  }

  visible = new Set(
    [...visible].filter((nodeId) => {
      const node = graph.nodes.find((entry) => entry.id === nodeId);
      if (!node) return false;
      const nodeType = mapNodeType(node);
      if (!nodeType) return false;
      if (!filters.layers[nodeType]) return false;
      if (
        filters.severity &&
        FINDING_NODE_TYPES.has(nodeType) &&
        !meetsSeverityThreshold(node.severity, filters.severity)
      ) {
        return false;
      }
      return true;
    }),
  );

  return visible;
}

function toLineageData(
  node: UnifiedNode,
  nodeType: LineageNodeType,
  outgoing: Map<string, UnifiedEdge[]>,
  incoming: Map<string, UnifiedEdge[]>,
  nodeById: Map<string, UnifiedNode>,
): LineageNodeData {
  const attributes = node.attributes ?? {};
  const data: LineageNodeData = {
    label: node.label,
    nodeType,
    entityType: String(node.entity_type),
    status: String(node.status ?? ""),
    riskScore: node.risk_score,
    severity: node.severity,
    firstSeen: node.first_seen,
    lastSeen: node.last_seen,
    dataSources: node.data_sources ?? [],
    complianceTags: node.compliance_tags ?? [],
    attributes,
    isCritical: isCriticalNode(node),
  };

  switch (nodeType) {
    case "provider":
      data.agentCount = countOutgoing(node.id, outgoing, RelationshipType.HOSTS);
      break;
    case "agent":
      data.agentType = stringAttr(node, "agent_type");
      data.agentStatus = stringAttr(node, "status");
      data.serverCount = countOutgoing(node.id, outgoing, RelationshipType.USES);
      data.packageCount = countReachableTypes(node.id, outgoing, nodeById, new Set([EntityType.PACKAGE]), 3);
      data.vulnCount = countReachableTypes(
        node.id,
        outgoing,
        nodeById,
        new Set([EntityType.VULNERABILITY, EntityType.MISCONFIGURATION]),
        5,
      );
      break;
    case "user":
    case "group":
    case "serviceAccount":
      data.description =
        stringAttr(node, "owner") ||
        stringAttr(node, "email") ||
        stringAttr(node, "description");
      break;
    case "environment":
    case "fleet":
    case "cluster":
      data.description =
        stringAttr(node, "environment") ||
        stringAttr(node, "provider") ||
        stringAttr(node, "cluster_type") ||
        stringAttr(node, "description");
      data.agentCount = countReachableTypes(node.id, outgoing, nodeById, new Set([EntityType.AGENT]), 4);
      data.serverCount = countReachableTypes(node.id, outgoing, nodeById, new Set([EntityType.SERVER]), 4);
      break;
    case "server":
      data.command = stringAttr(node, "command") || stringAttr(node, "transport") || stringAttr(node, "url");
      data.toolCount = countOutgoing(node.id, outgoing, RelationshipType.PROVIDES_TOOL);
      data.credentialCount = countOutgoing(node.id, outgoing, RelationshipType.EXPOSES_CRED);
      data.packageCount = countOutgoing(node.id, outgoing, RelationshipType.DEPENDS_ON);
      data.vulnCount = countReachableTypes(
        node.id,
        outgoing,
        nodeById,
        new Set([EntityType.VULNERABILITY, EntityType.MISCONFIGURATION]),
        4,
      );
      break;
    case "package":
      data.ecosystem = stringAttr(node, "ecosystem");
      data.version = stringAttr(node, "version");
      data.vulnCount = countOutgoing(node.id, outgoing, RelationshipType.VULNERABLE_TO);
      break;
    case "vulnerability":
      data.cvssScore = numberAttr(node, "cvss_score");
      data.epssScore = numberAttr(node, "epss_score");
      data.isKev = booleanAttr(node, "is_kev");
      data.fixedVersion = stringAttr(node, "fixed_version");
      data.owaspTags = complianceSubset(node.compliance_tags, "OWASP");
      data.atlasTags = complianceSubset(node.compliance_tags, "ATLAS");
      break;
    case "misconfiguration":
      data.description =
        stringAttr(node, "recommendation") ||
        stringAttr(node, "evidence") ||
        stringAttr(node, "rule_id") ||
        stringAttr(node, "check_id");
      break;
    case "credential":
      data.serverName = firstLinkedLabel(node.id, incoming, nodeById, EntityType.SERVER);
      break;
    case "tool":
      data.description = stringAttr(node, "description");
      break;
    case "model":
      data.description = stringAttr(node, "framework") || stringAttr(node, "source");
      data.version = stringAttr(node, "hash");
      break;
    case "dataset":
      data.description = stringAttr(node, "description") || stringAttr(node, "source_url");
      data.version = stringAttr(node, "version");
      break;
    case "container":
      data.description = stringAttr(node, "container_image") || stringAttr(node, "framework");
      break;
    case "cloudResource":
      data.description = stringAttr(node, "cloud_provider") || stringAttr(node, "source_section");
      break;
    default:
      break;
  }

  return data;
}

function toFlowEdge(edge: UnifiedEdge): Edge {
  const relationship = String(edge.relationship);
  const color = RELATIONSHIP_COLOR_MAP[relationship] ?? "#52525b";
  const dashed = DASHED_RELATIONSHIPS.has(relationship);
  const animated = ANIMATED_RELATIONSHIPS.has(relationship) || edge.weight >= 4;

  return {
    id: edge.id || `${edge.source}:${relationship}:${edge.target}`,
    source: edge.source,
    target: edge.target,
    type: "smoothstep",
    animated,
    style: {
      stroke: color,
      strokeWidth: Math.min(Math.max(edge.weight, 1.2), 4.5),
      opacity: animated ? 0.95 : 0.82,
      strokeDasharray: dashed ? "6 3" : undefined,
    },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color,
      width: 14,
      height: 10,
    },
  };
}

function buildSummary(
  nodes: Node<LineageNodeData>[],
  graph: UnifiedGraphData,
): UnifiedGraphFlowSummary {
  const findings = nodes.filter((node) => FINDING_NODE_TYPES.has(node.data.nodeType)).length;
  const critical = nodes.filter(
    (node) =>
      FINDING_NODE_TYPES.has(node.data.nodeType) &&
      (node.data.severity?.toLowerCase() === "critical" || node.data.isCritical),
  ).length;
  const visibleNodeIds = new Set(nodes.map((node) => node.id));
  const runtimeEdges = graph.edges.filter(
    (edge) =>
      visibleNodeIds.has(edge.source) &&
      visibleNodeIds.has(edge.target) &&
      RUNTIME_RELATIONSHIPS.has(String(edge.relationship)),
  ).length;

  return {
    agents: nodes.filter((node) => node.data.nodeType === "agent").length,
    servers: nodes.filter((node) => node.data.nodeType === "server").length,
    findings,
    critical,
    attackPaths: graph.attack_paths.length,
    runtimeEdges,
  };
}

function legendForNodeTypes(nodeTypes: Set<LineageNodeType>): LegendItem[] {
  return [
    "provider",
    "agent",
    "user",
    "group",
    "serviceAccount",
    "environment",
    "fleet",
    "cluster",
    "server",
    "package",
    "model",
    "dataset",
    "container",
    "cloudResource",
    "credential",
    "tool",
    "vulnerability",
    "misconfiguration",
  ]
    .filter((nodeType): nodeType is LineageNodeType => nodeTypes.has(nodeType as LineageNodeType))
    .map((nodeType) => ({
      label: NODE_LABELS[nodeType],
      color: NODE_COLORS[nodeType],
      shape: legendShapeForNodeType(nodeType),
    }));
}

function buildAdjacency(edges: UnifiedEdge[], side: "source" | "target"): Map<string, UnifiedEdge[]> {
  const map = new Map<string, UnifiedEdge[]>();
  for (const edge of edges) {
    const key = side === "source" ? edge.source : edge.target;
    const existing = map.get(key);
    if (existing) {
      existing.push(edge);
    } else {
      map.set(key, [edge]);
    }
  }
  return map;
}

function buildUndirectedAdjacency(edges: UnifiedEdge[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const edge of edges) {
    addNeighbor(map, edge.source, edge.target);
    addNeighbor(map, edge.target, edge.source);
  }
  return map;
}

function collectNeighborhood(
  seeds: string[],
  adjacency: Map<string, Set<string>>,
  maxDepth: number,
): Set<string> {
  if (seeds.length === 0) return new Set();

  const visited = new Set(seeds);
  const queue: Array<[string, number]> = seeds.map((seed) => [seed, 0]);

  while (queue.length > 0) {
    const [current, depth] = queue.shift()!;
    if (depth >= maxDepth) continue;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (visited.has(neighbor)) continue;
      visited.add(neighbor);
      queue.push([neighbor, depth + 1]);
    }
  }

  return visited;
}

function countOutgoing(
  nodeId: string,
  outgoing: Map<string, UnifiedEdge[]>,
  relationship: RelationshipType,
): number {
  return (outgoing.get(nodeId) ?? []).filter((edge) => edge.relationship === relationship).length;
}

function countReachableTypes(
  startId: string,
  outgoing: Map<string, UnifiedEdge[]>,
  nodeById: Map<string, UnifiedNode>,
  entityTypes: Set<EntityType>,
  maxDepth: number,
): number {
  const visited = new Set<string>([startId]);
  const matched = new Set<string>();
  const queue: Array<[string, number]> = [[startId, 0]];

  while (queue.length > 0) {
    const [current, depth] = queue.shift()!;
    if (depth >= maxDepth) continue;
    for (const edge of outgoing.get(current) ?? []) {
      const next = edge.target;
      if (visited.has(next)) continue;
      visited.add(next);
      const nextNode = nodeById.get(next);
      if (nextNode && entityTypes.has(nextNode.entity_type as EntityType)) {
        matched.add(next);
      }
      queue.push([next, depth + 1]);
    }
  }

  return matched.size;
}

function firstLinkedLabel(
  nodeId: string,
  incoming: Map<string, UnifiedEdge[]>,
  nodeById: Map<string, UnifiedNode>,
  entityType: EntityType,
): string {
  for (const edge of incoming.get(nodeId) ?? []) {
    const sourceNode = nodeById.get(edge.source);
    if (sourceNode?.entity_type === entityType) {
      return sourceNode.label;
    }
  }
  return "";
}

function intersectSets(left: Set<string>, right: Set<string>): Set<string> {
  if (right.size === 0) return new Set();
  return new Set([...left].filter((value) => right.has(value)));
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
  none: 0,
};

function severityRank(severity: string | null | undefined): number {
  return SEVERITY_RANK[String(severity ?? "unknown").toLowerCase()] ?? 0;
}

function meetsSeverityThreshold(
  severity: string | null | undefined,
  threshold: string | null | undefined,
): boolean {
  if (!threshold) return true;
  return severityRank(severity) >= severityRank(threshold);
}

function addNeighbor(map: Map<string, Set<string>>, source: string, target: string): void {
  const existing = map.get(source);
  if (existing) {
    existing.add(target);
  } else {
    map.set(source, new Set([target]));
  }
}

function legendShapeForNodeType(nodeType: LineageNodeType): LegendItem["shape"] {
  if (nodeType === "vulnerability" || nodeType === "misconfiguration") return "diamond";
  if (nodeType === "server" || nodeType === "sharedServer" || nodeType === "container" || nodeType === "cloudResource") return "square";
  if (nodeType === "package" || nodeType === "tool" || nodeType === "model" || nodeType === "dataset") return "pill";
  return "dot";
}

function mapNodeType(node: UnifiedNode): LineageNodeType | null {
  return ENTITY_TO_NODE_TYPE[String(node.entity_type)] ?? null;
}

function stringAttr(node: UnifiedNode, key: string): string {
  const value = node.attributes?.[key];
  return typeof value === "string" ? value : "";
}

function numberAttr(node: UnifiedNode, key: string): number | undefined {
  const value = node.attributes?.[key];
  return typeof value === "number" ? value : undefined;
}

function booleanAttr(node: UnifiedNode, key: string): boolean {
  return node.attributes?.[key] === true;
}

function complianceSubset(tags: string[], prefix: string): string[] {
  return tags.filter((tag) => tag.toUpperCase().startsWith(prefix));
}

function isCriticalNode(node: UnifiedNode): boolean {
  if (node.severity?.toLowerCase() === "critical") return true;
  return booleanAttr(node, "is_kev") || (numberAttr(node, "risk_score") ?? 0) >= 8;
}
