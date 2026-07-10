/**
 * Context graph builder — transforms API context-graph data into ReactFlow
 * nodes/edges for the /context page.
 */

import { type Node, type Edge, MarkerType } from "@xyflow/react";
import type {
  LineageNodeData,
  LineageNodeType,
} from "@/components/lineage-nodes";
import {
  readReachBreakdown,
  readReachScore,
  reachEdgeWidth,
  reachStrokeColor,
} from "@/lib/effective-reach";
import { RELATIONSHIP_COLOR_MAP } from "@/lib/graph-schema";

// ─── Types (mirror Python context_graph.to_serializable) ────────────────────

export interface ContextGraphNode {
  id: string;
  kind:
    "agent" | "server" | "credential" | "tool" | "vulnerability" | "iam_role";
  entity_type?: string;
  label: string;
  metadata: Record<string, unknown>;
}

export interface ContextGraphEdge {
  source: string;
  target: string;
  kind: string;
  relationship?: string;
  weight: number;
  metadata: Record<string, unknown>;
}

export interface LateralPath {
  source: string;
  target: string;
  hops: string[];
  edges: string[];
  composite_risk: number;
  summary: string;
  credential_exposure: string[];
  tool_exposure: string[];
  vuln_ids: string[];
}

export interface InteractionRisk {
  pattern: string;
  agents: string[];
  risk_score: number;
  description: string;
  owasp_agentic_tag?: string;
}

export interface ContextStats {
  total_nodes: number;
  total_edges: number;
  agent_count: number;
  shared_server_count: number;
  shared_credential_count: number;
  lateral_path_count: number;
  max_lateral_depth: number;
  highest_path_risk: number;
  interaction_risk_count: number;
}

export interface ContextGraphData {
  nodes: ContextGraphNode[];
  edges: ContextGraphEdge[];
  lateral_paths: LateralPath[];
  interaction_risks: InteractionRisk[];
  stats: ContextStats;
}

// ─── Kind → ReactFlow node type ──────────────────────────────────────────────

const KIND_TO_NODE_TYPE: Record<string, LineageNodeType> = {
  agent: "agent",
  server: "server",
  credential: "credential",
  tool: "tool",
  vulnerability: "vulnerability",
  org: "org",
  account: "account",
  role: "role",
  policy: "policy",
  service_principal: "servicePrincipal",
  federated_identity: "federatedIdentity",
  iam_role: "serviceAccount",
  service_account: "serviceAccount",
};

const NODE_TYPE_TO_RENDERER: Record<LineageNodeType, string> = {
  provider: "providerNode",
  agent: "agentNode",
  server: "serverNode",
  package: "packageNode",
  vulnerability: "vulnNode",
  misconfiguration: "misconfigNode",
  credential: "credentialNode",
  tool: "toolNode",
  model: "modelNode",
  dataset: "datasetNode",
  container: "containerNode",
  cloudResource: "cloudResourceNode",
  org: "providerNode",
  account: "providerNode",
  user: "userNode",
  group: "groupNode",
  role: "credentialNode",
  policy: "credentialNode",
  serviceAccount: "serviceAccountNode",
  servicePrincipal: "serviceAccountNode",
  federatedIdentity: "serviceAccountNode",
  environment: "environmentNode",
  fleet: "fleetNode",
  cluster: "clusterNode",
  sharedServer: "sharedServerNode",
  managedIdentity: "managedIdentityNode",
  accessGrant: "accessGrantNode",
  accessPolicy: "accessPolicyNode",
  driftIncident: "driftIncidentNode",
  dataStore: "dataStoreNode",
  directory: "containerNode",
  sourceFile: "packageNode",
  configFile: "packageNode",
};

// ─── Edge colors ─────────────────────────────────────────────────────────────

const EDGE_COLORS: Record<string, string> = {
  uses: "#10b981", // emerald  agent→server
  exposes: "#f59e0b", // amber    server→credential
  exposes_cred: "#f59e0b", // amber    server→credential
  provides: "#a855f7", // purple   server→tool
  provides_tool: "#a855f7", // purple   server→tool
  vulnerable_to: "#ef4444", // red      server→vulnerability
  shares_server: "#22d3ee", // cyan     agent↔agent
  shares_credential: "#f97316", // orange agent↔agent
  shares_cred: "#f97316", // orange   agent↔agent
  member_of: "#60a5fa", // blue     identity→agent
};

// ─── Builder ─────────────────────────────────────────────────────────────────

const UNTRUSTED_METADATA_PREFIX = "[UNTRUSTED MCP METADATA] ";

/** Strip scanner trust prefix; omit empty external-metadata placeholders. */
export function displayContextDescription(raw: string | undefined): string | undefined {
  if (!raw?.trim()) return undefined;
  const text = raw.startsWith(UNTRUSTED_METADATA_PREFIX)
    ? raw.slice(UNTRUSTED_METADATA_PREFIX.length).trim()
    : raw.trim();
  return text || undefined;
}

export function topLateralPathForAgent(
  paths: LateralPath[],
  selectedAgent: string | undefined,
): LateralPath | null {
  if (!selectedAgent) return null;
  const sourceId = `agent:${selectedAgent}`;
  const ranked = paths
    .filter((path) => path.source === sourceId)
    .sort((left, right) => right.composite_risk - left.composite_risk);
  return ranked[0] ?? null;
}

/**
 * Build ReactFlow nodes/edges from context graph API data.
 * When `selectedAgent` is provided, lateral paths from that agent are
 * highlighted in orange with dashed animation.
 */
export function buildContextFlowGraph(
  data: ContextGraphData,
  selectedAgent?: string,
  options?: { topPathOnly?: boolean },
): { nodes: Node[]; edges: Edge[]; focusedPath: LateralPath | null } {
  const focusedPath =
    options?.topPathOnly && selectedAgent
      ? topLateralPathForAgent(data.lateral_paths, selectedAgent)
      : null;

  // Collect IDs on the selected agent's lateral paths
  const pathNodeIds = new Set<string>();
  const pathEdgePairs = new Set<string>();
  const pathsForScope =
    focusedPath != null
      ? [focusedPath]
      : selectedAgent
        ? data.lateral_paths.filter((path) => path.source === `agent:${selectedAgent}`)
        : [];

  if (selectedAgent && pathsForScope.length > 0) {
    for (const p of pathsForScope) {
      for (const h of p.hops) pathNodeIds.add(h);
      for (let i = 0; i < p.hops.length - 1; i++) {
        pathEdgePairs.add(`${p.hops[i]}→${p.hops[i + 1]}`);
        pathEdgePairs.add(`${p.hops[i + 1]}→${p.hops[i]}`); // bidirectional
      }
    }
  }
  if (selectedAgent && pathNodeIds.size === 0) {
    const seedId = `agent:${selectedAgent}`;
    pathNodeIds.add(seedId);
    for (const edge of data.edges) {
      if (edge.source === seedId) pathNodeIds.add(edge.target);
      if (edge.target === seedId) pathNodeIds.add(edge.source);
    }
  }
  const visibleIds =
    selectedAgent && pathNodeIds.size > 0
      ? pathNodeIds
      : new Set(data.nodes.map((node) => node.id));

  // Shared server IDs
  const sharedServerNames = new Set<string>();
  for (const e of data.edges) {
    const relationship = e.relationship ?? e.kind;
    if (relationship === "shares_server") {
      const srv = (e.metadata?.server as string) ?? "";
      if (srv) sharedServerNames.add(srv);
    }
  }

  const nodes: Node[] = data.nodes
    .filter((node) => visibleIds.has(node.id))
    .map((n) => {
      const graphKind = n.entity_type ?? n.kind;
      let nodeType = KIND_TO_NODE_TYPE[graphKind] ?? "server";
      if (n.kind === "server" && sharedServerNames.has(n.label)) {
        nodeType = "sharedServer";
      }

      const dimmed = selectedAgent
        ? !pathNodeIds.has(n.id) && pathNodeIds.size > 0
        : false;
      const highlighted = selectedAgent ? pathNodeIds.has(n.id) : false;

      const nodeData: LineageNodeData = {
        nodeType,
        label: n.label,
        dimmed,
        highlighted,
        severity: (n.metadata?.severity as string) ?? undefined,
        cvssScore: (n.metadata?.cvss_score as number) ?? undefined,
        epssScore: (n.metadata?.epss_score as number) ?? undefined,
        isKev: n.metadata?.is_kev === true,
        effectiveReach: readReachBreakdown(n.metadata?.effective_reach),
        description: displayContextDescription(n.metadata?.description as string | undefined),
        serverName: (n.metadata?.agent as string) ?? undefined,
        serverCount: (n.metadata?.server_count as number) ?? undefined,
      };

      return {
        id: n.id,
        type: NODE_TYPE_TO_RENDERER[nodeType] ?? "serverNode",
        data: nodeData,
        position: { x: 0, y: 0 },
      };
    });

  const edges: Edge[] = data.edges
    .filter(
      (edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target),
    )
    .map((e, i) => {
      const isOnPath = pathEdgePairs.has(`${e.source}→${e.target}`);
      const relationship = e.relationship ?? e.kind;
      const baseColor =
        RELATIONSHIP_COLOR_MAP[relationship] ??
        EDGE_COLORS[relationship] ??
        "#52525b";
      const reachScore = readReachScore(e.metadata?.effective_reach_score);
      const reachColor = reachStrokeColor(reachScore);
      const strokeColor = isOnPath ? "#f97316" : (reachColor ?? baseColor);

      return {
        id: `ctx-edge-${i}`,
        source: e.source,
        target: e.target,
        type: "smoothstep",
        data: {
          relationship,
          relationshipLabel: relationship.replace(/_/g, " "),
          evidenceMode: isOnPath
            ? "selected_path"
            : relationship.includes("runtime")
              ? "runtime"
              : "static",
        },
        animated: isOnPath,
        style: {
          stroke: strokeColor,
          strokeWidth: isOnPath
            ? 2.5
            : Math.max(1.5, reachEdgeWidth(reachScore)),
          strokeDasharray: isOnPath ? "8 4" : undefined,
          opacity:
            selectedAgent && pathNodeIds.size > 0 && !isOnPath ? 0.15 : 1,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 12,
          height: 12,
        },
        label:
          relationship === "shares_server"
            ? `shared: ${(e.metadata?.server as string) ?? ""}`
            : relationship === "shares_credential" ||
                relationship === "shares_cred"
              ? `shared: ${(e.metadata?.credential as string) ?? ""}`
              : undefined,
        labelStyle: { fontSize: 9, fill: "#71717a" },
      };
    });

  return { nodes, edges, focusedPath };
}
