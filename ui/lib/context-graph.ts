/**
 * Context graph builder — transforms API context-graph data into ReactFlow
 * nodes/edges for the /context page.
 */

import { type Node, type Edge, MarkerType } from "@xyflow/react";
import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

// ─── Types (mirror Python context_graph.to_serializable) ────────────────────

export interface ContextGraphNode {
  id: string;
  kind: "agent" | "server" | "credential" | "tool" | "vulnerability";
  label: string;
  metadata: Record<string, unknown>;
}

export interface ContextGraphEdge {
  source: string;
  target: string;
  kind: string;
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
};

// ─── Edge colors ─────────────────────────────────────────────────────────────

const EDGE_COLORS: Record<string, string> = {
  uses: "#10b981",          // emerald  agent→server
  exposes: "#f59e0b",       // amber    server→credential
  provides: "#a855f7",      // purple   server→tool
  vulnerable_to: "#ef4444", // red      server→vulnerability
  shares_server: "#22d3ee", // cyan     agent↔agent
  shares_credential: "#f97316", // orange agent↔agent
};

// ─── Builder ─────────────────────────────────────────────────────────────────

/**
 * Build ReactFlow nodes/edges from context graph API data.
 * When `selectedAgent` is provided, lateral paths from that agent are
 * highlighted in orange with dashed animation.
 */
export function buildContextFlowGraph(
  data: ContextGraphData,
  selectedAgent?: string
): { nodes: Node[]; edges: Edge[] } {
  // Collect IDs on the selected agent's lateral paths
  const pathNodeIds = new Set<string>();
  const pathEdgePairs = new Set<string>();
  if (selectedAgent) {
    for (const p of data.lateral_paths) {
      if (p.source === `agent:${selectedAgent}`) {
        for (const h of p.hops) pathNodeIds.add(h);
        for (let i = 0; i < p.hops.length - 1; i++) {
          pathEdgePairs.add(`${p.hops[i]}→${p.hops[i + 1]}`);
          pathEdgePairs.add(`${p.hops[i + 1]}→${p.hops[i]}`); // bidirectional
        }
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
  const visibleIds = selectedAgent && pathNodeIds.size > 0
    ? pathNodeIds
    : new Set(data.nodes.map((node) => node.id));

  // Shared server IDs
  const sharedServerNames = new Set<string>();
  for (const e of data.edges) {
    if (e.kind === "shares_server") {
      const srv = (e.metadata?.server as string) ?? "";
      if (srv) sharedServerNames.add(srv);
    }
  }

  const nodes: Node[] = data.nodes
    .filter((node) => visibleIds.has(node.id))
    .map((n) => {
    let nodeType = KIND_TO_NODE_TYPE[n.kind] ?? "server";
    if (n.kind === "server" && sharedServerNames.has(n.label)) {
      nodeType = "sharedServer";
    }

    const dimmed = selectedAgent ? !pathNodeIds.has(n.id) && pathNodeIds.size > 0 : false;
    const highlighted = selectedAgent ? pathNodeIds.has(n.id) : false;

    const nodeData: LineageNodeData = {
      nodeType,
      label: n.label,
      dimmed,
      highlighted,
      severity: (n.metadata?.severity as string) ?? undefined,
      cvssScore: (n.metadata?.cvss_score as number) ?? undefined,
      description: (n.metadata?.description as string) ?? undefined,
      serverName: (n.metadata?.agent as string) ?? undefined,
      serverCount: (n.metadata?.server_count as number) ?? undefined,
    };

      return {
        id: n.id,
        type: nodeType,
        data: nodeData,
        position: { x: 0, y: 0 },
      };
    });

  const edges: Edge[] = data.edges
    .filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
    .map((e, i) => {
    const isOnPath = pathEdgePairs.has(`${e.source}→${e.target}`);
    const baseColor = EDGE_COLORS[e.kind] ?? "#52525b";

      return {
        id: `ctx-edge-${i}`,
        source: e.source,
        target: e.target,
        type: "smoothstep",
        animated: isOnPath,
        style: {
          stroke: isOnPath ? "#f97316" : baseColor,
          strokeWidth: isOnPath ? 2.5 : 1.5,
          strokeDasharray: isOnPath ? "8 4" : undefined,
          opacity: selectedAgent && pathNodeIds.size > 0 && !isOnPath ? 0.15 : 1,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isOnPath ? "#f97316" : baseColor,
          width: 12,
          height: 12,
        },
        label: e.kind === "shares_server"
          ? `shared: ${(e.metadata?.server as string) ?? ""}`
          : e.kind === "shares_credential"
          ? `shared: ${(e.metadata?.credential as string) ?? ""}`
          : undefined,
        labelStyle: { fontSize: 9, fill: "#71717a" },
      };
    });

  return { nodes, edges };
}
