/**
 * Shared mesh graph builder — builds ReactFlow nodes/edges from scan results.
 * Used by /mesh page and /scan?view=mesh.
 */

import { type Node, type Edge, MarkerType } from "@xyflow/react";
import type { ScanResult, MCPServer } from "@/lib/api";
import type { LineageNodeData } from "@/components/lineage-nodes";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface MeshStatsData {
  totalAgents: number;
  sharedServers: number;
  uniqueCredentials: number;
  toolOverlap: number;
  credentialBlast: string[];
  totalPackages: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  kevCount: number;
}

export interface ServerGroup {
  name: string;
  agents: Set<string>;
  servers: MCPServer[];
  totalTools: number;
  totalCreds: number;
  totalPackages: number;
  credNames: Set<string>;
}

export type NodeTypeFilter = {
  packages: boolean;
  vulnerabilities: boolean;
  credentials: boolean;
  tools: boolean;
};

export type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

// ─── Credential detection ───────────────────────────────────────────────────

const CRED_RE = /key|token|secret|password|credential|auth/i;

function getCredKeys(server: MCPServer): string[] {
  return server.env ? Object.keys(server.env).filter((k) => CRED_RE.test(k)) : [];
}

// ─── Shared Server Detection ────────────────────────────────────────────────

export function detectSharedServers(result: ScanResult): Map<string, ServerGroup> {
  const groups = new Map<string, ServerGroup>();

  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      const key = server.name;
      const existing = groups.get(key);
      const creds = getCredKeys(server);
      if (existing) {
        existing.agents.add(agent.name);
        existing.servers.push(server);
        existing.totalTools += server.tools?.length ?? 0;
        existing.totalCreds += creds.length;
        existing.totalPackages += server.packages.length;
        creds.forEach((c) => existing.credNames.add(c));
      } else {
        groups.set(key, {
          name: server.name,
          agents: new Set([agent.name]),
          servers: [server],
          totalTools: server.tools?.length ?? 0,
          totalCreds: creds.length,
          totalPackages: server.packages.length,
          credNames: new Set(creds),
        });
      }
    }
  }

  return groups;
}

// ─── Severity helpers ───────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

function sevColor(sev: string): string {
  switch (sev) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#3b82f6";
    default: return "#52525b";
  }
}

function meetsSeverityFilter(sev: string, filter: SeverityFilter): boolean {
  if (filter === "all") return true;
  return (SEV_ORDER[sev] ?? 0) >= (SEV_ORDER[filter] ?? 0);
}

// ─── Graph Builder ──────────────────────────────────────────────────────────

export function buildMeshGraph(
  result: ScanResult,
  nodeFilter?: NodeTypeFilter,
  severityFilter?: SeverityFilter,
): {
  nodes: Node[];
  edges: Edge[];
  stats: MeshStatsData;
} {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();

  const showPkgs = nodeFilter?.packages ?? true;
  const showVulns = nodeFilter?.vulnerabilities ?? true;
  const showCreds = nodeFilter?.credentials ?? true;
  const showTools = nodeFilter?.tools ?? true;
  const sevFilter = severityFilter ?? "all";

  const serverGroups = detectSharedServers(result);
  const sharedServerNames = new Set(
    [...serverGroups.entries()]
      .filter(([, g]) => g.agents.size > 1)
      .map(([name]) => name)
  );

  // Credential blast: creds exposed to multiple agents
  const credAgentMap = new Map<string, Set<string>>();
  for (const [, group] of serverGroups) {
    for (const cred of group.credNames) {
      const existing = credAgentMap.get(cred) ?? new Set<string>();
      group.agents.forEach((a) => existing.add(a));
      credAgentMap.set(cred, existing);
    }
  }
  const credentialBlast = [...credAgentMap.entries()]
    .filter(([, agents]) => agents.size > 1)
    .map(([cred, agents]) => `${cred} → ${agents.size} agents`);

  // All creds
  const allCreds = new Set<string>();
  for (const [, g] of serverGroups) g.credNames.forEach((c) => allCreds.add(c));

  // Tool overlap: tools available to >1 agent
  const toolAgentMap = new Map<string, Set<string>>();
  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      for (const tool of server.tools ?? []) {
        const existing = toolAgentMap.get(tool.name) ?? new Set<string>();
        existing.add(agent.name);
        toolAgentMap.set(tool.name, existing);
      }
    }
  }
  const toolOverlap = [...toolAgentMap.values()].filter((a) => a.size > 1).length;

  // Vulnerability stats
  let totalPackages = 0;
  let totalVulnerabilities = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let kevCount = 0;

  for (const agent of result.agents) {
    for (const server of agent.mcp_servers) {
      totalPackages += server.packages.length;
      for (const pkg of server.packages) {
        for (const vuln of pkg.vulnerabilities ?? []) {
          totalVulnerabilities++;
          switch (vuln.severity) {
            case "critical": criticalCount++; break;
            case "high": highCount++; break;
            case "medium": mediumCount++; break;
            case "low": lowCount++; break;
          }
          if (vuln.cisa_kev) kevCount++;
        }
      }
    }
  }

  const stats: MeshStatsData = {
    totalAgents: result.agents.length,
    sharedServers: sharedServerNames.size,
    uniqueCredentials: allCreds.size,
    toolOverlap,
    credentialBlast,
    totalPackages,
    totalVulnerabilities,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    kevCount,
  };

  // ── Agent nodes ──
  for (const agent of result.agents) {
    const agentId = `agent:${agent.name}`;
    const totalVulns = agent.mcp_servers.reduce(
      (s, srv) => s + srv.packages.reduce((vs, p) => vs + (p.vulnerabilities?.length ?? 0), 0),
      0
    );
    nodes.push({
      id: agentId,
      type: "agentNode",
      position: { x: 0, y: 0 },
      data: {
        label: agent.name,
        nodeType: "agent",
        agentType: agent.agent_type,
        agentStatus: agent.status,
        serverCount: agent.mcp_servers.length,
        packageCount: agent.mcp_servers.reduce((s, srv) => s + srv.packages.length, 0),
        vulnCount: totalVulns,
      } satisfies LineageNodeData,
    });
  }

  // ── Server nodes (shared vs regular) ──
  for (const [name, group] of serverGroups) {
    const isShared = group.agents.size > 1;
    const serverId = `server:${name}`;
    const firstServer = group.servers[0];

    nodes.push({
      id: serverId,
      type: isShared ? "sharedServerNode" : "serverNode",
      position: { x: 0, y: 0 },
      data: {
        label: name,
        nodeType: isShared ? "sharedServer" : "server",
        command: firstServer.command || firstServer.transport || "",
        toolCount: group.totalTools,
        credentialCount: group.totalCreds,
        packageCount: group.totalPackages,
        sharedBy: group.agents.size,
        sharedAgents: [...group.agents],
      } satisfies LineageNodeData,
    });

    // Agent → Server edges
    for (const agentName of group.agents) {
      const edgeId = `agent:${agentName}->server:${name}`;
      if (!seen.has(edgeId)) {
        seen.add(edgeId);
        edges.push({
          id: edgeId,
          source: `agent:${agentName}`,
          target: serverId,
          type: "smoothstep",
          animated: isShared,
          style: {
            stroke: isShared ? "#22d3ee" : "#10b981",
            strokeWidth: isShared ? 2.5 : 1.5,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isShared ? "#22d3ee" : "#10b981",
          },
        });
      }
    }

    // ── Credential nodes ──
    if (showCreds) {
      for (const cred of group.credNames) {
        const credId = `cred:${name}:${cred}`;
        if (!seen.has(credId)) {
          seen.add(credId);
          const multiAgent = (credAgentMap.get(cred)?.size ?? 0) > 1;
          nodes.push({
            id: credId,
            type: "credentialNode",
            position: { x: 0, y: 0 },
            data: {
              label: cred,
              nodeType: "credential",
              serverName: name,
              sharedBy: credAgentMap.get(cred)?.size,
            } satisfies LineageNodeData,
          });
          edges.push({
            id: `${serverId}->${credId}`,
            source: serverId,
            target: credId,
            type: "smoothstep",
            style: {
              stroke: multiAgent ? "#f59e0b" : "#92400e",
              strokeWidth: multiAgent ? 2 : 1,
              strokeDasharray: "5 3",
            },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#f59e0b" },
          });
        }
      }
    }

    // ── Tool nodes (limit 5 per server) ──
    if (showTools) {
      const allTools = group.servers.flatMap((s) => s.tools ?? []);
      const uniqueTools = [...new Map(allTools.map((t) => [t.name, t])).values()].slice(0, 5);
      for (const tool of uniqueTools) {
        const toolId = `tool:${name}:${tool.name}`;
        if (!seen.has(toolId)) {
          seen.add(toolId);
          const multiAgent = (toolAgentMap.get(tool.name)?.size ?? 0) > 1;
          nodes.push({
            id: toolId,
            type: "toolNode",
            position: { x: 0, y: 0 },
            data: {
              label: tool.name,
              nodeType: "tool",
              description: tool.description,
            } satisfies LineageNodeData,
          });
          edges.push({
            id: `${serverId}->${toolId}`,
            source: serverId,
            target: toolId,
            type: "smoothstep",
            style: {
              stroke: multiAgent ? "#a855f7" : "#6b21a8",
              strokeWidth: multiAgent ? 1.5 : 1,
            },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#a855f7" },
          });
        }
      }
    }

    // ── Package nodes ──
    if (showPkgs) {
      // Collect all unique packages across server instances in this group
      const pkgMap = new Map<string, { pkg: typeof group.servers[0]["packages"][0]; serverName: string }>();
      for (const srv of group.servers) {
        for (const pkg of srv.packages) {
          const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
          if (!pkgMap.has(key)) {
            pkgMap.set(key, { pkg, serverName: name });
          }
        }
      }

      // Show vulnerable packages first, then top 3 non-vulnerable
      const vulnPkgs = [...pkgMap.values()].filter((p) => (p.pkg.vulnerabilities?.length ?? 0) > 0);
      const cleanPkgs = [...pkgMap.values()].filter((p) => (p.pkg.vulnerabilities?.length ?? 0) === 0).slice(0, 3);
      const displayPkgs = [...vulnPkgs, ...cleanPkgs];

      for (const { pkg, serverName } of displayPkgs) {
        const pkgId = `pkg:${serverName}:${pkg.ecosystem}:${pkg.name}`;
        if (seen.has(pkgId)) continue;
        seen.add(pkgId);

        const vulnCount = pkg.vulnerabilities?.length ?? 0;
        nodes.push({
          id: pkgId,
          type: "packageNode",
          position: { x: 0, y: 0 },
          data: {
            label: `${pkg.name}@${pkg.version}`,
            nodeType: "package",
            ecosystem: pkg.ecosystem,
            version: pkg.version,
            vulnCount,
          } satisfies LineageNodeData,
        });
        edges.push({
          id: `${serverId}->${pkgId}`,
          source: serverId,
          target: pkgId,
          type: "smoothstep",
          style: {
            stroke: vulnCount > 0 ? "#ef4444" : "#52525b",
            strokeWidth: vulnCount > 0 ? 1.5 : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: vulnCount > 0 ? "#ef4444" : "#52525b",
          },
        });

        // ── Vulnerability nodes ──
        if (showVulns && pkg.vulnerabilities) {
          for (const vuln of pkg.vulnerabilities) {
            if (!meetsSeverityFilter(vuln.severity, sevFilter)) continue;
            const vulnId = `vuln:${pkg.name}:${vuln.id}`;
            if (seen.has(vulnId)) continue;
            seen.add(vulnId);

            // Look up blast radius data for this vuln
            const br = result.blast_radius?.find((b) => b.vulnerability_id === vuln.id);

            nodes.push({
              id: vulnId,
              type: "vulnNode",
              position: { x: 0, y: 0 },
              data: {
                label: vuln.id,
                nodeType: "vulnerability",
                severity: vuln.severity,
                cvssScore: vuln.cvss_score,
                epssScore: vuln.epss_score,
                isKev: vuln.cisa_kev,
                fixedVersion: vuln.fixed_version,
                owaspTags: br?.owasp_tags,
                atlasTags: br?.atlas_tags,
              } satisfies LineageNodeData,
            });
            edges.push({
              id: `${pkgId}->${vulnId}`,
              source: pkgId,
              target: vulnId,
              type: "smoothstep",
              animated: vuln.severity === "critical" || vuln.severity === "high",
              style: {
                stroke: sevColor(vuln.severity),
                strokeWidth: vuln.severity === "critical" ? 2.5 : 1.5,
              },
              markerEnd: {
                type: MarkerType.ArrowClosed,
                color: sevColor(vuln.severity),
              },
            });
          }
        }
      }
    }
  }

  return { nodes, edges, stats };
}

// ─── Hover Highlighting ─────────────────────────────────────────────────────

export function getConnectedIds(nodeId: string, edges: Edge[]): Set<string> {
  const connected = new Set<string>([nodeId]);
  const queue = [nodeId];
  const visited = new Set<string>([nodeId]);
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const e of edges) {
      if (e.source === current && !visited.has(e.target)) {
        visited.add(e.target);
        connected.add(e.target);
        queue.push(e.target);
      }
      if (e.target === current && !visited.has(e.source)) {
        visited.add(e.source);
        connected.add(e.source);
        queue.push(e.source);
      }
    }
  }
  return connected;
}

// ─── Search ─────────────────────────────────────────────────────────────────

export function searchNodes(nodes: Node[], query: string): Set<string> {
  if (!query.trim()) return new Set();
  const q = query.toLowerCase();
  const matches = new Set<string>();
  for (const n of nodes) {
    const d = n.data as LineageNodeData;
    if (
      d.label?.toLowerCase().includes(q) ||
      d.nodeType?.toLowerCase().includes(q) ||
      d.severity?.toLowerCase().includes(q) ||
      d.ecosystem?.toLowerCase().includes(q)
    ) {
      matches.add(n.id);
    }
  }
  return matches;
}
