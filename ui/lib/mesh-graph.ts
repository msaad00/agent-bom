/**
 * Shared mesh graph builder — builds ReactFlow nodes/edges from scan results.
 * Used by /mesh page and /scan?view=mesh.
 */

import { type Node, type Edge, MarkerType } from "@xyflow/react";
import type { ScanResult, MCPServer, Agent, Vulnerability } from "@/lib/api";
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
type VulnerabilitySeverity = Vulnerability["severity"];

export interface MeshGraphScope {
  selectedAgents?: string[];
  vulnerableOnly?: boolean;
}

// ─── Credential detection ───────────────────────────────────────────────────

const CRED_RE = /key|token|secret|password|credential|auth/i;

function getCredKeys(server: MCPServer): string[] {
  return server.env ? Object.keys(server.env).filter((k) => CRED_RE.test(k)) : [];
}

function mergeServers(existing: MCPServer, incoming: MCPServer): MCPServer {
  const packages = new Map(existing.packages.map((pkg) => [`${pkg.ecosystem}:${pkg.name}:${pkg.version}`, pkg]));
  for (const pkg of incoming.packages) {
    const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
    const current = packages.get(key);
    if (current) {
      const vulnerabilities = new Map((current.vulnerabilities ?? []).map((vuln) => [vuln.id, vuln]));
      for (const vuln of pkg.vulnerabilities ?? []) {
        vulnerabilities.set(vuln.id, vuln);
      }
      packages.set(key, { ...current, vulnerabilities: [...vulnerabilities.values()] });
    } else {
      packages.set(key, pkg);
    }
  }

  const tools = new Map((existing.tools ?? []).map((tool) => [tool.name, tool]));
  for (const tool of incoming.tools ?? []) {
    tools.set(tool.name, tool);
  }

  return {
    ...existing,
    command: existing.command || incoming.command,
    transport: existing.transport || incoming.transport,
    packages: [...packages.values()],
    tools: [...tools.values()],
    env: { ...(existing.env ?? {}), ...(incoming.env ?? {}) },
  };
}

function normalizeAgents(agents: Agent[]): Agent[] {
  const merged = new Map<string, Agent>();

  for (const agent of agents) {
    const existing = merged.get(agent.name);
    if (!existing) {
      merged.set(agent.name, {
        ...agent,
        mcp_servers: [...agent.mcp_servers],
      });
      continue;
    }

    const serverMap = new Map(
      existing.mcp_servers.map((server) => [`${server.name}|${server.command ?? ""}|${server.transport ?? ""}`, server]),
    );

    for (const server of agent.mcp_servers) {
      const key = `${server.name}|${server.command ?? ""}|${server.transport ?? ""}`;
      const current = serverMap.get(key);
      serverMap.set(key, current ? mergeServers(current, server) : server);
    }

    merged.set(agent.name, {
      ...existing,
      agent_type: existing.agent_type || agent.agent_type,
      status: existing.status || agent.status,
      mcp_servers: [...serverMap.values()],
    });
  }

  return [...merged.values()];
}

// ─── Shared Server Detection ────────────────────────────────────────────────

export function detectSharedServers(agents: Agent[]): Map<string, ServerGroup> {
  const groups = new Map<string, ServerGroup>();

  for (const agent of agents) {
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

function severityWeight(sev: string | undefined): number {
  return SEV_ORDER[sev ?? "none"] ?? 0;
}

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

function compareVulnerabilities(left: Vulnerability, right: Vulnerability): number {
  const severityDiff = severityWeight(right.severity) - severityWeight(left.severity);
  if (severityDiff !== 0) return severityDiff;
  const cvssDiff = (right.cvss_score ?? 0) - (left.cvss_score ?? 0);
  if (cvssDiff !== 0) return cvssDiff;
  return (right.epss_score ?? 0) - (left.epss_score ?? 0);
}

function normalizeSeverity(severity: string | undefined): VulnerabilitySeverity {
  const normalized = String(severity ?? "none").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "none";
}

// ─── Graph Builder ──────────────────────────────────────────────────────────

export function buildMeshGraph(
  result: ScanResult,
  nodeFilter?: NodeTypeFilter,
  severityFilter?: SeverityFilter,
  scope?: MeshGraphScope,
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
  const selectedAgents = scope?.selectedAgents ?? [];
  const vulnerableOnly = scope?.vulnerableOnly ?? false;
  const scopedAgents =
    selectedAgents.length > 0
      ? result.agents.filter((agent) => selectedAgents.includes(agent.name))
      : result.agents;
  const normalizedAgents = normalizeAgents(scopedAgents);
  const blastByVulnId = new Map(result.blast_radius?.map((item) => [item.vulnerability_id, item]) ?? []);

  const hasVisiblePackage = (server: MCPServer): boolean => {
    return server.packages.some((pkg) =>
      (pkg.vulnerabilities ?? []).some((vuln) => {
        const blast = blastByVulnId.get(vuln.id);
        return meetsSeverityFilter(blast?.severity ?? vuln.severity, sevFilter);
      }),
    );
  };

  const activeAgents = vulnerableOnly
    ? normalizedAgents.filter((agent) => agent.mcp_servers.some(hasVisiblePackage))
    : normalizedAgents;

  const serverGroups = detectSharedServers(activeAgents);
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
  for (const agent of activeAgents) {
    for (const server of agent.mcp_servers) {
      for (const tool of server.tools ?? []) {
        const existing = toolAgentMap.get(tool.name) ?? new Set<string>();
        existing.add(agent.name);
        toolAgentMap.set(tool.name, existing);
      }
    }
  }
  const toolOverlap = [...toolAgentMap.values()].filter((a) => a.size > 1).length;

  // View stats
  let totalPackages = 0;
  let totalVulnerabilities = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let kevCount = 0;

  // ── Agent nodes ──
  for (const agent of activeAgents) {
    const agentId = `agent:${agent.name}`;
    const visibleServers = vulnerableOnly ? agent.mcp_servers.filter(hasVisiblePackage) : agent.mcp_servers;
    const visiblePackageCount = visibleServers.reduce((sum, server) => {
      return sum + server.packages.filter((pkg) => {
        const matching = (pkg.vulnerabilities ?? []).some((vuln) => {
          const blast = blastByVulnId.get(vuln.id);
          return meetsSeverityFilter(blast?.severity ?? vuln.severity, sevFilter);
        });
        return vulnerableOnly ? matching : true;
      }).length;
    }, 0);
    const totalVulns = agent.mcp_servers.reduce((sum, server) => {
      return sum + server.packages.reduce((packageSum, pkg) => {
        const matching = (pkg.vulnerabilities ?? []).filter((vuln) => {
          const blast = blastByVulnId.get(vuln.id);
          const severity = blast?.severity ?? vuln.severity;
          return meetsSeverityFilter(severity, sevFilter);
        });
        return packageSum + matching.length;
      }, 0);
    }, 0);
    nodes.push({
      id: agentId,
      type: "agentNode",
      position: { x: 0, y: 0 },
      data: {
        label: agent.name,
        nodeType: "agent",
        agentType: agent.agent_type,
        agentStatus: agent.status,
        serverCount: visibleServers.length,
        packageCount: visiblePackageCount,
        vulnCount: totalVulns,
      } satisfies LineageNodeData,
    });
  }

  // ── Server nodes (shared vs regular) ──
  for (const [name, group] of serverGroups) {
    const isShared = group.agents.size > 1;
    const serverId = `server:${name}`;
    const firstServer = group.servers[0];
    if (!firstServer) continue;

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
          data: { relationship: "uses" },
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
            data: { relationship: "exposes_cred" },
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
            data: { relationship: "provides_tool" },
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
      const rankedPackages = [...pkgMap.values()].map((entry) => {
        const matchingVulns = (entry.pkg.vulnerabilities ?? [])
          .map((vuln) => {
            const blast = blastByVulnId.get(vuln.id);
            return {
              ...vuln,
              severity: normalizeSeverity(blast?.severity ?? vuln.severity),
              cvss_score: blast?.cvss_score ?? vuln.cvss_score,
              epss_score: blast?.epss_score ?? vuln.epss_score,
              cisa_kev: (blast?.is_kev ?? blast?.cisa_kev ?? vuln.cisa_kev) || false,
              fixed_version: blast?.fixed_version ?? vuln.fixed_version,
            } satisfies Vulnerability;
          })
          .filter((vuln) => meetsSeverityFilter(vuln.severity, sevFilter))
          .sort(compareVulnerabilities);
        return { ...entry, matchingVulns };
      });
      const vulnPkgs = rankedPackages
        .filter((entry) => entry.matchingVulns.length > 0)
        .sort((left, right) => {
          const severityDiff = severityWeight(right.matchingVulns[0]?.severity) - severityWeight(left.matchingVulns[0]?.severity);
          if (severityDiff !== 0) return severityDiff;
          return right.matchingVulns.length - left.matchingVulns.length;
        });
      const cleanPkgs = rankedPackages
        .filter((entry) => entry.matchingVulns.length === 0)
        .slice(0, vulnerableOnly ? 0 : 2);
      const displayPkgs = [...vulnPkgs.slice(0, vulnerableOnly ? 8 : 6), ...cleanPkgs];

      for (const { pkg, serverName, matchingVulns } of displayPkgs) {
        const pkgId = `pkg:${serverName}:${pkg.ecosystem}:${pkg.name}`;
        if (seen.has(pkgId)) continue;
        seen.add(pkgId);

        const vulnCount = matchingVulns.length;
        if (vulnerableOnly && vulnCount === 0) continue;
        totalPackages++;
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
          data: { relationship: "depends_on" },
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
        if (showVulns && matchingVulns.length > 0) {
          for (const vuln of matchingVulns.slice(0, vulnerableOnly ? 6 : 5)) {
            const vulnId = `vuln:${pkg.name}:${vuln.id}`;
            if (seen.has(vulnId)) continue;
            seen.add(vulnId);
            totalVulnerabilities++;
            switch (vuln.severity) {
              case "critical": criticalCount++; break;
              case "high": highCount++; break;
              case "medium": mediumCount++; break;
              case "low": lowCount++; break;
              default: break;
            }
            if (vuln.cisa_kev) kevCount++;

            // Look up blast radius data for this vuln
            const br = blastByVulnId.get(vuln.id);

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
              data: { relationship: "vulnerable_to" },
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

  const stats: MeshStatsData = {
    totalAgents: activeAgents.length,
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
