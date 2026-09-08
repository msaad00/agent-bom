import type { Edge, Node } from "@xyflow/react";

import type { Agent } from "@/lib/api";
import { credentialEnvKeys } from "@/lib/credential-key";

export const MAX_TOPOLOGY_AGENTS = 75;
export const MAX_TOPOLOGY_SERVERS = 220;
export type TopologyFilter = "all" | "attention" | "credentialed" | "unlinked";

type MCPServer = NonNullable<Agent["mcp_servers"]>[number];

export interface TopologyServiceSummary {
  key: string;
  label: string;
  agentNames: Set<string>;
  pkgCount: number;
  toolCount: number;
  hasCredentials: boolean;
  vulnCount: number;
  warningCount: number;
  riskScore: number;
}

export function topologyAgentTypeLabel(agentType: string): string {
  const labels: Record<string, string> = {
    cursor: "Cursor IDE",
    "claude-desktop": "Claude Desktop",
    "codex-cli": "Codex CLI",
    "claude-code": "Claude Code",
    "docker-mcp": "Docker MCP",
    custom: "Custom runtime",
  };
  if (labels[agentType]) return labels[agentType];
  return agentType
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function topologyAgentDisplayName(agent: Agent): string {
  const enrollment = typeof agent.enrollment_name === "string" ? agent.enrollment_name.trim() : "";
  if (enrollment) return enrollment;
  return formatInventoryAgentLabel(agent.name);
}

export function formatInventoryAgentLabel(name: string): string {
  return name
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function serverVulnerabilityCount(server: MCPServer): number {
  return (
    (server.vulnerabilities?.length ?? 0) +
    (server.packages ?? []).reduce((sum, pkg) => sum + (pkg.vulnerabilities?.length ?? 0), 0)
  );
}

export function serverHasCredentials(server: MCPServer): boolean {
  return Boolean(
    server.has_credentials ||
      credentialEnvKeys(server.env).length > 0 ||
      (server.credential_env_vars?.length ?? 0) > 0,
  );
}

export function serviceKey(server: MCPServer): string {
  return `${server.name}|${server.transport ?? ""}|${server.url ?? server.command ?? ""}`;
}

export function serverMatchesFilter(server: MCPServer, filter: TopologyFilter): boolean {
  if (filter === "credentialed") return serverHasCredentials(server);
  if (filter === "attention") {
    return (
      serverHasCredentials(server) ||
      serverVulnerabilityCount(server) > 0 ||
      (server.security_warnings?.length ?? 0) > 0
    );
  }
  return true;
}

export function agentRiskScore(agent: Agent): number {
  const servers = agent.mcp_servers ?? [];
  if (servers.length === 0) return 1;
  return servers.reduce((total, server) => total + edgeRiskScore(server), 0);
}

export function edgeRiskScore(server: MCPServer): number {
  const vulns = serverVulnerabilityCount(server);
  const creds = serverHasCredentials(server) ? 4 : 0;
  const warnings = (server.security_warnings?.length ?? 0) * 2;
  return vulns * 3 + creds + warnings;
}

export function buildServiceSummaries(agents: Agent[]): Map<string, TopologyServiceSummary> {
  const summaries = new Map<string, TopologyServiceSummary>();

  for (const agent of agents) {
    for (const server of agent.mcp_servers ?? []) {
      const key = serviceKey(server);
      const existing = summaries.get(key) ?? {
        key,
        label: server.name,
        agentNames: new Set<string>(),
        pkgCount: 0,
        toolCount: 0,
        hasCredentials: false,
        vulnCount: 0,
        warningCount: 0,
        riskScore: 0,
      };
      existing.agentNames.add(agent.name);
      existing.pkgCount += server.packages?.length ?? 0;
      existing.toolCount += server.tools?.length ?? 0;
      existing.hasCredentials = existing.hasCredentials || serverHasCredentials(server);
      existing.vulnCount += serverVulnerabilityCount(server);
      existing.warningCount += server.security_warnings?.length ?? 0;
      existing.riskScore += edgeRiskScore(server);
      summaries.set(key, existing);
    }
  }

  return summaries;
}

export function filterTopologyAgents(agents: Agent[], filter: TopologyFilter): Agent[] {
  if (filter === "all") return agents;
  if (filter === "unlinked") return agents.filter((agent) => (agent.mcp_servers?.length ?? 0) === 0);
  return agents.map((agent) => ({
    ...agent,
    mcp_servers: (agent.mcp_servers ?? []).filter((server) => serverMatchesFilter(server, filter)),
  })).filter((agent) => agent.mcp_servers.length > 0);
}

/** Bound the view without dropping a retained service's explicit memberships. */
export function limitTopologyAgents(agents: Agent[]): Agent[] {
  const services = new Set<string>();
  const selected: Agent[] = [];
  const ordered = [...agents].sort((a, b) => agentRiskScore(b) - agentRiskScore(a) || a.name.localeCompare(b.name));
  for (const agent of ordered) {
    if (selected.length >= MAX_TOPOLOGY_AGENTS) break;
    const servers = (agent.mcp_servers ?? []).filter((server) => {
      const key = serviceKey(server);
      if (!services.has(key) && services.size >= MAX_TOPOLOGY_SERVERS) return false;
      services.add(key);
      return true;
    });
    if (servers.length > 0 || !agent.mcp_servers?.length) selected.push({ ...agent, mcp_servers: servers });
  }
  return selected;
}

export function buildTopologyGraph(agents: Agent[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const summaries = buildServiceSummaries(agents);

  const serviceEntries = [...summaries.values()].sort((left, right) => {
    return (
      right.riskScore - left.riskScore ||
      Number(right.hasCredentials) - Number(left.hasCredentials) ||
      right.agentNames.size - left.agentNames.size ||
      left.label.localeCompare(right.label)
    );
  });
  const visibleServices = serviceEntries.slice(0, MAX_TOPOLOGY_SERVERS);
  const visibleServiceKeys = new Set(visibleServices.map((service) => service.key));

  for (const agent of agents) {
    const servers = agent.mcp_servers ?? [];
    const totalVulns = servers.reduce((sum, server) => sum + serverVulnerabilityCount(server), 0);
    const credCount = servers.filter(serverHasCredentials).length;
    nodes.push({
      id: `agent-${agent.name}`,
      type: "agentNode",
      position: { x: 0, y: 0 },
      data: {
        label: topologyAgentDisplayName(agent),
        slug: agent.name,
        typeLabel: topologyAgentTypeLabel(agent.agent_type || "agent"),
        serverCount: servers.length,
        vulnCount: totalVulns,
        credCount,
        unlinked: servers.length === 0,
        riskScore: agentRiskScore(agent),
      },
    });
  }

  for (const service of visibleServices) {
    nodes.push({
      id: `srv-${service.key}`,
      type: "serverNode",
      position: { x: 0, y: 0 },
      data: {
        label: service.label,
        serviceKey: service.key,
        agentCount: service.agentNames.size,
        pkgCount: service.pkgCount,
        toolCount: service.toolCount,
        hasCredentials: service.hasCredentials,
        vulnCount: service.vulnCount,
        shared: service.agentNames.size > 1,
        riskScore: service.riskScore,
      },
    });
  }

  for (const agent of agents) {
    const agentId = `agent-${agent.name}`;
    for (const server of agent.mcp_servers ?? []) {
      const key = serviceKey(server);
      if (!visibleServiceKeys.has(key)) continue;
      const vulns = serverVulnerabilityCount(server);
      const hasCredential = serverHasCredentials(server);
      edges.push({
        id: `e-${agentId}-${key}`,
        source: agentId,
        target: `srv-${key}`,
        type: "smoothstep",
        animated: vulns > 0 || hasCredential,
        style: {
          // Inventory edges stay visible on light + dark canvases (was ~0.35 / slate).
          stroke: vulns > 0 ? "#f87171" : hasCredential ? "#d97706" : "#94a3b8",
          strokeWidth: vulns > 0 || hasCredential ? 2.2 : 1.5,
          opacity: vulns > 0 || hasCredential ? 0.9 : 0.7,
        },
      });
    }
  }

  return { nodes, edges };
}

export function topologySummary(agents: Agent[]) {
  const servers = agents.flatMap((agent) => agent.mcp_servers ?? []);
  const serviceSummaries = buildServiceSummaries(agents);
  const attentionServers = [...serviceSummaries.values()].filter(
    (service) => service.hasCredentials || service.vulnCount > 0 || service.warningCount > 0,
  ).length;
  const sharedServers = [...serviceSummaries.values()].filter((service) => service.agentNames.size > 1).length;

  return {
    agents: agents.length,
    servers: servers.length,
    uniqueServices: serviceSummaries.size,
    packages: servers.reduce((sum, server) => sum + (server.packages?.length ?? 0), 0),
    tools: servers.reduce((sum, server) => sum + (server.tools?.length ?? 0), 0),
    vulnerableServers: [...serviceSummaries.values()].filter((service) => service.vulnCount > 0).length,
    credentialedServers: [...serviceSummaries.values()].filter((service) => service.hasCredentials).length,
    attentionServers,
    sharedServers,
    unlinkedAgents: agents.filter((agent) => (agent.mcp_servers?.length ?? 0) === 0).length,
    environments: new Set(agents.map((agent) => agent.environment || "local")).size,
    owners: new Set(agents.map((agent) => agent.owner).filter(Boolean)).size,
  };
}
