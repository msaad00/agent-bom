"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  useReactFlow,
  Handle,
  Position,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Lock, Network, Package, Server, ShieldAlert, Wrench } from "lucide-react";
import type { Agent, AuthMeResponse } from "@/lib/api";

const MAX_RENDERED_AGENTS = 75;
const MAX_RENDERED_SERVERS = 220;
type TopologyFilter = "all" | "attention" | "credentialed" | "unlinked";

// ─── Custom Node Components with proper Handles ─────────────────────────────

function AgentNode({ data }: { data: { label: string; type: string; serverCount: number; vulnCount: number; unlinked: boolean } }) {
  return (
    <div
      className={`min-w-[168px] rounded-xl border bg-zinc-950/95 px-4 py-3 shadow-sm backdrop-blur transition-colors ${
        data.unlinked
          ? "border-zinc-700/70 hover:border-zinc-500"
          : "cursor-pointer border-zinc-700/80 hover:border-emerald-500/45"
      }`}
    >
      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-emerald-400 !border-emerald-500" />
      <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 !bg-emerald-400 !border-emerald-500" />
      <div className="flex items-center gap-2.5 mb-1.5">
        <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-zinc-900 ring-1 ring-zinc-800">
          <ShieldAlert className={`w-3.5 h-3.5 ${data.unlinked ? "text-zinc-500" : "text-zinc-300"}`} />
        </div>
        <div className="min-w-0">
          <span className="text-xs font-semibold text-zinc-100 block truncate">{data.label}</span>
          <span className="text-[10px] text-zinc-500">{data.type}</span>
        </div>
      </div>
      <div className="flex items-center gap-3 text-[10px] text-zinc-500 mt-1 border-t border-zinc-800/60 pt-1.5">
        <span className="flex items-center gap-1">
          <Server className="w-3 h-3" />
          {data.serverCount}
        </span>
        {data.unlinked && (
          <span className="flex items-center gap-1 text-zinc-400">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
            no services
          </span>
        )}
        {data.vulnCount > 0 && (
          <span className="flex items-center gap-1 text-red-400">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
            {data.vulnCount} CVE{data.vulnCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

function ServerNode({
  data,
}: {
  data: { label: string; agentCount: number; pkgCount: number; toolCount: number; hasCredentials: boolean; vulnCount: number };
}) {
  const borderColor = data.vulnCount > 0 ? "border-red-500/35 hover:border-red-400/50" : "border-zinc-700/80 hover:border-blue-500/45";
  const shadowColor = data.vulnCount > 0 ? "shadow-red-500/5" : "shadow-zinc-950/10";

  return (
    <div className={`min-w-[178px] rounded-xl border ${borderColor} bg-zinc-950/95 px-4 py-3 shadow-sm ${shadowColor} backdrop-blur transition-colors`}>
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-blue-400 !border-blue-500" />
      <Handle type="target" position={Position.Top} className="!w-2 !h-2 !bg-blue-400 !border-blue-500" />
      <div className="flex items-center gap-2.5 mb-1.5">
        <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-zinc-900 ring-1 ring-zinc-800">
          <Server className={`w-3.5 h-3.5 ${data.vulnCount > 0 ? "text-red-300" : "text-zinc-300"}`} />
        </div>
        <span className="text-xs font-semibold text-zinc-100 truncate max-w-[120px]">{data.label}</span>
      </div>
      <div className="flex items-center gap-2.5 text-[10px] text-zinc-500 mt-1 border-t border-zinc-800/60 pt-1.5 flex-wrap">
        <span className="flex items-center gap-1">
          <ShieldAlert className="w-3 h-3" />
          {data.agentCount}
        </span>
        <span className="flex items-center gap-1">
          <Package className="w-3 h-3" />
          {data.pkgCount}
        </span>
        {data.toolCount > 0 && (
          <span className="flex items-center gap-1">
            <Wrench className="w-3 h-3" />
            {data.toolCount}
          </span>
        )}
        {data.hasCredentials && (
          <span className="flex items-center gap-1 text-yellow-400">
            <Lock className="w-3 h-3" />
          </span>
        )}
        {data.vulnCount > 0 && (
          <span className="flex items-center gap-1 text-red-400 font-medium">
            {data.vulnCount} CVE{data.vulnCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

const nodeTypes = { agentNode: AgentNode, serverNode: ServerNode };

// ─── Graph builder ──────────────────────────────────────────────────────────

function serverVulnerabilityCount(server: NonNullable<Agent["mcp_servers"]>[number]): number {
  return (
    (server.vulnerabilities?.length ?? 0) +
    (server.packages ?? []).reduce((sum, pkg) => sum + (pkg.vulnerabilities?.length ?? 0), 0)
  );
}

function serverHasCredentials(server: NonNullable<Agent["mcp_servers"]>[number]): boolean {
  return Boolean(
    server.has_credentials ||
      Object.keys(server.env ?? {}).length > 0 ||
      (server.credential_env_vars?.length ?? 0) > 0
  );
}

function serverMatchesFilter(server: NonNullable<Agent["mcp_servers"]>[number], filter: TopologyFilter): boolean {
  if (filter === "credentialed") return serverHasCredentials(server);
  if (filter === "attention") return serverHasCredentials(server) || serverVulnerabilityCount(server) > 0 || (server.security_warnings?.length ?? 0) > 0;
  return true;
}

function serviceKey(server: NonNullable<Agent["mcp_servers"]>[number]): string {
  return `${server.name}|${server.transport ?? ""}|${server.url ?? server.command ?? ""}`;
}

function buildGraph(agents: Agent[], direction: "LR" | "TB" = "LR"): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const GAP_Y = 132;
  const GAP_X = 220;
  const OFFSET = 420;

  const serviceSummaries = new Map<
    string,
    {
      label: string;
      agentNames: Set<string>;
      pkgCount: number;
      toolCount: number;
      hasCredentials: boolean;
      vulnCount: number;
    }
  >();

  for (const agent of agents) {
    for (const server of agent.mcp_servers ?? []) {
      const key = serviceKey(server);
      const existing = serviceSummaries.get(key) ?? {
        label: server.name,
        agentNames: new Set<string>(),
        pkgCount: 0,
        toolCount: 0,
        hasCredentials: false,
        vulnCount: 0,
      };
      existing.agentNames.add(agent.name);
      existing.pkgCount += server.packages?.length ?? 0;
      existing.toolCount += server.tools?.length ?? 0;
      existing.hasCredentials = existing.hasCredentials || serverHasCredentials(server);
      existing.vulnCount += serverVulnerabilityCount(server);
      serviceSummaries.set(key, existing);
    }
  }

  const serviceEntries = [...serviceSummaries.entries()].sort(([, left], [, right]) => {
    return (
      Number(right.hasCredentials) - Number(left.hasCredentials) ||
      right.vulnCount - left.vulnCount ||
      right.agentNames.size - left.agentNames.size ||
      left.label.localeCompare(right.label)
    );
  });
  const visibleServiceEntries = serviceEntries.slice(0, MAX_RENDERED_SERVERS);
  const visibleServiceKeys = new Set(visibleServiceEntries.map(([key]) => key));
  const totalAgentHeight = Math.max(agents.length - 1, 0) * GAP_Y;
  const totalServiceHeight = Math.max(visibleServiceEntries.length - 1, 0) * GAP_Y;
  const agentBaseY = Math.max(0, (totalServiceHeight - totalAgentHeight) / 2);
  const serviceBaseY = Math.max(0, (totalAgentHeight - totalServiceHeight) / 2);

  agents.forEach((agent, index) => {
    const servers = agent.mcp_servers ?? [];
    const totalVulns = servers.reduce((sum, server) => sum + serverVulnerabilityCount(server), 0);
    nodes.push({
      id: `agent-${agent.name}`,
      type: "agentNode",
      position: direction === "TB" ? { x: index * GAP_X, y: 0 } : { x: 0, y: agentBaseY + index * GAP_Y },
      data: {
        label: agent.name,
        type: agent.agent_type || "agent",
        serverCount: servers.length,
        vulnCount: totalVulns,
        unlinked: servers.length === 0,
      },
    });
  });

  visibleServiceEntries.forEach(([key, service], index) => {
    const id = `srv-${key}`;
    nodes.push({
      id,
      type: "serverNode",
      position: direction === "TB" ? { x: index * GAP_X, y: OFFSET } : { x: OFFSET, y: serviceBaseY + index * GAP_Y },
      data: {
        label: service.label,
        agentCount: service.agentNames.size,
        pkgCount: service.pkgCount,
        toolCount: service.toolCount,
        hasCredentials: service.hasCredentials,
        vulnCount: service.vulnCount,
      },
    });
  });

  for (const agent of agents) {
    const agentId = `agent-${agent.name}`;
    for (const server of agent.mcp_servers ?? []) {
      const key = serviceKey(server);
      if (!visibleServiceKeys.has(key)) continue;
      const srvVulns = serverVulnerabilityCount(server);
      const hasCredential = serverHasCredentials(server);
      edges.push({
        id: `e-${agentId}-${key}`,
        source: agentId,
        target: `srv-${key}`,
        type: "smoothstep",
        animated: srvVulns > 0 || hasCredential,
        style: {
          stroke: srvVulns > 0 ? "#f87171" : hasCredential ? "#d97706" : "#64748b",
          strokeWidth: srvVulns > 0 || hasCredential ? 2 : 1.3,
          opacity: srvVulns > 0 || hasCredential ? 0.78 : 0.45,
        },
      });
    }
  }

  return { nodes, edges };
}

// ─── Inner flow (needs ReactFlowProvider) ───────────────────────────────────

function TopologyFlow({ agents, onAgentClick, direction = "LR" }: { agents: Agent[]; onAgentClick: (name: string) => void; direction?: "LR" | "TB" }) {
  const { fitView } = useReactFlow();
  const { nodes, edges } = useMemo(() => buildGraph(agents, direction), [agents, direction]);

  useEffect(() => {
    const timer = window.setTimeout(() => fitView({ padding: 0.18, duration: 350 }), 120);
    return () => window.clearTimeout(timer);
  }, [fitView, nodes]);

  const handleNodeClick = useCallback(
    (_: unknown, node: Node) => {
      if (node.id.startsWith("agent-")) {
        onAgentClick(node.id.replace("agent-", ""));
      }
    },
    [onAgentClick],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={handleNodeClick}
      fitView
      minZoom={0.2}
      maxZoom={1.6}
      panOnDrag
      zoomOnScroll
      className="!bg-transparent"
      proOptions={{ hideAttribution: true }}
    >
      <Background color="#24242a" gap={28} size={1} />
      <Controls
        showInteractive={false}
        className="!bg-zinc-900 !border-zinc-700 !rounded-lg !shadow-lg [&>button]:!bg-zinc-800 [&>button]:!border-zinc-700 [&>button]:!text-zinc-400 [&>button:hover]:!bg-zinc-700"
      />
    </ReactFlow>
  );
}

// ─── Public component ───────────────────────────────────────────────────────

export function AgentTopology({
  agents,
  direction = "LR",
  session,
}: {
  agents: Agent[];
  direction?: "LR" | "TB";
  session?: AuthMeResponse | null;
}) {
  const router = useRouter();
  const [filter, setFilter] = useState<TopologyFilter>("all");
  const summary = useMemo(() => {
    const servers = agents.flatMap((agent) => agent.mcp_servers ?? []);
    const packages = servers.reduce((sum, server) => sum + (server.packages?.length ?? 0), 0);
    const tools = servers.reduce((sum, server) => sum + (server.tools?.length ?? 0), 0);
    const vulnerableServers = servers.filter((srv) =>
      serverVulnerabilityCount(srv) > 0
    ).length;
    const credentialedServers = servers.filter(serverHasCredentials).length;
    const unlinkedAgents = agents.filter((agent) => (agent.mcp_servers?.length ?? 0) === 0).length;
    const environments = new Set(agents.map((agent) => agent.environment || "local")).size;
    const owners = new Set(agents.map((agent) => agent.owner).filter(Boolean)).size;
    return {
      agents: agents.length,
      servers: servers.length,
      packages,
      tools,
      vulnerableServers,
      credentialedServers,
      unlinkedAgents,
      environments,
      owners,
    };
  }, [agents]);
  const filteredAgents = useMemo(() => {
    if (filter === "all") return agents;
    if (filter === "unlinked") {
      return agents
        .filter((agent) => (agent.mcp_servers?.length ?? 0) === 0)
        .map((agent) => ({ ...agent, mcp_servers: [] }));
    }
    return agents
      .map((agent) => ({ ...agent, mcp_servers: (agent.mcp_servers ?? []).filter((server) => serverMatchesFilter(server, filter)) }))
      .filter((agent) => agent.mcp_servers.length > 0);
  }, [agents, filter]);
  const displayAgents = useMemo(() => {
    let renderedServers = 0;
    return [...filteredAgents]
      .sort((left, right) => {
        const leftServers = left.mcp_servers ?? [];
        const rightServers = right.mcp_servers ?? [];
        const leftVulns = leftServers.reduce(
          (total, server) => total + (server.packages ?? []).reduce((sum, pkg) => sum + (pkg.vulnerabilities?.length ?? 0), 0),
          0,
        );
        const rightVulns = rightServers.reduce(
          (total, server) => total + (server.packages ?? []).reduce((sum, pkg) => sum + (pkg.vulnerabilities?.length ?? 0), 0),
          0,
        );
        return rightVulns - leftVulns || rightServers.length - leftServers.length || left.name.localeCompare(right.name);
      })
      .filter((agent) => {
        if (renderedServers >= MAX_RENDERED_SERVERS) return false;
        renderedServers += agent.mcp_servers?.length ?? 0;
        return true;
      })
      .slice(0, MAX_RENDERED_AGENTS);
  }, [filteredAgents]);
  const visibleServerCount = displayAgents.flatMap((agent) => agent.mcp_servers ?? []).length;
  const hiddenAgentCount = Math.max(0, filteredAgents.length - displayAgents.length);
  const hiddenServerCount = Math.max(0, filteredAgents.flatMap((agent) => agent.mcp_servers ?? []).length - visibleServerCount);
  const filterOptions = useMemo(
    () => [
      { key: "all" as const, label: "All", count: summary.servers + summary.unlinkedAgents },
      { key: "attention" as const, label: "Attention", count: summary.vulnerableServers + summary.credentialedServers },
      { key: "credentialed" as const, label: "Credentialed", count: summary.credentialedServers },
      { key: "unlinked" as const, label: "Unlinked", count: summary.unlinkedAgents },
    ],
    [summary.credentialedServers, summary.servers, summary.unlinkedAgents, summary.vulnerableServers],
  );

  const handleAgentClick = useCallback(
    (name: string) => {
      router.push(`/agents?name=${encodeURIComponent(name)}`);
    },
    [router],
  );

  if (!agents || agents.length === 0) {
    return (
      <div className="bg-zinc-900/50 border border-zinc-800/60 rounded-xl flex items-center justify-center h-[320px]">
        <div className="text-center">
          <Network className="w-8 h-8 text-zinc-700 mx-auto mb-2" />
          <p className="text-sm text-zinc-500">No agents discovered yet</p>
          <p className="text-xs text-zinc-600 mt-1">Run a scan to see the topology</p>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-zinc-800/70 bg-zinc-950/80">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 px-4 py-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.22em] text-zinc-500">Topology</p>
          <h3 className="mt-1 text-sm font-semibold text-zinc-100">Agent to server trust mesh</h3>
          <p className="mt-1 text-xs text-zinc-500">
            Live Agent and MCPServer evidence, grouped by shared service identity with isolation context and unlinked agents called out.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-1.5 text-xs text-zinc-300">
            <span className="font-mono text-zinc-100">{summary.agents}</span> agents
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-1.5 text-xs text-zinc-300">
            <span className="font-mono text-zinc-100">{summary.servers}</span> servers
          </div>
          <div className="rounded-xl border border-red-500/20 bg-zinc-900/80 px-3 py-1.5 text-xs text-red-200">
            <span className="font-mono text-red-100">{summary.vulnerableServers}</span> vulnerable
          </div>
          <div className="rounded-xl border border-amber-500/20 bg-zinc-900/80 px-3 py-1.5 text-xs text-amber-200">
            <span className="font-mono text-amber-100">{summary.credentialedServers}</span> credentialed
          </div>
        </div>
      </div>
      <div className="grid gap-3 border-b border-zinc-800/80 bg-zinc-950/65 px-4 py-3 lg:grid-cols-[1fr_auto]">
        <div className="flex flex-wrap items-center gap-2">
          {filterOptions.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setFilter(option.key)}
              className={`rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${
                filter === option.key
                  ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                  : "border-zinc-800 bg-zinc-900/70 text-zinc-400 hover:border-zinc-700 hover:text-zinc-100"
              }`}
            >
              {option.label}
              <span className="ml-2 font-mono text-[10px] text-zinc-500">{option.count}</span>
            </button>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 px-3 py-2">
            <div className="flex items-center gap-1.5 text-zinc-500"><Package className="h-3.5 w-3.5" />Packages</div>
            <div className="mt-1 font-mono text-sm text-zinc-100">{summary.packages}</div>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 px-3 py-2">
            <div className="flex items-center gap-1.5 text-zinc-500"><Wrench className="h-3.5 w-3.5" />Tools</div>
            <div className="mt-1 font-mono text-sm text-zinc-100">{summary.tools}</div>
          </div>
          <div className="rounded-xl border border-amber-500/20 bg-zinc-900/70 px-3 py-2">
            <div className="flex items-center gap-1.5 text-amber-300/80"><Lock className="h-3.5 w-3.5" />Secrets</div>
            <div className="mt-1 font-mono text-sm text-amber-100">{summary.credentialedServers}</div>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 px-3 py-2">
            <div className="flex items-center gap-1.5 text-zinc-500"><Network className="h-3.5 w-3.5" />Unlinked</div>
            <div className="mt-1 font-mono text-sm text-zinc-100">{summary.unlinkedAgents}</div>
          </div>
        </div>
      </div>
      {(hiddenAgentCount > 0 || hiddenServerCount > 0) && (
        <div className="border-b border-zinc-800/80 bg-zinc-950/70 px-4 py-2 text-xs text-zinc-400">
          Showing the highest-risk {displayAgents.length} agents and{" "}
          {displayAgents.flatMap((agent) => agent.mcp_servers ?? []).length} servers to keep the canvas responsive. Use Fleet search or the
          Security Graph for the remaining {hiddenAgentCount} agents and {hiddenServerCount} servers.
        </div>
      )}
      <div className="grid min-h-[460px] lg:grid-cols-[1fr_270px]">
        <div className="px-2 pb-2 pt-1" style={{ height: 460 }}>
          {displayAgents.length === 0 ? (
            <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-950/50">
              <div className="max-w-sm text-center">
                <ShieldAlert className="mx-auto h-7 w-7 text-zinc-600" />
                <p className="mt-3 text-sm font-medium text-zinc-300">No topology entities match this filter</p>
                <p className="mt-1 text-xs text-zinc-500">Switch filters or run a scan with more agent and MCP server evidence.</p>
              </div>
            </div>
          ) : (
            <ReactFlowProvider>
              <TopologyFlow agents={displayAgents} onAgentClick={handleAgentClick} direction={direction} />
            </ReactFlowProvider>
          )}
        </div>
        <aside className="border-t border-zinc-800/80 bg-zinc-950/55 p-4 lg:border-l lg:border-t-0">
          <p className="text-[10px] uppercase tracking-[0.22em] text-zinc-500">Operator readout</p>
          <div className="mt-3 space-y-3">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-3">
              <p className="text-xs font-semibold text-zinc-200">Isolation context</p>
              <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <div>
                  <dt className="text-zinc-500">Tenant</dt>
                  <dd className="mt-0.5 truncate font-mono text-zinc-200">{session?.tenant_id ?? "local"}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Role</dt>
                  <dd className="mt-0.5 truncate font-mono text-zinc-200">{session?.role_summary?.display_name ?? session?.role ?? "viewer"}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Envs</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200">{summary.environments}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Owners</dt>
                  <dd className="mt-0.5 font-mono text-zinc-200">{summary.owners || "n/a"}</dd>
                </div>
              </dl>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-3">
              <p className="text-xs font-semibold text-zinc-200">Shared service map</p>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                Duplicate MCP service identities are grouped so shared packages, tools, and credentials do not appear as disconnected copies.
              </p>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-3">
              <p className="text-xs font-semibold text-zinc-200">Unlinked agents</p>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                {summary.unlinkedAgents > 0
                  ? `${summary.unlinkedAgents} agent${summary.unlinkedAgents === 1 ? "" : "s"} have no MCP service edge in the current evidence.`
                  : "Every rendered agent has at least one MCP service edge."}
              </p>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-3">
              <p className="text-xs font-semibold text-zinc-200">Priority lanes</p>
              <p className="mt-1 text-xs leading-5 text-zinc-500">
                Neutral edges are inventory. Amber edges carry credential evidence. Red edges carry vulnerability evidence.
              </p>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
