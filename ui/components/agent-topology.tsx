"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  ReactFlowProvider,
  useReactFlow,
  Handle,
  Position,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Lock, Network, Users } from "lucide-react";
import type { Agent, AuthMeResponse } from "@/lib/api";
import {
  MAX_TOPOLOGY_AGENTS,
  MAX_TOPOLOGY_SERVERS,
  agentRiskScore,
  buildTopologyGraph,
  selectAgentsForLens,
  serverMatchesFilter,
  topologySummary,
  type TopologyFilter,
  type TopologyLens,
} from "@/lib/agent-topology-graph";
import { useDagreLrLayout } from "@/lib/use-dagre-lr";
import { BACKGROUND_COLOR, BACKGROUND_GAP, CONTROLS_CLASS } from "@/lib/graph-utils";
import { TopologyDetailDrawer } from "@/components/topology-detail-drawer";

function AgentNode({
  data,
}: {
  data: {
    label: string;
    slug: string;
    typeLabel: string;
    serverCount: number;
    vulnCount: number;
    credCount: number;
    unlinked: boolean;
  };
}) {
  return (
    <div
      className={`min-w-[132px] max-w-[168px] rounded-lg border bg-zinc-950/95 px-3 py-2 shadow-sm backdrop-blur transition-colors ${
        data.unlinked
          ? "border-zinc-700/70 hover:border-zinc-500"
          : "cursor-pointer border-emerald-900/40 hover:border-emerald-500/50"
      }`}
    >
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-emerald-500 !bg-emerald-400" />
      <p className="truncate text-xs font-semibold text-zinc-100">{data.label}</p>
      <p className="truncate text-[10px] text-zinc-500">{data.typeLabel}</p>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-zinc-500">
        {!data.unlinked ? <span>{data.serverCount} svc</span> : <span>unlinked</span>}
        {data.credCount > 0 ? <span className="text-amber-300">{data.credCount} cred</span> : null}
        {data.vulnCount > 0 ? <span className="text-red-300">{data.vulnCount} CVE</span> : null}
      </div>
    </div>
  );
}

function ServerNode({
  data,
}: {
  data: {
    label: string;
    serviceKey: string;
    agentCount: number;
    pkgCount: number;
    toolCount: number;
    hasCredentials: boolean;
    vulnCount: number;
    shared: boolean;
  };
}) {
  const hot = data.vulnCount > 0 || data.hasCredentials;
  return (
    <div
      className={`min-w-[132px] max-w-[168px] cursor-pointer rounded-lg border bg-zinc-950/95 px-3 py-2 shadow-sm backdrop-blur transition-colors ${
        data.vulnCount > 0
          ? "border-red-900/50 hover:border-red-500/50"
          : data.hasCredentials
            ? "border-amber-900/40 hover:border-amber-500/45"
            : "border-blue-900/40 hover:border-blue-500/45"
      }`}
    >
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-blue-500 !bg-blue-400" />
      <div className="flex items-start justify-between gap-2">
        <p className="truncate text-xs font-semibold text-zinc-100">{data.label}</p>
        {data.shared ? <Users className="h-3 w-3 shrink-0 text-cyan-300" aria-hidden /> : null}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-zinc-500">
        <span>{data.agentCount} agent{data.agentCount === 1 ? "" : "s"}</span>
        {data.pkgCount > 0 ? <span>{data.pkgCount} pkg</span> : null}
        {data.hasCredentials ? <Lock className="h-3 w-3 text-amber-300" /> : null}
        {data.vulnCount > 0 ? <span className="text-red-300">{data.vulnCount} CVE</span> : null}
      </div>
      {!hot ? <p className="mt-1 text-[10px] text-zinc-600">inventory edge</p> : null}
    </div>
  );
}

const nodeTypes = { agentNode: AgentNode, serverNode: ServerNode };

function TopologyFlow({
  agents,
  onSelect,
}: {
  agents: Agent[];
  onSelect: (selection: { kind: "agent"; name: string } | { kind: "server"; serviceKey: string; label: string }) => void;
}) {
  const { fitView } = useReactFlow();
  const { nodes: rawNodes, edges } = useMemo(() => buildTopologyGraph(agents), [agents]);
  const { nodes, pending } = useDagreLrLayout(rawNodes, edges, {
    nodeWidth: 168,
    nodeHeight: 72,
    rankSep: 120,
    nodeSep: 28,
  });

  useEffect(() => {
    if (pending) return;
    const timer = window.setTimeout(() => fitView({ padding: 0.2, duration: 300 }), 80);
    return () => window.clearTimeout(timer);
  }, [fitView, nodes, pending]);

  const handleNodeClick = useCallback(
    (_: unknown, node: Node) => {
      if (node.id.startsWith("agent-")) {
        onSelect({ kind: "agent", name: String(node.data.slug ?? node.id.replace("agent-", "")) });
        return;
      }
      if (node.id.startsWith("srv-")) {
        onSelect({
          kind: "server",
          serviceKey: String(node.data.serviceKey ?? node.id.replace("srv-", "")),
          label: String(node.data.label ?? "MCP service"),
        });
      }
    },
    [onSelect],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={handleNodeClick}
      fitView
      minZoom={0.15}
      maxZoom={1.5}
      panOnDrag
      zoomOnScroll
      className="!bg-transparent"
      proOptions={{ hideAttribution: true }}
    >
      <Background color={BACKGROUND_COLOR} gap={BACKGROUND_GAP} size={1} />
      <Controls showInteractive={false} className={CONTROLS_CLASS} />
    </ReactFlow>
  );
}

export function AgentTopology({
  agents,
  session,
}: {
  agents: Agent[];
  direction?: "LR" | "TB";
  session?: AuthMeResponse | null;
}) {
  const [filter, setFilter] = useState<TopologyFilter>("all");
  const [lens, setLens] = useState<TopologyLens>("path");
  const [selection, setSelection] = useState<
    { kind: "agent"; name: string } | { kind: "server"; serviceKey: string; label: string } | null
  >(null);
  const [showReadout, setShowReadout] = useState(false);

  const summary = useMemo(() => topologySummary(agents), [agents]);

  const filteredAgents = useMemo(() => {
    if (filter === "all") return agents;
    if (filter === "unlinked") {
      return agents
        .filter((agent) => (agent.mcp_servers?.length ?? 0) === 0)
        .map((agent) => ({ ...agent, mcp_servers: [] }));
    }
    return agents
      .map((agent) => ({
        ...agent,
        mcp_servers: (agent.mcp_servers ?? []).filter((server) => serverMatchesFilter(server, filter)),
      }))
      .filter((agent) => agent.mcp_servers.length > 0);
  }, [agents, filter]);

  const lensAgents = useMemo(
    () => selectAgentsForLens(filteredAgents, lens),
    [filteredAgents, lens],
  );

  const displayAgents = useMemo(() => {
    let renderedServers = 0;
    return [...lensAgents]
      .sort(
        (left, right) =>
          agentRiskScore(right) - agentRiskScore(left) ||
          (right.mcp_servers?.length ?? 0) - (left.mcp_servers?.length ?? 0) ||
          left.name.localeCompare(right.name),
      )
      .filter((agent) => {
        if (renderedServers >= MAX_TOPOLOGY_SERVERS) return false;
        renderedServers += agent.mcp_servers?.length ?? 0;
        return true;
      })
      .slice(0, MAX_TOPOLOGY_AGENTS);
  }, [lensAgents]);

  const hiddenAgentCount = Math.max(0, filteredAgents.length - displayAgents.length);
  const filterOptions = useMemo(
    () => [
      { key: "all" as const, label: "All", count: summary.agents },
      { key: "attention" as const, label: "Attention", count: summary.attentionServers },
      { key: "credentialed" as const, label: "Credentialed", count: summary.credentialedServers },
      { key: "unlinked" as const, label: "Unlinked", count: summary.unlinkedAgents },
    ],
    [summary],
  );

  const handleSelect = useCallback(
    (next: { kind: "agent"; name: string } | { kind: "server"; serviceKey: string; label: string }) => {
      setSelection(next);
    },
    [],
  );

  if (!agents || agents.length === 0) {
    return (
      <div className="flex h-[320px] items-center justify-center rounded-xl border border-zinc-800/60 bg-zinc-900/50">
        <div className="text-center">
          <Network className="mx-auto mb-2 h-8 w-8 text-zinc-700" />
          <p className="text-sm text-zinc-500">No agents discovered yet</p>
          <p className="mt-1 text-xs text-zinc-600">Run a scan to see the topology</p>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-zinc-800/70 bg-zinc-950/80">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-zinc-800/80 px-4 py-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.22em] text-zinc-500">Agent topology</p>
          <h3 className="mt-1 text-sm font-semibold text-zinc-100">Trust mesh</h3>
          <p className="mt-1 max-w-2xl text-xs text-zinc-500">
            Scanned AI runtimes connected to MCP services. Shared identities collapse into one server node; amber edges
            mean credentials, red edges mean CVE evidence.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <StatPill label="Agents" value={summary.agents} />
          <StatPill label="Services" value={summary.uniqueServices} />
          <StatPill label="Shared" value={summary.sharedServers} tone="cyan" />
          <StatPill label="CVE" value={summary.vulnerableServers} tone="danger" />
          <StatPill label="Secrets" value={summary.credentialedServers} tone="amber" />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-lg border border-zinc-800 p-0.5">
            {(["path", "full"] as const).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setLens(value)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                  lens === value ? "bg-zinc-800 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {value === "path" ? "Risk path" : "Full mesh"}
              </button>
            ))}
          </div>
          {filterOptions.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setFilter(option.key)}
              className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
                filter === option.key
                  ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                  : "border-zinc-800 bg-zinc-900/70 text-zinc-400 hover:border-zinc-700"
              }`}
            >
              {option.label}
              <span className="ml-1.5 font-mono text-[10px] text-zinc-500">{option.count}</span>
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[10px] text-zinc-500">
          <span className="flex items-center gap-1"><span className="h-2 w-4 rounded bg-zinc-500/50" /> inventory</span>
          <span className="flex items-center gap-1"><span className="h-2 w-4 rounded bg-amber-500/80" /> credentials</span>
          <span className="flex items-center gap-1"><span className="h-2 w-4 rounded bg-red-500/80" /> CVE evidence</span>
          <button type="button" onClick={() => setShowReadout((value) => !value)} className="text-zinc-400 hover:text-zinc-200">
            {showReadout ? "Hide context" : "Context"}
          </button>
        </div>
      </div>

      {hiddenAgentCount > 0 ? (
        <div className="border-b border-zinc-800/80 bg-zinc-950/70 px-4 py-2 text-xs text-zinc-400">
          Showing the highest-risk slice ({displayAgents.length} agents). Switch to Full mesh or open Agent Mesh for the
          remaining {hiddenAgentCount} agents.
        </div>
      ) : null}

      {showReadout ? (
        <div className="border-b border-zinc-800/80 bg-zinc-950/55 px-4 py-3 text-xs text-zinc-500">
          Tenant {session?.tenant_id ?? "local"} · role {session?.role_summary?.display_name ?? session?.role ?? "viewer"} ·{" "}
          {summary.environments} env{summary.environments === 1 ? "" : "s"} ·{" "}
          {summary.unlinkedAgents > 0
            ? `${summary.unlinkedAgents} agent${summary.unlinkedAgents === 1 ? "" : "s"} have no MCP edge in current evidence.`
            : "Every agent has at least one MCP edge."}
        </div>
      ) : null}

      <div className="px-2 pb-2 pt-1" style={{ height: 440 }}>
        {displayAgents.length === 0 ? (
          <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-950/50">
            <div className="max-w-sm text-center">
              <p className="text-sm font-medium text-zinc-300">No topology entities match this filter</p>
              <p className="mt-1 text-xs text-zinc-500">Try All or Risk path, or run a scan with MCP server evidence.</p>
            </div>
          </div>
        ) : (
          <ReactFlowProvider>
            <TopologyFlow agents={displayAgents} onSelect={handleSelect} />
          </ReactFlowProvider>
        )}
      </div>

      <TopologyDetailDrawer agents={agents} selection={selection} onClose={() => setSelection(null)} />
    </div>
  );
}

function StatPill({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: number;
  tone?: "neutral" | "danger" | "amber" | "cyan";
}) {
  const toneClass =
    tone === "danger"
      ? "border-red-500/20 text-red-200"
      : tone === "amber"
        ? "border-amber-500/20 text-amber-200"
        : tone === "cyan"
          ? "border-cyan-500/20 text-cyan-200"
          : "border-zinc-800 text-zinc-300";
  return (
    <div className={`rounded-lg border bg-zinc-900/80 px-2.5 py-1.5 ${toneClass}`}>
      <span className="font-mono text-zinc-100">{value}</span> {label.toLowerCase()}
    </div>
  );
}
