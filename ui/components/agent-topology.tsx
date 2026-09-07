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
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Lock, Network, Users } from "lucide-react";
import type { Agent, AuthMeResponse } from "@/lib/api";
import {
  buildTopologyGraph,
  filterTopologyAgents,
  limitTopologyAgents,
  topologyAgentDisplayName,
  serviceKey,
  serverHasCredentials,
  serverVulnerabilityCount,
  topologySummary,
  type TopologyFilter,
} from "@/lib/agent-topology-graph";
import { useDagreLrLayout } from "@/lib/use-dagre-lr";
import { useThemeMode } from "@/lib/theme-mode";
import { TopologyDetailDrawer } from "@/components/topology-detail-drawer";
import { graphNodeDisplayLabels, readableGraphEdges } from "@/lib/graph-utils";

const TOPOLOGY_CONTROLS_CLASS =
  "!rounded-lg !border !border-[color:var(--border-subtle)] !bg-[color:var(--surface-elevated)] !backdrop-blur-sm [&>button]:!border-[color:var(--border-subtle)] [&>button]:!bg-[color:var(--surface)] [&>button]:!text-[color:var(--text-secondary)] [&>button:hover]:!bg-[color:var(--surface-muted)] [&>button:hover]:!text-[color:var(--foreground)]";

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
      className={`min-w-[132px] max-w-[168px] rounded-lg border bg-[color:var(--surface-elevated)] px-3 py-2 shadow-sm transition-colors ${
        data.unlinked
          ? "border-[color:var(--border-subtle)] hover:border-[color:var(--border-strong)]"
          : "cursor-pointer border-emerald-600/35 hover:border-emerald-500/60"
      }`}
    >
      <Handle
        type="source"
        position={Position.Right}
        className="!h-1.5 !w-1.5 !border-emerald-500 !bg-emerald-400"
      />
      <p className="truncate text-xs font-semibold text-[color:var(--foreground)]">{data.label}</p>
      <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{data.typeLabel}</p>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-[color:var(--text-tertiary)]">
        {!data.unlinked ? <span>{data.serverCount} svc</span> : <span>unlinked</span>}
        {data.credCount > 0 ? <span className="text-amber-600 dark:text-amber-300">{data.credCount} cred</span> : null}
        {data.vulnCount > 0 ? <span className="text-red-600 dark:text-red-300">{data.vulnCount} CVE</span> : null}
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
      className={`min-w-[132px] max-w-[168px] cursor-pointer rounded-lg border bg-[color:var(--surface-elevated)] px-3 py-2 shadow-sm transition-colors ${
        data.vulnCount > 0
          ? "border-red-600/40 hover:border-red-500/60"
          : data.hasCredentials
            ? "border-amber-600/40 hover:border-amber-500/55"
            : "border-sky-600/35 hover:border-sky-500/55"
      }`}
    >
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-sky-500 !bg-sky-400" />
      <div className="flex items-start justify-between gap-2">
        <p className="truncate text-xs font-semibold text-[color:var(--foreground)]">{data.label}</p>
        {data.shared ? <Users className="h-3 w-3 shrink-0 text-cyan-600 dark:text-cyan-300" aria-hidden /> : null}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-[color:var(--text-tertiary)]">
        <span>
          {data.agentCount} agent{data.agentCount === 1 ? "" : "s"}
        </span>
        {data.pkgCount > 0 ? <span>{data.pkgCount} pkg</span> : null}
        {data.hasCredentials ? <Lock className="h-3 w-3 text-amber-600 dark:text-amber-300" /> : null}
        {data.vulnCount > 0 ? <span className="text-red-600 dark:text-red-300">{data.vulnCount} CVE</span> : null}
      </div>
      {!hot ? <p className="mt-1 text-[10px] text-[color:var(--text-tertiary)]">inventory edge</p> : null}
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
  const theme = useThemeMode();
  const { fitView, getViewport, setViewport } = useReactFlow();
  const { nodes: rawNodes, edges } = useMemo(() => buildTopologyGraph(agents), [agents]);
  const { nodes, pending } = useDagreLrLayout(rawNodes, edges, {
    nodeWidth: 168,
    nodeHeight: 72,
    rankSep: 120,
    nodeSep: 28,
    minSeparation: { width: 168, height: 72, gap: 24 },
  });
  const displayEdges = useMemo(
    () =>
      readableGraphEdges(edges as Edge[], undefined, {
        nodeLabels: graphNodeDisplayLabels(nodes),
        preserveVisualStyle: true,
      }),
    [edges, nodes],
  );
  const backgroundDot = theme === "light" ? "#94a3b8" : "#5b6472";

  useEffect(() => {
    if (pending) return;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      await fitView({ padding: 0.14, duration: 0, minZoom: 0.9, maxZoom: 1.05 });
      if (cancelled) return;
      const viewport = getViewport();
      const top = Math.min(...nodes.map((node) => node.position.y), 0);
      // Start at the beginning of the readable columns, not halfway through
      // tall inventory. Remaining rows remain available by panning.
      void setViewport({ ...viewport, y: 24 - top * viewport.zoom });
    }, 80);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [fitView, getViewport, setViewport, nodes, pending]);

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
      edges={displayEdges}
      nodeTypes={nodeTypes}
      onNodeClick={handleNodeClick}
      fitView
      fitViewOptions={{ padding: 0.14, minZoom: 0.9, maxZoom: 1.05 }}
      minZoom={0.65}
      maxZoom={1.5}
      panOnDrag
      zoomOnScroll
      className="!bg-[color:var(--surface-muted)]"
      proOptions={{ hideAttribution: true }}
    >
      <Background color={backgroundDot} gap={24} size={1} />
      <Controls showInteractive={false} className={TOPOLOGY_CONTROLS_CLASS} />
    </ReactFlow>
  );
}

export function AgentTopology({
  agents,
  session,
  sourceScope,
}: {
  agents: Agent[];
  direction?: "LR" | "TB";
  session?: AuthMeResponse | null;
  sourceScope?: string | undefined;
}) {
  const [filter, setFilter] = useState<TopologyFilter>("attention");
  const [selection, setSelection] = useState<
    { kind: "agent"; name: string } | { kind: "server"; serviceKey: string; label: string } | null
  >(null);
  const [showReadout, setShowReadout] = useState(false);

  const summary = useMemo(() => topologySummary(agents), [agents]);

  const filteredAgents = useMemo(() => filterTopologyAgents(agents, filter), [agents, filter]);
  const displayAgents = useMemo(() => limitTopologyAgents(filteredAgents), [filteredAgents]);
  const connectedAgents = useMemo(
    () => displayAgents.filter((agent) => (agent.mcp_servers?.length ?? 0) > 0),
    [displayAgents],
  );
  const unlinkedAgents = useMemo(
    () => displayAgents.filter((agent) => (agent.mcp_servers?.length ?? 0) === 0),
    [displayAgents],
  );
  const visible = topologySummary(displayAgents);
  const matched = topologySummary(filteredAgents);
  const capped = displayAgents.length < filteredAgents.length || visible.uniqueServices < matched.uniqueServices;
  const filterOptions = [
    { key: "all" as const, label: "Full mesh" },
    { key: "attention" as const, label: "Needs attention" },
    { key: "credentialed" as const, label: "Credential references" },
    { key: "unlinked" as const, label: "Unlinked" },
  ];

  const handleSelect = useCallback(
    (next: { kind: "agent"; name: string } | { kind: "server"; serviceKey: string; label: string }) => {
      setSelection(next);
    },
    [],
  );

  if (!agents || agents.length === 0) {
    return (
      <div className="flex h-[320px] items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
        <div className="text-center">
          <Network className="mx-auto mb-2 h-8 w-8 text-[color:var(--text-tertiary)]" />
          <p className="text-sm text-[color:var(--text-secondary)]">No agent configurations available</p>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">Configure supported clients on this API host, then refresh the inventory</p>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border-subtle)] px-4 py-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.22em] text-[color:var(--text-tertiary)]">Agent topology</p>
          <h3 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">Agent mesh</h3>
          <p className="mt-1 max-w-2xl text-xs text-[color:var(--text-secondary)]">
            Configured relationships, grouped for display. Service groups do not establish shared runtime identity or an attack path.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <StatPill label="Agents" value={summary.agents} />
          <StatPill label="Service groups" value={summary.uniqueServices} />
          <StatPill label="Multi-agent groups" value={summary.sharedServers} tone="cyan" />
          <StatPill label="Groups with CVE refs" value={summary.vulnerableServers} tone="danger" />
          <StatPill label="Groups with credential refs" value={summary.credentialedServers} tone="amber" />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border-subtle)] px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          {filterOptions.map((option) => (
            <button
              key={option.key}
              type="button"
              onClick={() => setFilter(option.key)}
              aria-pressed={filter === option.key}
              className={`rounded-full border px-2.5 py-1 text-xs font-medium ${
                filter === option.key
                  ? "border-[color:var(--border-strong)] bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[10px] text-[color:var(--text-tertiary)]">
          <span className="flex items-center gap-1">
            <span className="h-2 w-4 rounded bg-slate-400/80" /> inventory
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-4 rounded bg-amber-500/80" /> credential references
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-4 rounded bg-red-500/80" /> CVE evidence
          </span>
          <button
            type="button"
            onClick={() => setShowReadout((value) => !value)}
            className="text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
          >
            {showReadout ? "Hide context" : "Context"}
          </button>
        </div>
      </div>

      <div className="border-b border-[color:var(--border-subtle)] px-4 py-2 text-xs text-[color:var(--text-secondary)]" aria-live="polite">
        Showing {displayAgents.length} of {matched.agents} matching agents · {visible.uniqueServices} of {matched.uniqueServices} matching service groups.
        {" "}Full inventory: {summary.agents} agents · {summary.uniqueServices} service groups · {summary.servers} configured relationships.
        {capped ? " View limit reached. Narrow the filter or inspect the Agents inventory for the remaining records." : null}
        {connectedAgents.length > 0 ? <span className="hidden md:inline"> Pan or zoom to inspect connections beyond the viewport.</span> : null}
        <p className="mt-1">
          {sourceScope === "local_discovery"
            ? "Local configuration discovery; vulnerabilities are not assessed by this source. This scope differs from scanned findings."
            : summary.vulnerableServers === 0 ? "No linked CVE evidence in this mesh; this does not establish a clean estate." : "CVE labels reflect evidence linked to this mesh only."}
        </p>
      </div>

      {showReadout ? (
        <div className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3 text-xs text-[color:var(--text-secondary)]">
          Tenant {session?.tenant_id ?? "local"} · role {session?.role_summary?.display_name ?? session?.role ?? "viewer"} ·{" "}
          {summary.environments} env{summary.environments === 1 ? "" : "s"} ·{" "}
          {summary.unlinkedAgents > 0
            ? `${summary.unlinkedAgents} agent${summary.unlinkedAgents === 1 ? "" : "s"} have no service relationship in current evidence.`
            : "Every agent has at least one configured service relationship."}
        </div>
      ) : null}

      {connectedAgents.length > 0 ? (
        <div className="hidden px-2 pb-2 pt-1 md:block" style={{ height: Math.min(720, Math.max(440, visible.uniqueServices * 90)) }}>
          <ReactFlowProvider>
            <TopologyFlow agents={connectedAgents} onSelect={handleSelect} />
          </ReactFlowProvider>
        </div>
      ) : displayAgents.length === 0 ? (
        <div className="px-4 py-10 text-center">
          <p className="text-sm font-medium text-[color:var(--foreground)]">
            {filter === "attention" ? "No attention signals in this mesh" : "No agents match this filter"}
          </p>
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">
            Choose Full mesh to inspect all configured relationships. No signal does not mean an assessment passed.
          </p>
        </div>
      ) : null}
      {connectedAgents.length > 0 ? (
        <section aria-label="Configured service relationships" className="p-4 md:hidden">
          <ul className="space-y-4">
            {connectedAgents.map((agent) => (
              <li key={agent.name}>
                <button type="button" aria-label={`Inspect agent ${topologyAgentDisplayName(agent)}`}
                  onClick={() => handleSelect({ kind: "agent", name: agent.name })}
                  className="text-left text-sm font-semibold text-[color:var(--foreground)]">
                  {topologyAgentDisplayName(agent)}
                </button>
                <ul className="mt-2 space-y-2 border-l border-[color:var(--border-subtle)] pl-3">
                  {(agent.mcp_servers ?? []).map((server) => (
                    <li key={serviceKey(server)}>
                      <button type="button" aria-label={`Inspect service ${server.name} for ${topologyAgentDisplayName(agent)}`}
                        onClick={() => handleSelect({ kind: "server", serviceKey: serviceKey(server), label: server.name })}
                        className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-left text-sm text-[color:var(--foreground)]">
                        <span className="block break-words font-medium">{server.name}</span>
                        <span className="mt-1 block text-xs text-[color:var(--text-secondary)]">
                          Configured connection{serverHasCredentials(server) ? " · Credential reference" : ""}
                          {serverVulnerabilityCount(server) > 0 ? ` · ${serverVulnerabilityCount(server)} linked CVE records` : ""}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {unlinkedAgents.length > 0 ? (
        <section aria-label="Agents without service relationships" className="border-t border-[color:var(--border-subtle)] p-4">
          <h4 className="text-xs font-semibold text-[color:var(--foreground)]">No service relationship observed</h4>
          <ul className="mt-2 flex flex-wrap gap-2">
            {unlinkedAgents.map((agent) => (
              <li key={agent.name}>
                <button type="button" aria-label={`Inspect ${topologyAgentDisplayName(agent)}`}
                  onClick={() => handleSelect({ kind: "agent", name: agent.name })}
                  className="rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-xs text-[color:var(--foreground)] hover:bg-[color:var(--surface-muted)]">
                  {topologyAgentDisplayName(agent)}
                </button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

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
      ? "border-red-500/25 text-red-700 dark:text-red-200"
      : tone === "amber"
        ? "border-amber-500/25 text-amber-800 dark:text-amber-200"
        : tone === "cyan"
          ? "border-cyan-500/25 text-cyan-800 dark:text-cyan-200"
          : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)]";
  return (
    <div className={`rounded-lg border bg-[color:var(--surface-elevated)] px-2.5 py-1.5 ${toneClass}`}>
      <span className="font-mono text-[color:var(--foreground)]">{value}</span> {label.toLowerCase()}
    </div>
  );
}
