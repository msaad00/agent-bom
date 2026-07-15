"use client";

import Link from "next/link";
import { Lock, Package, Server, ShieldAlert, Users, Wrench, X } from "lucide-react";

import { useEscToClose } from "@/hooks/use-esc-to-close";
import type { Agent } from "@/lib/api";
import {
  serverHasCredentials,
  serverVulnerabilityCount,
  serviceKey,
  topologyAgentDisplayName,
  topologyAgentTypeLabel,
} from "@/lib/agent-topology-graph";

type MCPServer = NonNullable<Agent["mcp_servers"]>[number];

export function TopologyDetailDrawer({
  agents,
  selection,
  onClose,
}: {
  agents: Agent[];
  selection:
    | { kind: "agent"; name: string }
    | { kind: "server"; serviceKey: string; label: string }
    | null;
  onClose: () => void;
}) {
  useEscToClose(selection !== null, onClose);
  if (!selection) return null;

  const agent =
    selection.kind === "agent" ? agents.find((entry) => entry.name === selection.name) : undefined;
  const connectedAgents =
    selection.kind === "server"
      ? agents.filter((entry) =>
          (entry.mcp_servers ?? []).some((server) => serviceKey(server) === selection.serviceKey),
        )
      : [];
  const serverMatches =
    selection.kind === "server"
      ? agents.flatMap((entry) =>
          (entry.mcp_servers ?? [])
            .filter((server) => serviceKey(server) === selection.serviceKey)
            .map((server) => ({ agent: entry, server })),
        )
      : agent
        ? (agent.mcp_servers ?? []).map((server) => ({ agent, server }))
        : [];

  const title =
    selection.kind === "agent"
      ? topologyAgentDisplayName(agent ?? { name: selection.name, agent_type: "agent", mcp_servers: [] })
      : selection.label;
  const subtitle =
    selection.kind === "agent"
      ? `${topologyAgentTypeLabel(agent?.agent_type ?? "agent")} · ${selection.name}`
      : `${connectedAgents.length} agent${connectedAgents.length === 1 ? "" : "s"} share this service identity`;

  const totalVulns = serverMatches.reduce((sum, match) => sum + serverVulnerabilityCount(match.server), 0);
  const totalTools = serverMatches.reduce((sum, match) => sum + (match.server.tools?.length ?? 0), 0);
  const totalPackages = serverMatches.reduce((sum, match) => sum + (match.server.packages?.length ?? 0), 0);
  const hasCredentials = serverMatches.some((match) => serverHasCredentials(match.server));

  return (
    <div
      className="fixed inset-0 z-[80] flex justify-end bg-black/45 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`Topology details for ${title}`}
    >
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Close topology details" onClick={onClose} />
      <aside className="relative h-full w-full max-w-md overflow-y-auto border-l border-[var(--border-subtle)] bg-[var(--background)] p-5 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] pb-4">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
              {selection.kind === "agent" ? "Agent runtime" : "Shared MCP service"}
            </p>
            <h2 className="mt-2 text-lg font-semibold text-[var(--foreground)]">{title}</h2>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">{subtitle}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] p-2 text-[var(--text-secondary)] transition hover:text-[var(--foreground)]"
            aria-label="Close topology drawer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mb-4 grid grid-cols-2 gap-2">
          <Metric label="Servers" value={serverMatches.length} icon={Server} />
          <Metric label="Packages" value={totalPackages} icon={Package} />
          <Metric label="Tools" value={totalTools} icon={Wrench} />
          <Metric label="CVEs" value={totalVulns} icon={ShieldAlert} tone={totalVulns > 0 ? "danger" : "neutral"} />
        </div>

        {hasCredentials ? (
          <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 dark:bg-amber-950/20 px-3 py-2 text-xs text-amber-700 dark:text-amber-200">
            <Lock className="mr-1.5 inline h-3.5 w-3.5" />
            Credential-backed env vars detected on this service path.
          </div>
        ) : null}

        {selection.kind === "server" && connectedAgents.length > 1 ? (
          <div className="mb-4">
            <p className="mb-2 flex items-center gap-1.5 text-xs text-[var(--text-tertiary)]">
              <Users className="h-3.5 w-3.5" />
              Shared blast radius
            </p>
            <div className="flex flex-wrap gap-1.5">
              {connectedAgents.map((entry) => (
                <span key={entry.name} className="rounded bg-[var(--surface)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">
                  {topologyAgentDisplayName(entry)}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        <div className="space-y-2">
          {serverMatches.map(({ agent: entry, server }) => (
            <ServerCard key={`${entry.name}:${serviceKey(server)}`} agentName={entry.name} server={server} />
          ))}
        </div>

        <div className="mt-5 flex flex-wrap gap-2 border-t border-[var(--border-subtle)] pt-4">
          {selection.kind === "agent" ? (
            <Link
              href={`/agents?name=${encodeURIComponent(selection.name)}`}
              className="rounded-lg border border-emerald-700/50 bg-emerald-500/10 dark:bg-emerald-950/30 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200"
            >
              Open agent record
            </Link>
          ) : null}
          <Link
            href="/mesh"
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)]"
          >
            Agent mesh
          </Link>
          <Link
            href="/security-graph"
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)]"
          >
            Security graph
          </Link>
        </div>
      </aside>
    </div>
  );
}

function Metric({
  label,
  value,
  icon: Icon,
  tone = "neutral",
}: {
  label: string;
  value: number;
  icon: typeof Server;
  tone?: "neutral" | "danger";
}) {
  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/70 px-3 py-2">
      <div className={`flex items-center gap-1.5 text-[10px] ${tone === "danger" ? "text-red-300" : "text-[var(--text-tertiary)]"}`}>
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className={`mt-1 font-mono text-sm ${tone === "danger" ? "text-red-100" : "text-[var(--foreground)]"}`}>{value}</div>
    </div>
  );
}

function ServerCard({ agentName, server }: { agentName: string; server: MCPServer }) {
  const vulns = serverVulnerabilityCount(server);
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-[var(--foreground)]">{server.name}</span>
        {serverHasCredentials(server) ? <Lock className="h-3.5 w-3.5 text-amber-300" /> : null}
      </div>
      <p className="mt-1 truncate font-mono text-[10px] text-[var(--text-tertiary)]">{agentName}</p>
      <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-[var(--text-tertiary)]">
        <span>{server.packages?.length ?? 0} packages</span>
        <span>{server.tools?.length ?? 0} tools</span>
        {vulns > 0 ? <span className="text-red-300">{vulns} CVE{vulns === 1 ? "" : "s"}</span> : null}
      </div>
    </div>
  );
}
