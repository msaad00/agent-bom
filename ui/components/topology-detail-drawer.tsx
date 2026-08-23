"use client";

import Link from "next/link";
import { useState } from "react";
import { Lock, Package, Server, ShieldAlert, Users, Wrench } from "lucide-react";

import { Drawer } from "@/components/drawer";
import type { Agent } from "@/lib/api";
import {
  serverHasCredentials,
  serverVulnerabilityCount,
  serviceKey,
  topologyAgentDisplayName,
  topologyAgentTypeLabel,
} from "@/lib/agent-topology-graph";

type MCPServer = NonNullable<Agent["mcp_servers"]>[number];
type DetailTab = "overview" | "services" | "actions";

const DETAIL_TABS: { id: DetailTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "services", label: "Services" },
  { id: "actions", label: "Actions" },
];

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
  const [activeTab, setActiveTab] = useState<DetailTab>("overview");
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
    <Drawer
      open
      onClose={onClose}
      size="2xl"
      ariaLabel={`Topology details for ${title}`}
      closeLabel="Close topology details"
      backdropLabel="Dismiss topology details"
      bodyClassName="!overflow-hidden !p-0"
      eyebrow={selection.kind === "agent" ? "Agent runtime" : "Shared MCP service"}
      title={title}
      subtitle={subtitle}
    >
      <div className="flex h-full min-h-0 flex-col">
        <div className="border-b border-[var(--border-subtle)] px-5 pt-4">
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Metric label="Servers" value={serverMatches.length} icon={Server} />
            <Metric label="Packages" value={totalPackages} icon={Package} />
            <Metric label="Tools" value={totalTools} icon={Wrench} />
            <Metric label="CVEs" value={totalVulns} icon={ShieldAlert} tone={totalVulns > 0 ? "danger" : "neutral"} />
          </div>
          <div className="flex gap-1" role="tablist" aria-label="Topology detail sections">
            {DETAIL_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={activeTab === tab.id}
                aria-controls={`topology-${tab.id}-panel`}
                id={`topology-${tab.id}-tab`}
                onClick={() => setActiveTab(tab.id)}
                className={`border-b-2 px-3 py-2 text-xs font-semibold transition-colors ${
                  activeTab === tab.id
                    ? "border-emerald-500 text-[var(--foreground)]"
                    : "border-transparent text-[var(--text-tertiary)] hover:text-[var(--foreground)]"
                }`}
              >
                {tab.label}
                {tab.id === "services" ? (
                  <span className="ml-1.5 rounded-full bg-[var(--surface-muted)] px-1.5 py-0.5 font-mono text-[10px]">
                    {serverMatches.length}
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          {activeTab === "overview" ? (
            <section role="tabpanel" id="topology-overview-panel" aria-labelledby="topology-overview-tab" className="space-y-4">
              {hasCredentials ? (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/20 dark:text-amber-200">
                  <Lock className="mr-1.5 inline h-3.5 w-3.5" />
                  Credential-backed env vars detected on this service path.
                </div>
              ) : (
                <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-muted)] px-3 py-2 text-xs text-[var(--text-secondary)]">
                  No credential-backed environment variables were observed on this service path.
                </div>
              )}
              {selection.kind === "server" && connectedAgents.length > 1 ? (
                <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-muted)] p-4">
                  <p className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-[var(--foreground)]">
                    <Users className="h-3.5 w-3.5" /> Shared blast radius
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {connectedAgents.map((entry) => (
                      <span key={entry.name} className="rounded bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text-secondary)]">
                        {topologyAgentDisplayName(entry)}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="grid gap-3 sm:grid-cols-2">
                <SummaryCard label="Evidence scope" value={`${serverMatches.length} service path${serverMatches.length === 1 ? "" : "s"}`} />
                <SummaryCard
                  label="Priority"
                  value={totalVulns > 0 ? `${totalVulns} vulnerability finding${totalVulns === 1 ? "" : "s"}` : "No CVE evidence in this view"}
                  tone={totalVulns > 0 ? "danger" : "neutral"}
                />
              </div>
            </section>
          ) : null}
          {activeTab === "services" ? (
            <section role="tabpanel" id="topology-services-panel" aria-labelledby="topology-services-tab" className="grid gap-2 sm:grid-cols-2">
              {serverMatches.map(({ agent: entry, server }) => (
                <ServerCard key={`${entry.name}:${serviceKey(server)}`} agentName={entry.name} server={server} />
              ))}
            </section>
          ) : null}
          {activeTab === "actions" ? (
            <section role="tabpanel" id="topology-actions-panel" aria-labelledby="topology-actions-tab" className="grid gap-3 sm:grid-cols-2">
              {selection.kind === "agent" ? (
                <ActionLink href={`/agents?name=${encodeURIComponent(selection.name)}`} title="Open agent record" description="Review inventory, ownership, and discovered services." />
              ) : null}
              <ActionLink href="/mesh" title="Open agent mesh" description="Compare agent-to-agent and shared-service relationships." />
              <ActionLink href="/security-graph" title="Open security graph" description="Traverse correlated findings, reachability, and ranked paths." />
            </section>
          ) : null}
        </div>
      </div>
    </Drawer>
  );
}

function SummaryCard({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string;
  tone?: "neutral" | "danger";
}) {
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-muted)] p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--text-tertiary)]">{label}</p>
      <p
        className={`mt-2 text-sm font-medium ${
          tone === "danger" ? "text-red-700 dark:text-red-200" : "text-[var(--foreground)]"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function ActionLink({ href, title, description }: { href: string; title: string; description: string }) {
  return (
    <Link
      href={href}
      className="group rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-muted)] p-4 transition-colors hover:border-emerald-500/45 hover:bg-emerald-500/5"
    >
      <p className="text-sm font-semibold text-[var(--foreground)] group-hover:text-emerald-700 dark:group-hover:text-emerald-200">
        {title}
      </p>
      <p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">{description}</p>
    </Link>
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
      <div className={`flex items-center gap-1.5 text-[10px] ${tone === "danger" ? "text-red-700 dark:text-red-300" : "text-[var(--text-tertiary)]"}`}>
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className={`mt-1 font-mono text-sm ${tone === "danger" ? "text-red-700 dark:text-red-100" : "text-[var(--foreground)]"}`}>{value}</div>
    </div>
  );
}

function ServerCard({ agentName, server }: { agentName: string; server: MCPServer }) {
  const vulns = serverVulnerabilityCount(server);
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-[var(--foreground)]">{server.name}</span>
        {serverHasCredentials(server) ? <Lock className="h-3.5 w-3.5 text-amber-700 dark:text-amber-300" /> : null}
      </div>
      <p className="mt-1 truncate font-mono text-[10px] text-[var(--text-tertiary)]">{agentName}</p>
      <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-[var(--text-tertiary)]">
        <span>{server.packages?.length ?? 0} packages</span>
        <span>{server.tools?.length ?? 0} tools</span>
        {vulns > 0 ? <span className="text-red-700 dark:text-red-300">{vulns} CVE{vulns === 1 ? "" : "s"}</span> : null}
      </div>
    </div>
  );
}
