"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  api,
  Agent,
  isConfigured,
  agentClassCounts,
  type AgentDetailResponse,
  type DiscoveryEnvelope,
  type DiscoveryProvenance,
  type AgentLifecycleResponse,
  type AttackFlowNodeData,
  OWASP_LLM_TOP10,
  MITRE_ATLAS,
} from "@/lib/api";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  ReactFlowProvider,
  useReactFlow,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  ArrowLeft,
  ArrowRight,
  AlertCircle,
  Bug,
  ChevronDown,
  ChevronRight,
  Clock3,
  Download,
  GitBranch,
  Key,
  KeyRound,
  Link2,
  Loader2,
  Network,
  Package,
  Search,
  Server,
  Shield,
  ShieldAlert,
  TerminalSquare,
  Wrench,
  X,
} from "lucide-react";
import { DeploymentSurfaceRequiredState } from "@/components/deployment-surface-required-state";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { isDeploymentSurfaceAvailable } from "@/lib/deployment-context";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { StatStrip } from "@/components/stat-strip";
import { Collapsible } from "@/components/collapsible";
import { Drawer } from "@/components/drawer";

// ─── Agents List Helpers ────────────────────────────────────────────────────

function useAgentStats(agents: Agent[]) {
  const configured = agents.filter(isConfigured);
  const notConfigured = agents.filter((a) => !isConfigured(a));
  const totalServers = agents.reduce((s, a) => s + a.mcp_servers.length, 0);
  const totalPackages = agents.reduce(
    (s, a) => s + a.mcp_servers.reduce((ss, srv) => ss + srv.packages.length, 0),
    0
  );
  const totalCredentials = agents.reduce(
    (s, a) =>
      s +
      a.mcp_servers.reduce(
        (ss, srv) =>
          ss +
          (srv.env
            ? Object.keys(srv.env).filter((k) =>
                /key|token|secret|password|credential|auth/i.test(k)
              ).length
            : 0),
        0
      ),
    0
  );

  // ecosystem breakdown
  const ecosystems: Record<string, number> = {};
  for (const a of agents) {
    for (const srv of a.mcp_servers) {
      for (const pkg of srv.packages) {
        const eco = (pkg as { ecosystem?: string }).ecosystem || "unknown";
        ecosystems[eco] = (ecosystems[eco] || 0) + 1;
      }
    }
  }

  const serversWithCredentials = agents.reduce(
    (count, agent) => count + agent.mcp_servers.filter((srv) => (srv.credential_env_vars?.length ?? 0) > 0 || srv.has_credentials).length,
    0
  );
  const blockedServers = agents.reduce(
    (count, agent) => count + agent.mcp_servers.filter((srv) => srv.security_blocked).length,
    0
  );
  const remoteServers = agents.reduce(
    (count, agent) =>
      count +
      agent.mcp_servers.filter((srv) => {
        const transport = (srv.transport || "").toLowerCase();
        return transport.includes("sse") || transport.includes("http");
      }).length,
    0
  );

  return {
    configured,
    notConfigured,
    totalServers,
    totalPackages,
    totalCredentials,
    ecosystems,
    serversWithCredentials,
    blockedServers,
    remoteServers,
  };
}

function provenanceTags(provenance?: DiscoveryProvenance): string[] {
  if (!provenance) return [];
  const tags = [
    provenance.source_type,
    provenance.provider,
    provenance.service,
    provenance.observed_via,
    provenance.version_source,
    provenance.confidence,
  ];
  return tags
    .flatMap((value) => (Array.isArray(value) ? value : value ? [value] : []))
    .map((value) => String(value).replaceAll("_", " "))
    .filter((value, index, all) => value && all.indexOf(value) === index)
    .slice(0, 6);
}

function DiscoveryProvenanceTags({ provenance }: { provenance: DiscoveryProvenance | undefined }) {
  const tags = provenanceTags(provenance);
  if (tags.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {tags.map((tag) => (
        <span key={tag} className="rounded border border-sky-500/30 dark:border-sky-900/60 bg-sky-500/10 dark:bg-sky-950/30 px-1.5 py-0.5 text-[10px] font-mono text-sky-700 dark:text-sky-300">
          {tag}
        </span>
      ))}
    </div>
  );
}

function safeReferenceHref(reference: string): string | null {
  try {
    const url = new URL(reference);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

function safeDisplayUrl(value: string | undefined): string {
  if (!value) return "";
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? `${url.protocol}//${url.host}${url.pathname}` : value;
  } catch {
    return value;
  }
}

function safeCommandLine(command: string | undefined, args: string[] | undefined): string {
  return [command, ...(args ?? [])]
    .filter((part): part is string => Boolean(part))
    .map((part) => (/(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}/i.test(part) ? "<redacted>" : part))
    .join(" ");
}

function safeDisplayText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/g, (match) => safeDisplayUrl(match))
    .replace(/(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|(?:sk|pk|rk)[-_](?:live|test|prod)[-_]\w{10,}/gi, "<redacted>");
}

// ─── Agents List View ───────────────────────────────────────────────────────

const CRED_ENV_RE = /key|token|secret|password|credential|auth/i;

function serverCredentialCount(srv: Agent["mcp_servers"][number]): number {
  if (srv.credential_env_vars?.length) return srv.credential_env_vars.length;
  return srv.env ? Object.keys(srv.env).filter((k) => CRED_ENV_RE.test(k)).length : 0;
}

function agentPackageCount(agent: Agent): number {
  return agent.mcp_servers.reduce((sum, srv) => sum + srv.packages.length, 0);
}

function agentCredentialCount(agent: Agent): number {
  return agent.mcp_servers.reduce((sum, srv) => sum + serverCredentialCount(srv), 0);
}

function ConfiguredPill() {
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
      style={{ color: "var(--status-success)" }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--status-success)" }} aria-hidden="true" />
      configured
    </span>
  );
}

function AgentsList() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [hintDismissed, setHintDismissed] = useState(false);
  const { counts } = useDeploymentContext();

  useEffect(() => {
    api.listAgents()
      .then((r) => setAgents(r.agents))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const { configured, notConfigured: installedOnly, totalServers, totalPackages, totalCredentials, ecosystems, serversWithCredentials, blockedServers, remoteServers } =
    useAgentStats(agents);
  // Split real agents into AI clients (host apps) vs background/framework agents,
  // so the headline doesn't imply e.g. Cursor is an autonomous agent.
  const agentClasses = agentClassCounts(agents);

  const filteredConfigured = configured.filter((a) =>
    !search || a.name.toLowerCase().includes(search.toLowerCase())
  );

  const activeAgent = selectedAgent
    ? configured.find((a) => a.name === selectedAgent) ?? null
    : null;

  const ecosystemHint =
    Object.entries(ecosystems)
      .map(([eco, count]) => `${eco}: ${count}`)
      .join(", ") || undefined;

  const configuredColumns: DataTableColumn<Agent>[] = [
    {
      key: "name",
      header: "Name",
      cell: (agent) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-[color:var(--foreground)]">{agent.name}</div>
          {agent.source ? (
            <div className="truncate text-xs text-[color:var(--text-tertiary)]">{agent.source}</div>
          ) : null}
        </div>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (agent) => (
        <span className="font-mono text-xs text-[color:var(--text-secondary)]">{agent.agent_type}</span>
      ),
    },
    {
      key: "servers",
      header: "Servers",
      align: "right",
      cell: (agent) => <span className="tabular-nums">{agent.mcp_servers.length}</span>,
    },
    {
      key: "packages",
      header: "Packages",
      align: "right",
      cell: (agent) => <span className="tabular-nums">{agentPackageCount(agent)}</span>,
    },
    {
      key: "credentials",
      header: "Credentials",
      align: "right",
      cell: (agent) => {
        const count = agentCredentialCount(agent);
        return (
          <span
            className="tabular-nums"
            style={count > 0 ? { color: "var(--status-warn)" } : undefined}
          >
            {count}
          </span>
        );
      },
    },
    {
      key: "status",
      header: "Status",
      cell: () => <ConfiguredPill />,
    },
  ];

  const installedColumns: DataTableColumn<Agent>[] = [
    {
      key: "name",
      header: "Name",
      cell: (agent) => (
        <span className="font-medium text-[color:var(--text-secondary)]">{agent.name}</span>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (agent) => (
        <span className="font-mono text-xs text-[color:var(--text-tertiary)]">{agent.agent_type}</span>
      ),
    },
    {
      key: "config",
      header: "Config path",
      cell: (agent) => (
        <span className="truncate font-mono text-xs text-[color:var(--text-tertiary)]">
          {agent.config_path || "—"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: () => (
        <span
          className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
          style={{ color: "var(--status-warn)" }}
        >
          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: "var(--status-warn)" }} aria-hidden="true" />
          not configured
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Agents</h1>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">
            Discovered AI clients/hosts and background agents, with their MCP servers
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href="/agents/topology"
            className="flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)]"
          >
            <Network className="h-4 w-4" />
            Agent mesh
          </Link>
          <Link
            href="/mesh"
            className="flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--text-secondary)] transition-colors hover:border-[color:var(--border-strong)]"
          >
            <GitBranch className="h-4 w-4" />
            Mesh View
          </Link>
        </div>
      </div>

      {!loading && agents.length > 0 && !hintDismissed && (
        <div className="flex items-start gap-2 rounded-lg border border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] px-3 py-2 text-xs leading-5 text-[color:var(--text-secondary)]">
          <Shield className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[color:var(--accent)]" />
          <p className="min-w-0 flex-1">
            <span className="font-semibold text-[color:var(--foreground)]">Inventory-first:</span> this page is useful on
            discovery alone — MCP servers, transport, tools, and env-backed credentials. Proxy and gateway add runtime
            enforcement later; they are not required for visibility.
          </p>
          <button
            type="button"
            onClick={() => setHintDismissed(true)}
            aria-label="Dismiss hint"
            className="shrink-0 rounded p-0.5 text-[color:var(--text-tertiary)] transition-colors hover:text-[color:var(--foreground)]"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {!loading && agents.length > 0 && (
        <StatStrip
          data-testid="agents-kpis"
          items={[
            {
              label: "Agents",
              value: agents.length,
              icon: Shield,
              hint: `${configured.length} configured${installedOnly.length > 0 ? ` · ${installedOnly.length} not` : ""}`,
            },
            { label: "Servers", value: totalServers, icon: Server, hint: `${remoteServers} remote` },
            { label: "Packages", value: totalPackages, icon: Package, hint: ecosystemHint },
            {
              label: "Credentials",
              value: totalCredentials,
              icon: Key,
              accent: "warn",
              hint: `${serversWithCredentials} servers`,
            },
            {
              label: "Blocked / risky",
              value: blockedServers,
              icon: AlertCircle,
              accent: "critical",
            },
            {
              label: "Clients · background",
              value: `${agentClasses.client} · ${agentClasses.background}`,
              icon: Network,
            },
          ]}
        />
      )}

      {!loading && agents.length > 0 && (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-sm">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search agents or agent type"
              className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] py-2 pl-9 pr-3 text-sm text-[color:var(--foreground)] placeholder-[color:var(--text-tertiary)] focus:border-[color:var(--border-strong)] focus:outline-none"
            />
          </div>
          <p className="text-xs text-[color:var(--text-tertiary)]">
            {filteredConfigured.length} configured · {installedOnly.length} installed only
          </p>
        </div>
      )}

      {loading && (
        <PageLoadingState
          title="Discovering agents"
          detail="Loading configured agents, MCP servers, packages, credentials, and inventory metadata from the API."
          data-testid="agents-loading-state"
        />
      )}
      {error && (
        <PageErrorState
          title="Could not load agents"
          detail={error}
          suggestions={[
            "Confirm the API is reachable for this dashboard session.",
            "Run a local discovery scan if this is a first-run environment.",
            "Use the scan page to generate a fresh inventory artifact.",
          ]}
          command="agent-bom agents --demo --offline"
        />
      )}

      {!loading && !error && agents.length === 0 &&
        (counts && !isDeploymentSurfaceAvailable("agents", counts) ? (
          <DeploymentSurfaceRequiredState surface="agents" counts={counts} detail={error || null} />
        ) : (
          <PageEmptyState
            title="No agents discovered yet"
            detail="Run discovery against this workspace or load a demo scan to populate configured agents, MCP servers, packages, and credentials."
            icon={Server}
            suggestions={[
              "Start with the offline demo if you need a reproducible sample.",
              "Run a local scan from the same environment where MCP clients are configured.",
              "Open the mesh view after discovery to inspect agent and server relationships.",
            ]}
            command="agent-bom agents --demo --offline"
            actions={FIRST_SCAN_ACTIONS}
            data-testid="agents-empty-state"
          />
        ))}

      {/* Configured agents — dense table, row → detail drawer */}
      {!loading && configured.length > 0 && (
        <section className="space-y-2">
          <div className="flex items-baseline justify-between">
            <h2 className="text-base font-semibold text-[color:var(--foreground)]">Configured agents</h2>
            <p className="text-xs text-[color:var(--text-tertiary)]">Row → servers, tools, and credentials</p>
          </div>
          <DataTable<Agent>
            data-testid="agents-configured-table"
            columns={configuredColumns}
            rows={filteredConfigured}
            rowKey={(agent) => agent.name}
            onRowClick={(agent) => setSelectedAgent(agent.name)}
            selectedKey={selectedAgent ?? undefined}
            maxHeight="34rem"
            caption="Configured agents with server, package, and credential counts"
            empty={
              search
                ? "No configured agents match the current search."
                : "No configured agents in this inventory."
            }
          />
        </section>
      )}

      {/* Installed but not configured */}
      {!loading && installedOnly.length > 0 && (
        <Collapsible
          title="Installed but not configured"
          icon={AlertCircle}
          count={installedOnly.length}
          defaultOpen={false}
        >
          <p className="mb-3 text-xs text-[color:var(--text-secondary)]">
            Binaries detected on PATH. Run setup to configure MCP servers.
          </p>
          <DataTable<Agent>
            data-testid="agents-installed-table"
            columns={installedColumns}
            rows={installedOnly}
            rowKey={(agent, index) => `${agent.name}-${index}`}
            maxHeight="24rem"
            caption="Installed but unconfigured agents"
          />
        </Collapsible>
      )}

      <AgentDetailDrawer agent={activeAgent} open={activeAgent != null} onClose={() => setSelectedAgent(null)} />
    </div>
  );
}

function AgentDetailDrawer({
  agent,
  open,
  onClose,
}: {
  agent: Agent | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!agent) return null;
  const packages = agentPackageCount(agent);
  const credentials = agentCredentialCount(agent);
  const tools = agent.mcp_servers.reduce((sum, srv) => sum + (srv.tools?.length ?? 0), 0);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow={agent.agent_type}
      title={agent.name}
      subtitle={agent.source ?? agent.config_path}
      headerAside={<ConfiguredPill />}
      size="2xl"
      ariaLabel={`Agent ${agent.name}`}
      footer={
        <div className="flex flex-wrap gap-2">
          <Link
            href={`/agents?name=${encodeURIComponent(agent.name)}`}
            className="inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-3 py-2 text-xs font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)]"
          >
            <ArrowRight className="h-3.5 w-3.5" />
            Full detail
          </Link>
          <Link
            href={`/agents?name=${encodeURIComponent(agent.name)}&view=lifecycle`}
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
          >
            <GitBranch className="h-3.5 w-3.5" />
            Lifecycle graph
          </Link>
        </div>
      }
    >
      <div className="space-y-4" data-testid={`agent-detail-${agent.name}`}>
        <StatStrip
          items={[
            { label: "Servers", value: agent.mcp_servers.length },
            { label: "Packages", value: packages },
            { label: "Tools", value: tools },
            { label: "Credentials", value: credentials, accent: "warn" },
          ]}
        />

        {agent.discovery_provenance ? (
          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
              <Shield className="h-3.5 w-3.5" />
              Asset discovery provenance
            </div>
            <DiscoveryProvenanceTags provenance={agent.discovery_provenance} />
          </div>
        ) : null}

        {agent.discovery_envelope ? <DiscoveryEnvelopeCard envelope={agent.discovery_envelope} /> : null}

        <div className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--foreground)]">
            <Server className="h-4 w-4 text-[color:var(--text-secondary)]" />
            MCP servers
            <span className="text-xs font-normal text-[color:var(--text-tertiary)]">({agent.mcp_servers.length})</span>
          </h3>
          {agent.mcp_servers.map((srv, index) => {
            const credEnv = srv.credential_env_vars ?? [];
            return (
              <div
                key={`${srv.name}-${index}`}
                className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-[color:var(--foreground)]">{srv.name}</span>
                    {srv.security_blocked && (
                      <span
                        className="rounded border px-1.5 py-0.5 text-[10px] font-mono"
                        style={{
                          borderColor: "var(--status-danger-border)",
                          backgroundColor: "var(--status-danger-bg)",
                          color: "var(--status-danger)",
                        }}
                      >
                        blocked
                      </span>
                    )}
                    {credEnv.length > 0 && (
                      <span
                        className="rounded border px-1.5 py-0.5 text-[10px] font-mono"
                        style={{
                          borderColor: "var(--status-warn-border)",
                          backgroundColor: "var(--status-warn-bg)",
                          color: "var(--status-warn)",
                        }}
                      >
                        creds
                      </span>
                    )}
                  </div>
                  {srv.transport && (
                    <span className="font-mono text-xs text-[color:var(--text-tertiary)]">{srv.transport}</span>
                  )}
                </div>

                <div className="mt-2">
                  <DiscoveryProvenanceTags provenance={srv.discovery_provenance} />
                </div>

                {srv.command && (
                  <div className="mt-2 flex items-start gap-1.5 font-mono text-xs text-[color:var(--text-tertiary)]">
                    <TerminalSquare className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span className="break-all">{safeCommandLine(srv.command, srv.args)}</span>
                  </div>
                )}
                {srv.url && (
                  <div className="mt-2 flex items-start gap-1.5 font-mono text-xs text-[color:var(--text-tertiary)]">
                    <Link2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span className="break-all">{safeDisplayUrl(srv.url)}</span>
                  </div>
                )}

                <div className="mt-2 flex flex-wrap gap-3 text-xs text-[color:var(--text-tertiary)]">
                  {srv.packages.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Package className="h-3 w-3" />
                      {srv.packages.length} package{srv.packages.length !== 1 ? "s" : ""}
                    </span>
                  )}
                  {srv.tools && srv.tools.length > 0 && (
                    <span className="flex items-center gap-1">
                      <Wrench className="h-3 w-3" />
                      {srv.tools.length} tool{srv.tools.length !== 1 ? "s" : ""}
                    </span>
                  )}
                  {credEnv.length > 0 && (
                    <span className="flex items-center gap-1" style={{ color: "var(--status-warn)" }}>
                      <Key className="h-3 w-3" />
                      {credEnv.length} credential{credEnv.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>

                {credEnv.length > 0 && (
                  <div className="mt-3">
                    <p
                      className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em]"
                      style={{ color: "var(--status-warn)" }}
                    >
                      Credential-backed env vars
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {credEnv.map((envVar) => (
                        <span
                          key={envVar}
                          className="rounded border px-2 py-0.5 text-[11px] font-mono"
                          style={{
                            borderColor: "var(--status-warn-border)",
                            backgroundColor: "var(--status-warn-bg)",
                            color: "var(--status-warn)",
                          }}
                        >
                          {envVar}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {srv.tools && srv.tools.length > 0 && (
                  <div className="mt-3">
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                      Tools
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {srv.tools.map((tool) => (
                        <span
                          key={tool.name}
                          className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 text-[11px] text-[color:var(--text-secondary)]"
                        >
                          {tool.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Drawer>
  );
}

// ─── Agent Detail Components ────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-3">
      <div className="flex items-center gap-1.5 text-xs text-[color:var(--text-tertiary)] mb-1">
        <Icon className={`w-3.5 h-3.5 ${color}`} />
        {label}
      </div>
      <div className="text-xl font-bold">{value}</div>
    </div>
  );
}

// ─── Agent Detail View ──────────────────────────────────────────────────────

function AgentDetail({ agentName }: { agentName: string }) {
  const [data, setData] = useState<AgentDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedServers, setExpandedServers] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .getAgentDetail(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[color:var(--surface)] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-[color:var(--surface)] p-8">
        <Link href="/agents" className="text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] flex items-center gap-1 mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="text-red-400 bg-red-950 border border-red-800 rounded-lg p-4">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  const { agent, summary, blast_radius, credentials, fleet } = data;
  const sev = {
    critical: summary.severity_breakdown.critical ?? 0,
    high: summary.severity_breakdown.high ?? 0,
    medium: summary.severity_breakdown.medium ?? 0,
    low: summary.severity_breakdown.low ?? 0,
  };

  const toggleServer = (name: string) => {
    setExpandedServers((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="min-h-screen bg-[color:var(--surface)] text-[color:var(--foreground)]">
      {/* Header */}
      <div className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <Link href="/agents" className="text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)] flex items-center gap-1 text-sm mb-2">
            <ArrowLeft className="w-3.5 h-3.5" /> All Agents
          </Link>
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-3">
                <ShieldAlert className="w-6 h-6 text-emerald-400" />
                {agent.name}
              </h1>
              <div className="flex items-center gap-3 mt-1 text-sm text-[color:var(--text-tertiary)]">
                <span className="bg-[color:var(--surface-elevated)] px-2 py-0.5 rounded text-xs">
                  {agent.agent_type}
                </span>
                {agent.config_path && (
                  <span className="font-mono text-xs truncate max-w-md">
                    {agent.config_path}
                  </span>
                )}
              </div>
            </div>
            <Link
              href={`/agents?name=${encodeURIComponent(agentName)}&view=lifecycle`}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
            >
              <GitBranch className="w-4 h-4" />
              View Lifecycle Graph
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {fleet && (
          <div className="rounded-xl border border-sky-900/60 bg-sky-950/20 p-4">
            <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-sky-400">Observed state</p>
            <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 px-3 py-2">
                <div className="text-[color:var(--text-tertiary)] text-xs">Lifecycle state</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.lifecycle_state}</div>
              </div>
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 px-3 py-2">
                <div className="text-[color:var(--text-tertiary)] text-xs">Trust score</div>
                <div className="mt-1 text-sm font-semibold text-emerald-400">{fleet.trust_score.toFixed(1)}</div>
              </div>
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 px-3 py-2">
                <div className="text-[color:var(--text-tertiary)] text-xs">Last discovery</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.last_discovery || "not synced yet"}</div>
              </div>
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 px-3 py-2">
                <div className="text-[color:var(--text-tertiary)] text-xs">Last scan</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.last_scan || "not scanned yet"}</div>
              </div>
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/80 px-3 py-2">
                <div className="text-[color:var(--text-tertiary)] text-xs">Updated</div>
                <div className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{fleet.updated_at || "unknown"}</div>
              </div>
            </div>
          </div>
        )}
        <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-4">
          <p className="text-[11px] font-mono uppercase tracking-[0.2em] text-emerald-400">Inventory-first view</p>
          <p className="mt-1 text-sm leading-6 text-[color:var(--text-secondary)]">
            This detail page is valuable before runtime proxy rollout. It shows the granted MCP surface area for
            <span className="mx-1 font-semibold text-[color:var(--foreground)]">{agent.name}</span>
            using discovery and scan data alone: server transport, exposed tools, env-backed credentials, and attached package risk.
          </p>
        </div>
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard icon={Server} label="MCP Servers" value={summary.total_servers} color="text-blue-400" />
          <StatCard icon={Package} label="Packages" value={summary.total_packages} color="text-[color:var(--text-secondary)]" />
          <StatCard icon={Wrench} label="Tools" value={summary.total_tools} color="text-purple-400" />
          <StatCard icon={KeyRound} label="Credentials" value={summary.total_credentials} color="text-yellow-400" />
          <StatCard icon={Bug} label="Vulnerabilities" value={summary.total_vulnerabilities} color="text-red-400" />
          <div className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-3">
            <div className="text-xs text-[color:var(--text-tertiary)] mb-1">Severity</div>
            <div className="flex items-center gap-2 text-xs">
              {sev.critical > 0 && <span className="text-red-400 font-bold">{sev.critical}C</span>}
              {sev.high > 0 && <span className="text-orange-400 font-bold">{sev.high}H</span>}
              {sev.medium > 0 && <span className="text-yellow-400">{sev.medium}M</span>}
              {sev.low > 0 && <span className="text-blue-400">{sev.low}L</span>}
              {sev.critical + sev.high + sev.medium + sev.low === 0 && (
                <span className="text-emerald-400 font-medium">Clean</span>
              )}
            </div>
          </div>
        </div>

        {/* Exposed Credentials */}
        {credentials.length > 0 && (
          <div className="bg-yellow-950/30 border border-yellow-800/50 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-yellow-400 flex items-center gap-2 mb-2">
              <KeyRound className="w-4 h-4" /> Exposed Credentials ({credentials.length})
            </h3>
            <div className="flex flex-wrap gap-2">
              {credentials?.map((c) => (
                <span key={c} className="bg-yellow-950 border border-yellow-800 text-yellow-300 px-2 py-0.5 rounded text-xs font-mono">
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* MCP Servers */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" /> MCP Servers
          </h2>
          <div className="space-y-2">
            {agent.mcp_servers?.map((srv) => {
              const isExpanded = expandedServers.has(srv.name);
              const srvPkgs = srv.packages || [];
              const srvTools = srv.tools || [];
              const vulnCount = srvPkgs.reduce(
                (sum, p) => sum + (p.vulnerabilities?.length ?? 0),
                0
              );
              return (
                <div key={srv.name} className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl overflow-hidden">
                  <button
                    onClick={() => toggleServer(srv.name)}
                    className="w-full px-4 py-3 flex items-center justify-between hover:bg-[color:var(--surface-elevated)]/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-[color:var(--text-tertiary)]" /> : <ChevronRight className="w-4 h-4 text-[color:var(--text-tertiary)]" />}
                      <span className="font-medium">{srv.name}</span>
                      <span className="text-xs bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)] px-2 py-0.5 rounded">
                        {srv.transport || "stdio"}
                      </span>
                      {srv.security_blocked && (
                        <span className="rounded border border-rose-800 bg-rose-950 px-1.5 py-0.5 text-[10px] font-mono text-rose-300">
                          blocked
                        </span>
                      )}
                      {(srv.credential_env_vars?.length ?? 0) > 0 && (
                        <span className="rounded border border-yellow-800 bg-yellow-950 px-1.5 py-0.5 text-[10px] font-mono text-yellow-300">
                          {srv.credential_env_vars?.length ?? 0} credential env
                        </span>
                      )}
                      {srv.auth_mode && (
                        <span className="rounded border border-sky-800 bg-sky-950 px-1.5 py-0.5 text-[10px] font-mono text-sky-300">
                          {srv.auth_mode}
                        </span>
                      )}
                      {srv.provenance?.observed_via?.map((source) => (
                        <span
                          key={source}
                          className="rounded border border-emerald-900 bg-emerald-950 px-1.5 py-0.5 text-[10px] font-mono text-emerald-300"
                        >
                          {source}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-[color:var(--text-tertiary)]">
                      <span>{srvPkgs.length} pkgs</span>
                      <span>{srvTools.length} tools</span>
                      {vulnCount > 0 && (
                        <span className="text-red-400 font-medium">{vulnCount} vulns</span>
                      )}
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="border-t border-[color:var(--border-subtle)] px-4 py-3 space-y-3">
                      <div className="grid gap-3 md:grid-cols-2">
                        {srv.command && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                              <TerminalSquare className="h-3.5 w-3.5" />
                              Command
                            </div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">
                              {safeCommandLine(srv.command, srv.args)}
                            </div>
                          </div>
                        )}
                        {srv.url && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                              <Link2 className="h-3.5 w-3.5" />
                              Remote URL
                            </div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">{safeDisplayUrl(srv.url)}</div>
                          </div>
                        )}
                      </div>
                      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                        {srv.config_path && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Config path</div>
                            <div className="font-mono text-xs text-[color:var(--text-secondary)] break-all">{srv.config_path}</div>
                          </div>
                        )}
                        {srv.auth_mode && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Auth mode</div>
                            <div className="text-xs text-[color:var(--text-secondary)]">{srv.auth_mode}</div>
                          </div>
                        )}
                        <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                          <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                            <Clock3 className="h-3.5 w-3.5" />
                            Discovery context
                          </div>
                          <div className="text-xs text-[color:var(--text-secondary)]">
                            {fleet?.last_discovery ? `Seen in fleet sync at ${fleet.last_discovery}` : "Discovery-only, not synced through fleet yet"}
                          </div>
                        </div>
                        {srv.provenance && (
                          <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]/60 px-3 py-2">
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Provenance</div>
                            <div className="flex flex-wrap gap-1.5">
                              {srv.provenance.observed_via.map((source) => (
                                <span
                                  key={source}
                                  className="rounded border border-emerald-900 bg-emerald-950 px-1.5 py-0.5 text-[10px] font-mono text-emerald-300"
                                >
                                  {source}
                                </span>
                              ))}
                            </div>
                            <div className="mt-2 space-y-1 text-[11px] text-[color:var(--text-secondary)]">
                              {srv.provenance.last_seen && <div>Last seen: <span className="text-[color:var(--text-secondary)]">{srv.provenance.last_seen}</span></div>}
                              {srv.provenance.last_synced && <div>Last synced: <span className="text-[color:var(--text-secondary)]">{srv.provenance.last_synced}</span></div>}
                              {srv.provenance.source_agents.length > 0 && (
                                <div>
                                  Gateway sources: <span className="text-[color:var(--text-secondary)]">{srv.provenance.source_agents.join(", ")}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      {/* Tools */}
                      {srvTools.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-purple-400 mb-1">Tools</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {srvTools?.map((t) => (
                              <span key={t.name} className="bg-purple-950 border border-purple-800 text-purple-300 px-2 py-0.5 rounded text-xs">
                                {t.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.security_warnings?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-rose-400 mb-1">Security warnings</h4>
                          <div className="space-y-1">
                            {srv.security_warnings?.map((warning) => (
                              <div key={warning} className="rounded border border-rose-900/60 bg-rose-950/20 px-3 py-2 text-xs text-rose-300">
                                {safeDisplayText(warning)}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.security_intelligence?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-cyan-300">
                            <ShieldAlert className="h-3.5 w-3.5" />
                            Security intelligence
                          </h4>
                          <div className="space-y-2">
                            {srv.security_intelligence?.map((entry) => (
                              <div key={entry.entry_id} className="rounded border border-cyan-900/60 bg-cyan-950/15 px-3 py-2">
                                <div className="flex flex-wrap items-start justify-between gap-2">
                                  <div className="min-w-0">
                                    <div className="text-xs font-semibold text-cyan-100">{entry.title}</div>
                                    <div className="mt-1 flex flex-wrap gap-1.5">
                                      <span className="rounded border border-cyan-800 bg-cyan-950 px-1.5 py-0.5 text-[10px] uppercase text-cyan-300">
                                        {entry.confidence}
                                      </span>
                                      {entry.source_type && (
                                        <span className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-1.5 py-0.5 text-[10px] uppercase text-[color:var(--text-secondary)]">
                                          {entry.source_type}
                                        </span>
                                      )}
                                      {entry.last_verified && (
                                        <span className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-1.5 py-0.5 text-[10px] text-[color:var(--text-secondary)]">
                                          Verified {entry.last_verified}
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                                <div className="mt-2 text-xs text-[color:var(--text-secondary)]">Recommendation: {entry.default_recommendation}</div>
                                {(entry.remediation_actions?.length ?? 0) > 0 && (
                                  <div className="mt-2 flex flex-wrap gap-1.5">
                                    {entry.remediation_actions?.map((action) => (
                                      <span key={action} className="rounded border border-emerald-900 bg-emerald-950 px-1.5 py-0.5 text-[11px] text-emerald-300">
                                        {action}
                                      </span>
                                    ))}
                                  </div>
                                )}
                                {(entry.references?.some((reference) => safeReferenceHref(reference) !== null) ?? false) && (
                                  <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                                    {entry.references?.map((reference, index) => {
                                      const href = safeReferenceHref(reference);
                                      if (!href) return null;
                                      return (
                                        <a
                                          key={`${entry.entry_id}-${reference}`}
                                          href={href}
                                          target="_blank"
                                          rel="noreferrer"
                                          className="text-cyan-300 underline decoration-cyan-800 underline-offset-2 hover:text-cyan-200"
                                        >
                                          Reference {index + 1}
                                        </a>
                                      );
                                    })}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(srv.credential_env_vars?.length ?? 0) > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-yellow-400 mb-1">Credential-backed env vars</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {srv.credential_env_vars?.map((envVar) => (
                              <span key={envVar} className="rounded border border-yellow-800 bg-yellow-950 px-2 py-0.5 text-[11px] font-mono text-yellow-300">
                                {envVar}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {srv.security_blocked && (
                        <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 px-3 py-2 text-xs text-rose-300">
                          This server is marked as blocked or risky by the discovery/security pipeline. Inventory visibility works without
                          runtime proxy; proxy and gateway are the later enforcement layer.
                        </div>
                      )}
                      {/* Packages */}
                      {srvPkgs.length > 0 && (
                        <div>
                          <h4 className="text-xs font-semibold text-[color:var(--text-secondary)] mb-1">Packages</h4>
                          <div className="space-y-1">
                            {srvPkgs?.map((pkg) => (
                              <div key={`${pkg.name}@${pkg.version}`} className="flex items-center justify-between text-xs">
                                <span className="font-mono">
                                  {pkg.name}
                                  <span className="text-[color:var(--text-tertiary)]">@{pkg.version}</span>
                                </span>
                                <span className="text-[color:var(--text-tertiary)]">{pkg.ecosystem}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Blast Radius */}
        {blast_radius.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Bug className="w-5 h-5 text-red-400" /> Blast Radius ({blast_radius.length})
            </h2>
            <div className="space-y-2">
              {blast_radius?.map((br, i) => (
                <div key={`${br.vulnerability_id}-${i}`} className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={br.severity} />
                      <span className="font-mono font-medium">{br.vulnerability_id}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
                      {br.cvss_score && <span>CVSS {br.cvss_score}</span>}
                      {br.is_kev && <span className="text-red-400 font-bold">KEV</span>}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3 text-xs text-[color:var(--text-secondary)]">
                    {br.package && <span>Package: <span className="text-[color:var(--text-secondary)]">{br.package}</span></span>}
                    {br.exposed_credentials.length > 0 && (
                      <span className="text-yellow-400">{br.exposed_credentials.length} credentials exposed</span>
                    )}
                    {(br.exposed_tools ?? br.reachable_tools).length > 0 && (
                      <span className="text-purple-400">{(br.exposed_tools ?? br.reachable_tools).length} tools reachable</span>
                    )}
                  </div>
                  {/* Framework tags */}
                  <div className="flex flex-wrap gap-1 mt-2">
                    {(br.owasp_tags ?? []).map((t) => (
                      <span key={t} className="bg-indigo-950 border border-indigo-800 text-indigo-300 px-1.5 py-0.5 rounded text-[10px]">
                        {t} {OWASP_LLM_TOP10[t] ?? ""}
                      </span>
                    ))}
                    {(br.atlas_tags ?? []).map((t) => (
                      <span key={t} className="bg-rose-950 border border-rose-800 text-rose-300 px-1.5 py-0.5 rounded text-[10px]">
                        {t} {MITRE_ATLAS[t] ?? ""}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Lifecycle Graph Constants ──────────────────────────────────────────────

const NODE_ICONS: Record<string, React.ElementType> = {
  cve: Bug,
  package: Package,
  server: Server,
  agent: ShieldAlert,
  credential: KeyRound,
  tool: Wrench,
};

const NODE_COLORS: Record<string, string> = {
  cve: "border-red-600 bg-red-950/80",
  package: "border-[color:var(--border-strong)] bg-[color:var(--surface-muted)]/80",
  server: "border-blue-600 bg-blue-950/80",
  agent: "border-emerald-600 bg-emerald-950/80",
  credential: "border-yellow-600 bg-yellow-950/80",
  tool: "border-purple-600 bg-purple-950/80",
};

const MINIMAP_COLORS: Record<string, string> = {
  cve: "#ef4444",
  package: "#52525b",
  server: "#3b82f6",
  agent: "#10b981",
  credential: "#eab308",
  tool: "#a855f7",
};

// ─── Lifecycle Custom Node ──────────────────────────────────────────────────

function LifecycleNode({ data }: { data: AttackFlowNodeData }) {
  const nodeType = data.nodeType;
  const Icon = NODE_ICONS[nodeType] ?? Bug;

  const sevColors: Record<string, string> = {
    critical: "border-red-500 bg-red-950",
    high: "border-orange-500 bg-orange-950",
    medium: "border-yellow-500 bg-yellow-950",
    low: "border-blue-500 bg-blue-950",
  };
  const border = nodeType === "cve" && data.severity
    ? sevColors[data.severity.toLowerCase()] ?? NODE_COLORS[nodeType]
    : NODE_COLORS[nodeType];

  return (
    <div className={`rounded-lg border-2 px-3 py-2 min-w-[140px] max-w-[200px] shadow-lg ${border}`}>
      <Handle type="target" position={Position.Left} className="!bg-[color:var(--text-tertiary)] !w-2 !h-2" />
      <div className="flex items-center gap-2">
        <Icon className="w-3.5 h-3.5 shrink-0 text-[color:var(--text-secondary)]" />
        <span className="text-xs font-semibold text-[color:var(--foreground)] truncate">{data.label}</span>
      </div>
      {data.version && (
        <div className="text-[10px] text-[color:var(--text-tertiary)] mt-0.5 font-mono">{data.version}</div>
      )}
      {data.severity && (
        <div className="mt-1"><SeverityBadge severity={data.severity} /></div>
      )}
      {data.description && (
        <div className="text-[10px] text-[color:var(--text-tertiary)] mt-0.5 truncate">{data.description}</div>
      )}
      <Handle type="source" position={Position.Right} className="!bg-[color:var(--text-tertiary)] !w-2 !h-2" />
    </div>
  );
}

const nodeTypes = { lifecycleNode: LifecycleNode };

// ─── Lifecycle Stats Bar ────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: Record<string, number> }) {
  const items = [
    { label: "Servers", value: stats.total_servers ?? 0, color: "text-blue-400" },
    { label: "Packages", value: stats.total_packages ?? 0, color: "text-[color:var(--text-secondary)]" },
    { label: "Tools", value: stats.total_tools ?? 0, color: "text-purple-400" },
    { label: "Credentials", value: stats.total_credentials ?? 0, color: "text-yellow-400" },
    { label: "Vulns", value: stats.total_vulnerabilities ?? 0, color: "text-red-400" },
  ];
  return (
    <div className="flex items-center gap-4 text-xs">
      {items?.map((s) => (
        <div key={s.label} className="flex items-center gap-1">
          <span className={`font-bold ${s.color}`}>{s.value}</span>
          <span className="text-[color:var(--text-tertiary)]">{s.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Lifecycle Detail Panel ─────────────────────────────────────────────────

function DetailPanel({
  node,
  onClose,
}: {
  node: Node<AttackFlowNodeData>;
  onClose: () => void;
}) {
  const d = node.data;
  const Icon = NODE_ICONS[d.nodeType] ?? Bug;
  return (
    <div className="absolute top-4 right-4 w-72 bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl shadow-2xl z-50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[color:var(--border-subtle)]">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-[color:var(--text-secondary)]" />
          <span className="font-semibold text-sm">{d.label}</span>
        </div>
        <button onClick={onClose} className="text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="px-4 py-3 space-y-2 text-xs">
        <div className="flex justify-between text-[color:var(--text-secondary)]">
          <span>Type</span>
          <span className="text-[color:var(--foreground)] capitalize">{d.nodeType}</span>
        </div>
        {d.severity && (
          <div className="flex justify-between">
            <span className="text-[color:var(--text-secondary)]">Severity</span>
            <SeverityBadge severity={d.severity} />
          </div>
        )}
        {d.cvss_score != null && (
          <div className="flex justify-between text-[color:var(--text-secondary)]">
            <span>CVSS</span>
            <span className="text-[color:var(--foreground)]">{d.cvss_score}</span>
          </div>
        )}
        {d.version && (
          <div className="flex justify-between text-[color:var(--text-secondary)]">
            <span>Version</span>
            <span className="text-[color:var(--foreground)] font-mono">{d.version}</span>
          </div>
        )}
        {d.ecosystem && (
          <div className="flex justify-between text-[color:var(--text-secondary)]">
            <span>Ecosystem</span>
            <span className="text-[color:var(--foreground)]">{d.ecosystem}</span>
          </div>
        )}
        {d.agent_type && (
          <div className="flex justify-between text-[color:var(--text-secondary)]">
            <span>Agent Type</span>
            <span className="text-[color:var(--foreground)]">{d.agent_type}</span>
          </div>
        )}
        {d.description && (
          <div className="text-[color:var(--text-secondary)] pt-1 border-t border-[color:var(--border-subtle)]">
            <span className="block mb-0.5">Description</span>
            <span className="text-[color:var(--text-secondary)]">{d.description}</span>
          </div>
        )}
        {d.fixed_version && (
          <div className="flex justify-between text-[color:var(--text-secondary)]">
            <span>Fix Available</span>
            <span className="text-emerald-400 font-mono">{d.fixed_version}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Lifecycle Flow Canvas ──────────────────────────────────────────────────

function LifecycleFlow({
  data,
  agentName,
}: {
  data: AgentLifecycleResponse;
  agentName: string;
}) {
  const { fitView } = useReactFlow();
  const [selectedNode, setSelectedNode] = useState<Node<AttackFlowNodeData> | null>(null);

  useEffect(() => {
    setTimeout(() => fitView({ padding: 0.2 }), 100);
  }, [fitView, data]);

  const onNodeClick = useCallback((_: unknown, node: Node) => {
    setSelectedNode(node as Node<AttackFlowNodeData>);
  }, []);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${agentName}-lifecycle.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative w-full h-full">
      {/* Header bar */}
      <div className="absolute top-0 left-0 right-0 z-10 bg-[color:var(--surface)]/90 backdrop-blur-sm border-b border-[color:var(--border-subtle)] px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            href={`/agents?name=${encodeURIComponent(agentName)}`}
            className="text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] flex items-center gap-1 text-sm"
          >
            <ArrowLeft className="w-4 h-4" /> {agentName}
          </Link>
          <span className="text-[color:var(--text-tertiary)]">|</span>
          <span className="text-sm font-semibold text-[color:var(--text-secondary)]">Lifecycle Graph</span>
        </div>
        <div className="flex items-center gap-4">
          <StatsBar stats={data.stats} />
          <button
            onClick={handleExport}
            className="text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] flex items-center gap-1 text-xs border border-[color:var(--border-subtle)] rounded px-2 py-1"
          >
            <Download className="w-3.5 h-3.5" /> Export
          </button>
        </div>
      </div>

      <ReactFlow
        nodes={data.nodes as Node[]}
        edges={data.edges as Edge[]}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        fitView
        minZoom={0.1}
        maxZoom={2}
        className="!bg-[color:var(--surface)]"
      >
        <Background color="#27272a" gap={20} />
        <Controls className="!bg-[color:var(--surface-muted)] !border-[color:var(--border-subtle)] !rounded-lg [&>button]:!bg-[color:var(--surface-elevated)] [&>button]:!border-[color:var(--border-subtle)] [&>button]:!text-[color:var(--text-secondary)]" />
        <MiniMap
          nodeColor={(n) => MINIMAP_COLORS[(n.data as AttackFlowNodeData)?.nodeType] ?? "#52525b"}
          className="!bg-[color:var(--surface-muted)] !border-[color:var(--border-subtle)] !rounded-lg"
          maskColor="rgba(0,0,0,0.7)"
        />
      </ReactFlow>

      {selectedNode && (
        <DetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
}

// ─── Lifecycle View ─────────────────────────────────────────────────────────

function AgentLifecycle({ agentName }: { agentName: string }) {
  const [data, setData] = useState<AgentLifecycleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAgentLifecycle(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="h-screen bg-[color:var(--surface)] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="h-screen bg-[color:var(--surface)] p-8">
        <Link href="/agents" className="text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] flex items-center gap-1 mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="text-red-400 bg-red-950 border border-red-800 rounded-lg p-4">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-[color:var(--surface)]">
      <ReactFlowProvider>
        <LifecycleFlow data={data} agentName={agentName} />
      </ReactFlowProvider>
    </div>
  );
}

// ─── Router Component ───────────────────────────────────────────────────────

function AgentsRouter() {
  const searchParams = useSearchParams();
  const name = searchParams.get("name") || "";
  const view = searchParams.get("view") || "";

  if (name && view === "lifecycle") {
    return <AgentLifecycle agentName={name} />;
  }

  if (name) {
    return <AgentDetail agentName={name} />;
  }

  return <AgentsList />;
}

// ─── Page (with Suspense boundary for useSearchParams) ──────────────────────

export default function AgentsPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center min-h-screen"><Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" /></div>}>
      <AgentsRouter />
    </Suspense>
  );
}

// ─── Discovery envelope card (#2083) ──────────────────────────────────────

const SCAN_MODE_LABEL: Record<string, string> = {
  local_only: "local only",
  cloud_read_only: "cloud read-only",
  saas_read_only: "SaaS read-only",
  runtime_probe: "runtime probe",
  container_local: "container (local)",
  endpoint_push: "endpoint push",
};

const REDACTION_LABEL: Record<string, string> = {
  never_collected: "never collected",
  redacted_in_place: "redacted in place",
  central_sanitizer_applied: "central sanitizer",
  not_applicable: "n/a",
};

function DiscoveryEnvelopeCard({ envelope }: { envelope: DiscoveryEnvelope }) {
  const captured = envelope.captured_at
    ? new Date(envelope.captured_at).toLocaleString()
    : null;
  const mode = SCAN_MODE_LABEL[envelope.scan_mode] ?? envelope.scan_mode;
  const redaction = REDACTION_LABEL[envelope.redaction_status] ?? envelope.redaction_status;
  return (
    <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-3">
      <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-300">
        <Shield className="h-3.5 w-3.5" />
        Scan trust contract
      </div>
      <p className="mb-2 text-[11px] text-emerald-200/80">
        Scan ran from your local or self-hosted deployment boundary with read-only roles. Sensitive values are never collected or are redacted before storage.
      </p>
      <div className="mb-2 flex flex-wrap gap-1.5">
        <span className="rounded border border-emerald-800 bg-emerald-950/60 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.14em] text-emerald-300">
          {mode}
        </span>
        <span className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]/60 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-secondary)]">
          redaction: {redaction}
        </span>
      </div>
      {envelope.discovery_scope.length > 0 && (
        <div className="mt-2 text-[11px] text-[color:var(--text-secondary)]">
          <div className="mb-1 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Scope</div>
          <div className="flex flex-wrap gap-1.5">
            {envelope.discovery_scope.map((s) => (
              <span key={s} className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-1.5 py-0.5 font-mono text-[color:var(--text-secondary)]">
                {s}
              </span>
            ))}
          </div>
        </div>
      )}
      {envelope.permissions_used.length > 0 && (
        <details className="mt-2 text-[11px] text-[color:var(--text-secondary)]">
          <summary className="cursor-pointer text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)] hover:text-[color:var(--text-secondary)]">
            Permissions used ({envelope.permissions_used.length})
          </summary>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {envelope.permissions_used.map((p) => (
              <span key={p} className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-1.5 py-0.5 font-mono text-[color:var(--text-secondary)]">
                {p}
              </span>
            ))}
          </div>
        </details>
      )}
      {captured && (
        <div className="mt-2 text-[10px] text-[color:var(--text-tertiary)]">
          Captured {captured} · envelope v{envelope.envelope_version}
        </div>
      )}
    </div>
  );
}
