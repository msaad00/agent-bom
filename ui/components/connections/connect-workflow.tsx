"use client";

import { useAuthState } from "@/components/auth-provider";
import { Card,Section } from "@/components/card";
import { CONNECTOR_CATALOG,CONNECTOR_CATEGORIES,CONNECTOR_CATEGORY_TONE,type CatalogConnector,type ConnectorCategory,type HubTab } from "@/components/connections/catalog";
import { ProviderLogo } from "@/components/connections/display";
import { CopyTextButton } from "@/components/connections/wizard-controls";
import { Drawer } from "@/components/drawer";
import { FirstRunJourney } from "@/components/first-run-journey";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import {
  type CloudConnectionRecord,
  type SourceKind
} from "@/lib/api";
import { serviceEntry } from "@/lib/service-registry";
import {
  ArrowRight,
  Bot,
  Boxes,
  CheckCircle2,
  FileCode,
  Lock,
  Plug,
  Search,
  Shield,
  ShieldCheck,
  Terminal
} from "lucide-react";


// ── Segmented control ─────────────────────────────────────────────────────────

export function HubTabs({
  tab,
  onChange,
  connectCount,
  sourceCount,
}: {
  tab: HubTab;
  onChange: (tab: HubTab) => void;
  connectCount: number;
  sourceCount: number;
}) {
  const tabs: { key: HubTab; label: string; count?: number; icon: typeof Plug }[] = [
    { key: "connect", label: "Add source", count: connectCount, icon: Plug },
    { key: "sources", label: "Sources", count: sourceCount, icon: Boxes },
    { key: "endpoints", label: "Endpoints", icon: Shield },
  ];
  return (
    <div
      className="inline-flex max-w-full flex-wrap items-center gap-1 rounded-xl border border-outline bg-surface-muted p-1"
      role="tablist"
      aria-label="Connections segment"
    >
      {tabs.map((item) => {
        const Icon = item.icon;
        const selected = item.key === tab;
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
              event.preventDefault();
              const index = tabs.findIndex(candidate => candidate.key === item.key);
              const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
              onChange(tabs[nextIndex]!.key);
              const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("[role=tab]");
              buttons?.[nextIndex]?.focus();
            }}
            onClick={() => onChange(item.key)}
            className={`inline-flex items-center gap-2 rounded-lg px-4 py-1.5 text-sm font-medium transition-colors ${
              selected
                ? "bg-surface text-foreground shadow-sm"
                : "text-ink-tertiary hover:text-foreground"
            }`}
          >
            <Icon className="h-4 w-4" />
            {item.label}
            {item.count !== undefined && <span className="rounded-full border border-outline bg-surface-elevated px-1.5 py-0.5 text-[10px] font-mono text-ink-tertiary">
              {item.count}
            </span>}
          </button>
        );
      })}
    </div>
  );
}


// ── Connect segment ───────────────────────────────────────────────────────────

export function ConnectSegment({
  session,
  connections,
  connectionsCount,
  canManage,
  gallery,
  onConnect,
}: {
  session: ReturnType<typeof useAuthState>["session"];
  counts: ReturnType<typeof useDeploymentContext>["counts"];
  cloudService: ReturnType<typeof serviceEntry>;
  connections: CloudConnectionRecord[];
  connectionsCount: number;
  canManage: boolean;
  gallery: React.ReactNode;
  onConnect: () => void;
}) {
  const verifiedConnectionsCount = connections.filter(
    (connection) => connection.capability_probe_status === "verified",
  ).length;
  const scannedConnectionsCount = connections.filter(
    (connection) =>
      connection.capability_probe_status === "verified" && Boolean(connection.last_scan_at || connection.last_scan_id),
  ).length;

  return (
    <div className="space-y-6">
      <FirstRunJourney
        showPermissionNotice={false}
        connectionsCount={connectionsCount}
        verifiedConnectionsCount={verifiedConnectionsCount}
        scannedConnectionsCount={scannedConnectionsCount}
        canManage={canManage}
        session={session}
        onConnect={onConnect}
      />

      <Section
        label="Connect a source"
        description="Cloud accounts open a read-only wizard; code, AI, and data sources register in the control plane and appear under Sources."
      >
        {gallery}
      </Section>

    </div>
  );
}


export function ConnectorGallery({
  activeCategory,
  onCategoryChange,
  search,
  onSearchChange,
  connectedCountFor,
  canManage,
  canManageSources,
  managedTrial,
  managedTrialProviders,
  onConnectCloud,
  onRegisterSource,
  onConnectCodingAgent,
}: {
  activeCategory: ConnectorCategory | "all";
  onCategoryChange: (category: ConnectorCategory | "all") => void;
  search: string;
  onSearchChange: (value: string) => void;
  connectedCountFor: (connector: CatalogConnector) => number;
  canManage: boolean;
  canManageSources: boolean;
  managedTrial: boolean;
  managedTrialProviders: string[] | null;
  onConnectCloud: (provider: string) => void;
  onRegisterSource: (kind: SourceKind) => void;
  onConnectCodingAgent: () => void;
}) {
  const query = search.trim().toLowerCase();
  const visible = CONNECTOR_CATALOG.filter((connector) => {
    const inCategory = activeCategory === "all" || connector.category === activeCategory;
    if (!inCategory) return false;
    if (!query) return true;
    const haystack = `${connector.label} ${connector.tagline} ${connector.keywords ?? ""}`.toLowerCase();
    return haystack.includes(query);
  });

  function categoryCount(category: ConnectorCategory | "all"): number {
    if (category === "all") return CONNECTOR_CATALOG.length;
    return CONNECTOR_CATALOG.filter((c) => c.category === category).length;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Connector category">
          {CONNECTOR_CATEGORIES.map((category) => {
            const active = activeCategory === category.id;
            return (
              <button
                key={category.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onCategoryChange(category.id)}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? "border-emerald-600/60 bg-emerald-500/10 text-foreground"
                    : "border-outline text-ink-secondary hover:border-outline-strong"
                }`}
              >
                {category.label}
                <span className="text-[10px] text-ink-tertiary">{categoryCount(category.id)}</span>
              </button>
            );
          })}
        </div>
        <label className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-tertiary" />
          <input
            type="search"
            aria-label="Search connectors"
            placeholder="Search connectors…"
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            className="w-full rounded-lg border border-outline bg-surface-muted py-1.5 pl-8 pr-3 text-sm text-foreground outline-none transition focus:border-emerald-500"
          />
        </label>
      </div>

      {visible.length === 0 ? (
        <p className="rounded-xl border border-outline bg-surface-muted px-4 py-8 text-center text-sm text-ink-secondary">
          No connectors match “{search}”.
        </p>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {visible.map((connector) => (
            <ConnectorTile
              key={connector.id}
              connector={connector}
              connectedCount={connectedCountFor(connector)}
              canManage={canManage}
              canManageSources={canManageSources}
              managedTrial={managedTrial}
              managedTrialProviders={managedTrialProviders}
              onConnectCloud={onConnectCloud}
              onRegisterSource={onRegisterSource}
              onConnectCodingAgent={onConnectCodingAgent}
            />
          ))}
        </div>
      )}
    </div>
  );
}


export function ConnectorTile({
  connector,
  connectedCount,
  canManage,
  canManageSources,
  managedTrial,
  managedTrialProviders,
  onConnectCloud,
  onRegisterSource,
  onConnectCodingAgent,
}: {
  connector: CatalogConnector;
  connectedCount: number;
  canManage: boolean;
  canManageSources: boolean;
  managedTrial: boolean;
  managedTrialProviders: string[] | null;
  onConnectCloud: (provider: string) => void;
  onRegisterSource: (kind: SourceKind) => void;
  onConnectCodingAgent: () => void;
}) {
  const Icon = connector.icon;
  const categoryLabel =
    CONNECTOR_CATEGORIES.find((c) => c.id === connector.category)?.label ?? connector.category;
  const connected = connectedCount > 0;
  const cloudAllowed =
    canManage &&
    (!managedTrial ||
      (connector.action.type === "cloud" &&
        Boolean(managedTrialProviders?.includes(connector.action.provider))));

  return (
    <Card className="flex h-full min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-outline bg-[linear-gradient(145deg,var(--surface-elevated),var(--surface-muted))] shadow-inner shadow-black/20">
            {connector.logo ? (
              <ProviderLogo provider={connector.logo} className="h-6 w-6" />
            ) : (
              <Icon className="h-5 w-5 text-emerald-400" />
            )}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold leading-snug text-foreground [overflow-wrap:anywhere]">{connector.label}</p>
            <p className="mt-1 text-xs leading-snug text-ink-secondary">{connector.tagline}</p>
          </div>
        </div>
        <span
          className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium ${CONNECTOR_CATEGORY_TONE[connector.category]}`}
        >
          {categoryLabel}
        </span>
      </div>

      <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-1">
        {connector.action.type === "coding-agent" ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-ink-tertiary">
            <Lock className="h-3 w-3" /> Read-only
          </span>
        ) : connected ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-emerald-300">
            <CheckCircle2 className="h-3 w-3" />
            {connectedCount} connected
          </span>
        ) : (
          <span className="text-[11px] text-ink-tertiary">Not connected</span>
        )}

        {connector.action.type === "cloud" ? (
          <button
            type="button"
            onClick={() => onConnectCloud(connector.action.type === "cloud" ? connector.action.provider : "")}
            disabled={!cloudAllowed}
            title={managedTrial && !cloudAllowed ? "Managed trial supports AWS account connections only." : undefined}
            aria-label={`Connect ${connector.label}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Plug className="h-3.5 w-3.5" />
            Connect
          </button>
        ) : connector.action.type === "coding-agent" ? (
          <button
            type="button"
            onClick={onConnectCodingAgent}
            aria-label="Set up coding agent"
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/20"
          >
            <Plug className="h-3.5 w-3.5" />
            Set up
          </button>
        ) : (
          <button
            type="button"
            onClick={() => onRegisterSource(connector.action.type === "source" ? connector.action.sourceKind : "scan.repo")}
            disabled={!canManageSources}
            aria-label={`Register ${connector.label}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-2.5 py-1.5 text-xs font-medium text-foreground transition hover:border-emerald-600 hover:text-emerald-700 dark:hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Register
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </Card>
  );
}


// ── Coding-agent onboarding drawer ────────────────────────────────────────────

export const CODING_AGENT_MCP_SNIPPET = `{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp-server"]
    }
  }
}`;


export function CodingAgentDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      size="lg"
      eyebrow="AI · Read-only"
      title="Connect a coding agent"
      subtitle={
        <span className="text-[11px] text-ink-tertiary">
          Local MCP server + skills for Claude Code & Cursor
        </span>
      }
      headerAside={
        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 px-2.5 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
          <Bot className="h-3 w-3" /> 89 MCP tools
        </span>
      }
    >
      <div className="space-y-4 text-sm text-ink-secondary">
        <p>
          Expose Agent-BOM&apos;s read-only tools — scan, blast-radius, exposure-paths, SBOM, compliance, and
          remediation — to your coding agent over the Model Context Protocol. Everything runs locally against your
          control plane; no code or credentials leave your machine.
        </p>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-ink-tertiary">
            <Terminal className="h-3.5 w-3.5" /> 1 · Start the MCP server
          </h3>
          <div className="flex items-center justify-between gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2">
            <code className="overflow-x-auto whitespace-nowrap font-mono text-[12px] text-foreground">
              agent-bom mcp-server
            </code>
            <CopyTextButton text="agent-bom mcp-server" />
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-ink-tertiary">
            <FileCode className="h-3.5 w-3.5" /> 2 · Register it in your agent
          </h3>
          <p className="text-[12px]">
            Add to your agent&apos;s MCP config (Claude Code <code className="font-mono">mcp.json</code>, Cursor{" "}
            <code className="font-mono">~/.cursor/mcp.json</code>):
          </p>
          <div className="relative">
            <pre className="overflow-x-auto rounded-lg border border-outline bg-surface-muted p-3 font-mono text-[11px] leading-5 text-foreground">
              {CODING_AGENT_MCP_SNIPPET}
            </pre>
            <div className="mt-2">
              <CopyTextButton text={CODING_AGENT_MCP_SNIPPET} label="Copy config" />
            </div>
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-ink-tertiary">
            <ShieldCheck className="h-3.5 w-3.5" /> Bundled skills
          </h3>
          <ul className="space-y-1.5 text-[12px]">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span>
                <strong className="text-foreground">Cortex Code</strong> — scan-on-save, exposure-path
                lookups, and SBOM diffing inside your editor.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span>
                <strong className="text-foreground">OpenCLAW</strong> — agent-driven remediation and
                compliance workflows over the same read-only tools.
              </span>
            </li>
          </ul>
        </section>

        <p className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-900/50 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-2 text-[11px] text-emerald-700 dark:text-emerald-300">
          <Lock className="h-3.5 w-3.5 shrink-0" /> Collection uses read-only source access. Scan evidence and connection settings are stored in the control plane.
        </p>
      </div>
    </Drawer>
  );
}
