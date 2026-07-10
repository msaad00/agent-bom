"use client";

import { useEffect, useMemo, useState } from "react";
import type { ElementType } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Bot,
  Box,
  Cloud,
  Download,
  GitBranch,
  KeyRound,
  Loader2,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Blocks,
  Sparkles,
} from "lucide-react";

import { Card, Section } from "@/components/card";
import { Collapsible } from "@/components/collapsible";
import { PageLaneHeader } from "@/components/page-lane";
import { StatCard } from "@/components/stat-card";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import {
  DEFAULT_MANIFEST_FILTERS,
  deriveManifestRows,
  filterManifestRows,
  manifestFilterOptions,
  type ManifestFilters,
} from "@/lib/agent-bom-manifest";
import {
  aiBomScopeLabel,
  countActiveEvidenceSources,
  deriveAiBomEvidenceSources,
  summarizeAiBomEntities,
  type AiBomEvidenceSource,
} from "@/lib/ai-bom-evidence";
import { api, formatDate, type AgentBomManifestResponse } from "@/lib/api";

function downloadManifest(manifest: AgentBomManifestResponse) {
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ai-bom-${manifest.tenant_id ?? "local"}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function ScopeChip({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-200">
      {label}
    </span>
  );
}

function BoundaryBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
          : "border-amber-500/30 bg-amber-500/10 text-amber-200"
      }`}
    >
      {ok ? <ShieldCheck className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
      {label}
    </span>
  );
}

function DriftStatusBadge({ status }: { status: string }) {
  const needsReview = status === "needs_review";
  const aligned = status === "aligned";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${
        needsReview
          ? "border-amber-500/30 bg-amber-500/10 text-amber-200"
          : aligned
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
            : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)]"
      }`}
    >
      {needsReview ? <AlertTriangle className="h-3 w-3" /> : <ShieldCheck className="h-3 w-3" />}
      blueprint {status.replaceAll("_", " ")}
    </span>
  );
}

function EvidenceSourceRow({ source }: { source: AiBomEvidenceSource }) {
  const body = (
    <div
      className={`flex items-center justify-between gap-3 rounded-lg border px-2.5 py-2 transition ${
        source.active
          ? "border-emerald-600/35 bg-emerald-500/10 hover:border-emerald-500/50"
          : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]/60 opacity-75"
      } ${source.href ? "cursor-pointer" : ""}`}
    >
      <div className="min-w-0">
        <p className="truncate text-xs font-medium text-[color:var(--foreground)]">{source.label}</p>
        <p className="mt-0.5 truncate text-[10px] text-[color:var(--text-tertiary)]">{source.detail}</p>
      </div>
      <span
        className={`shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
          source.active ? "bg-emerald-500/15 text-emerald-300" : "bg-[color:var(--surface)] text-[color:var(--text-tertiary)]"
        }`}
      >
        {source.active ? "Live" : "Off"}
      </span>
    </div>
  );

  if (source.href) {
    return (
      <Link href={source.href} className="block">
        {body}
      </Link>
    );
  }
  return body;
}

function MetricChip({
  label,
  value,
  icon: Icon,
  href,
}: {
  label: string;
  value: number;
  icon: ElementType;
  href?: string;
}) {
  const content = (
    <div
      className={`flex items-center gap-2.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition ${
        href ? "hover:border-[color:var(--border-strong)]" : ""
      }`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0 text-[color:var(--text-tertiary)]" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">{label}</p>
        <p className="font-mono text-sm font-semibold tabular-nums text-[color:var(--foreground)]">
          {value.toLocaleString()}
        </p>
      </div>
    </div>
  );
  if (href) {
    return (
      <Link href={href} className="block">
        {content}
      </Link>
    );
  }
  return content;
}

function MiniGraph({ manifest }: { manifest: AgentBomManifestResponse }) {
  const nodes = manifest.graph.nodes.slice(0, 12);
  const edges = manifest.graph.edges.slice(0, 20);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] text-[color:var(--text-secondary)]">
          {manifest.graph.stats.nodes} nodes · {manifest.graph.stats.edges} edges
        </p>
        <Link
          href="/graph?layers=agent,server,tool,credential"
          className="inline-flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300"
        >
          Open lineage <GitBranch className="h-3 w-3" />
        </Link>
      </div>

      <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
        {nodes.map((node) => (
          <div
            key={node.id}
            className="flex items-center justify-between gap-2 rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5"
          >
            <span className="truncate text-xs text-[color:var(--foreground)]" title={node.label}>
              {node.label}
            </span>
            <span className="shrink-0 text-[9px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
              {node.entity_type}
            </span>
          </div>
        ))}
        {nodes.length === 0 ? (
          <p className="text-xs text-[color:var(--text-secondary)]">No graph nodes yet.</p>
        ) : null}
      </div>

      <div className="max-h-36 overflow-auto rounded-lg border border-[color:var(--border-subtle)]">
        <table className="w-full text-left text-[11px]">
          <thead className="sticky top-0 bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]">
            <tr>
              <th className="px-2 py-1.5 font-medium">Rel</th>
              <th className="px-2 py-1.5 font-medium">From</th>
              <th className="px-2 py-1.5 font-medium">To</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[color:var(--border-subtle)]">
            {edges.map((edge) => (
              <tr key={edge.id}>
                <td className="px-2 py-1.5 text-[color:var(--foreground)]">{edge.relationship}</td>
                <td className="max-w-[6rem] truncate px-2 py-1.5 text-[color:var(--text-secondary)]">{edge.source}</td>
                <td className="max-w-[6rem] truncate px-2 py-1.5 text-[color:var(--text-secondary)]">{edge.target}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function AgentBomManifestPage() {
  const { counts } = useDeploymentContext();
  const [manifest, setManifest] = useState<AgentBomManifestResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<ManifestFilters>(DEFAULT_MANIFEST_FILTERS);

  const load = () => {
    setLoading(true);
    setError(null);
    api
      .getAgentBomManifest()
      .then(setManifest)
      .catch((err) => setError(err instanceof Error ? err.message : "Manifest request failed"))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const allRows = useMemo(() => (manifest ? deriveManifestRows(manifest) : []), [manifest]);
  const rows = useMemo(() => filterManifestRows(allRows, filters), [allRows, filters]);
  const options = useMemo(() => manifestFilterOptions(allRows), [allRows]);
  const hasActiveFilters = JSON.stringify(filters) !== JSON.stringify(DEFAULT_MANIFEST_FILTERS);
  const evidenceSources = useMemo(() => deriveAiBomEvidenceSources(counts, manifest), [counts, manifest]);
  const entityRollup = useMemo(() => summarizeAiBomEntities(manifest), [manifest]);
  const activeSources = countActiveEvidenceSources(evidenceSources);
  const scopeLabel = aiBomScopeLabel(counts, manifest);

  const updateFilter = <K extends keyof ManifestFilters>(key: K, value: ManifestFilters[K]) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const metrics: { label: string; value: number; icon: ElementType; href?: string }[] = [
    { label: "Agents", value: entityRollup.agents, icon: Bot, href: "/agents" },
    { label: "MCP servers", value: entityRollup.mcpServers, icon: Server },
    { label: "Models", value: entityRollup.models, icon: Sparkles },
    { label: "Frameworks", value: entityRollup.frameworks, icon: Blocks },
    { label: "Packages", value: entityRollup.packages, icon: Box },
    { label: "Cloud assets", value: entityRollup.cloudAssets, icon: Cloud, href: "/connections" },
    { label: "Credential refs", value: entityRollup.credentials, icon: KeyRound },
    { label: "Findings", value: entityRollup.findings, icon: AlertTriangle, href: "/findings" },
    {
      label: "Runtime seen",
      value: manifest?.summary.runtime_observed_servers ?? 0,
      icon: Activity,
      href: "/runtime",
    },
  ];

  return (
    <div className="space-y-4">
      <PageLaneHeader
        lane="ai-estate"
        title="AI BOM"
        subtitle="Live inventory from connected agents, cloud accounts, endpoints, and runtime — not a static upload."
        scopeChip={<ScopeChip label={scopeLabel} />}
        actions={
          <>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Refresh
            </button>
            <button
              type="button"
              disabled={!manifest}
              onClick={() => manifest && downloadManifest(manifest)}
              className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Download className="h-4 w-4" />
              Export JSON
            </button>
          </>
        }
      />

      {error ? (
        <Card className="border-red-500/30 bg-red-500/10 !p-3 text-sm text-red-200">{error}</Card>
      ) : null}

      {/* Top row: sources | inventory metrics — side by side, scroll inside */}
      <div className="grid gap-3 lg:grid-cols-12">
        <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 lg:col-span-4">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
                Evidence sources
              </p>
              <p className="mt-0.5 text-[11px] text-[color:var(--text-secondary)]">
                What is plugged in and feeding this BOM
              </p>
            </div>
            <div className="rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1 text-right">
              <p className="font-mono text-sm font-semibold text-emerald-300">{activeSources}</p>
              <p className="text-[9px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">live</p>
            </div>
          </div>
          <div className="max-h-52 space-y-1.5 overflow-y-auto pr-0.5">
            {evidenceSources.map((source) => (
              <EvidenceSourceRow key={source.id} source={source} />
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3 lg:col-span-8">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
                Inventory roll-up
              </p>
              <p className="mt-0.5 text-[11px] text-[color:var(--text-secondary)]">
                Counts from the current manifest snapshot
              </p>
            </div>
            {manifest ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <BoundaryBadge ok={!manifest.boundaries.stores_credential_values} label="creds redacted" />
                <BoundaryBadge ok={!manifest.boundaries.stores_raw_prompts} label="no raw prompts" />
                <DriftStatusBadge status={manifest.blueprint_drift.status} />
              </div>
            ) : null}
          </div>
          {manifest || !loading ? (
            <div className="grid max-h-52 grid-cols-2 gap-1.5 overflow-y-auto sm:grid-cols-4">
              {metrics.map((metric) => (
                <MetricChip key={metric.label} {...metric} />
              ))}
            </div>
          ) : (
            <p className="py-8 text-center text-xs text-[color:var(--text-secondary)]">
              <Loader2 className="mr-1.5 inline h-3.5 w-3.5 animate-spin" />
              Loading inventory…
            </p>
          )}
          {manifest ? (
            <p className="mt-2 text-[10px] text-[color:var(--text-tertiary)]">
              {manifest.schema_version} · generated {formatDate(manifest.generated_at)}
            </p>
          ) : null}
        </section>
      </div>

      {manifest?.blueprint_drift.status === "needs_review" ? (
        <Card className="border-amber-500/30 bg-amber-500/10 !p-3">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-200" />
            <div>
              <h2 className="text-sm font-semibold text-amber-50">Observation-only drift review</h2>
              <p className="mt-0.5 text-xs text-amber-100/85">
                {manifest.blueprint_drift.signal_count} signal(s) from manifest/runtime evidence. This view
                reports drift candidates; enforcement policy is unchanged.
              </p>
            </div>
          </div>
        </Card>
      ) : null}

      {manifest ? (
        <div className="grid gap-3 lg:grid-cols-12">
          {/* Inventory table — primary, scrollable */}
          <div className="min-w-0 lg:col-span-8">
            <Section
              label="Agent runtime inventory"
              description="MCP servers and credential refs from agent runtimes. Cloud models appear when connectors are linked."
              divider
            >
              <Card flush className="overflow-hidden">
                <div className="flex flex-col gap-2 border-b border-[color:var(--border-subtle)] p-3 sm:flex-row sm:items-center sm:justify-between">
                  <p className="text-xs text-[color:var(--text-secondary)]">
                    {rows.length} of {allRows.length} rows
                  </p>
                  <label className="relative w-full sm:w-72">
                    <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-[color:var(--text-tertiary)]" />
                    <input
                      value={filters.query}
                      onChange={(event) => updateFilter("query", event.target.value)}
                      placeholder="Search agents, servers…"
                      className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] py-1.5 pl-8 pr-2.5 text-xs text-[color:var(--foreground)] outline-none focus:border-emerald-600"
                    />
                  </label>
                </div>

                <div className="grid gap-2 border-b border-[color:var(--border-subtle)] p-3 sm:grid-cols-2 xl:grid-cols-6">
                  {(
                    [
                      ["source", "Source", options.sources],
                      ["owner", "Owner", options.owners],
                    ] as const
                  ).map(([key, label, values]) => (
                    <label key={key} className="flex flex-col gap-0.5 text-[10px] text-[color:var(--text-tertiary)]">
                      {label}
                      <select
                        value={filters[key]}
                        onChange={(event) => updateFilter(key, event.target.value)}
                        className="rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5 text-xs text-[color:var(--foreground)]"
                      >
                        <option value="all">All</option>
                        {values.map((value) => (
                          <option key={value} value={value}>
                            {value}
                          </option>
                        ))}
                      </select>
                    </label>
                  ))}
                  {(
                    [
                      ["risk", "Risk", ["all", "high", "medium", "low"]],
                      ["freshness", "Freshness", ["all", "seen_24h", "seen_7d", "stale", "unknown"]],
                      ["runtime", "Runtime", ["all", "gateway bound", "runtime observed", "shadow runtime", "inventory only"]],
                    ] as const
                  ).map(([key, label, values]) => (
                    <label key={key} className="flex flex-col gap-0.5 text-[10px] text-[color:var(--text-tertiary)]">
                      {label}
                      <select
                        value={filters[key]}
                        onChange={(event) => updateFilter(key, event.target.value as ManifestFilters[typeof key])}
                        className="rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5 text-xs text-[color:var(--foreground)]"
                      >
                        {values.map((value) => (
                          <option key={value} value={value}>
                            {value === "all" ? "All" : value}
                          </option>
                        ))}
                      </select>
                    </label>
                  ))}
                  <div className="flex items-end">
                    <button
                      type="button"
                      disabled={!hasActiveFilters}
                      onClick={() => setFilters(DEFAULT_MANIFEST_FILTERS)}
                      className="inline-flex w-full items-center justify-center rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5 text-xs text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="max-h-[28rem] overflow-auto">
                  <table className="w-full min-w-[720px] text-left text-xs">
                    <thead className="sticky top-0 z-10 bg-[color:var(--surface-muted)] text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
                      <tr>
                        {["Agent", "Owner", "Source", "Env", "MCP server", "Risk", "Transport", "Runtime", "Tools", "Creds", "Last seen"].map(
                          (heading) => (
                            <th key={heading} className="whitespace-nowrap px-3 py-2 font-medium">
                              {heading}
                            </th>
                          ),
                        )}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[color:var(--border-subtle)]">
                      {rows.map((row, index) => (
                        <tr key={`${row.id}:${index}`} className="hover:bg-[color:var(--surface-muted)]/60">
                          <td className="px-3 py-2 text-[color:var(--foreground)]">{row.agentName}</td>
                          <td className="px-3 py-2 text-[color:var(--text-secondary)]">{row.owner}</td>
                          <td className="px-3 py-2 text-[color:var(--text-secondary)]">{row.source}</td>
                          <td className="px-3 py-2 text-[color:var(--text-secondary)]">{row.environment}</td>
                          <td className="px-3 py-2 font-medium text-[color:var(--foreground)]">{row.name}</td>
                          <td className="px-3 py-2">
                            <span
                              className={`rounded-full px-1.5 py-0.5 text-[10px] ${
                                row.riskLevel === "high"
                                  ? "bg-red-500/10 text-red-300"
                                  : row.riskLevel === "medium"
                                    ? "bg-amber-500/10 text-amber-200"
                                    : "bg-emerald-500/10 text-emerald-200"
                              }`}
                            >
                              {row.riskLevel}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-[color:var(--text-secondary)]">{row.transport}</td>
                          <td className="px-3 py-2 text-[color:var(--text-secondary)]">{row.runtimeState}</td>
                          <td className="px-3 py-2 text-[color:var(--foreground)]">{row.toolCount}</td>
                          <td className="max-w-[8rem] truncate px-3 py-2 text-[color:var(--text-secondary)]">
                            {row.credentialRefs.join(", ") || "—"}
                          </td>
                          <td className="whitespace-nowrap px-3 py-2 text-[color:var(--text-secondary)]">{row.lastSeen}</td>
                        </tr>
                      ))}
                      {rows.length === 0 ? (
                        <tr>
                          <td colSpan={11} className="px-3 py-8 text-center text-xs text-[color:var(--text-secondary)]">
                            No MCP servers yet. Connect accounts or run{" "}
                            <code className="rounded bg-[color:var(--surface-muted)] px-1 py-0.5">agent-bom agents</code>{" "}
                            to populate evidence.
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </Card>
            </Section>
          </div>

          {/* Side column: graph + extended metrics */}
          <aside className="space-y-3 lg:col-span-4">
            <Collapsible
              title="Reachability"
              subtitle={`${manifest.graph.stats.nodes} nodes · ${manifest.graph.stats.edges} edges`}
              defaultOpen
              scrollMaxHeight="22rem"
            >
              <MiniGraph manifest={manifest} />
            </Collapsible>

            <Collapsible
              title="Visibility"
              subtitle="Operator metrics"
              defaultOpen={false}
              scrollMaxHeight="16rem"
            >
              <div className="grid grid-cols-2 gap-2">
                <StatCard label="Tools" value={manifest.summary.tools} accent="info" />
                <StatCard label="Gateway" value={manifest.summary.gateway_registered_servers} />
                <StatCard label="Owners" value={manifest.visibility.owners} />
                <StatCard label="Unowned" value={manifest.visibility.unowned_agents} accent="medium" />
                <StatCard label="Shadow" value={manifest.visibility.shadow_runtime_servers} accent="high" />
                <StatCard label="Untracked" value={manifest.visibility.untracked_runtime_servers} accent="high" />
                <StatCard label="Warnings" value={manifest.visibility.servers_with_warnings} accent="medium" />
                <StatCard label="Risky refs" value={manifest.visibility.risky_credential_refs} accent="critical" />
              </div>
            </Collapsible>
          </aside>
        </div>
      ) : loading ? (
        <Card className="!p-6 text-sm text-[color:var(--text-secondary)]">
          <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />
          Loading AI BOM evidence
        </Card>
      ) : null}
    </div>
  );
}
