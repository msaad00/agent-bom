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
  Sparkles,
} from "lucide-react";

import { Card, Section } from "@/components/card";
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
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${
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
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${
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

function EvidenceSourceCard({ source }: { source: AiBomEvidenceSource }) {
  const body = (
    <div
      className={`rounded-xl border px-3 py-2.5 transition ${
        source.active
          ? "border-emerald-600/40 bg-emerald-500/10"
          : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] opacity-70"
      }`}
    >
      <div className="text-sm font-medium text-[color:var(--foreground)]">{source.label}</div>
      <p className="mt-1 text-[11px] leading-5 text-[color:var(--text-secondary)]">{source.detail}</p>
      <p className="mt-2 text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
        {source.active ? "Evidence flowing" : "Not connected"}
      </p>
    </div>
  );

  if (source.href && source.active) {
    return <Link href={source.href}>{body}</Link>;
  }
  return body;
}

function MetricTile({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number;
  icon: ElementType;
}) {
  return (
    <Card className="flex items-center justify-between gap-3 !p-4">
      <div>
        <div className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</div>
        <div className="mt-2 font-mono text-2xl font-semibold text-[color:var(--foreground)]">
          {value.toLocaleString()}
        </div>
      </div>
      <Icon className="h-5 w-5 text-[color:var(--text-tertiary)]" />
    </Card>
  );
}

function MiniGraph({ manifest }: { manifest: AgentBomManifestResponse }) {
  const nodes = manifest.graph.nodes.slice(0, 16);
  const edges = manifest.graph.edges.slice(0, 24);
  const columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(nodes.length || 1))));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-[color:var(--foreground)]">Reachability graph</h3>
          <p className="mt-1 text-xs text-[color:var(--text-secondary)]">
            {manifest.graph.stats.nodes} nodes · {manifest.graph.stats.edges} edges
          </p>
        </div>
        <Link
          href="/graph?layers=agent,server,tool,credential"
          className="inline-flex items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1.5 text-xs text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
        >
          Open lineage <GitBranch className="h-3 w-3" />
        </Link>
      </div>

      <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
        {nodes.map((node) => (
          <div
            key={node.id}
            className="min-h-20 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3"
          >
            <div className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
              {node.entity_type}
            </div>
            <div className="mt-2 truncate text-sm font-medium text-[color:var(--foreground)]" title={node.label}>
              {node.label}
            </div>
          </div>
        ))}
        {nodes.length === 0 ? (
          <div className="text-sm text-[color:var(--text-secondary)]">No graph nodes in this manifest yet.</div>
        ) : null}
      </div>

      <div className="max-h-48 overflow-auto rounded-lg border border-[color:var(--border-subtle)]">
        <table className="w-full text-left text-xs">
          <thead className="bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]">
            <tr>
              <th className="px-3 py-2 font-medium">Relationship</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Target</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[color:var(--border-subtle)]">
            {edges.map((edge) => (
              <tr key={edge.id}>
                <td className="px-3 py-2 text-[color:var(--foreground)]">{edge.relationship}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{edge.source}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{edge.target}</td>
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

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="ai-estate"
        title="AI BOM"
        subtitle="Reachability-backed inventory from connected agents, cloud accounts, endpoints, and runtime observations — not a static file upload."
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
        banner={
          <Card className="!p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--foreground)]">
                  <Sparkles className="h-4 w-4 text-emerald-300" />
                  Evidence sources
                </div>
                <p className="mt-1 max-w-3xl text-sm text-[color:var(--text-secondary)]">
                  AI BOM rolls up whatever is connected: workstation discovery, fleet ingest, cloud connectors,
                  Kubernetes scans, and runtime enforcement. Agent runtime rows below are one layer of that estate.
                </p>
              </div>
              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-right">
                <div className="font-mono text-xl font-semibold text-emerald-300">{activeSources}</div>
                <div className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                  active sources
                </div>
              </div>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {evidenceSources.map((source) => (
                <EvidenceSourceCard key={source.id} source={source} />
              ))}
            </div>
          </Card>
        }
      />

      {error ? (
        <Card className="border-red-500/30 bg-red-500/10 !p-4 text-sm text-red-200">{error}</Card>
      ) : null}

      {manifest ? (
        <>
          <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricTile label="Agents" value={entityRollup.agents} icon={Bot} />
            <MetricTile label="MCP servers" value={entityRollup.mcpServers} icon={Server} />
            <MetricTile label="Models" value={entityRollup.models} icon={Sparkles} />
            <MetricTile label="Packages" value={entityRollup.packages} icon={Box} />
            <MetricTile label="Cloud assets" value={entityRollup.cloudAssets} icon={Cloud} />
            <MetricTile label="Credential refs" value={entityRollup.credentials} icon={KeyRound} />
            <MetricTile label="Findings" value={entityRollup.findings} icon={AlertTriangle} />
            <MetricTile label="Runtime seen" value={manifest.summary.runtime_observed_servers} icon={Activity} />
          </section>

          <section className="flex flex-wrap items-center gap-2">
            <BoundaryBadge ok={!manifest.boundaries.stores_credential_values} label="credential values redacted" />
            <BoundaryBadge ok={!manifest.boundaries.stores_raw_prompts} label="raw prompts not persisted" />
            <DriftStatusBadge status={manifest.blueprint_drift.status} />
            <span className="text-xs text-[color:var(--text-tertiary)]">
              {manifest.schema_version} · generated {formatDate(manifest.generated_at)}
            </span>
          </section>

          {manifest.blueprint_drift.status === "needs_review" ? (
            <Card className="border-amber-500/30 bg-amber-500/10 !p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-200" />
                <div>
                  <h2 className="text-sm font-semibold text-amber-50">Observation-only drift review</h2>
                  <p className="mt-1 text-xs text-amber-100/85">
                    {manifest.blueprint_drift.signal_count} signal(s) from manifest/runtime evidence. This view reports drift candidates; enforcement policy is unchanged.
                  </p>
                </div>
              </div>
            </Card>
          ) : null}

          <Section
            label="Agent runtime inventory"
            description="MCP servers, tools, and credential references discovered from agent runtimes. Cloud-managed models and endpoint AI services appear when those connectors are linked."
            divider
          >
            <Card flush className="overflow-hidden">
              <div className="flex flex-col gap-3 border-b border-[color:var(--border-subtle)] p-4 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm text-[color:var(--text-secondary)]">
                    {rows.length} of {allRows.length} server rows visible
                  </p>
                </div>
                <label className="relative w-full md:w-80">
                  <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[color:var(--text-tertiary)]" />
                  <input
                    value={filters.query}
                    onChange={(event) => updateFilter("query", event.target.value)}
                    placeholder="Search agents, servers, transports"
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] py-2 pl-9 pr-3 text-sm text-[color:var(--foreground)] outline-none focus:border-emerald-600"
                  />
                </label>
              </div>

              <div className="grid gap-3 border-b border-[color:var(--border-subtle)] p-4 md:grid-cols-2 xl:grid-cols-6">
                {(
                  [
                    ["source", "Source", options.sources],
                    ["owner", "Owner", options.owners],
                  ] as const
                ).map(([key, label, values]) => (
                  <label key={key} className="flex flex-col gap-1 text-xs text-[color:var(--text-tertiary)]">
                    {label}
                    <select
                      value={filters[key]}
                      onChange={(event) => updateFilter(key, event.target.value)}
                      className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)]"
                    >
                      <option value="all">All {label.toLowerCase()}</option>
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
                  <label key={key} className="flex flex-col gap-1 text-xs text-[color:var(--text-tertiary)]">
                    {label}
                    <select
                      value={filters[key]}
                      onChange={(event) => updateFilter(key, event.target.value as ManifestFilters[typeof key])}
                      className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)]"
                    >
                      {values.map((value) => (
                        <option key={value} value={value}>
                          {value === "all" ? `All ${label.toLowerCase()}` : value}
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
                    className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Clear filters
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-[color:var(--surface-muted)] text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                    <tr>
                      {["Agent", "Owner", "Source", "Environment", "MCP server", "Risk", "Transport", "Runtime", "Tools", "Credential refs", "Last seen"].map((heading) => (
                        <th key={heading} className="px-4 py-3 font-medium">
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[color:var(--border-subtle)]">
                    {rows.map((row, index) => (
                      <tr key={`${row.id}:${index}`} className="hover:bg-[color:var(--surface-muted)]/60">
                        <td className="px-4 py-3 text-[color:var(--foreground)]">{row.agentName}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.owner}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.source}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.environment}</td>
                        <td className="px-4 py-3 font-medium text-[color:var(--foreground)]">{row.name}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full px-2 py-1 text-xs ${
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
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.transport}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.runtimeState}</td>
                        <td className="px-4 py-3 text-[color:var(--foreground)]">{row.toolCount}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.credentialRefs.join(", ") || "none"}</td>
                        <td className="px-4 py-3 text-[color:var(--text-secondary)]">{row.lastSeen}</td>
                      </tr>
                    ))}
                    {rows.length === 0 ? (
                      <tr>
                        <td colSpan={11} className="px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
                          No MCP servers in this tenant yet. Connect cloud accounts or run{" "}
                          <code className="rounded bg-[color:var(--surface-muted)] px-1.5 py-0.5">agent-bom agents</code>{" "}
                          to populate AI BOM evidence.
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </Card>
          </Section>

          <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 text-sm font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
              Extended visibility metrics
              <span className="text-xs text-[color:var(--text-tertiary)]">operators</span>
            </summary>
            <div className="grid gap-3 border-t border-[color:var(--border-subtle)] p-4 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard label="Tools" value={manifest.summary.tools} accent="info" />
              <StatCard label="Gateway bound" value={manifest.summary.gateway_registered_servers} />
              <StatCard label="Owners" value={manifest.visibility.owners} />
              <StatCard label="Unowned agents" value={manifest.visibility.unowned_agents} accent="medium" />
              <StatCard label="Shadow runtime" value={manifest.visibility.shadow_runtime_servers} accent="high" />
              <StatCard label="Untracked runtime" value={manifest.visibility.untracked_runtime_servers} accent="high" />
              <StatCard label="Warnings" value={manifest.visibility.servers_with_warnings} accent="medium" />
              <StatCard label="Risky refs" value={manifest.visibility.risky_credential_refs} accent="critical" />
            </div>
          </details>

          <details className="group rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
            <summary className="cursor-pointer list-none px-5 py-4 text-sm font-medium text-[color:var(--foreground)] [&::-webkit-details-marker]:hidden">
              Reachability graph · {manifest.graph.stats.nodes} nodes · {manifest.graph.stats.edges} edges
            </summary>
            <div className="border-t border-[color:var(--border-subtle)] p-5">
              <MiniGraph manifest={manifest} />
            </div>
          </details>
        </>
      ) : loading ? (
        <Card className="!p-8 text-sm text-[color:var(--text-secondary)]">
          <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />
          Loading AI BOM evidence
        </Card>
      ) : null}
    </div>
  );
}
