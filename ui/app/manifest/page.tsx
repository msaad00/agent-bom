"use client";

import { useEffect, useMemo, useState } from "react";
import type { ElementType } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Download,
  Eye,
  GitBranch,
  KeyRound,
  Loader2,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  TerminalSquare,
  UserRound,
  Wrench,
} from "lucide-react";
import { api, type AgentBomManifestResponse } from "@/lib/api";
import {
  DEFAULT_MANIFEST_FILTERS,
  deriveManifestRows,
  filterManifestRows,
  manifestFilterOptions,
  type ManifestFilters,
} from "@/lib/agent-bom-manifest";
import { PageLaneHeader } from "@/components/page-lane";

function downloadManifest(manifest: AgentBomManifestResponse) {
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `agent-bom-manifest-${manifest.tenant_id ?? "local"}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function SummaryCard({
  label,
  value,
  icon: Icon,
  tone = "text-zinc-300",
}: {
  label: string;
  value: number;
  icon: ElementType;
  tone?: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm text-[var(--muted-foreground)]">{label}</span>
        <Icon className={`h-4 w-4 ${tone}`} />
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight text-[var(--foreground)]">{value.toLocaleString()}</div>
    </div>
  );
}

function BoundaryBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${
        ok ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
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
          ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
          : aligned
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
            : "border-[var(--border)] bg-[var(--muted)] text-[var(--muted-foreground)]"
      }`}
    >
      {needsReview ? <AlertTriangle className="h-3 w-3" /> : <ShieldCheck className="h-3 w-3" />}
      blueprint {status.replaceAll("_", " ")}
    </span>
  );
}

function MiniGraph({ manifest }: { manifest: AgentBomManifestResponse }) {
  const nodes = manifest.graph.nodes.slice(0, 16);
  const edges = manifest.graph.edges.slice(0, 24);
  const columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(nodes.length || 1))));

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--foreground)]">Manifest graph</h2>
          <p className="mt-1 text-xs text-[var(--muted-foreground)]">
            {manifest.graph.stats.nodes} nodes · {manifest.graph.stats.edges} edges
          </p>
        </div>
        <Link
          href="/graph?layers=agent,server,tool,credential"
          className="inline-flex items-center gap-1 rounded-md border border-[var(--border)] px-2.5 py-1.5 text-xs text-[var(--foreground)] hover:bg-[var(--accent)]"
        >
          Open graph <GitBranch className="h-3 w-3" />
        </Link>
      </div>

      <div className="mt-4 grid gap-3" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
        {nodes.map((node) => (
          <div key={node.id} className="min-h-20 rounded-md border border-[var(--border)] bg-[var(--background)] p-3">
            <div className="text-xs uppercase tracking-wide text-[var(--muted-foreground)]">{node.entity_type}</div>
            <div className="mt-2 truncate text-sm font-medium text-[var(--foreground)]" title={node.label}>
              {node.label}
            </div>
          </div>
        ))}
        {nodes.length === 0 ? <div className="text-sm text-[var(--muted-foreground)]">No manifest graph nodes yet.</div> : null}
      </div>

      <div className="mt-4 max-h-48 overflow-auto rounded-md border border-[var(--border)]">
        <table className="w-full text-left text-xs">
          <thead className="bg-[var(--muted)] text-[var(--muted-foreground)]">
            <tr>
              <th className="px-3 py-2 font-medium">Relationship</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Target</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {edges.map((edge) => (
              <tr key={edge.id}>
                <td className="px-3 py-2 text-[var(--foreground)]">{edge.relationship}</td>
                <td className="px-3 py-2 text-[var(--muted-foreground)]">{edge.source}</td>
                <td className="px-3 py-2 text-[var(--muted-foreground)]">{edge.target}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function AgentBomManifestPage() {
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

  const updateFilter = <K extends keyof ManifestFilters>(key: K, value: ManifestFilters[K]) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  return (
    <main className="min-h-screen bg-[var(--background)] p-6 text-[var(--foreground)]">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <PageLaneHeader
          lane="ai-estate"
          title="Agent BOM"
          subtitle="Your tenant inventory of agents, MCP servers, tools, and credential references."
          actions={
            <>
              <button
                type="button"
                onClick={load}
                className="inline-flex items-center gap-2 rounded-md border border-[var(--border)] px-3 py-2 text-sm hover:bg-[var(--accent)]"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
                Refresh
              </button>
              <button
                type="button"
                disabled={!manifest}
                onClick={() => manifest && downloadManifest(manifest)}
                className="inline-flex items-center gap-2 rounded-md border border-[var(--border)] px-3 py-2 text-sm hover:bg-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                <Download className="h-4 w-4" />
                Download JSON
              </button>
            </>
          }
        />

        {error ? <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{error}</div> : null}

        {manifest ? (
          <>
            <section className="grid gap-3 sm:grid-cols-3">
              <SummaryCard label="Agents" value={manifest.summary.agents} icon={TerminalSquare} tone="text-blue-300" />
              <SummaryCard label="MCP servers" value={manifest.summary.mcp_servers} icon={Server} tone="text-cyan-300" />
              <SummaryCard label="Credential refs" value={manifest.summary.credential_refs} icon={KeyRound} tone="text-yellow-300" />
            </section>

            <details className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-4">
              <summary className="cursor-pointer list-none text-sm font-medium text-[var(--foreground)] [&::-webkit-details-marker]:hidden">
                Extended visibility metrics
              </summary>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <SummaryCard label="Tools" value={manifest.summary.tools} icon={Wrench} tone="text-emerald-300" />
                <SummaryCard label="Runtime seen" value={manifest.summary.runtime_observed_servers} icon={Activity} tone="text-pink-300" />
                <SummaryCard label="Gateway bound" value={manifest.summary.gateway_registered_servers} icon={Network} tone="text-violet-300" />
                <SummaryCard label="Owners" value={manifest.visibility.owners} icon={UserRound} tone="text-teal-300" />
                <SummaryCard label="Unowned agents" value={manifest.visibility.unowned_agents} icon={AlertTriangle} tone="text-yellow-300" />
                <SummaryCard label="Shadow runtime" value={manifest.visibility.shadow_runtime_servers} icon={Eye} tone="text-red-300" />
                <SummaryCard label="Untracked runtime" value={manifest.visibility.untracked_runtime_servers} icon={Network} tone="text-orange-300" />
                <SummaryCard label="Warnings" value={manifest.visibility.servers_with_warnings} icon={AlertTriangle} tone="text-amber-300" />
                <SummaryCard label="Risky refs" value={manifest.visibility.risky_credential_refs} icon={KeyRound} tone="text-rose-300" />
              </div>
            </details>

            <section className="flex flex-wrap items-center gap-2">
              <BoundaryBadge ok={!manifest.boundaries.stores_credential_values} label="credential values redacted" />
              <BoundaryBadge ok={!manifest.boundaries.stores_raw_prompts} label="raw prompts not persisted" />
              <DriftStatusBadge status={manifest.blueprint_drift.status} />
              <span className="text-xs text-[var(--muted-foreground)]">
                {manifest.schema_version} · {manifest.tenant_id ?? "local"} · {new Date(manifest.generated_at).toLocaleString()}
              </span>
            </section>

            {manifest.blueprint_drift.status === "needs_review" ? (
              <section className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-300" />
                  <div>
                    <h2 className="text-sm font-semibold text-yellow-100">Observation-only drift review</h2>
                    <p className="mt-1 text-xs text-yellow-100/80">
                      {manifest.blueprint_drift.signal_count} signal(s) from manifest/runtime evidence. This view reports drift candidates; enforcement policy is unchanged.
                    </p>
                    <ul className="mt-3 grid gap-2 text-xs text-yellow-100/90">
                      {manifest.blueprint_drift.signals.slice(0, 4).map((signal) => (
                        <li key={`${signal.kind}:${signal.entity_id}`} className="rounded-md border border-yellow-500/20 bg-black/10 px-3 py-2">
                          <span className="font-medium">{signal.kind.replaceAll("_", " ")}</span>: {signal.message}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </section>
            ) : null}

            <div className="space-y-6">
              <section className="rounded-lg border border-[var(--border)] bg-[var(--card)]">
                <div className="flex flex-col gap-3 border-b border-[var(--border)] p-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h2 className="text-sm font-semibold">Agent and MCP inventory</h2>
                    <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                      {rows.length} of {allRows.length} server rows visible
                    </p>
                  </div>
                  <label className="relative w-full md:w-80">
                    <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[var(--muted-foreground)]" />
                    <input
                      value={filters.query}
                      onChange={(event) => updateFilter("query", event.target.value)}
                      placeholder="Search agents, servers, transports"
                      className="w-full rounded-md border border-[var(--border)] bg-[var(--background)] py-2 pl-9 pr-3 text-sm outline-none focus:border-emerald-500"
                    />
                  </label>
                </div>
                <div className="grid gap-3 border-b border-[var(--border)] p-4 md:grid-cols-2 xl:grid-cols-6">
                  <label className="flex flex-col gap-1 text-xs text-[var(--muted-foreground)]">
                    Source
                    <select
                      value={filters.source}
                      onChange={(event) => updateFilter("source", event.target.value)}
                      className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]"
                    >
                      <option value="all">All sources</option>
                      {options.sources.map((source) => (
                        <option key={source} value={source}>
                          {source}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="flex flex-col gap-1 text-xs text-[var(--muted-foreground)]">
                    Owner
                    <select
                      value={filters.owner}
                      onChange={(event) => updateFilter("owner", event.target.value)}
                      className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]"
                    >
                      <option value="all">All owners</option>
                      {options.owners.map((owner) => (
                        <option key={owner} value={owner}>
                          {owner}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="flex flex-col gap-1 text-xs text-[var(--muted-foreground)]">
                    Risk
                    <select
                      value={filters.risk}
                      onChange={(event) => updateFilter("risk", event.target.value as ManifestFilters["risk"])}
                      className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]"
                    >
                      <option value="all">All risk</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </label>
                  <label className="flex flex-col gap-1 text-xs text-[var(--muted-foreground)]">
                    Freshness
                    <select
                      value={filters.freshness}
                      onChange={(event) => updateFilter("freshness", event.target.value as ManifestFilters["freshness"])}
                      className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]"
                    >
                      <option value="all">All freshness</option>
                      <option value="seen_24h">Seen 24h</option>
                      <option value="seen_7d">Seen 7d</option>
                      <option value="stale">Stale</option>
                      <option value="unknown">Unknown</option>
                    </select>
                  </label>
                  <label className="flex flex-col gap-1 text-xs text-[var(--muted-foreground)]">
                    Runtime
                    <select
                      value={filters.runtime}
                      onChange={(event) => updateFilter("runtime", event.target.value as ManifestFilters["runtime"])}
                      className="rounded-md border border-[var(--border)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)]"
                    >
                      <option value="all">All runtime</option>
                      <option value="gateway bound">Gateway bound</option>
                      <option value="runtime observed">Runtime observed</option>
                      <option value="shadow runtime">Shadow runtime</option>
                      <option value="inventory only">Inventory only</option>
                    </select>
                  </label>
                  <div className="flex items-end">
                    <button
                      type="button"
                      disabled={!hasActiveFilters}
                      onClick={() => setFilters(DEFAULT_MANIFEST_FILTERS)}
                      className="inline-flex w-full items-center justify-center gap-2 rounded-md border border-[var(--border)] px-3 py-2 text-sm text-[var(--foreground)] hover:bg-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Clear filters
                    </button>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-[var(--muted)] text-xs uppercase tracking-wide text-[var(--muted-foreground)]">
                      <tr>
                        <th className="px-4 py-3 font-medium">Agent</th>
                        <th className="px-4 py-3 font-medium">Owner</th>
                        <th className="px-4 py-3 font-medium">Source</th>
                        <th className="px-4 py-3 font-medium">Environment</th>
                        <th className="px-4 py-3 font-medium">MCP server</th>
                        <th className="px-4 py-3 font-medium">Risk</th>
                        <th className="px-4 py-3 font-medium">Transport</th>
                        <th className="px-4 py-3 font-medium">Runtime</th>
                        <th className="px-4 py-3 font-medium">Tools</th>
                        <th className="px-4 py-3 font-medium">Credential refs</th>
                        <th className="px-4 py-3 font-medium">Last seen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border)]">
                      {rows.map((row, index) => (
                        <tr key={`${row.id}:${index}`}>
                          <td className="px-4 py-3 text-[var(--foreground)]">{row.agentName}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.owner}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.source}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.environment}</td>
                          <td className="px-4 py-3 font-medium text-[var(--foreground)]">{row.name}</td>
                          <td className="px-4 py-3">
                            <span
                              className={`rounded-full px-2 py-1 text-xs ${
                                row.riskLevel === "high"
                                  ? "bg-red-500/10 text-red-300"
                                  : row.riskLevel === "medium"
                                    ? "bg-yellow-500/10 text-yellow-300"
                                    : "bg-emerald-500/10 text-emerald-300"
                              }`}
                            >
                              {row.riskLevel}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.transport}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.runtimeState}</td>
                          <td className="px-4 py-3 text-[var(--foreground)]">{row.toolCount}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.credentialRefs.join(", ") || "none"}</td>
                          <td className="px-4 py-3 text-[var(--muted-foreground)]">{row.lastSeen}</td>
                        </tr>
                      ))}
                      {rows.length === 0 ? (
                        <tr>
                          <td colSpan={11} className="px-4 py-8 text-center text-sm text-[var(--muted-foreground)]">
                            No MCP servers in this tenant yet. Run{" "}
                            <code className="rounded bg-[var(--muted)] px-1.5 py-0.5">agent-bom manifest</code> locally to
                            generate evidence, or clear filters to inspect the full manifest.
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </section>

              <details className="rounded-lg border border-[var(--border)] bg-[var(--card)]">
                <summary className="cursor-pointer list-none px-4 py-3 text-sm font-medium [&::-webkit-details-marker]:hidden">
                  Manifest graph · {manifest.graph.stats.nodes} nodes · {manifest.graph.stats.edges} edges
                </summary>
                <div className="border-t border-[var(--border)] p-4">
                  <MiniGraph manifest={manifest} />
                </div>
              </details>
            </div>
          </>
        ) : loading ? (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--card)] p-8 text-sm text-[var(--muted-foreground)]">
            <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />
            Loading Agent BOM manifest
          </div>
        ) : null}
      </div>
    </main>
  );
}
