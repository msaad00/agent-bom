"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  Package,
  KeyRound,
  Wrench,
  ChevronRight,
  Loader2,
  AlertTriangle,
  Filter,
  ArrowLeft,
  ExternalLink,
  Bug,
  Info,
  Scale,
  Tag,
} from "lucide-react";
import { api, type RegistryServer } from "@/lib/api";
import { CatalogBanner, PageLaneHeader } from "@/components/page-lane";

/* ------------------------------------------------------------------ */
/*  Shared helpers                                                     */
/* ------------------------------------------------------------------ */

function riskColor(risk: string) {
  switch (risk) {
    case "high": return "text-red-400 bg-red-950 border-red-800";
    case "medium": return "text-yellow-400 bg-yellow-950 border-yellow-800";
    case "low": return "text-emerald-400 bg-emerald-950 border-emerald-800";
    default: return "text-[color:var(--text-secondary)] bg-[color:var(--surface-elevated)] border-[color:var(--border-subtle)]";
  }
}

function riskBorderColor(risk: string) {
  switch (risk) {
    case "high": return "border-red-800";
    case "medium": return "border-yellow-800";
    case "low": return "border-emerald-800";
    default: return "border-[color:var(--border-subtle)]";
  }
}

/* ------------------------------------------------------------------ */
/*  Detail-view Section component                                      */
/* ------------------------------------------------------------------ */

function DetailSection({ title, icon: Icon, children, accent }: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  accent?: string | undefined;
}) {
  return (
    <div className="bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-xl p-4">
      <div className={`flex items-center gap-2 mb-3 text-xs font-medium uppercase tracking-wider ${accent || "text-[color:var(--text-tertiary)]"}`}>
        <Icon className="w-3.5 h-3.5" />
        {title}
      </div>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Detail view (shown when ?id=… is present)                          */
/* ------------------------------------------------------------------ */

type RiskFilter = "all" | "high" | "medium" | "low";
type RegistryView = "table" | "cards";

function RegistryDetail({ serverId }: { serverId: string }) {
  const router = useRouter();
  const [server, setServer] = useState<RegistryServer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!serverId) return;
    api
      .getRegistryServer(serverId)
      .then((res) => setServer(res))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [serverId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-[color:var(--text-secondary)]">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading server details...
      </div>
    );
  }

  if (error || !server) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-[color:var(--text-secondary)] gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">{error || "Server not found"}</p>
        <button onClick={() => router.push("/registry")} className="text-xs text-emerald-400 hover:text-emerald-300">
          Back to Registry
        </button>
      </div>
    );
  }

  const tools = server.tools || [];
  const creds = server.credential_env_vars || [];
  const cves = server.known_cves || [];

  return (
    <div className="py-6 space-y-6">
      {/* Back button */}
      <button
        onClick={() => router.push("/registry")}
        className="flex items-center gap-1.5 text-sm text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)] transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Registry
      </button>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          {server.verified ? (
            <ShieldCheck className="w-6 h-6 text-emerald-400 mt-0.5 shrink-0" />
          ) : (
            <ShieldAlert className="w-6 h-6 text-[color:var(--text-tertiary)] mt-0.5 shrink-0" />
          )}
          <div>
            <h1 className="text-2xl font-semibold text-[color:var(--foreground)]">{server.name}</h1>
            <div className="flex items-center gap-2 mt-1 text-sm text-[color:var(--text-tertiary)]">
              <span className="font-mono">{server.publisher}</span>
              {server.packages?.[0]?.ecosystem && (
                <>
                  <span className="text-[color:var(--text-tertiary)]">&middot;</span>
                  <span>{server.packages[0].ecosystem}</span>
                </>
              )}
              {server.license && (
                <>
                  <span className="text-[color:var(--text-tertiary)]">&middot;</span>
                  <Scale className="w-3 h-3" />
                  <span>{server.license}</span>
                </>
              )}
              {server.category && (
                <>
                  <span className="text-[color:var(--text-tertiary)]">&middot;</span>
                  <Tag className="w-3 h-3" />
                  <span>{server.category}</span>
                </>
              )}
              {server.latest_version && (
                <>
                  <span className="text-[color:var(--text-tertiary)]">&middot;</span>
                  <span className="font-mono text-xs">{server.latest_version}</span>
                </>
              )}
            </div>
            {server.description && (
              <p className="text-sm text-[color:var(--text-secondary)] mt-2">{server.description}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span
            className={`text-xs px-2 py-1 rounded border font-mono uppercase font-medium ${riskColor(server.risk_level)}`}
            title={server.risk_justification ?? "Capability risk"}
          >
            {server.risk_level} capability
          </span>
          {server.verified && (
            <span className="text-[10px] px-1.5 py-0.5 rounded border font-mono border-emerald-800 bg-emerald-950 text-emerald-400">
              verified
            </span>
          )}
        </div>
      </div>

      {/* Risk Justification */}
      {server.risk_justification && (
        <div className={`rounded-xl border-2 p-4 ${riskBorderColor(server.risk_level)} bg-[color:var(--surface-muted)]`}>
          <div className="flex items-center gap-2 mb-2 text-xs font-medium uppercase tracking-wider text-[color:var(--text-tertiary)]">
            <Info className="w-3.5 h-3.5" />
            Risk rationale
          </div>
          <p className="text-sm text-[color:var(--text-secondary)] leading-relaxed">{server.risk_justification}</p>
          {cves.length === 0 ? (
            <p className="mt-2 text-xs text-[color:var(--text-tertiary)]">
              This classification is capability-based. No known CVEs are currently attached to this server in registry data.
            </p>
          ) : null}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Tools */}
        <DetailSection title={`Tools (${tools.length})`} icon={Wrench}>
          {tools.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {tools?.map((tool) => (
                <span key={tool} className="px-2 py-1 bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] rounded text-xs font-mono text-[color:var(--text-secondary)]">
                  {tool}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[color:var(--text-tertiary)]">No tools documented</p>
          )}
        </DetailSection>

        {/* Credentials */}
        <DetailSection title={`Credentials (${creds.length})`} icon={KeyRound} accent={creds.length > 0 ? "text-amber-500" : undefined}>
          {creds.length > 0 ? (
            <div className="space-y-1.5">
              {creds?.map((cred) => (
                <div key={cred} className="flex items-center gap-2 px-2 py-1.5 bg-amber-950/30 border border-amber-900/50 rounded">
                  <KeyRound className="w-3 h-3 text-amber-500 shrink-0" />
                  <code className="text-xs font-mono text-amber-400">{cred}</code>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[color:var(--text-tertiary)]">No credential environment variables</p>
          )}
        </DetailSection>

        {/* Packages */}
        <DetailSection title="Package" icon={Package}>
          {server.packages?.map((pkg) => (
            <div key={pkg.name} className="space-y-1">
              <code className="text-sm font-mono text-[color:var(--foreground)]">{pkg.name}</code>
              <div className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
                <span className="px-1.5 py-0.5 bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] rounded font-mono">
                  {pkg.ecosystem}
                </span>
                {server.latest_version && (
                  <span>Latest: <span className="text-emerald-400 font-mono">{server.latest_version}</span></span>
                )}
              </div>
            </div>
          ))}
        </DetailSection>

        {/* Known CVEs */}
        <DetailSection title={`Known CVEs (${cves.length})`} icon={Bug} accent={cves.length > 0 ? "text-red-400" : undefined}>
          {cves.length > 0 ? (
            <div className="space-y-1">
              {cves?.map((cve) => (
                <a
                  key={cve}
                  href={`https://osv.dev/vulnerability/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-xs font-mono text-red-400 hover:text-red-300 transition-colors"
                >
                  <Bug className="w-3 h-3" />
                  {cve}
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[color:var(--text-tertiary)]">No known CVEs for this server</p>
          )}
        </DetailSection>
      </div>

      {/* Source link */}
      {server.source_url && (
        <a
          href={server.source_url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 text-sm text-emerald-400 hover:text-emerald-300 transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
          {server.source_url}
        </a>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  List view (shown when no ?id param)                                */
/* ------------------------------------------------------------------ */

function RegistryList() {
  const router = useRouter();
  const [servers, setServers] = useState<RegistryServer[]>([]);
  const [meta, setMeta] = useState<{
    updated?: string | null;
    total_servers?: number | null;
    sources?: string[];
    source_url?: string | null;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [viewMode, setViewMode] = useState<RegistryView>("table");

  useEffect(() => {
    api
      .listRegistry()
      .then((res) => {
        setServers(res.servers);
        setMeta(res.meta ?? null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const categories = useMemo(() => {
    const cats = new Set<string>();
    for (const s of servers) {
      if (s.category) cats.add(s.category);
    }
    return Array.from(cats).sort();
  }, [servers]);

  const filtered = servers.filter((s) => {
    const matchesSearch =
      !search ||
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      s.description?.toLowerCase().includes(search.toLowerCase()) ||
      s.publisher?.toLowerCase().includes(search.toLowerCase()) ||
      s.category?.toLowerCase().includes(search.toLowerCase());
    const matchesRisk = riskFilter === "all" || s.risk_level === riskFilter;
    const matchesCat = categoryFilter === "all" || s.category === categoryFilter;
    return matchesSearch && matchesRisk && matchesCat;
  });

  const riskCounts = {
    all: servers.length,
    high: servers.filter((s) => s.risk_level === "high").length,
    medium: servers.filter((s) => s.risk_level === "medium").length,
    low: servers.filter((s) => s.risk_level === "low").length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-[color:var(--text-secondary)]">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading MCP registry...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-[color:var(--text-secondary)] gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not load MCP registry</p>
        <p className="text-xs text-[color:var(--text-tertiary)]">Make sure the API is running at localhost:8422</p>
      </div>
    );
  }

  return (
    <div className="py-6 space-y-6">
      <PageLaneHeader
        lane="reference"
        title="MCP Catalog"
        subtitle={`${(meta?.total_servers ?? servers.length).toLocaleString()} known servers · capability risk (not CVE status) · ${riskCounts.high} high · ${riskCounts.medium} medium`}
        banner={<CatalogBanner />}
      />

      {meta && (meta.updated || meta.sources?.length) ? (
        <p className="-mt-3 text-xs text-[color:var(--text-tertiary)]">
          Synced from{" "}
          {meta.sources?.includes("mcp-official")
            ? "the official MCP registry"
            : meta.sources?.join(", ") || "curated sources"}
          {meta.updated ? ` · updated ${meta.updated}` : ""}
          {typeof meta.total_servers === "number" ? ` · ${meta.total_servers.toLocaleString()} servers` : ""}
        </p>
      ) : null}

      {/* Search + Filters */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[240px] flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[color:var(--text-tertiary)]" />
            <input
              type="text"
              placeholder="Search servers, publishers, categories..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] rounded-lg text-sm text-[color:var(--text-secondary)] placeholder:text-[color:var(--text-tertiary)] focus:outline-none focus:border-emerald-600"
            />
          </div>

          <div className="flex items-center gap-1">
            <Filter className="w-3.5 h-3.5 text-[color:var(--text-tertiary)] mr-1" />
            {(["all", "high", "medium", "low"] as RiskFilter[]).map((r) => (
              <button
                key={r}
                onClick={() => setRiskFilter(r)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  riskFilter === r
                    ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
                    : "text-[color:var(--text-secondary)] hover:bg-[color:var(--surface-elevated)] hover:text-[color:var(--foreground)]"
                }`}
              >
                {r === "all" ? "All" : r.charAt(0).toUpperCase() + r.slice(1)}{" "}
                <span className="text-[color:var(--text-tertiary)]">({riskCounts[r]})</span>
              </button>
            ))}
          </div>

          {categories.length > 0 && (
            <label className="flex items-center gap-2 text-xs text-[color:var(--text-tertiary)]">
              Category
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="rounded-md border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1.5 text-xs text-[color:var(--foreground)]"
              >
                <option value="all">All categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </label>
          )}

          <div className="ml-auto flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] p-0.5">
            <button
              type="button"
              onClick={() => setViewMode("table")}
              className={`rounded px-2.5 py-1 text-[11px] font-medium ${
                viewMode === "table" ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]" : "text-[color:var(--text-tertiary)]"
              }`}
            >
              Table
            </button>
            <button
              type="button"
              onClick={() => setViewMode("cards")}
              className={`rounded px-2.5 py-1 text-[11px] font-medium ${
                viewMode === "cards" ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]" : "text-[color:var(--text-tertiary)]"
              }`}
            >
              Cards
            </button>
          </div>
        </div>
      </div>

      {viewMode === "table" ? (
        <div className="overflow-x-auto rounded-lg border border-[color:var(--border-subtle)]">
          <table className="w-full text-left text-sm">
            <thead className="bg-[color:var(--surface-muted)] text-xs uppercase tracking-wide text-[color:var(--text-tertiary)]">
              <tr>
                <th className="px-4 py-3 font-medium">Server</th>
                <th className="px-4 py-3 font-medium">Publisher</th>
                <th className="px-4 py-3 font-medium">Version</th>
                <th
                  className="px-4 py-3 font-medium"
                  title="Inherent tool capability risk — not whether the publisher has unpatched CVEs"
                >
                  Capability
                </th>
                <th className="px-4 py-3 font-medium">Tools</th>
                <th className="px-4 py-3 font-medium">Creds</th>
                <th className="px-4 py-3 font-medium">Category</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[color:var(--border-subtle)]">
              {filtered.map((server) => (
                <tr
                  key={server.id}
                  className="cursor-pointer hover:bg-[color:var(--surface-muted)]/70"
                  onClick={() => router.push(`/registry?id=${server.id}`)}
                >
                  <td className="px-4 py-3 font-medium text-[color:var(--foreground)]">{server.name}</td>
                  <td className="px-4 py-3 text-[color:var(--text-tertiary)]">{server.publisher ?? "—"}</td>
                  <td className="px-4 py-3 font-mono text-xs text-[color:var(--text-secondary)]">{server.latest_version ?? "—"}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${riskColor(server.risk_level)}`}
                      title={server.risk_justification ?? "Capability risk from tools, credentials, and category."}
                    >
                      {server.risk_level}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-secondary)]">{server.tools?.length ?? 0}</td>
                  <td className="px-4 py-3 text-[color:var(--text-secondary)]">{server.credential_env_vars?.length ?? 0}</td>
                  <td className="px-4 py-3 text-[color:var(--text-tertiary)]">{server.category ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filtered?.map((server) => (
            <div
              key={server.id}
              className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)]/50 p-4 hover:border-[color:var(--border-strong)] transition-colors cursor-pointer group"
              onClick={() => router.push(`/registry?id=${server.id}`)}
            >
              {/* Top row */}
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  {server.verified ? (
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <ShieldAlert className="w-4 h-4 text-[color:var(--text-tertiary)] shrink-0" />
                  )}
                  <span className="font-mono text-sm font-medium text-[color:var(--foreground)] truncate">
                    {server.name}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${riskColor(server.risk_level)}`}
                    title={server.risk_justification ?? "Capability risk"}
                  >
                    {server.risk_level}
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 text-[color:var(--text-tertiary)] group-hover:text-[color:var(--text-secondary)] transition-colors" />
                </div>
              </div>

              {/* Description */}
              {server.description && (
                <p className="text-xs text-[color:var(--text-tertiary)] mb-2 line-clamp-2">{server.description}</p>
              )}

              {/* Stats row */}
              <div className="flex items-center gap-3 text-[10px] text-[color:var(--text-tertiary)]">
                {server.packages && server.packages.length > 0 && (
                  <span className="flex items-center gap-0.5">
                    <Package className="w-2.5 h-2.5" /> {server.packages[0]!.ecosystem}
                  </span>
                )}
                {server.latest_version && (
                  <span className="font-mono">{server.latest_version}</span>
                )}
                {server.tools && server.tools.length > 0 && (
                  <span className="flex items-center gap-0.5">
                    <Wrench className="w-2.5 h-2.5" /> {server.tools.length} tools
                  </span>
                )}
                {server.credential_env_vars && server.credential_env_vars.length > 0 && (
                  <span className="flex items-center gap-0.5 text-amber-500">
                    <KeyRound className="w-2.5 h-2.5" /> {server.credential_env_vars.length} creds
                  </span>
                )}
                {server.category && (
                  <span className="truncate">{server.category}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {filtered.length === 0 && (
        <div className="text-center py-12 text-[color:var(--text-tertiary)] text-sm">
          No servers match your search
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Router: reads ?id= and dispatches to detail or list               */
/* ------------------------------------------------------------------ */

function RegistryRouter() {
  const searchParams = useSearchParams();
  const serverId = searchParams.get("id") || "";

  if (serverId) {
    return <RegistryDetail serverId={serverId} />;
  }
  return <RegistryList />;
}

/* ------------------------------------------------------------------ */
/*  Page export (wrapped in Suspense for useSearchParams)              */
/* ------------------------------------------------------------------ */

export default function RegistryPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-[80vh] text-[color:var(--text-secondary)]">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          Loading...
        </div>
      }
    >
      <RegistryRouter />
    </Suspense>
  );
}
