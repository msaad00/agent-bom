"use client";

import { useEffect, useState, useMemo } from "react";
import { api, Vulnerability, ScanJob, ScanResult, severityColor, severityDot, OWASP_LLM_TOP10, MITRE_ATLAS } from "@/lib/api";
import { Bug, ExternalLink, ChevronDown, ChevronUp, Layers, Package, Server } from "lucide-react";

interface EnrichedVuln extends Vulnerability {
  packages: string[];
  agents: string[];
  sources: string[]; // scan source labels (e.g., "python:3.11-slim", "claude-desktop")
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type SortKey = "severity" | "cvss" | "epss" | "id";
type GroupKey = "none" | "package" | "agent" | "severity";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

function CisaKevBadge() {
  return (
    <span className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">
      KEV
    </span>
  );
}

function SortButton({
  label,
  field,
  current,
  dir,
  onClick,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: "asc" | "desc";
  onClick: (f: SortKey) => void;
}) {
  const active = current === field;
  return (
    <button
      onClick={() => onClick(field)}
      className={`flex items-center gap-0.5 text-xs font-medium uppercase tracking-wide transition-colors ${
        active ? "text-zinc-200" : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
      {active ? (
        dir === "desc" ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
      ) : null}
    </button>
  );
}

export default function VulnsPage() {
  const [vulns, setVulns] = useState<EnrichedVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [search, setSearch] = useState("");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");

  useEffect(() => {
    async function load() {
      try {
        const jobsResp = await api.listJobs();
        const doneJobs = jobsResp.jobs.filter((j) => j.status === "done");

        const fullJobs: ScanJob[] = await Promise.all(
          doneJobs.map((j) => api.getScan(j.job_id))
        );

        const vulnMap = new Map<string, EnrichedVuln>();
        for (const job of fullJobs) {
          if (!job.result) continue;
          const result = job.result as ScanResult;

          // Determine scan source labels
          const scanSources: string[] = [];
          if (job.request.images?.length) scanSources.push(...job.request.images);
          if (job.request.k8s) scanSources.push("kubernetes");
          if (job.request.sbom) scanSources.push("sbom-import");
          if (scanSources.length === 0) scanSources.push("local-agents");

          for (const agent of result.agents) {
            for (const srv of agent.mcp_servers) {
              for (const pkg of srv.packages) {
                for (const vuln of pkg.vulnerabilities ?? []) {
                  const existing = vulnMap.get(vuln.id);
                  if (existing) {
                    if (!existing.packages.includes(pkg.name)) existing.packages.push(pkg.name);
                    if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
                    for (const src of scanSources) {
                      if (!existing.sources.includes(src)) existing.sources.push(src);
                    }
                  } else {
                    vulnMap.set(vuln.id, {
                      ...vuln,
                      packages: [pkg.name],
                      agents: [agent.name],
                      sources: [...scanSources],
                    });
                  }
                }
              }
            }
          }
        }
        setVulns(Array.from(vulnMap.values()));
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  function handleSort(field: SortKey) {
    if (sortKey === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(field);
      setSortDir("desc");
    }
  }

  const displayed = useMemo(() => {
    let list = vulns;
    if (filter !== "all") {
      list = list.filter((v) => v.severity.toLowerCase() === filter);
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (v) =>
          v.id.toLowerCase().includes(q) ||
          v.description?.toLowerCase().includes(q) ||
          v.packages.some((p) => p.toLowerCase().includes(q)) ||
          v.agents.some((a) => a.toLowerCase().includes(q))
      );
    }
    list = [...list].sort((a, b) => {
      let diff = 0;
      if (sortKey === "severity") {
        diff = (SEVERITY_ORDER[a.severity.toLowerCase()] ?? 0) - (SEVERITY_ORDER[b.severity.toLowerCase()] ?? 0);
      } else if (sortKey === "cvss") {
        diff = (a.cvss_score ?? 0) - (b.cvss_score ?? 0);
      } else if (sortKey === "epss") {
        diff = (a.epss_score ?? 0) - (b.epss_score ?? 0);
      } else {
        diff = a.id.localeCompare(b.id);
      }
      return sortDir === "desc" ? -diff : diff;
    });
    return list;
  }, [vulns, filter, search, sortKey, sortDir]);

  // Group displayed vulns
  const grouped = useMemo(() => {
    if (groupBy === "none") return null;

    const groups = new Map<string, EnrichedVuln[]>();
    for (const v of displayed) {
      let keys: string[] = [];
      if (groupBy === "package") keys = v.packages;
      else if (groupBy === "agent") keys = v.agents;
      else if (groupBy === "severity") keys = [v.severity];

      for (const key of keys) {
        const existing = groups.get(key) ?? [];
        existing.push(v);
        groups.set(key, existing);
      }
    }

    // Sort groups: by count descending
    return Array.from(groups.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [displayed, groupBy]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of vulns) {
      const s = v.severity.toLowerCase() as keyof typeof c;
      if (s in c) c[s]++;
    }
    return c;
  }, [vulns]);

  const FILTERS: { key: SeverityFilter; label: string; color: string }[] = [
    { key: "all",      label: `All (${vulns.length})`,          color: "text-zinc-300" },
    { key: "critical", label: `Critical (${counts.critical})`,  color: "text-red-400" },
    { key: "high",     label: `High (${counts.high})`,          color: "text-orange-400" },
    { key: "medium",   label: `Medium (${counts.medium})`,      color: "text-yellow-400" },
    { key: "low",      label: `Low (${counts.low})`,            color: "text-blue-400" },
  ];

  const GROUP_OPTIONS: { key: GroupKey; label: string; icon: React.ElementType }[] = [
    { key: "none", label: "Flat", icon: Layers },
    { key: "severity", label: "Severity", icon: Bug },
    { key: "package", label: "Package", icon: Package },
    { key: "agent", label: "Agent", icon: Server },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
        <p className="text-zinc-400 text-sm mt-1">
          {vulns.length} unique CVEs aggregated across all scans
        </p>
      </div>

      {loading && <p className="text-zinc-500 text-sm">Loading vulnerabilities…</p>}
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {!loading && vulns.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Bug className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No vulnerabilities found.</p>
          <p className="text-zinc-600 text-xs mt-1">
            Run a scan with enrichment enabled to see CVE data here.
          </p>
        </div>
      )}

      {vulns.length > 0 && (
        <>
          {/* Controls */}
          <div className="flex flex-col gap-3">
            {/* Filters + search */}
            <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
              <div className="flex items-center gap-1 flex-wrap">
                {FILTERS.map(({ key, label, color }) => (
                  <button
                    key={key}
                    onClick={() => setFilter(key)}
                    className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                      filter === key
                        ? `${color} border-zinc-600 bg-zinc-800`
                        : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <input
                type="text"
                placeholder="Search CVE, package, agent…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full sm:w-64 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>

            {/* Group by */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Group by</span>
              {GROUP_OPTIONS.map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setGroupBy(key)}
                  className={`flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors ${
                    groupBy === key
                      ? "text-zinc-200 border-zinc-600 bg-zinc-800"
                      : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Grouped view */}
          {grouped ? (
            <div className="space-y-6">
              {grouped.map(([groupLabel, groupVulns]) => (
                <div key={groupLabel}>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-sm font-semibold text-zinc-300">{groupLabel}</h3>
                    <span className="text-xs font-mono text-zinc-600 bg-zinc-800 rounded px-1.5 py-0.5">
                      {groupVulns.length}
                    </span>
                  </div>
                  <VulnTable vulns={groupVulns} sortKey={sortKey} sortDir={sortDir} handleSort={handleSort} />
                </div>
              ))}
            </div>
          ) : (
            <VulnTable vulns={displayed} sortKey={sortKey} sortDir={sortDir} handleSort={handleSort} />
          )}

          <p className="text-xs text-zinc-600 text-right">
            Showing {displayed.length} of {vulns.length} vulnerabilities
          </p>
        </>
      )}
    </div>
  );
}

function VulnTable({
  vulns,
  sortKey,
  sortDir,
  handleSort,
}: {
  vulns: EnrichedVuln[];
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  handleSort: (f: SortKey) => void;
}) {
  return (
    <div className="border border-zinc-800 rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-zinc-900 border-b border-zinc-800">
          <tr>
            <th className="text-left px-4 py-3">
              <SortButton label="CVE" field="id" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="Severity" field="severity" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="CVSS" field="cvss" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="EPSS" field="epss" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Packages</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Agents</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Fix</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 bg-zinc-950">
          {vulns.map((v) => (
            <tr key={v.id} className="hover:bg-zinc-900 transition-colors">
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(v.severity)}`} />
                  <a
                    href={`https://osv.dev/vulnerability/${v.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-zinc-200 hover:text-emerald-400 flex items-center gap-1 group"
                  >
                    {v.id}
                    <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </a>
                  {v.cisa_kev && <CisaKevBadge />}
                </div>
                {v.description && (
                  <p className="text-xs text-zinc-600 mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
                    {v.description}
                  </p>
                )}
              </td>
              <td className="px-4 py-3">
                <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(v.severity)}`}>
                  {v.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                {v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}
              </td>
              <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                {v.epss_score != null ? (v.epss_score * 100).toFixed(1) + "%" : "—"}
              </td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1">
                  {v.packages.slice(0, 3).map((p) => (
                    <span key={p} className="text-xs font-mono bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-400">
                      {p}
                    </span>
                  ))}
                  {v.packages.length > 3 && (
                    <span className="text-xs text-zinc-600">+{v.packages.length - 3}</span>
                  )}
                </div>
              </td>
              <td className="px-4 py-3 text-xs text-zinc-500">
                {v.agents.slice(0, 2).join(", ")}
                {v.agents.length > 2 && <span className="text-zinc-600"> +{v.agents.length - 2}</span>}
              </td>
              <td className="px-4 py-3 text-xs font-mono text-emerald-500">
                {v.fixed_version ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {vulns.length === 0 && (
        <div className="px-4 py-8 text-center text-zinc-600 text-sm">
          No vulnerabilities match your filters.
        </div>
      )}
    </div>
  );
}
