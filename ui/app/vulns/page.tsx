"use client";

import { Fragment, Suspense, useCallback, useEffect, useState, useMemo, type ReactNode } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api, Vulnerability, ScanJob, ScanResult, severityColor, severityDot, JobListItem, RemediationItem } from "@/lib/api";
import { ApiOfflineState } from "@/components/api-offline-state";
import { Bug, Download, ExternalLink, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Layers, Loader2, Package, Server, ShieldOff, Radar, FileSearch, ShieldAlert } from "lucide-react";

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

interface EnrichedVuln extends Vulnerability {
  packages: string[];
  agents: string[];
  sources: string[]; // scan source labels (e.g., "python:3.11-slim", "claude-desktop")
  affected_servers: string[];
  exposed_credentials: string[];
  reachable_tools: string[];
  references: string[];
  advisory_sources: string[];
  attack_vector_summary?: string;
  impact_category?: string;
  risk_score?: number;
  remediation_items: RemediationSummary[];
}

interface RemediationSummary {
  package: string;
  ecosystem: string;
  current_version: string;
  fixed_version: string | null;
  action?: string;
  command?: string | null;
  verify_command?: string | null;
  references: string[];
  risk_narrative: string;
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type SortKey = "severity" | "cvss" | "epss" | "id";
type GroupKey = "none" | "package" | "agent" | "severity";
type ScanScope = "latest" | "all";

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

function uniqueStrings(items: Array<string | null | undefined>) {
  return [...new Set(items.filter((item): item is string => Boolean(item && item.trim())).map((item) => item.trim()))];
}

function toRemediationSummary(item: RemediationItem): RemediationSummary {
  return {
    package: item.package,
    ecosystem: item.ecosystem,
    current_version: item.current_version,
    fixed_version: item.fixed_version,
    action: item.action,
    command: item.command,
    verify_command: item.verify_command,
    references: item.references ?? [],
    risk_narrative: item.risk_narrative,
  };
}

function mergeRemediationItems(existing: RemediationSummary[], incoming: RemediationSummary[]) {
  const merged = new Map(existing.map((item) => [`${item.package}:${item.current_version}:${item.fixed_version ?? "none"}`, item]));
  for (const item of incoming) {
    const key = `${item.package}:${item.current_version}:${item.fixed_version ?? "none"}`;
    if (!merged.has(key)) {
      merged.set(key, item);
    }
  }
  return Array.from(merged.values());
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

export default function VulnsPageWrapper() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center py-20 text-zinc-400">
        <Loader2 className="h-6 w-6 animate-spin mr-2" />
        Loading vulnerabilities...
      </div>
    }>
      <VulnsPage />
    </Suspense>
  );
}

function VulnsPage() {
  const searchParams = useSearchParams();
  const paramSeverity = searchParams.get("severity");
  const paramCve = searchParams.get("cve");
  const paramAgent = searchParams.get("agent");

  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [vulns, setVulns] = useState<EnrichedVuln[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState("");
  const [scope, setScope] = useState<ScanScope>("latest");
  const [filter, setFilter] = useState<SeverityFilter>(
    paramSeverity && ["critical", "high", "medium", "low"].includes(paramSeverity)
      ? (paramSeverity as SeverityFilter)
      : "all"
  );
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [search, setSearch] = useState(paramCve ?? paramAgent ?? "");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [suppressed, setSuppressed] = useState<Set<string>>(new Set());
  const [expandedId, setExpandedId] = useState<string | null>(paramCve ?? null);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  const collectVulns = useCallback((fullJobs: ScanJob[]) => {
    const vulnMap = new Map<string, EnrichedVuln>();
    for (const job of fullJobs) {
      if (!job.result) continue;
      const result = job.result as ScanResult;
      const blastById = new Map(result.blast_radius?.map((item) => [item.vulnerability_id, item]) ?? []);
      const remediationByVulnId = new Map<string, RemediationSummary[]>();
      for (const item of result.remediation_plan ?? []) {
        const summary = toRemediationSummary(item);
        for (const vulnId of item.vulnerabilities ?? []) {
          const existing = remediationByVulnId.get(vulnId) ?? [];
          existing.push(summary);
          remediationByVulnId.set(vulnId, existing);
        }
      }

      const scanSources: string[] = [];
      if (job.request.images?.length) scanSources.push(...job.request.images);
      if (job.request.k8s) scanSources.push("kubernetes");
      if (job.request.sbom) scanSources.push("sbom-import");
      if (scanSources.length === 0) scanSources.push("local-agents");

      for (const agent of result.agents) {
        for (const srv of agent.mcp_servers) {
          for (const pkg of srv.packages) {
            for (const vuln of pkg.vulnerabilities ?? []) {
              const blast = blastById.get(vuln.id);
              const remediationItems = remediationByVulnId.get(vuln.id) ?? [];
              const existing = vulnMap.get(vuln.id);
              if (existing) {
                if (!existing.packages.includes(pkg.name)) existing.packages.push(pkg.name);
                if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
                for (const src of scanSources) {
                  if (!existing.sources.includes(src)) existing.sources.push(src);
                }
                existing.cvss_score = existing.cvss_score ?? blast?.cvss_score ?? vuln.cvss_score;
                existing.epss_score = existing.epss_score ?? blast?.epss_score ?? vuln.epss_score;
                existing.fixed_version = existing.fixed_version ?? blast?.fixed_version ?? vuln.fixed_version;
                existing.summary = existing.summary ?? blast?.attack_vector_summary ?? vuln.summary ?? vuln.description;
                existing.attack_vector_summary = existing.attack_vector_summary ?? blast?.attack_vector_summary;
                existing.impact_category = existing.impact_category ?? blast?.impact_category;
                existing.risk_score = existing.risk_score ?? blast?.risk_score ?? blast?.blast_score;
                existing.affected_servers = uniqueStrings([...existing.affected_servers, ...(blast?.affected_servers ?? [])]);
                existing.exposed_credentials = uniqueStrings([...existing.exposed_credentials, ...(blast?.exposed_credentials ?? [])]);
                existing.reachable_tools = uniqueStrings([
                  ...existing.reachable_tools,
                  ...(blast?.exposed_tools ?? []),
                  ...(blast?.reachable_tools ?? []),
                ]);
                existing.references = uniqueStrings([...existing.references, ...(vuln.references ?? []), ...remediationItems.flatMap((item) => item.references)]);
                existing.advisory_sources = uniqueStrings([...existing.advisory_sources, ...(vuln.advisory_sources ?? [])]);
                existing.aliases = uniqueStrings([...(existing.aliases ?? []), ...(vuln.aliases ?? [])]);
                existing.remediation_items = mergeRemediationItems(existing.remediation_items, remediationItems);
              } else {
                vulnMap.set(vuln.id, {
                  ...vuln,
                  cvss_score: blast?.cvss_score ?? vuln.cvss_score,
                  epss_score: blast?.epss_score ?? vuln.epss_score,
                  fixed_version: blast?.fixed_version ?? vuln.fixed_version,
                  summary: blast?.attack_vector_summary ?? vuln.summary ?? vuln.description,
                  packages: [pkg.name],
                  agents: [agent.name],
                  sources: [...scanSources],
                  affected_servers: blast?.affected_servers ?? [],
                  exposed_credentials: blast?.exposed_credentials ?? [],
                  reachable_tools: uniqueStrings([...(blast?.exposed_tools ?? []), ...(blast?.reachable_tools ?? [])]),
                  references: uniqueStrings([...(vuln.references ?? []), ...remediationItems.flatMap((item) => item.references)]),
                  advisory_sources: vuln.advisory_sources ?? [],
                  aliases: vuln.aliases ?? [],
                  attack_vector_summary: blast?.attack_vector_summary,
                  impact_category: blast?.impact_category,
                  risk_score: blast?.risk_score ?? blast?.blast_score,
                  remediation_items: remediationItems,
                });
              }
            }
          }
        }
      }
    }
    return Array.from(vulnMap.values());
  }, []);

  const handleMarkFP = useCallback(async (vulnId: string, packageName: string) => {
    try {
      await api.createException({
        vulnerability_id: vulnId,
        package_name: packageName,
        reason: "false_positive",
      });
      setSuppressed((prev) => new Set(prev).add(vulnId));
    } catch {
      // silently fail — button stays visible for retry
    }
  }, []);

  useEffect(() => {
    async function loadSummaries() {
      try {
        const jobsResp = await api.listJobs();
        const doneJobs = jobsResp.jobs
          .filter((j) => j.status === "done")
          .sort((a, b) => b.created_at.localeCompare(a.created_at));
        setJobs(doneJobs);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        setLoading(false);
      }
    }
    void loadSummaries();
  }, []);

  useEffect(() => {
    async function loadDetails() {
      if (loading) return;
      if (jobs.length === 0) {
        setVulns([]);
        setDetailLoading(false);
        return;
      }

      setDetailLoading(true);
      setError("");
      try {
        if (scope === "latest") {
          const latestJob = await api.getScan(jobs[0].job_id);
          setVulns(collectVulns([latestJob]));
        } else {
          const fullJobs = await Promise.all(jobs.map((job) => api.getScan(job.job_id).catch(() => null)));
          setVulns(collectVulns(fullJobs.filter((job): job is ScanJob => Boolean(job))));
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        setDetailLoading(false);
      }
    }

    void loadDetails();
  }, [jobs, scope, loading, collectVulns]);

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
          (v.summary ?? v.description)?.toLowerCase().includes(q) ||
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

  // Reset page when filters change
  useEffect(() => { setPage(1); }, [filter, search, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(displayed.length / PAGE_SIZE));
  const paged = displayed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

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
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
          <p className="text-zinc-400 text-sm mt-1">
            {scope === "latest"
              ? `${vulns.length} vulnerability findings from the latest completed scan.`
              : `${vulns.length} vulnerability findings aggregated across all completed scans.`}{" "}
            This surface is vulnerability-first today and will expand to broader finding types over time. CVSS and EPSS appear only when the underlying advisory includes them.
          </p>
        </div>
        {vulns.length > 0 && (
          <button
            onClick={() => downloadJson(displayed, `findings-${new Date().toISOString().slice(0, 10)}.json`)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm font-medium rounded-lg transition-colors"
            title="Export filtered findings as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
        )}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading scan summaries...
        </div>
      )}
      {!loading && detailLoading && vulns.length === 0 && (
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          {scope === "latest" ? "Loading latest scan..." : "Aggregating completed scans..."}
        </div>
      )}
      {!loading && error && (
        <ApiOfflineState
          title="Findings need the agent-bom API"
          detail={error}
        />
      )}

      {!loading && !error && vulns.length === 0 && (
          <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Bug className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No findings found.</p>
          <p className="text-zinc-600 text-xs mt-1">
            Run a scan with enrichment enabled to see CVE-backed findings here.
          </p>
        </div>
      )}

      {!error && vulns.length > 0 && (
        <>
          {/* Controls */}
          <div className="flex flex-col gap-3">
            {/* Filters + search */}
            <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
              <div className="flex items-center gap-1 flex-wrap">
                {FILTERS?.map(({ key, label, color }) => (
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

            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Scope</span>
                <select
                  value={scope}
                  onChange={(e) => setScope(e.target.value as ScanScope)}
                  className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
                >
                  <option value="latest">Latest completed scan</option>
                  <option value="all">All completed scans</option>
                </select>
              </div>
              <p className="text-xs text-zinc-600">
                Default stays scoped for speed. Expand to all scans only when you need history-wide findings aggregation.
              </p>
            </div>

            {detailLoading && vulns.length > 0 && (
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {scope === "latest" ? "Refreshing latest scan..." : "Refreshing historical aggregation..."}
              </div>
            )}

            {/* Group by */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Group by</span>
              {GROUP_OPTIONS?.map(({ key, label, icon: Icon }) => (
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
              {grouped?.map(([groupLabel, groupVulns]) => (
                <div key={groupLabel}>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-sm font-semibold text-zinc-300">{groupLabel}</h3>
                    <span className="text-xs font-mono text-zinc-600 bg-zinc-800 rounded px-1.5 py-0.5">
                      {groupVulns.length}
                    </span>
                  </div>
                  <VulnTable
                    vulns={groupVulns}
                    sortKey={sortKey}
                    sortDir={sortDir}
                    handleSort={handleSort}
                    suppressed={suppressed}
                    onMarkFP={handleMarkFP}
                    expandedId={expandedId}
                    onToggleExpanded={setExpandedId}
                  />
                </div>
              ))}
            </div>
          ) : (
            <VulnTable
              vulns={paged}
              sortKey={sortKey}
              sortDir={sortDir}
              handleSort={handleSort}
              suppressed={suppressed}
              onMarkFP={handleMarkFP}
              expandedId={expandedId}
              onToggleExpanded={setExpandedId}
            />
          )}

          {/* Pagination controls (flat view only) */}
          {!grouped && (
            <div className="flex items-center justify-between">
              <p className="text-xs text-zinc-600">
                Page {page} of {totalPages} ({displayed.length} total)
              </p>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-3 h-3" />
                  Prev
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Next
                  <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          )}

          {grouped && (
            <p className="text-xs text-zinc-600 text-right">
              Showing {displayed.length} of {vulns.length} findings
            </p>
          )}
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
  suppressed,
  onMarkFP,
  expandedId,
  onToggleExpanded,
}: {
  vulns: EnrichedVuln[];
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  handleSort: (f: SortKey) => void;
  suppressed: Set<string>;
  onMarkFP: (vulnId: string, packageName: string) => void;
  expandedId: string | null;
  onToggleExpanded: (vulnId: string | null) => void;
}) {
  return (
    <div className="border border-zinc-800 rounded-xl overflow-hidden overflow-x-auto">
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
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 bg-zinc-950">
          {vulns?.map((v) => {
            const isExpanded = expandedId === v.id;
            return (
              <Fragment key={v.id}>
                <tr key={v.id} className={`transition-colors ${isExpanded ? "bg-zinc-900/80" : "hover:bg-zinc-900"}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-start gap-2">
                      <button
                        type="button"
                        onClick={() => onToggleExpanded(isExpanded ? null : v.id)}
                        className="mt-0.5 rounded p-0.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                        aria-label={isExpanded ? `Collapse ${v.id}` : `Expand ${v.id}`}
                      >
                        {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                      </button>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(v.severity)}`} />
                          <button
                            type="button"
                            onClick={() => onToggleExpanded(isExpanded ? null : v.id)}
                            className="font-mono text-xs text-zinc-200 transition-colors hover:text-emerald-400"
                          >
                            {v.id}
                          </button>
                          <a
                            href={`https://osv.dev/vulnerability/${v.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] font-medium text-zinc-400 transition-colors hover:border-zinc-600 hover:text-zinc-200"
                          >
                            OSV
                            <ExternalLink className="h-3 w-3" />
                          </a>
                          {(v.is_kev ?? v.cisa_kev) && <CisaKevBadge />}
                        </div>
                        {(v.summary ?? v.description) && (
                          <p className="text-xs text-zinc-600 mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
                            {v.summary ?? v.description}
                          </p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(v.severity)}`}>
                      {v.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {renderScoreValue(v.cvss_score, "CVSS not published by the current advisory")}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {renderPercentValue(v.epss_score, "EPSS not available for this advisory")}
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
                    {v.fixed_version ?? "N/A"}
                  </td>
                  <td className="px-4 py-3">
                    {suppressed.has(v.id) ? (
                      <span className="text-xs font-medium px-2 py-0.5 rounded border bg-zinc-800 border-zinc-700 text-zinc-400">
                        Suppressed
                      </span>
                    ) : (
                      <button
                        onClick={() => onMarkFP(v.id, v.packages[0] ?? "")}
                        className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-zinc-700 hover:bg-zinc-600 text-zinc-300 transition-colors"
                      >
                        <ShieldOff className="w-3 h-3" />
                        Mark FP
                      </button>
                    )}
                  </td>
                </tr>
                {isExpanded && (
                  <tr key={`${v.id}-detail`} className="bg-zinc-950">
                    <td colSpan={8} className="px-4 pb-4">
                      <VulnDetailPanel vuln={v} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
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

function renderScoreValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toFixed(1);
  }
  return (
    <span className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-500" title={missingLabel}>
      N/A
    </span>
  );
}

function renderPercentValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${(value * 100).toFixed(1)}%`;
  }
  return (
    <span className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-500" title={missingLabel}>
      N/A
    </span>
  );
}

function VulnDetailPanel({ vuln }: { vuln: EnrichedVuln }) {
  const summary = vuln.attack_vector_summary ?? vuln.summary ?? vuln.description ?? "No advisory summary available.";
  const cweMatches = summary.match(/CWE-\d+/gi) ?? [];
  const published = vuln.published_at ?? vuln.published ?? vuln.nvd_published;
  const modified = vuln.modified_at;
  const references = uniqueStrings(vuln.references).slice(0, 6);
  const fixCandidates = vuln.remediation_items.filter((item) => item.fixed_version || item.command || item.verify_command);
  const investigationSources = uniqueStrings([
    ...vuln.sources,
    ...vuln.advisory_sources,
  ]);

  return (
    <div className="ml-6 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
        <div className="space-y-4">
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Attack summary</h4>
            <p className="mt-2 text-sm leading-6 text-zinc-300">{summary}</p>
            {cweMatches.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {[...new Set(cweMatches)].map((cwe) => (
                  <span key={cwe} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs font-mono text-zinc-400">
                    {cwe}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <DetailStat label="Severity" value={vuln.severity} accent={severityColor(vuln.severity)} />
            <DetailStat label="CVSS" value={typeof vuln.cvss_score === "number" ? vuln.cvss_score.toFixed(1) : "Not published"} />
            <DetailStat label="EPSS" value={typeof vuln.epss_score === "number" ? `${(vuln.epss_score * 100).toFixed(1)}%` : "Not available"} />
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <ContextCard
              icon={Radar}
              title="Asset and reach context"
              items={[
                `${vuln.packages.length} package${vuln.packages.length === 1 ? "" : "s"}`,
                `${vuln.agents.length} agent${vuln.agents.length === 1 ? "" : "s"}`,
                `${vuln.affected_servers.length} server${vuln.affected_servers.length === 1 ? "" : "s"}`,
                vuln.risk_score ? `Risk score ${vuln.risk_score.toFixed(1)}` : null,
                vuln.impact_category ? `Impact ${vuln.impact_category}` : null,
              ]}
              detail={
                <>
                  <TagList label="Packages" values={vuln.packages} mono />
                  <TagList label="Agents" values={vuln.agents} />
                  <TagList label="Servers" values={vuln.affected_servers} />
                </>
              }
            />
            <ContextCard
              icon={ShieldAlert}
              title="Exposure at risk"
              items={[
                `${vuln.exposed_credentials.length} credential${vuln.exposed_credentials.length === 1 ? "" : "s"} exposed`,
                `${vuln.reachable_tools.length} reachable tool${vuln.reachable_tools.length === 1 ? "" : "s"}`,
              ]}
              detail={
                <>
                  <TagList label="Credentials" values={vuln.exposed_credentials} mono />
                  <TagList label="Tools" values={vuln.reachable_tools} mono />
                </>
              }
            />
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Fix context</h4>
            <div className="mt-3 space-y-2 text-sm text-zinc-300">
              <div><span className="text-zinc-500">Fix:</span> {vuln.fixed_version ?? "No published fix"}</div>
              {published && <div><span className="text-zinc-500">Published:</span> {new Date(published).toLocaleDateString()}</div>}
              {modified && <div><span className="text-zinc-500">Modified:</span> {new Date(modified).toLocaleDateString()}</div>}
              {typeof vuln.confidence === "number" && <div><span className="text-zinc-500">Confidence:</span> {(vuln.confidence * 100).toFixed(0)}%</div>}
              {vuln.severity_source && <div><span className="text-zinc-500">Severity source:</span> {vuln.severity_source}</div>}
            </div>
            {fixCandidates.length > 0 && (
              <div className="mt-4 space-y-3">
                {fixCandidates.slice(0, 2).map((item) => (
                  <div key={`${item.package}:${item.current_version}`} className="rounded-lg border border-zinc-800 bg-zinc-900/70 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium text-zinc-200">{item.package}</span>
                      <span className="text-[11px] font-mono text-emerald-400">
                        {item.current_version} → {item.fixed_version ?? "monitor"}
                      </span>
                    </div>
                    {item.action && <p className="mt-2 text-xs text-zinc-400">{item.action}</p>}
                    {item.command && <CodeLine label="Apply" value={item.command} />}
                    {item.verify_command && <CodeLine label="Verify" value={item.verify_command} />}
                  </div>
                ))}
              </div>
            )}
            {vuln.remediation_items[0]?.risk_narrative && (
              <p className="mt-3 text-xs leading-5 text-zinc-400">{vuln.remediation_items[0].risk_narrative}</p>
            )}
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
            <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">Investigation sources</h4>
            <div className="mt-3 space-y-3">
              <TagList label="Signals" values={investigationSources} />
              <TagList label="Aliases" values={vuln.aliases ?? []} mono />
              {references.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">Advisories</div>
                  <div className="flex flex-col gap-2">
                    {references.map((ref) => (
                      <a
                        key={ref}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/70 px-3 py-2 text-xs text-zinc-300 transition-colors hover:border-zinc-700 hover:text-zinc-100"
                      >
                        <FileSearch className="h-3.5 w-3.5 text-zinc-500" />
                        <span className="truncate">{ref}</span>
                        <ExternalLink className="ml-auto h-3 w-3 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <a
              href={`https://osv.dev/vulnerability/${vuln.id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:border-zinc-600 hover:text-zinc-100"
            >
              Open on OSV
              <ExternalLink className="h-3 w-3" />
            </a>
            <Link
              href={`/vulns?cve=${vuln.id}`}
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-950/70"
            >
              Keep this CVE scoped
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailStat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={`mt-2 text-sm font-medium text-zinc-100 ${accent ?? ""}`}>{value}</div>
    </div>
  );
}

function ContextCard({
  icon: Icon,
  title,
  items,
  detail,
}: {
  icon: typeof Radar;
  title: string;
  items: Array<string | null | undefined>;
  detail: ReactNode;
}) {
  const visibleItems = items.filter(Boolean) as string[];
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
      <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-zinc-500">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {visibleItems.length > 0 && (
        <ul className="mt-3 space-y-1 text-xs text-zinc-300">
          {visibleItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
      <div className="mt-3 space-y-2">{detail}</div>
    </div>
  );
}

function TagList({ label, values, mono = false }: { label: string; values: string[]; mono?: boolean }) {
  if (values.length === 0) {
    return null;
  }
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {values.map((value) => (
          <span
            key={`${label}:${value}`}
            className={`rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs text-zinc-300 ${mono ? "font-mono" : ""}`}
          >
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

function CodeLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="mt-2">
      <div className="text-[11px] font-medium uppercase tracking-wide text-zinc-500">{label}</div>
      <code className="mt-1 block overflow-x-auto rounded bg-black/30 px-2 py-1.5 text-[11px] text-emerald-300">
        {value}
      </code>
    </div>
  );
}
