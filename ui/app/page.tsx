"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { api, ScanJob, ScanResult, BlastRadius, Agent, JobListItem, PostureResponse, formatDate, OWASP_LLM_TOP10, MITRE_ATLAS } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
import { TrustStack } from "@/components/trust-stack";
import { SeverityBadge } from "@/components/severity-badge";
import { ActivityFeed } from "@/components/activity-feed";
import {
  PostureGrade,
} from "@/components/posture-grade";
import { AttackPathCard } from "@/components/attack-path-card";
import { ApiOfflineState } from "@/components/api-offline-state";
import { buildSecurityGraphHref } from "@/lib/attack-paths";
import {
  ShieldAlert, Server, Package, Bug, Zap, ArrowRight, Clock,
  AlertTriangle, Container, Layers, FileText, ExternalLink, GitBranch, ChevronRight,
} from "lucide-react";
import { VulnTrendChart, EpssDistributionChart, EpssVsCvssChart, TrendDataPoint, EpssDataPoint, EpssVsCvssPoint } from "@/components/charts";

// ─── Aggregation helpers ──────────────────────────────────────────────────────

interface AggregatedPackage {
  name: string;
  version: string;
  ecosystem: string;
  vulnCount: number;
  critCount: number;
  highCount: number;
  agents: string[];
}

function aggregatePackages(jobs: ScanJob[]): AggregatedPackage[] {
  const pkgMap = new Map<string, AggregatedPackage>();
  for (const job of jobs) {
    if (job.status !== "done" || !job.result) continue;
    const result = job.result as ScanResult;
    for (const agent of result.agents) {
      for (const srv of agent.mcp_servers) {
        for (const pkg of srv.packages) {
          const key = `${pkg.name}@${pkg.version}`;
          const existing = pkgMap.get(key);
          const vulns = pkg.vulnerabilities ?? [];
          const crit = vulns.filter((v) => v.severity === "critical").length;
          const high = vulns.filter((v) => v.severity === "high").length;
          if (existing) {
            existing.vulnCount = Math.max(existing.vulnCount, vulns.length);
            existing.critCount = Math.max(existing.critCount, crit);
            existing.highCount = Math.max(existing.highCount, high);
            if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
          } else {
            pkgMap.set(key, {
              name: pkg.name,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              vulnCount: vulns.length,
              critCount: crit,
              highCount: high,
              agents: [agent.name],
            });
          }
        }
      }
    }
  }
  return Array.from(pkgMap.values())
    .filter((p) => p.vulnCount > 0)
    .sort((a, b) => b.critCount - a.critCount || b.highCount - a.highCount || b.vulnCount - a.vulnCount);
}

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

function aggregateSeverity(allBlast: BlastRadius[]): SeverityCounts {
  const c = { critical: 0, high: 0, medium: 0, low: 0, total: allBlast.length };
  for (const b of allBlast) {
    const s = b.severity?.toLowerCase();
    if (s === "critical") c.critical++;
    else if (s === "high") c.high++;
    else if (s === "medium") c.medium++;
    else if (s === "low") c.low++;
  }
  return c;
}

interface ScanSource {
  label: string;
  icon: React.ElementType;
  count: number;
  vulns: number;
  critical: number;
}

const SOURCE_META: Record<string, { label: string; icon: React.ElementType }> = {
  agent_discovery: { label: "MCP Agents", icon: Server },
  image: { label: "Container Images", icon: Container },
  k8s: { label: "Kubernetes", icon: Layers },
  sbom: { label: "SBOM Imports", icon: FileText },
  filesystem: { label: "Filesystem", icon: FileText },
  terraform: { label: "Terraform", icon: Layers },
  github_actions: { label: "GitHub Actions", icon: Layers },
  browser_extensions: { label: "Browser Extensions", icon: ExternalLink },
  jupyter: { label: "Jupyter Notebooks", icon: FileText },
  gpu_infra: { label: "GPU Infrastructure", icon: Server },
};

function aggregateSources(jobs: ScanJob[]): ScanSource[] {
  const srcMap = new Map<string, ScanSource>();

  for (const job of jobs) {
    if (job.status !== "done") continue;
    const result = job.result as ScanResult | undefined;
    const blast = result?.blast_radius ?? [];
    // Prefer scan_sources from result (auto-detected), fall back to request inference
    const sources = result?.scan_sources ?? [];

    if (sources.length > 0) {
      for (const src of sources) {
        const meta = SOURCE_META[src] ?? { label: src, icon: FileText };
        const existing = srcMap.get(src);
        if (existing) {
          existing.count++;
          existing.vulns += blast.length;
          existing.critical += blast.filter((b) => b.severity === "critical").length;
        } else {
          srcMap.set(src, {
            label: meta.label,
            icon: meta.icon,
            count: 1,
            vulns: blast.length,
            critical: blast.filter((b) => b.severity === "critical").length,
          });
        }
      }
    } else {
      // Legacy fallback: infer from request
      const req = job.request;
      if (req.images && req.images.length > 0) {
        const e = srcMap.get("image") ?? { label: "Container Images", icon: Container, count: 0, vulns: 0, critical: 0 };
        e.count += req.images.length;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("image", e);
      } else {
        const e = srcMap.get("agent_discovery") ?? { label: "MCP Agents", icon: Server, count: 0, vulns: 0, critical: 0 };
        e.count++;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("agent_discovery", e);
      }
    }
  }
  return Array.from(srcMap.values());
}

function aggregateTrend(jobs: ScanJob[]): TrendDataPoint[] {
  const done = jobs
    .filter((j) => j.status === "done" && j.result)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  return done?.map((j) => {
    const blast = (j.result as ScanResult)?.blast_radius ?? [];
    const sev = aggregateSeverity(blast);
    const d = new Date(j.created_at);
    return {
      label: `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`,
      critical: sev.critical,
      high: sev.high,
      medium: sev.medium,
      low: sev.low,
    };
  });
}

function aggregateEpss(allBlast: BlastRadius[]): EpssDataPoint[] {
  const buckets = [
    { range: "0-10%", min: 0, max: 0.1, count: 0 },
    { range: "10-30%", min: 0.1, max: 0.3, count: 0 },
    { range: "30-50%", min: 0.3, max: 0.5, count: 0 },
    { range: "50-70%", min: 0.5, max: 0.7, count: 0 },
    { range: "70-90%", min: 0.7, max: 0.9, count: 0 },
    { range: "90-100%", min: 0.9, max: 1.01, count: 0 },
  ];
  for (const b of allBlast) {
    if (b.epss_score == null) continue;
    for (const bucket of buckets) {
      if (b.epss_score >= bucket.min && b.epss_score < bucket.max) {
        bucket.count++;
        break;
      }
    }
  }
  return buckets?.map(({ range, count }) => ({ range, count }));
}

function aggregateEpssVsCvss(allBlast: BlastRadius[]): EpssVsCvssPoint[] {
  return allBlast
    .filter((b) => b.cvss_score != null && b.epss_score != null)
    .map((b) => ({
      cve: b.vulnerability_id,
      cvss: b.cvss_score!,
      epss: b.epss_score!,
      blast: b.risk_score ?? b.blast_score,
      severity: b.severity?.toLowerCase() ?? "low",
      kev: !!(b.is_kev ?? b.cisa_kev),
      package: b.package,
    }));
}

// Compound issue: a finding that meets 2+ independent risk signals simultaneously.
// Each rule returns a subset of blast radius entries.
export interface CompoundIssue {
  id: string;
  title: string;
  description: string;
  count: number;
  severity: "critical" | "high";
  findings: BlastRadius[];
  filter: string; // URL param for /vulns deep-link
}

const SEVERITY_ORDER_MAP: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

function aggregateCompoundIssues(allBlast: BlastRadius[]): CompoundIssue[] {
  const issues: CompoundIssue[] = [];

  // 1. CISA KEV + reachable tool exposure
  const kevReachable = allBlast.filter(
    (b) => (b.is_kev ?? b.cisa_kev) && (b.exposed_tools ?? b.reachable_tools).length > 0
  );
  if (kevReachable.length > 0) {
    issues.push({
      id: "kev-reachable",
      title: "Actively Exploited + Tool Reachability",
      description:
        "Known-exploited vulnerabilities (CISA KEV) in packages reachable by MCP tools — immediate patching required.",
      count: kevReachable.length,
      severity: "critical",
      findings: kevReachable.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "kev=true",
    });
  }

  // 2. CISA KEV + credential exposure
  const kevCredential = allBlast.filter(
    (b) => (b.is_kev ?? b.cisa_kev) && b.exposed_credentials.length > 0
  );
  if (kevCredential.length > 0) {
    issues.push({
      id: "kev-credential",
      title: "Actively Exploited + Credential Exposure",
      description:
        "Known-exploited CVEs co-located with exposed credentials — data exfiltration risk.",
      count: kevCredential.length,
      severity: "critical",
      findings: kevCredential.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "kev=true",
    });
  }

  // 3. High EPSS (≥30%) + Critical/High CVSS (≥7) — imminent exploitation likely
  const epssHighCvss = allBlast.filter(
    (b) =>
      (b.epss_score ?? 0) >= 0.3 &&
      (b.cvss_score ?? 0) >= 7 &&
      !(b.is_kev ?? b.cisa_kev)
  );
  if (epssHighCvss.length > 0) {
    issues.push({
      id: "epss-cvss",
      title: "High Exploit Probability + Critical Severity",
      description:
        "CVEs with EPSS ≥ 30% and CVSS ≥ 7.0 — statistically likely to be exploited in the wild within 30 days.",
      count: epssHighCvss.length,
      severity: "high",
      findings: epssHighCvss.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "severity=high",
    });
  }

  // 4. Credential exposure + reachable exec tools
  const credExec = allBlast.filter(
    (b) =>
      b.exposed_credentials.length > 0 &&
      (b.exposed_tools ?? b.reachable_tools).some((t) =>
        ["bash", "exec", "shell", "run", "execute", "subprocess"].some((kw) =>
          t.toLowerCase().includes(kw)
        )
      )
  );
  if (credExec.length > 0) {
    issues.push({
      id: "cred-exec",
      title: "Credential Exposure + Code Execution Path",
      description:
        "Exposed credentials reachable from tools with code execution capability — privilege escalation vector.",
      count: credExec.length,
      severity: "critical",
      findings: credExec.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "severity=critical",
    });
  }

  return issues.sort(
    (a, b) =>
      (SEVERITY_ORDER_MAP[b.severity] ?? 0) -
      (SEVERITY_ORDER_MAP[a.severity] ?? 0)
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [detailJobs, setDetailJobs] = useState<ScanJob[]>([]);
  const [agentCount, setAgentCount] = useState<number>(0);
  const [agentList, setAgentList] = useState<Agent[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(true);
  const [apiError, setApiError] = useState(false);
  const [importedReport, setImportedReport] = useState<ScanResult | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);

  // Fetch posture grade
  useEffect(() => {
    api.getPosture().then(setPosture).catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadJobs() {
      setJobsLoading(true);
      try {
        const jobsRes = await api.listJobs();
        if (cancelled) return;
        const jobsList = Array.isArray(jobsRes?.jobs)
          ? [...jobsRes.jobs].sort((a, b) => b.created_at.localeCompare(a.created_at))
          : [];
        setJobs(jobsList);
        setApiError(false);
      } catch {
        if (cancelled) return;
        setApiError(true);
        setJobs([]);
        setDetailJobs([]);
      } finally {
        if (!cancelled) setJobsLoading(false);
      }
    }

    async function loadAgents() {
      setAgentsLoading(true);
      try {
        const agentsRes = await api.listAgents();
        if (cancelled) return;
        setAgentCount(agentsRes?.count ?? 0);
        setAgentList(Array.isArray(agentsRes?.agents) ? agentsRes.agents : []);
      } catch {
        if (cancelled) return;
        setAgentCount(0);
        setAgentList([]);
      } finally {
        if (!cancelled) setAgentsLoading(false);
      }
    }

    void loadJobs();
    void loadAgents();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    async function hydrateDetails() {
      if (apiError) {
        setDetailJobs([]);
        setDetailLoading(false);
        return;
      }

      const detailIds = jobs
        .filter((job) => job.status === "done")
        .slice(0, 10)
        .map((job) => job.job_id);

      if (detailIds.length === 0) {
        setDetailJobs([]);
        setDetailLoading(false);
        return;
      }

      setDetailLoading(true);
      try {
        const fullJobs = await Promise.all(
          detailIds.map((jobId) => api.getScan(jobId).catch(() => null))
        );
        const hydrated = fullJobs
          .filter((job): job is ScanJob => Boolean(job))
          .sort((a, b) => b.created_at.localeCompare(a.created_at));
        setDetailJobs(hydrated);
      } catch {
        setDetailJobs([]);
      } finally {
        setDetailLoading(false);
      }
    }
    void hydrateDetails();
  }, [jobs, apiError]);

  // When API is down but user imported a local report, synthesise a fake job
  // so all downstream useMemo aggregators work without changes.
  const effectiveJobs = useMemo<ScanJob[]>(() => {
    if (!apiError || !importedReport) return detailJobs;
    return [{
      job_id: "imported",
      status: "done",
      created_at: importedReport.scan_timestamp ?? new Date().toISOString(),
      request: {} as ScanJob["request"],
      progress: [],
      result: importedReport as unknown as Record<string, unknown>,
    } as unknown as ScanJob];
  }, [detailJobs, apiError, importedReport]);

  const effectiveRecentJobs = useMemo<JobListItem[]>(() => {
    if (!apiError || !importedReport) return jobs;
    return [{
      job_id: "imported",
      status: "done",
      created_at: importedReport.scan_timestamp ?? new Date().toISOString(),
      request: {},
      summary: importedReport.summary,
      scan_timestamp: importedReport.scan_timestamp,
      pushed: false,
    }];
  }, [jobs, apiError, importedReport]);

  const doneJobs = useMemo(
    () => effectiveJobs.filter((j) => j.status === "done" && j.result),
    [effectiveJobs]
  );

  const allBlast = useMemo(
    () => doneJobs.flatMap((j) => (j.result as ScanResult)?.blast_radius ?? []),
    [doneJobs]
  );

  const severity = useMemo(() => aggregateSeverity(allBlast), [allBlast]);
  const topPackages = useMemo(() => aggregatePackages(effectiveJobs), [effectiveJobs]);
  const sources = useMemo(() => aggregateSources(effectiveJobs), [effectiveJobs]);
  const trendData = useMemo(() => aggregateTrend(effectiveJobs), [effectiveJobs]);
  const epssData = useMemo(() => aggregateEpss(allBlast), [allBlast]);
  const scatterData = useMemo(() => aggregateEpssVsCvss(allBlast), [allBlast]);
  const compoundIssues = useMemo(() => aggregateCompoundIssues(allBlast), [allBlast]);
  const kevCount = useMemo(() => allBlast.filter((b) => (b.is_kev ?? b.cisa_kev) === true).length, [allBlast]);
  const credentialExposureCount = useMemo(() => allBlast.filter((b) => b.exposed_credentials.length > 0).length, [allBlast]);
  const reachableToolCount = useMemo(
    () => new Set(allBlast.flatMap((b) => b.exposed_tools ?? b.reachable_tools ?? [])).size,
    [allBlast]
  );

  // Unique CVE count
  const uniqueCVEs = useMemo(() => {
    const ids = new Set(allBlast?.map((b) => b.vulnerability_id));
    return ids.size;
  }, [allBlast]);
  const topRisk = useMemo(
    () =>
      [...allBlast].sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score))[0] ?? null,
    [allBlast]
  );

  // Total packages scanned across all jobs
  const totalPackages = useMemo(() => {
    const pkgs = new Set<string>();
    for (const job of doneJobs) {
      const result = job.result as ScanResult;
      for (const agent of result.agents) {
        for (const srv of agent.mcp_servers) {
          for (const pkg of srv.packages) {
            pkgs.add(`${pkg.name}@${pkg.version}`);
          }
        }
      }
    }
    return pkgs.size;
  }, [doneJobs]);

  // Derive agent count from imported report when API is unavailable
  const effectiveAgentCount = importedReport
    ? (importedReport.agents?.length ?? 0)
    : agentCount;
  const summaryStats = useMemo(() => {
    const latest = effectiveRecentJobs.find((job) => job.status === "done" && job.summary);
    return latest?.summary ?? null;
  }, [effectiveRecentJobs]);
  const displayedAgentCount = importedReport ? (importedReport.agents?.length ?? 0) : (agentsLoading ? null : effectiveAgentCount);
  const isLoading = jobsLoading && !importedReport;
  const summaryReady = !jobsLoading || Boolean(importedReport);
  const agentsReady = !agentsLoading || Boolean(importedReport);
  const detailsReady = !detailLoading || Boolean(importedReport);

  if (apiError && !importedReport) return <ApiOfflineState onImport={setImportedReport} />;

  return (
    <div className="space-y-8">
      <section className="relative overflow-hidden rounded-[28px] border border-zinc-800/80 bg-[radial-gradient(circle_at_top_left,rgba(16,185,129,0.16),transparent_24%),radial-gradient(circle_at_top_right,rgba(239,68,68,0.12),transparent_24%),linear-gradient(180deg,rgba(24,24,27,0.98),rgba(9,9,11,0.96))] p-6 shadow-2xl shadow-black/20">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-3xl">
            <p className="text-[11px] uppercase tracking-[0.24em] text-emerald-400">Overview</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-50 sm:text-4xl">
              Risk overview
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
              {effectiveRecentJobs.length} scan{effectiveRecentJobs.length !== 1 ? "s" : ""} · {(displayedAgentCount ?? "—")} agent{displayedAgentCount === 1 ? "" : "s"} · {detailsReady ? totalPackages : (summaryStats?.total_packages ?? 0)} packages · {detailsReady ? uniqueCVEs : (summaryStats?.total_vulnerabilities ?? 0)} CVEs
            </p>
            <p className="mt-5 text-[10px] font-semibold uppercase tracking-[0.22em] text-zinc-500">
              Overview KPIs
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <div className="rounded-2xl border border-red-500/20 bg-red-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-red-200/70">Actively exploited</div>
                <div className="mt-1 font-mono text-lg font-semibold text-red-100">{detailsReady ? kevCount : 0}</div>
              </div>
              <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-amber-200/70">Credential exposed</div>
                <div className="mt-1 font-mono text-lg font-semibold text-amber-100">{detailsReady ? credentialExposureCount : 0}</div>
              </div>
              <div className="rounded-2xl border border-sky-500/20 bg-sky-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-sky-200/70">Reachable tools</div>
                <div className="mt-1 font-mono text-lg font-semibold text-sky-100">{detailsReady ? reachableToolCount : 0}</div>
              </div>
              {topRisk && (
                <div className="rounded-2xl border border-zinc-700 bg-zinc-900/80 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">Top path</div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="font-mono text-lg font-semibold text-zinc-100">{(topRisk.risk_score ?? topRisk.blast_score).toFixed(1)}</span>
                    <span className="truncate text-xs text-zinc-400">{topRisk.vulnerability_id}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2 xl:justify-end">
            <Link
              href="/scan"
              className="flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500"
            >
              Run scan
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/graph"
              className="flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900/80 px-4 py-2.5 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-500 hover:bg-zinc-800"
            >
              Open graph
              <GitBranch className="h-4 w-4" />
            </Link>
          </div>
        </div>

        {posture && (
          <div className="mt-6">
            <PostureGrade
              grade={posture.grade}
              score={posture.score}
              dimensions={posture.dimensions}
              summary={posture.summary}
              variant="panel"
              defaultExpanded={false}
              drilldown
            />
          </div>
        )}
      </section>

      {(!isLoading) && allBlast.length > 0 && (
        <details open className="group/attack rounded-[28px] border border-zinc-800/90 bg-zinc-950/70 p-4 shadow-[0_24px_80px_-48px_rgba(16,185,129,0.28)]">
          <summary className="flex cursor-pointer list-none items-start justify-between gap-4 select-none">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-300">
                <GitBranch className="h-4 w-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <ChevronRight className="h-4 w-4 text-zinc-500 transition-transform group-open/attack:rotate-90" />
                  <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-widest">
                    Top Attack Paths
                  </h2>
                  <span className="rounded-full border border-zinc-800 bg-zinc-900/90 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
                    {Math.min(allBlast.length, 5)} shown
                  </span>
                </div>
                <p className="mt-1 max-w-3xl text-xs leading-5 text-zinc-500">
                  Collapse this list when you want a tighter landing view. Open any path card to jump straight into the focused security graph drilldown.
                </p>
              </div>
            </div>
            <span className="hidden rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-emerald-300 md:inline-flex">
              Clickable drilldowns
            </span>
          </summary>
          <div className="mt-4 space-y-2">
            {[...allBlast]
              .sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score))
              .slice(0, 5)
              .map((b) => {
                const nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[] = [
                  { type: "cve", label: b.vulnerability_id, severity: b.severity?.toLowerCase() },
                ];
                if (b.package) nodes.push({ type: "package", label: b.package });
                if (b.affected_servers && b.affected_servers.length > 0) nodes.push({ type: "server", label: b.affected_servers[0]! });
                if (b.affected_agents.length > 0) nodes.push({ type: "agent", label: b.affected_agents[0]! });
                if (b.exposed_credentials.length > 0) nodes.push({ type: "credential", label: b.exposed_credentials[0]! });
                return (
                  <AttackPathCard
                    key={b.vulnerability_id}
                    nodes={nodes}
                    riskScore={b.risk_score ?? b.blast_score / 10}
                    href={buildSecurityGraphHref({
                      cve: b.vulnerability_id,
                      packageName: b.package,
                      agentName: b.affected_agents[0],
                    })}
                  />
                );
              })}
          </div>
        </details>
      )}

      <details open className="group/metrics rounded-[28px] border border-zinc-800/90 bg-zinc-950/70 p-4 shadow-[0_24px_80px_-48px_rgba(59,130,246,0.24)]">
        <summary className="flex cursor-pointer list-none items-start justify-between gap-4 select-none">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-sky-500/20 bg-sky-500/10 text-sky-300">
              <Layers className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <ChevronRight className="h-4 w-4 text-zinc-500 transition-transform group-open/metrics:rotate-90" />
                <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-widest">
                  Exposure KPIs
                </h2>
              </div>
              <p className="mt-1 max-w-3xl text-xs leading-5 text-zinc-500">
                Coverage and backlog snapshot for the current scan set: total scans, agents, packages, unique CVEs, and critical findings.
              </p>
            </div>
          </div>
          <span className="hidden rounded-full border border-zinc-800 bg-zinc-900/90 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-zinc-400 md:inline-flex">
            5 tiles
          </span>
        </summary>
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
          <StatCard icon={Layers} label="Total scans" value={summaryReady ? String(effectiveRecentJobs.length) : "—"} color="zinc" href="/jobs" />
          <StatCard icon={Server} label="Agents" value={agentsReady ? String(effectiveAgentCount) : "—"} color="blue" href="/agents" />
          <StatCard icon={Package} label="Packages" value={summaryReady ? String(detailsReady ? totalPackages : (summaryStats?.total_packages ?? 0)) : "—"} color="orange" href="/findings" />
          <StatCard icon={Bug} label="Unique CVEs" value={summaryReady ? String(detailsReady ? uniqueCVEs : (summaryStats?.total_vulnerabilities ?? 0)) : "—"} color="red" href="/findings" />
          <StatCard icon={Zap} label="Critical" value={summaryReady ? String(detailsReady ? severity.critical : (summaryStats?.critical_findings ?? 0)) : "—"} color="red" href="/findings?severity=critical" />
        </div>
      </details>

      {/* Severity distribution + Sources — side by side */}
      {(!isLoading) && allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <SeverityChart severity={severity} />
          <SourceBreakdown sources={sources} />
        </div>
      )}

      {/* Trend charts */}
      {(!isLoading) && allBlast.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <VulnTrendChart data={trendData} />
          <EpssDistributionChart data={epssData} />
        </div>
      )}

      {/* EPSS × CVSS risk map */}
      {(!isLoading) && scatterData.length > 0 && (
        <EpssVsCvssChart data={scatterData} />
      )}

      {/* Compound Issues */}
      {(!isLoading) && compoundIssues.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
                Compound Issues
              </h2>
              <p className="text-[10px] text-zinc-600 mt-0.5">
                Findings that meet multiple independent risk criteria simultaneously
              </p>
            </div>
            <Link href="/findings" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {compoundIssues?.map((issue) => (
              <CompoundIssueCard key={issue.id} issue={issue} />
            ))}
          </div>
        </section>
      )}

      {/* Agent topology */}
      {(!isLoading) && agentList.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Agent Topology
            </h2>
            <Link href="/agents" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <AgentTopology agents={agentList} />
        </section>
      )}

      {/* AI Agent Trust Stack */}
      {(!isLoading) && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            AI Agent Trust Stack
          </h2>
          <TrustStack />
        </section>
      )}

      {/* Top vulnerable packages */}
      {(!isLoading) && topPackages.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Top vulnerable packages
          </h2>
          <div className="border border-zinc-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 border-b border-zinc-800">
                <tr>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Package</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Ecosystem</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">CVEs</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Crit</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">High</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-zinc-500 uppercase tracking-wide">Agents</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {topPackages.slice(0, 10).map((pkg) => (
                  <tr key={`${pkg.name}@${pkg.version}`} className="hover:bg-zinc-900 transition-colors">
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-xs text-zinc-200">{pkg.name}</span>
                      <span className="font-mono text-xs text-zinc-600 ml-1">@{pkg.version}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-zinc-500">{pkg.ecosystem}</td>
                    <td className="px-4 py-2.5 text-center">
                      <span className="font-mono text-xs text-zinc-300">{pkg.vulnCount}</span>
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      {pkg.critCount > 0 ? (
                        <span className="font-mono text-xs font-semibold text-red-400">{pkg.critCount}</span>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      {pkg.highCount > 0 ? (
                        <span className="font-mono text-xs font-semibold text-orange-400">{pkg.highCount}</span>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-zinc-500">
                      {pkg.agents.slice(0, 3).join(", ")}
                      {pkg.agents.length > 3 && <span className="text-zinc-600"> +{pkg.agents.length - 3}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {topPackages.length > 10 && (
            <p className="text-xs text-zinc-600 text-right mt-1">
              Showing 10 of {topPackages.length} — <Link href="/findings" className="text-emerald-500 hover:text-emerald-400">view all</Link>
            </p>
          )}
        </section>
      )}

      {/* Blast radius highlights */}
      {(!isLoading) && allBlast.length > 0 && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Highest risk findings
            </h2>
            <Link href="/findings" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-2">
            {[...allBlast]
              .sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score))
              .slice(0, 5)
              .map((b) => (
                <BlastCard
                  key={b.vulnerability_id}
                  blast={b}
                  detailHref={`/findings?cve=${b.vulnerability_id}`}
                />
              ))}
          </div>
        </section>
      )}

      {/* Recent scans + Activity feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <section className="lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest">
              Recent scans
            </h2>
            {effectiveRecentJobs.length > 8 && (
              <Link href="/jobs" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </Link>
            )}
          </div>
          {jobsLoading && !importedReport ? (
            <div className="text-zinc-500 text-sm">Loading...</div>
          ) : effectiveRecentJobs.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="space-y-2">
              {effectiveRecentJobs.slice(0, 8).map((job) => (
                <JobRow key={job.job_id} job={job} />
              ))}
            </div>
          )}
        </section>

        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-widest mb-3">
            Activity
          </h2>
          <ActivityFeed maxItems={15} initialJobs={effectiveRecentJobs.slice(0, 20)} refresh={false} />
        </section>
      </div>
    </div>
  );
}

// ─── Components ───────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  href,
  trend,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  color: "emerald" | "blue" | "orange" | "red" | "zinc";
  href?: string;
  trend?: { direction: "up" | "down" | "flat"; label: string };
}) {
  // Architecture diagram colors as top borders
  const colors = {
    emerald: { text: "text-emerald-400", glow: "shadow-emerald-500/5", accent: "bg-emerald-500", topBorder: "#3fb950" },
    blue:    { text: "text-blue-400",    glow: "shadow-blue-500/5",    accent: "bg-blue-500",    topBorder: "#58a6ff" },
    orange:  { text: "text-orange-400",  glow: "shadow-orange-500/5",  accent: "bg-orange-500",  topBorder: "#d29922" },
    red:     { text: "text-red-400",     glow: "shadow-red-500/5",     accent: "bg-red-500",     topBorder: "#f85149" },
    zinc:    { text: "text-zinc-400",    glow: "shadow-zinc-500/5",    accent: "bg-zinc-500",    topBorder: "#52525b" },
  };
  const c = colors[color];
  const inner = (
    <div
      className={`rounded-xl border p-4 ${href ? "cursor-pointer transition-all hover:border-[var(--border-strong)]" : ""} shadow-lg ${c.glow}`}
      style={{
        backgroundColor: "var(--surface)",
        borderColor: "var(--border-subtle)",
        borderTop: `2px solid ${c.topBorder}`,
        boxShadow: "0 18px 36px -24px var(--shadow-color)",
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <Icon className={`w-4 h-4 ${c.text}`} />
        {trend && (
          <span className={`text-[10px] font-medium ${
            trend.direction === "down" ? "text-emerald-400" : trend.direction === "up" ? "text-red-400" : "text-[var(--text-tertiary)]"
          }`}>
            {trend.direction === "up" ? "\u2191" : trend.direction === "down" ? "\u2193" : "\u2022"} {trend.label}
          </span>
        )}
      </div>
      <div className="text-2xl font-bold font-mono tracking-tight">{value}</div>
      <div className="flex items-center justify-between mt-1">
        <div className="text-xs text-[var(--text-tertiary)]">{label}</div>
        <div className={`w-8 h-1 rounded-full ${c.accent} opacity-30`} />
      </div>
    </div>
  );
  if (href) return <Link href={href}>{inner}</Link>;
  return inner;
}

function SeverityChart({ severity }: { severity: SeverityCounts }) {
  const total = severity.total || 1;
  const bars = [
    { label: "Critical", count: severity.critical, color: "bg-red-500", text: "text-red-400", ring: "ring-red-500/20" },
    { label: "High", count: severity.high, color: "bg-orange-500", text: "text-orange-400", ring: "ring-orange-500/20" },
    { label: "Medium", count: severity.medium, color: "bg-yellow-500", text: "text-yellow-400", ring: "ring-yellow-500/20" },
    { label: "Low", count: severity.low, color: "bg-blue-500", text: "text-blue-400", ring: "ring-blue-500/20" },
  ];

  return (
    <div
      className="rounded-xl border p-5 shadow-lg"
      style={{
        backgroundColor: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "0 18px 36px -24px var(--shadow-color)",
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-zinc-300">Severity Distribution</h3>
        <span className="text-xs font-mono text-[var(--text-tertiary)]">{total} total</span>
      </div>

      {/* Stacked bar */}
      <div className="mb-5 flex h-3 overflow-hidden rounded-full bg-[var(--surface-muted)]">
        {bars?.map((b) =>
          b.count > 0 ? (
            <Link
              key={b.label}
              href={`/findings?severity=${b.label.toLowerCase()}`}
              className={`${b.color} transition-all duration-500 hover:brightness-125`}
              style={{ width: `${(b.count / total) * 100}%` }}
              title={`${b.label}: ${b.count}`}
            />
          ) : null
        )}
      </div>

      {/* Legend with hover rings */}
      <div className="grid grid-cols-4 gap-2">
        {bars?.map((b) => (
          <Link key={b.label} href={`/findings?severity=${b.label.toLowerCase()}`} className={`rounded-lg py-2 text-center transition-all hover:bg-[var(--surface-muted)] hover:ring-1 ${b.ring}`}>
            <div className={`text-xl font-bold font-mono ${b.text}`}>{b.count}</div>
            <div className="text-[10px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">{b.label}</div>
            <div className="text-[10px] font-mono text-[var(--text-tertiary)]">{total > 0 ? Math.round((b.count / total) * 100) : 0}%</div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function SourceBreakdown({ sources }: { sources: ScanSource[] }) {
  return (
    <div
      className="rounded-xl border p-5 shadow-lg"
      style={{
        backgroundColor: "var(--surface)",
        borderColor: "var(--border-subtle)",
        boxShadow: "0 18px 36px -24px var(--shadow-color)",
      }}
    >
      <h3 className="text-sm font-semibold text-zinc-300 mb-4">Scan Sources</h3>
      {sources.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">No completed scans yet.</p>
      ) : (
        <div className="space-y-3">
          {sources?.map((s) => (
            <div
              key={s.label}
              className="flex items-center gap-3 rounded-lg border px-3 py-2.5"
              style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
            >
              <s.icon className="h-4 w-4 flex-shrink-0 text-[var(--text-secondary)]" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-200">{s.label}</span>
                  <span className="text-xs font-mono text-[var(--text-secondary)]">{s.count} scanned</span>
                </div>
                <div className="mt-0.5 flex items-center gap-3 text-xs text-[var(--text-tertiary)]">
                  <span>{s.vulns} findings</span>
                  {s.critical > 0 && (
                    <span className="text-red-400 font-semibold">{s.critical} critical</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlastCard({ blast, detailHref }: { blast: BlastRadius; detailHref: string }) {
  return (
    <div className="flex items-start gap-4 bg-zinc-900 border border-zinc-800 rounded-xl p-4 transition-colors hover:border-zinc-700">
      <SeverityBadge severity={blast.severity} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Link
            href={detailHref}
            className="font-mono text-sm font-semibold text-zinc-100 hover:text-emerald-400"
          >
            {blast.vulnerability_id}
          </Link>
          <a
            href={`https://osv.dev/vulnerability/${blast.vulnerability_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] font-medium text-zinc-400 transition-colors hover:border-zinc-600 hover:text-zinc-200"
          >
            OSV
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
        <div className="flex flex-wrap gap-3 mt-1.5 text-xs text-zinc-500">
          <span>{blast.affected_agents.length} agent{blast.affected_agents.length !== 1 ? "s" : ""}</span>
          {blast.exposed_credentials.length > 0 && (
            <span className="text-orange-400">{blast.exposed_credentials.length} credential{blast.exposed_credentials.length !== 1 ? "s" : ""}</span>
          )}
          <span>{(blast.exposed_tools ?? blast.reachable_tools).length} tool{(blast.exposed_tools ?? blast.reachable_tools).length !== 1 ? "s" : ""}</span>
          {(blast.is_kev ?? blast.cisa_kev) && <span className="text-red-400 font-semibold">CISA KEV</span>}
          {blast.cvss_score != null && <span>CVSS {blast.cvss_score.toFixed(1)}</span>}
          {blast.epss_score != null && <span>EPSS {(blast.epss_score * 100).toFixed(0)}%</span>}
        </div>
        {((blast.owasp_tags && blast.owasp_tags.length > 0) || (blast.atlas_tags && blast.atlas_tags.length > 0)) && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {blast.owasp_tags?.map((tag) => (
              <span key={tag} title={OWASP_LLM_TOP10[tag] ?? tag} className="text-xs font-mono bg-purple-950 border border-purple-800 text-purple-400 rounded px-1 py-0.5 cursor-help">{tag}</span>
            ))}
            {blast.atlas_tags?.map((tag) => (
              <span key={tag} title={MITRE_ATLAS[tag] ?? tag} className="text-xs font-mono bg-cyan-950 border border-cyan-800 text-cyan-400 rounded px-1 py-0.5 cursor-help">{tag}</span>
            ))}
          </div>
        )}
        {blast.attack_vector_summary && (
          <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-400">{blast.attack_vector_summary}</p>
        )}
      </div>
      <div className="flex flex-col items-end gap-2">
        {(blast.risk_score ?? blast.blast_score) > 0 && (
          <div className="text-right">
            <div className="text-lg font-bold font-mono text-red-400">{(blast.risk_score ?? blast.blast_score).toFixed(0)}</div>
            <div className="text-xs text-zinc-600">score</div>
          </div>
        )}
        <Link
          href={detailHref}
          className="text-xs font-medium text-emerald-400 transition-colors hover:text-emerald-300"
        >
          Review evidence
        </Link>
      </div>
    </div>
  );
}

function JobRow({ job }: { job: JobListItem }) {
  const statusColors: Record<string, string> = {
    done: "bg-emerald-500",
    failed: "bg-red-500",
    running: "bg-yellow-500 animate-pulse",
    pending: "bg-zinc-500",
    cancelled: "bg-zinc-600",
  };
  const vulnCount = job.summary?.total_vulnerabilities ?? 0;
  const critCount = job.summary?.critical_findings ?? 0;

  // Detect scan source tags
  const tags: string[] = [];
  if (job.request?.images && job.request.images.length > 0) tags.push(`${job.request.images.length} image${job.request.images.length > 1 ? "s" : ""}`);
  if (job.request?.k8s) tags.push("k8s");
  if (job.request?.sbom) tags.push("sbom");
  if (job.request?.inventory) tags.push("inventory");
  if (tags.length === 0 && job.status === "done") tags.push("agents");

  return (
    <Link
      href={`/scan?id=${job.job_id}`}
      className="flex items-center gap-4 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 rounded-xl p-4 transition-colors group"
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColors[job.status] ?? "bg-zinc-500"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-zinc-400">{job.job_id.slice(0, 8)}…</span>
          {tags?.map((t) => (
            <span key={t} className="text-xs bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-500">{t}</span>
          ))}
        </div>
        <div className="text-xs text-zinc-600 flex items-center gap-1 mt-0.5">
          <Clock className="w-3 h-3" />
          {formatDate(job.created_at)}
        </div>
      </div>
      <div className="flex items-center gap-3 text-xs">
        {job.status === "done" && (
          <>
            {critCount > 0 && (
              <span className="text-red-400 font-mono font-semibold">{critCount} CRIT</span>
            )}
            {vulnCount > 0 && (
              <span className="text-zinc-400">{vulnCount} vuln{vulnCount !== 1 ? "s" : ""}</span>
            )}
          </>
        )}
        {job.status === "failed" && (
          <span className="text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Failed
          </span>
        )}
        {job.status === "running" && (
          <span className="text-yellow-400">Running…</span>
        )}
      </div>
      <ArrowRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-400 transition-colors flex-shrink-0" />
    </Link>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
      <ShieldAlert className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
      <p className="text-zinc-500 text-sm">No scans yet.</p>
      <Link
        href="/scan"
        className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors"
      >
        Run your first scan
        <ArrowRight className="w-3.5 h-3.5" />
      </Link>
    </div>
  );
}

function CompoundIssueCard({ issue }: { issue: CompoundIssue }) {
  const isCrit = issue.severity === "critical";
  const borderColor = isCrit ? "border-red-900" : "border-orange-900/60";
  const badgeColor = isCrit
    ? "bg-red-950 border border-red-800 text-red-400"
    : "bg-orange-950 border border-orange-800 text-orange-400";
  const countColor = isCrit ? "text-red-400" : "text-orange-400";

  return (
    <Link href={`/findings?${issue.filter}`}>
      <div
        className={`bg-zinc-900 border ${borderColor} rounded-xl p-4 hover:bg-zinc-800/80 transition-colors cursor-pointer`}
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <AlertTriangle
              className={`w-4 h-4 shrink-0 ${isCrit ? "text-red-400" : "text-orange-400"}`}
            />
            <span className="text-sm font-semibold text-zinc-200 leading-tight">
              {issue.title}
            </span>
          </div>
          <span className={`text-xs font-mono font-bold ${countColor} shrink-0`}>
            {issue.count}
          </span>
        </div>
        <p className="text-xs text-zinc-500 leading-relaxed mb-3">
          {issue.description}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {issue.findings.slice(0, 4).map((f) => (
            <span
              key={f.vulnerability_id}
              className={`text-[10px] font-mono rounded px-1.5 py-0.5 ${badgeColor}`}
            >
              {f.vulnerability_id}
              {(f.is_kev ?? f.cisa_kev) && " ⚡"}
            </span>
          ))}
          {issue.findings.length > 4 && (
            <span className="text-[10px] text-zinc-600 font-mono px-1 py-0.5">
              +{issue.findings.length - 4} more
            </span>
          )}
        </div>
      </div>
    </Link>
  );
}
