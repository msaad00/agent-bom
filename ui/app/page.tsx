"use client";

import { useEffect, useState, useMemo } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import {
  api,
  ScanJob,
  ScanResult,
  Agent,
  JobListItem,
  PostureResponse,
  OverviewResponse,
  OverviewDomain,
  formatDate,
} from "@/lib/api";
import { TrustStackSignals } from "@/components/trust-stack";
import { ActivityFeed } from "@/components/activity-feed";
import { PostureGrade } from "@/components/posture-grade";
import { AttackPathCard } from "@/components/attack-path-card";
import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { deploymentModeLabel, hasDeploymentSignals } from "@/lib/deployment-context";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { buildSecurityGraphHref } from "@/lib/attack-paths";
import {
  aggregateCompoundIssues,
  aggregateEpss,
  aggregateEpssVsCvss,
  aggregateEstate,
  aggregatePackages,
  aggregateSeverity,
  aggregateSources,
  aggregateTrend,
  blastAgents,
  blastCredentials,
  blastTools,
} from "@/lib/dashboard-data";
import {
  ShieldAlert, Server, Package, Bug, Zap, ArrowRight, Clock,
  AlertTriangle, Layers, GitBranch, ChevronRight, BarChart3, LayoutGrid,
} from "lucide-react";

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

// Heavy, below-the-fold charts + tables. Loaded lazily (client-only) so recharts
// and the long tables stay out of the home route's first-paint bundle.
const DashboardAnalytics = dynamic(() => import("@/components/dashboard-analytics"), {
  ssr: false,
  loading: () => (
    <div className="rounded-[28px] border border-zinc-800/90 bg-zinc-950/60 p-8 text-center text-sm text-zinc-500">
      Loading analytics…
    </div>
  ),
});

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
  // Differentiate "API down" from "API rejected my request" (#2196 audit fix).
  // 401 -> "auth", 403 -> "forbidden", network/5xx -> "network".
  const [apiErrorKind, setApiErrorKind] = useState<"network" | "auth" | "forbidden">("network");
  const [apiErrorDetail, setApiErrorDetail] = useState<string | null>(null);
  const [importedReport, setImportedReport] = useState<ScanResult | null>(null);
  const [posture, setPosture] = useState<PostureResponse | null>(null);
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [activeTab, setActiveTab] = useState<"command" | "analytics">("command");
  const { counts } = useDeploymentContext();
  const captureMode = useCaptureMode();
  const seededEvidence = captureMode || Boolean(counts?.scan_sources?.some((source) => source.includes("demo")));

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("tab") === "analytics") {
      setActiveTab("analytics");
    }
  }, []);

  // Fetch posture grade + cross-domain overview (folded into the header scorecard)
  useEffect(() => {
    api.getPosture().then(setPosture).catch(() => {});
    api.getOverview().then(setOverview).catch(() => {});
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
      } catch (err) {
        if (cancelled) return;
        setApiError(true);
        setApiErrorKind(_classifyApiErrorKind(err));
        setApiErrorDetail(err instanceof Error ? err.message : null);
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
    const importedGeneratedAt = importedReport.scan_timestamp ?? importedReport.generated_at ?? new Date().toISOString();
    return [{
      job_id: "imported",
      status: "done",
      created_at: importedGeneratedAt,
      request: {} as ScanJob["request"],
      progress: [],
      result: importedReport as unknown as Record<string, unknown>,
    } as unknown as ScanJob];
  }, [detailJobs, apiError, importedReport]);

  const effectiveRecentJobs = useMemo<JobListItem[]>(() => {
    if (!apiError || !importedReport) return jobs;
    const importedGeneratedAt = importedReport.scan_timestamp ?? importedReport.generated_at ?? new Date().toISOString();
    return [{
      job_id: "imported",
      status: "done",
      created_at: importedGeneratedAt,
      request: {},
      summary: importedReport.summary,
      scan_timestamp: importedReport.scan_timestamp ?? importedGeneratedAt,
      generated_at: importedReport.generated_at ?? importedGeneratedAt,
      scan_run: importedReport.scan_run,
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
  const credentialExposureCount = useMemo(() => allBlast.filter((b) => blastCredentials(b).length > 0).length, [allBlast]);
  const reachableToolCount = useMemo(() => new Set(allBlast.flatMap(blastTools)).size, [allBlast]);
  const impactedAgentCount = useMemo(() => new Set(allBlast.flatMap(blastAgents)).size, [allBlast]);
  const estateSummary = useMemo(() => aggregateEstate(agentList), [agentList]);

  // Real signals feeding the AI trust stack — data sources connected (L1),
  // governance/context surfaces populated (L2), tools scanned (L3), and
  // supply-chain packages covered (L4). Counts come straight from scan output
  // and discovered agents so the stack reflects evidence, not a fixed label.
  const trustSignals = useMemo<TrustStackSignals>(() => {
    const pkgs = new Set<string>();
    for (const job of effectiveJobs) {
      if (job.status !== "done" || !job.result) continue;
      const result = job.result as ScanResult;
      for (const agent of result.agents) {
        for (const srv of agent.mcp_servers) {
          for (const pkg of srv.packages) pkgs.add(`${pkg.name}@${pkg.version}`);
        }
      }
    }
    return {
      1: { count: sources.length },
      2: { count: estateSummary.servers },
      3: { count: estateSummary.tools },
      4: { count: pkgs.size },
    };
  }, [effectiveJobs, sources.length, estateSummary.servers, estateSummary.tools]);

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
  const topExposurePath = useMemo(() => {
    if (!topRisk) return null;
    const agents = blastAgents(topRisk);
    const credentials = blastCredentials(topRisk);
    const nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[] = [
      { type: "cve", label: topRisk.vulnerability_id, severity: topRisk.severity?.toLowerCase() },
    ];
    if (topRisk.package) nodes.push({ type: "package", label: topRisk.package });
    if (topRisk.affected_servers && topRisk.affected_servers.length > 0) nodes.push({ type: "server", label: topRisk.affected_servers[0]! });
    if (agents.length > 0) nodes.push({ type: "agent", label: agents[0]! });
    if (credentials.length > 0) nodes.push({ type: "credential", label: credentials[0]! });
    return {
      nodes,
      riskScore: topRisk.risk_score ?? topRisk.blast_score / 10,
      href: buildSecurityGraphHref({
        cve: topRisk.vulnerability_id,
        packageName: topRisk.package,
        agentName: agents[0],
      }),
    };
  }, [topRisk]);

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

  const criticalCount = detailsReady
    ? (severity.critical || (seededEvidence ? (overview?.headline.critical ?? counts?.critical ?? summaryStats?.critical_findings ?? 0) : severity.critical))
    : (overview?.headline.critical ?? summaryStats?.critical_findings ?? counts?.critical ?? 0);
  const highCount = detailsReady
    ? (severity.high || (seededEvidence ? (overview?.headline.high ?? counts?.high ?? summaryStats?.high_findings ?? 0) : severity.high))
    : (overview?.headline.high ?? summaryStats?.high_findings ?? counts?.high ?? 0);
  const fallbackVulnTotal = overview?.headline.critical_high ?? counts?.total ?? summaryStats?.total_vulnerabilities ?? 0;
  const displayedUniqueCVEs = detailsReady
    ? (uniqueCVEs > 0 ? uniqueCVEs : (seededEvidence ? fallbackVulnTotal : uniqueCVEs))
    : (summaryStats?.total_vulnerabilities ?? fallbackVulnTotal);
  const displayedKevCount = detailsReady
    ? (kevCount > 0 ? kevCount : (seededEvidence ? (overview?.headline.kev ?? counts?.kev ?? 0) : kevCount))
    : (overview?.headline.kev ?? counts?.kev ?? 0);
  const displayedCredentialExposure = detailsReady
    ? (credentialExposureCount > 0 ? credentialExposureCount : (seededEvidence ? (overview?.headline.credential_exposed ?? 0) : credentialExposureCount))
    : (overview?.headline.credential_exposed ?? 0);
  const displayedReachableTools = detailsReady
    ? (reachableToolCount > 0 ? reachableToolCount : (seededEvidence ? estateSummary.tools : reachableToolCount))
    : estateSummary.tools;
  const displayedPackages = detailsReady
    ? (totalPackages > 0 ? totalPackages : (seededEvidence ? (summaryStats?.total_packages ?? 0) : totalPackages))
    : (summaryStats?.total_packages ?? 0);

  if (apiError && !importedReport) return <ApiOfflineState onImport={setImportedReport} kind={apiErrorKind} detail={apiErrorDetail} />;

  return (
    <div className="space-y-8">
      {/* Scorecard strip — one posture grade + risk score, critical/high, coverage,
          connect status. Folds the former /overview domain tiles into the home
          header so `/` opens above the fold with a single command surface. */}
      <ScorecardStrip
        posture={posture ?? (overview ? { grade: overview.posture.grade, score: overview.posture.score, summary: overview.posture.summary, dimensions: {} } : null)}
        overview={overview}
        critical={criticalCount}
        high={highCount}
        counts={counts}
        summaryReady={summaryReady}
      />

      <section className="relative overflow-hidden rounded-[28px] border border-zinc-800/80 bg-[radial-gradient(circle_at_top_left,rgba(16,185,129,0.16),transparent_24%),radial-gradient(circle_at_top_right,rgba(239,68,68,0.12),transparent_24%),linear-gradient(180deg,rgba(24,24,27,0.98),rgba(9,9,11,0.96))] p-6 shadow-2xl shadow-black/20">
        <div className="flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-3xl">
            <p className="text-[11px] uppercase tracking-[0.24em] text-emerald-400">Solution overview</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-50 sm:text-4xl">
              Exposure command center
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-300">
              Prioritized AI/MCP exposure paths, active services, credentials, packages, and response work across {effectiveRecentJobs.length} scan{effectiveRecentJobs.length !== 1 ? "s" : ""}, {(displayedAgentCount ?? "—")} agent{displayedAgentCount === 1 ? "" : "s"}, {summaryReady ? displayedPackages : (summaryStats?.total_packages ?? 0)} packages, and {summaryReady ? displayedUniqueCVEs : (summaryStats?.total_vulnerabilities ?? fallbackVulnTotal)} CVEs.
            </p>
            <p className="mt-5 text-[10px] font-semibold uppercase tracking-[0.22em] text-zinc-500">
              Active exposure
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <div className="rounded-2xl border border-red-500/20 bg-red-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-red-200/70">Actively exploited</div>
                <div className="mt-1 font-mono text-lg font-semibold text-red-100">{summaryReady ? displayedKevCount : 0}</div>
              </div>
              <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-amber-200/70">Credential exposed</div>
                <div className="mt-1 font-mono text-lg font-semibold text-amber-100">{summaryReady ? displayedCredentialExposure : 0}</div>
              </div>
              <div className="rounded-2xl border border-sky-500/20 bg-sky-500/10 px-3 py-2">
                <div className="text-[10px] uppercase tracking-[0.18em] text-sky-200/70">Reachable tools</div>
                <div className="mt-1 font-mono text-lg font-semibold text-sky-100">{summaryReady ? displayedReachableTools : 0}</div>
              </div>
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
              href="/security-graph"
              className="flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900/80 px-4 py-2.5 text-sm font-medium text-zinc-200 transition-colors hover:border-zinc-500 hover:bg-zinc-800"
            >
              Open graph
              <GitBranch className="h-4 w-4" />
            </Link>
          </div>
        </div>

        <div className="mt-6 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
          {topExposurePath ? (
            <div className="rounded-3xl border border-emerald-500/20 bg-emerald-500/[0.06] p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-emerald-300">Highest priority path</p>
                  <p className="mt-1 text-sm text-zinc-400">
                    Start here: this chain connects a finding to the agent/runtime surface that can exercise it.
                  </p>
                </div>
                <span className="rounded-full border border-red-500/25 bg-red-500/10 px-3 py-1 font-mono text-xs font-semibold text-red-200">
                  Risk {topExposurePath.riskScore.toFixed(1)}
                </span>
              </div>
              <AttackPathCard nodes={topExposurePath.nodes} riskScore={topExposurePath.riskScore} href={topExposurePath.href} captureMode />
            </div>
          ) : (
            <div className="rounded-3xl border border-zinc-800 bg-zinc-950/70 p-4">
              <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-emerald-300">Estate map</p>
              <p className="mt-1 max-w-2xl text-sm leading-6 text-zinc-400">
                No scored exposure path is available yet. The overview stays grounded in discovered environments, agent services, credential boundaries, and scan coverage until findings produce evidence.
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Link href="/agents" className="rounded-2xl border border-sky-500/20 bg-sky-500/10 p-4 transition-colors hover:border-sky-400/40">
                  <p className="text-[10px] uppercase tracking-[0.2em] text-sky-200/70">Agents</p>
                  <p className="mt-2 font-mono text-2xl font-semibold text-sky-100">{agentsReady ? estateSummary.configuredAgents : "—"}</p>
                  <p className="mt-1 text-xs text-sky-100/60">configured clients</p>
                </Link>
                <Link href="/agents" className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 transition-colors hover:border-emerald-400/40">
                  <p className="text-[10px] uppercase tracking-[0.2em] text-emerald-200/70">Services</p>
                  <p className="mt-2 font-mono text-2xl font-semibold text-emerald-100">{agentsReady ? estateSummary.servers : "—"}</p>
                  <p className="mt-1 text-xs text-emerald-100/60">MCP servers</p>
                </Link>
                <Link href="/security-graph" className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4 transition-colors hover:border-amber-400/40">
                  <p className="text-[10px] uppercase tracking-[0.2em] text-amber-200/70">Identities</p>
                  <p className="mt-2 font-mono text-2xl font-semibold text-amber-100">{agentsReady ? estateSummary.credentialedServers : "—"}</p>
                  <p className="mt-1 text-xs text-amber-100/60">credentialed services</p>
                </Link>
                <Link href="/security-graph" className="rounded-2xl border border-fuchsia-500/20 bg-fuchsia-500/10 p-4 transition-colors hover:border-fuchsia-400/40">
                  <p className="text-[10px] uppercase tracking-[0.2em] text-fuchsia-200/70">Environments</p>
                  <p className="mt-2 font-mono text-2xl font-semibold text-fuchsia-100">{agentsReady ? estateSummary.environments : "—"}</p>
                  <p className="mt-1 text-xs text-fuchsia-100/60">observed scopes</p>
                </Link>
              </div>
            </div>
          )}
          <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-1">
            <Link href="/findings?severity=critical" className="rounded-2xl border border-red-500/20 bg-red-500/10 p-4 transition-colors hover:border-red-400/40">
              <p className="text-[10px] uppercase tracking-[0.2em] text-red-200/70">Fix queue</p>
              <p className="mt-2 font-mono text-2xl font-semibold text-red-100">{severity.critical}</p>
              <p className="mt-1 text-xs text-red-100/60">critical findings</p>
            </Link>
            <Link href="/security-graph" className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4 transition-colors hover:border-amber-400/40">
              <p className="text-[10px] uppercase tracking-[0.2em] text-amber-200/70">Identity paths</p>
              <p className="mt-2 font-mono text-2xl font-semibold text-amber-100">{credentialExposureCount || estateSummary.credentialedServers}</p>
              <p className="mt-1 text-xs text-amber-100/60">credential-linked services</p>
            </Link>
            <Link href="/agents" className="rounded-2xl border border-sky-500/20 bg-sky-500/10 p-4 transition-colors hover:border-sky-400/40">
              <p className="text-[10px] uppercase tracking-[0.2em] text-sky-200/70">Active services</p>
              <p className="mt-2 font-mono text-2xl font-semibold text-sky-100">{impactedAgentCount || estateSummary.servers || (displayedAgentCount ?? 0)}</p>
              <p className="mt-1 text-xs text-sky-100/60">agent-facing services</p>
            </Link>
          </div>
        </div>

        {posture && doneJobs.length > 0 && (
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

      {/* Top exposure paths — the fix-first shortlist, kept above the fold. */}
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
                    Exposure Paths
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
              .map((b, index) => {
                const nodes: { type: "cve" | "package" | "server" | "agent" | "credential"; label: string; severity?: string }[] = [
                  { type: "cve", label: b.vulnerability_id, severity: b.severity?.toLowerCase() },
                ];
                if (b.package) nodes.push({ type: "package", label: b.package });
                if (b.affected_servers && b.affected_servers.length > 0) nodes.push({ type: "server", label: b.affected_servers[0]! });
                const agents = blastAgents(b);
                const credentials = blastCredentials(b);
                if (agents.length > 0) nodes.push({ type: "agent", label: agents[0]! });
                if (credentials.length > 0) nodes.push({ type: "credential", label: credentials[0]! });
                return (
                  <AttackPathCard
                    key={`${b.vulnerability_id}:${b.package ?? "unknown"}:${index}`}
                    nodes={nodes}
                    riskScore={b.risk_score ?? b.blast_score / 10}
                    href={buildSecurityGraphHref({
                      cve: b.vulnerability_id,
                      packageName: b.package,
                      agentName: agents[0],
                    })}
                  />
                );
              })}
          </div>
        </details>
      )}

      {/* Exposure KPIs — coverage + backlog snapshot. */}
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
          <StatCard icon={Package} label="Packages" value={summaryReady ? String(displayedPackages) : "—"} color="orange" href="/findings" />
          <StatCard icon={Bug} label="Unique CVEs" value={summaryReady ? String(displayedUniqueCVEs) : "—"} color="red" href="/findings" />
          <StatCard icon={Zap} label="Critical" value={summaryReady ? String(detailsReady ? severity.critical : (summaryStats?.critical_findings ?? 0)) : "—"} color="red" href="/findings?severity=critical" />
        </div>
      </details>

      {/* Tabbed area: the command-center feed is the default; deep analytics
          (recharts + long tables) lives behind a tab so it never loads on first
          paint. */}
      <div>
        <div className="mb-4 inline-flex rounded-2xl border border-zinc-800 bg-zinc-950/70 p-1">
          <TabButton icon={LayoutGrid} label="Command center" active={activeTab === "command"} onClick={() => setActiveTab("command")} />
          <TabButton icon={BarChart3} label="Deep analytics" active={activeTab === "analytics"} onClick={() => setActiveTab("analytics")} />
        </div>

        {activeTab === "command" ? (
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
        ) : (
          <DashboardAnalytics
            severity={severity}
            sources={sources}
            trendData={trendData}
            epssData={epssData}
            scatterData={scatterData}
            compoundIssues={compoundIssues}
            agentList={agentList}
            trustSignals={trustSignals}
            topPackages={topPackages}
            allBlast={allBlast}
          />
        )}
      </div>
    </div>
  );
}

// ─── Components ───────────────────────────────────────────────────────────────

function TabButton({
  icon: Icon,
  label,
  active,
  onClick,
}: {
  icon: React.ElementType;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition-colors ${
        active
          ? "bg-zinc-800 text-zinc-100"
          : "text-zinc-500 hover:text-zinc-200"
      }`}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

function statusTone(status: OverviewDomain["status"]): { dot: string; text: string } {
  switch (status) {
    case "critical":
      return { dot: "bg-red-500", text: "text-red-300" };
    case "warn":
      return { dot: "bg-amber-500", text: "text-amber-300" };
    case "ok":
      return { dot: "bg-emerald-500", text: "text-emerald-300" };
    default:
      return { dot: "bg-zinc-600", text: "text-zinc-500" };
  }
}

function ScorecardStrip({
  posture,
  overview,
  critical,
  high,
  counts,
  summaryReady,
}: {
  posture: PostureResponse | null;
  overview: OverviewResponse | null;
  critical: number;
  high: number;
  counts: ReturnType<typeof useDeploymentContext>["counts"];
  summaryReady: boolean;
}) {
  const domains = overview ? Object.values(overview.domains) : [];
  const activeDomains = domains.filter((d) => d.status !== "idle").length;
  const coverage = domains.length > 0 ? Math.round((activeDomains / domains.length) * 100) : null;
  const connected = hasDeploymentSignals(counts);
  const grade = posture?.grade ?? "—";
  const score = posture?.score;

  return (
    <section className="rounded-[28px] border border-zinc-800/80 bg-zinc-950/60 p-5">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {/* Posture grade + score */}
        <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.06] p-4">
          <p className="text-[10px] uppercase tracking-[0.2em] text-emerald-200/70">Posture grade</p>
          <div className="mt-1 flex items-end gap-2">
            <span className="font-mono text-3xl font-semibold text-emerald-100">{grade}</span>
            {typeof score === "number" && (
              <span className="mb-1 font-mono text-xs text-emerald-200/70">score {score}</span>
            )}
          </div>
          <p className="mt-1 text-xs text-emerald-100/60">overall risk grade</p>
        </div>

        {/* Critical */}
        <Link href="/findings?severity=critical" className="rounded-2xl border border-red-500/20 bg-red-500/10 p-4 transition-colors hover:border-red-400/40">
          <p className="text-[10px] uppercase tracking-[0.2em] text-red-200/70">Critical</p>
          <p className="mt-1 font-mono text-3xl font-semibold text-red-100">{summaryReady ? critical : "—"}</p>
          <p className="mt-1 text-xs text-red-100/60">open critical findings</p>
        </Link>

        {/* High */}
        <Link href="/findings?severity=high" className="rounded-2xl border border-orange-500/20 bg-orange-500/10 p-4 transition-colors hover:border-orange-400/40">
          <p className="text-[10px] uppercase tracking-[0.2em] text-orange-200/70">High</p>
          <p className="mt-1 font-mono text-3xl font-semibold text-orange-100">{summaryReady ? high : "—"}</p>
          <p className="mt-1 text-xs text-orange-100/60">open high findings</p>
        </Link>

        {/* Coverage */}
        <div className="rounded-2xl border border-sky-500/20 bg-sky-500/10 p-4">
          <p className="text-[10px] uppercase tracking-[0.2em] text-sky-200/70">Coverage</p>
          <p className="mt-1 font-mono text-3xl font-semibold text-sky-100">{coverage != null ? `${coverage}%` : "—"}</p>
          <p className="mt-1 text-xs text-sky-100/60">{activeDomains}/{domains.length || 5} domains active</p>
        </div>

        {/* Connect status */}
        <Link href="/connections" className="rounded-2xl border border-zinc-700/60 bg-zinc-900/60 p-4 transition-colors hover:border-zinc-500">
          <p className="text-[10px] uppercase tracking-[0.2em] text-zinc-400">Connect status</p>
          <div className="mt-1 flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${connected ? "bg-emerald-500" : "bg-amber-500"}`} />
            <span className="text-lg font-semibold text-zinc-100">{connected ? "Connected" : "Not connected"}</span>
          </div>
          <p className="mt-1 text-xs text-zinc-500">{deploymentModeLabel(counts?.deployment_mode)} mode</p>
        </Link>
      </div>

      {/* Cross-domain tiles folded in from the former /overview landing page. */}
      {domains.length > 0 && (
        <div className="mt-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
          {domains.map((domain) => {
            const tone = statusTone(domain.status);
            return (
              <Link
                key={domain.href}
                href={domain.graph_href ?? domain.href}
                className="flex items-center justify-between gap-2 rounded-xl border border-zinc-800 bg-zinc-950/70 px-3 py-2.5 transition-colors hover:border-zinc-600"
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-zinc-300">{domain.label}</p>
                  <p className="truncate text-[10px] text-zinc-500">{domain.metric_label}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`font-mono text-sm font-semibold ${tone.text}`}>{domain.metric}</span>
                  <span className={`h-2 w-2 rounded-full ${tone.dot}`} />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </section>
  );
}

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
            {trend.direction === "up" ? "↑" : trend.direction === "down" ? "↓" : "•"} {trend.label}
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
