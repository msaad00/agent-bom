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
  type PostureCountsResponse,
} from "@/lib/api";
import { TrustStackSignals } from "@/components/trust-stack";
import { ActivityFeed } from "@/components/activity-feed";
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
    <div className="space-y-5">
      <ScorecardStrip
        posture={posture ?? (overview ? { grade: overview.posture.grade, score: overview.posture.score, summary: overview.posture.summary, dimensions: {} } : null)}
        overview={overview}
        critical={criticalCount}
        high={highCount}
        counts={counts}
        summaryReady={summaryReady}
        scanCount={summaryReady ? (counts?.scan_count ?? effectiveRecentJobs.length) : null}
        latestScanLabel={
          summaryReady && effectiveRecentJobs[0]?.created_at
            ? formatDate(effectiveRecentJobs[0].created_at)
            : null
        }
        jobsReady={!jobsLoading}
      />

      <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold tracking-tight text-[color:var(--foreground)]">Overview</h1>
            <p className="mt-0.5 text-sm text-[color:var(--text-secondary)]">
              {(displayedAgentCount ?? "—")} agents · {summaryReady ? displayedPackages : "—"} packages · {summaryReady ? displayedUniqueCVEs : "—"} CVEs
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
              <MetricChip label="KEV" value={String(summaryReady ? displayedKevCount : 0)} tone="red" />
              <MetricChip label="Credentials" value={String(summaryReady ? displayedCredentialExposure : 0)} tone="amber" />
              <MetricChip label="Tools" value={String(summaryReady ? displayedReachableTools : 0)} tone="sky" />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500">
              Run scan <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/security-graph" className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-1.5 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]">
              Security graph <GitBranch className="h-4 w-4" />
            </Link>
          </div>
        </div>

        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
          {topExposurePath ? (
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.06] p-3">
              <div className="mb-1.5 flex items-center justify-between gap-2">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-600 dark:text-emerald-300">Top path</p>
                <span className="rounded-full border border-red-500/25 bg-red-500/10 px-2 py-0.5 font-mono text-xs text-[color:var(--foreground)]">
                  {topExposurePath.riskScore.toFixed(1)}
                </span>
              </div>
              <AttackPathCard nodes={topExposurePath.nodes} riskScore={topExposurePath.riskScore} href={topExposurePath.href} captureMode compact />
            </div>
          ) : (
            <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 text-sm text-[color:var(--text-secondary)]">
              No scored exposure path yet. Run a scan to populate attack-path evidence.
            </div>
          )}
          <div className="grid grid-cols-3 gap-2">
            <QuickLink href="/findings?severity=critical" label="Critical" value={String(severity.critical)} />
            <QuickLink href="/security-graph" label="Identity" value={String(credentialExposureCount || estateSummary.credentialedServers)} />
            <QuickLink href="/agents" label="Services" value={String(impactedAgentCount || estateSummary.servers || (displayedAgentCount ?? 0))} />
          </div>
        </div>
      </section>

      {/* Top exposure paths — the fix-first shortlist, kept above the fold. */}
      {(!isLoading) && allBlast.length > 0 && (
        <details className="group/attack rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 select-none">
            <div className="flex items-center gap-2">
              <ChevronRight className="h-4 w-4 text-[color:var(--text-tertiary)] transition-transform group-open/attack:rotate-90" />
              <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Exposure paths</h2>
              <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 font-mono text-[10px] text-[color:var(--text-secondary)]">
                {Math.min(allBlast.length, 5)}
              </span>
            </div>
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
      <details className="group/metrics rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3">
        <summary className="flex cursor-pointer list-none items-center gap-2 select-none">
          <ChevronRight className="h-4 w-4 text-[color:var(--text-tertiary)] transition-transform group-open/metrics:rotate-90" />
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">Exposure KPIs</h2>
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
        <div className="mb-4 inline-flex rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-1">
          <TabButton icon={LayoutGrid} label="Overview" active={activeTab === "command"} onClick={() => setActiveTab("command")} />
          <TabButton icon={BarChart3} label="Analytics" active={activeTab === "analytics"} onClick={() => setActiveTab("analytics")} />
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

function MetricChip({ label, value, tone }: { label: string; value: string; tone: "red" | "amber" | "sky" }) {
  const toneClass =
    tone === "red"
      ? "border-red-500/20 bg-red-500/10 text-[color:var(--foreground)]"
      : tone === "amber"
        ? "border-amber-500/20 bg-amber-500/10 text-[color:var(--foreground)]"
        : "border-sky-500/20 bg-sky-500/10 text-[color:var(--foreground)]";
  return (
    <span className={`rounded-lg border px-2.5 py-1 font-mono text-xs ${toneClass}`}>
      {label} {value}
    </span>
  );
}

function QuickLink({ href, label, value }: { href: string; label: string; value: string }) {
  return (
    <Link href={href} className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-2.5 text-center transition hover:border-[color:var(--border-strong)]">
      <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</p>
      <p className="mt-0.5 font-mono text-lg font-semibold text-[color:var(--foreground)]">{value}</p>
    </Link>
  );
}

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
      className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
        active
          ? "bg-[color:var(--surface-elevated)] text-[color:var(--foreground)]"
          : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
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

function countActiveServices(services: PostureCountsResponse["services"]): number {
  if (!services) return 0;
  return Object.values(services).filter((entry) => entry.state === "live" || entry.state === "connected").length;
}

function ScorecardStrip({
  posture,
  overview,
  critical,
  high,
  counts,
  summaryReady,
  scanCount,
  latestScanLabel,
  jobsReady,
}: {
  posture: PostureResponse | null;
  overview: OverviewResponse | null;
  critical: number;
  high: number;
  counts: ReturnType<typeof useDeploymentContext>["counts"];
  summaryReady: boolean;
  scanCount: number | null;
  latestScanLabel: string | null;
  jobsReady: boolean;
}) {
  const domains = overview ? Object.values(overview.domains) : [];
  const activeDomains = domains.filter((d) => d.status !== "idle").length;
  const coverage = domains.length > 0 ? Math.round((activeDomains / domains.length) * 100) : null;
  const connected = hasDeploymentSignals(counts);
  const grade = posture?.grade ?? "—";
  const score = posture?.score;
  const activeServices = countActiveServices(counts?.services);

  return (
    <section className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.06] px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Grade</p>
          <div className="flex items-end gap-2">
            <span className="font-mono text-xl font-semibold text-[color:var(--foreground)]">{grade}</span>
            {typeof score === "number" && (
              <span className="mb-0.5 font-mono text-[10px] text-[color:var(--text-tertiary)]">{score}</span>
            )}
          </div>
        </div>

        <Link href="/findings?severity=critical" className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 transition-colors hover:border-red-400/40">
          <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Critical</p>
          <p className="font-mono text-xl font-semibold text-[color:var(--foreground)]">{summaryReady ? critical : "—"}</p>
        </Link>

        <Link href="/findings?severity=high" className="rounded-lg border border-orange-500/20 bg-orange-500/10 px-3 py-2 transition-colors hover:border-orange-400/40">
          <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">High</p>
          <p className="font-mono text-xl font-semibold text-[color:var(--foreground)]">{summaryReady ? high : "—"}</p>
        </Link>

        <div className="rounded-lg border border-sky-500/20 bg-sky-500/10 px-3 py-2">
          <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Coverage</p>
          <p className="font-mono text-xl font-semibold text-[color:var(--foreground)]">{coverage != null ? `${coverage}%` : "—"}</p>
          <p className="text-[10px] text-[color:var(--text-tertiary)]">{activeDomains}/{domains.length || 5} domains</p>
        </div>

        <Link href="/connections" className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 transition-colors hover:border-[color:var(--border-strong)]">
          <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">Connect</p>
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-500" : "bg-amber-500"}`} />
            <span className="text-sm font-semibold text-[color:var(--foreground)]">{connected ? "Live" : "Setup"}</span>
          </div>
          <p className="text-[10px] text-[color:var(--text-tertiary)]">{deploymentModeLabel(counts?.deployment_mode)}</p>
        </Link>
      </div>

      <div className="mt-2 grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
        <Link
          href="/jobs"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition-colors hover:border-[color:var(--border-strong)]"
        >
          <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Scans</p>
          <p className="font-mono text-sm font-semibold text-[color:var(--foreground)]">
            {summaryReady && scanCount != null ? scanCount : "—"}
          </p>
        </Link>
        <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2">
          <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Latest scan</p>
          <p className="truncate text-sm font-medium text-[color:var(--foreground)]">
            {!jobsReady ? "…" : latestScanLabel ?? "—"}
          </p>
        </div>
        <Link
          href="/connections"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition-colors hover:border-[color:var(--border-strong)]"
        >
          <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Active services</p>
          <p className="font-mono text-sm font-semibold text-[color:var(--foreground)]">
            {summaryReady ? activeServices : "—"}
          </p>
        </Link>
        <Link
          href="/activity"
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition-colors hover:border-[color:var(--border-strong)]"
        >
          <p className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Deployment</p>
          <p className="truncate text-sm font-medium text-[color:var(--foreground)]">
            {deploymentModeLabel(counts?.deployment_mode)}
          </p>
          <p className="text-[10px] text-[color:var(--text-tertiary)]">{connected ? "signals detected" : "awaiting first scan"}</p>
        </Link>
      </div>

      {/* Cross-domain tiles folded in from the former /overview landing page. */}
      {domains.length > 0 && (
        <div className="mt-2 grid gap-1.5 sm:grid-cols-3 lg:grid-cols-5">
          {domains.map((domain) => {
            const tone = statusTone(domain.status);
            return (
              <Link
                key={domain.href}
                href={domain.graph_href ?? domain.href}
                className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-2 transition-colors hover:border-[color:var(--border-strong)]"
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-[color:var(--foreground)]">{domain.label}</p>
                  <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{domain.metric_label}</p>
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
