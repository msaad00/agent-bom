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
  ShieldAlert, ArrowRight, Clock,
  AlertTriangle, GitBranch, ChevronRight, BarChart3, LayoutGrid,
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

  const postureGrade = posture?.grade ?? overview?.posture.grade ?? "—";
  const postureScore = posture?.score ?? overview?.posture.score;
  const latestScanShort =
    summaryReady && effectiveRecentJobs[0]?.created_at
      ? formatShortScanTime(effectiveRecentJobs[0].created_at)
      : null;

  return (
    <div className="space-y-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Overview</h1>
          <p className="mt-1 text-sm text-[color:var(--text-secondary)]">
            Posture and exposure from the latest completed scan.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500"
          >
            Run scan <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            href="/security-graph"
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
          >
            Security graph <GitBranch className="h-4 w-4" />
          </Link>
        </div>
      </header>

      <OverviewSummaryBar
        grade={postureGrade}
        score={postureScore}
        critical={criticalCount}
        high={highCount}
        agents={displayedAgentCount}
        cves={summaryReady ? displayedUniqueCVEs : null}
        scans={summaryReady ? (counts?.scan_count ?? effectiveRecentJobs.length) : null}
        latestScan={jobsLoading ? null : latestScanShort}
        mode={deploymentModeLabel(counts?.deployment_mode)}
        summaryReady={summaryReady}
      />

      <section className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-[color:var(--foreground)]">Top exposure path</h2>
          {topExposurePath ? (
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-0.5 font-mono text-xs text-[color:var(--text-secondary)]">
              {topExposurePath.riskScore.toFixed(1)}
            </span>
          ) : null}
        </div>
        {topExposurePath ? (
          <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
            <AttackPathCard
              nodes={topExposurePath.nodes}
              riskScore={topExposurePath.riskScore}
              href={topExposurePath.href}
              captureMode
              compact
            />
          </div>
        ) : (
          <div className="rounded-xl border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
            No scored exposure path yet. Run a scan to populate attack-path evidence.
          </div>
        )}
      </section>

      <DomainSignalsPanel
        overview={overview}
        counts={counts}
        summaryReady={summaryReady}
        scanCount={summaryReady ? (counts?.scan_count ?? effectiveRecentJobs.length) : null}
        latestScanLabel={latestScanShort}
        kev={summaryReady ? displayedKevCount : null}
        credentials={summaryReady ? displayedCredentialExposure : null}
        tools={summaryReady ? displayedReachableTools : null}
        packages={summaryReady ? displayedPackages : null}
      />

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

      <div>
        <div className="mb-4 inline-flex rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-1">
          <TabButton icon={LayoutGrid} label="Feed" active={activeTab === "command"} onClick={() => setActiveTab("command")} />
          <TabButton icon={BarChart3} label="Analytics" active={activeTab === "analytics"} onClick={() => setActiveTab("analytics")} />
        </div>

        {activeTab === "command" ? (
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <section className="lg:col-span-2">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-sm font-medium text-[color:var(--foreground)]">Recent scans</h2>
                {effectiveRecentJobs.length > 8 && (
                  <Link href="/jobs" className="text-xs text-emerald-500 hover:text-emerald-400 flex items-center gap-1">
                    View all <ArrowRight className="w-3 h-3" />
                  </Link>
                )}
              </div>
              {jobsLoading && !importedReport ? (
                <div className="text-sm text-[color:var(--text-secondary)]">Loading…</div>
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
              <h2 className="mb-3 text-sm font-medium text-[color:var(--foreground)]">Activity</h2>
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

function formatShortScanTime(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "—";
  return parsed.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function OverviewSummaryBar({
  grade,
  score,
  critical,
  high,
  agents,
  cves,
  scans,
  latestScan,
  mode,
  summaryReady,
}: {
  grade: string;
  score?: number | undefined;
  critical: number;
  high: number;
  agents: number | null;
  cves: number | null;
  scans: number | null;
  latestScan: string | null;
  mode: string;
  summaryReady: boolean;
}) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-4 py-3">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-8">
        <SummaryMetric label="Posture" value={grade} sub={typeof score === "number" ? String(score) : undefined} />
        <SummaryMetric label="Critical" value={summaryReady ? String(critical) : "—"} href="/findings?severity=critical" tone="critical" />
        <SummaryMetric label="High" value={summaryReady ? String(high) : "—"} href="/findings?severity=high" tone="high" />
        <SummaryMetric label="Agents" value={summaryReady && agents != null ? String(agents) : "—"} href="/agents" />
        <SummaryMetric label="CVEs" value={summaryReady && cves != null ? String(cves) : "—"} href="/findings" />
        <SummaryMetric label="Scans" value={summaryReady && scans != null ? String(scans) : "—"} href="/jobs" />
        <SummaryMetric label="Last scan" value={latestScan ?? "—"} text />
        <SummaryMetric label="Mode" value={mode} text />
      </div>
    </div>
  );
}

function SummaryMetric({
  label,
  value,
  sub,
  href,
  tone,
  text,
}: {
  label: string;
  value: string;
  sub?: string | undefined;
  href?: string | undefined;
  tone?: "critical" | "high" | undefined;
  text?: boolean | undefined;
}) {
  const valueClass =
    tone === "critical"
      ? "text-red-500 dark:text-red-400"
      : tone === "high"
        ? "text-orange-500 dark:text-orange-400"
        : "text-[color:var(--foreground)]";

  const inner = (
    <div className="min-w-0">
      <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</p>
      <div className="mt-0.5 flex items-baseline gap-1.5">
        <p className={`truncate ${text ? "text-sm font-medium" : `font-mono text-lg font-semibold ${valueClass}`}`}>
          {value}
        </p>
        {sub ? <span className="font-mono text-[10px] text-[color:var(--text-tertiary)]">{sub}</span> : null}
      </div>
    </div>
  );

  if (href) {
    return (
      <Link href={href} className="rounded-lg transition-colors hover:bg-[color:var(--surface-muted)]">
        {inner}
      </Link>
    );
  }
  return inner;
}

function DomainSignalsPanel({
  overview,
  counts,
  summaryReady,
  scanCount,
  latestScanLabel,
  kev,
  credentials,
  tools,
  packages,
}: {
  overview: OverviewResponse | null;
  counts: ReturnType<typeof useDeploymentContext>["counts"];
  summaryReady: boolean;
  scanCount: number | null;
  latestScanLabel: string | null;
  kev: number | null;
  credentials: number | null;
  tools: number | null;
  packages: number | null;
}) {
  const domains = overview ? Object.values(overview.domains) : [];
  const activeDomains = domains.filter((d) => d.status !== "idle").length;
  const coverage = domains.length > 0 ? Math.round((activeDomains / domains.length) * 100) : null;
  const activeServices = countActiveServices(counts?.services);
  const connected = hasDeploymentSignals(counts);

  if (domains.length === 0 && !summaryReady) {
    return null;
  }

  return (
    <details className="group/signals rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 select-none">
        <ChevronRight className="h-4 w-4 text-[color:var(--text-tertiary)] transition-transform group-open/signals:rotate-90" />
        <span className="text-sm font-medium text-[color:var(--foreground)]">Domain & service signals</span>
        <span className="text-xs text-[color:var(--text-tertiary)]">
          {coverage != null ? `${coverage}% coverage` : "rollup"}
        </span>
      </summary>
      <div className="space-y-4 border-t border-[color:var(--border-subtle)] px-4 py-4">
        <div className="flex flex-wrap gap-2 text-xs">
          <SignalChip label="KEV" value={summaryReady && kev != null ? String(kev) : "—"} />
          <SignalChip label="Credentials" value={summaryReady && credentials != null ? String(credentials) : "—"} />
          <SignalChip label="Tools" value={summaryReady && tools != null ? String(tools) : "—"} />
          <SignalChip label="Packages" value={summaryReady && packages != null ? String(packages) : "—"} />
          <SignalChip label="Active services" value={summaryReady ? String(activeServices) : "—"} />
          <SignalChip label="Connect" value={connected ? "Live" : "Setup"} />
        </div>
        {domains.length > 0 ? (
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {domains.map((domain) => {
              const tone = statusTone(domain.status);
              return (
                <Link
                  key={domain.href}
                  href={domain.graph_href ?? domain.href}
                  className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 transition-colors hover:border-[color:var(--border-strong)]"
                >
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-[color:var(--foreground)]">{domain.label}</p>
                    <p className="truncate text-[10px] text-[color:var(--text-tertiary)]">{domain.metric_label}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className={`font-mono text-sm font-semibold ${tone.text}`}>{domain.metric}</span>
                    <span className={`h-2 w-2 rounded-full ${tone.dot}`} />
                  </div>
                </Link>
              );
            })}
          </div>
        ) : null}
        {(scanCount != null || latestScanLabel) && (
          <p className="text-xs text-[color:var(--text-tertiary)]">
            {scanCount != null ? `${scanCount} completed scan${scanCount === 1 ? "" : "s"}` : null}
            {scanCount != null && latestScanLabel ? " · " : null}
            {latestScanLabel ? `Latest ${latestScanLabel}` : null}
          </p>
        )}
      </div>
    </details>
  );
}

function SignalChip({ label, value }: { label: string; value: string }) {
  return (
    <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 text-[color:var(--text-secondary)]">
      <span className="text-[color:var(--text-tertiary)]">{label}</span> {value}
    </span>
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
