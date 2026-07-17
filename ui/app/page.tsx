"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import {
  api,
  ScanJob,
  ScanResult,
  JobListItem,
  PostureResponse,
  OverviewResponse,
  formatDate,
  type PostureCountsResponse,
  type ComplianceResponse,
} from "@/lib/api";
import { ActivityFeed } from "@/components/activity-feed";
import {
  OverviewCockpit,
  type ExposurePathView,
  type OverviewComplianceSnapshot,
  type PostureScoreFormat,
} from "@/components/overview-cockpit";
import { PageLaneHeader } from "@/components/page-lane";
import { ApiOfflineState } from "@/components/api-offline-state";
import { ApiAuthError, ApiForbiddenError } from "@/lib/api-errors";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { deploymentModeLabel, hasDeploymentSignals } from "@/lib/deployment-context";
import { useCaptureMode } from "@/lib/use-capture-mode";
import { complianceFrameworkSummaries } from "@/lib/compliance-frameworks";
import {
  aggregateSeverity,
  blastCredentials,
  blastTools,
  buildExposurePathView,
  buildExecExposurePaths,
} from "@/lib/dashboard-data";
import {
  ShieldAlert, ArrowRight, Clock,
  AlertTriangle, GitBranch, Network,
} from "lucide-react";

function _classifyApiErrorKind(err: unknown): "network" | "auth" | "forbidden" {
  if (err instanceof ApiAuthError) return "auth";
  if (err instanceof ApiForbiddenError) return "forbidden";
  return "network";
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [detailJobs, setDetailJobs] = useState<ScanJob[]>([]);
  const [agentCount, setAgentCount] = useState<number>(0);
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
  const [compliance, setCompliance] = useState<ComplianceResponse | null>(null);
  // Local display-format override; falls back to the persisted per-tenant
  // config carried on the overview posture. Toggling persists via the API (#3940).
  const [scoreFormatOverride, setScoreFormatOverride] = useState<PostureScoreFormat | null>(null);
  const { counts } = useDeploymentContext();
  const captureMode = useCaptureMode();
  const seededEvidence = captureMode || Boolean(counts?.scan_sources?.some((source) => source.includes("demo")));

  // Fetch posture grade + cross-domain overview (folded into the header scorecard)
  useEffect(() => {
    api.getPosture().then(setPosture).catch(() => {});
    api.getOverview().then(setOverview).catch(() => {});
    api.getCompliance().then(setCompliance).catch(() => {});
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
      } catch {
        if (cancelled) return;
        setAgentCount(0);
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

  // Tag each blast with its originating scan id (the graph snapshot scan_id is
  // the job id) so the exec→graph drill can target the finding's own scan
  // instead of falling back to the latest snapshot (#3966).
  const allBlast = useMemo(
    () =>
      doneJobs.flatMap((j) =>
        ((j.result as ScanResult)?.blast_radius ?? []).map((blast) => ({
          ...blast,
          scanId: j.job_id,
        })),
      ),
    [doneJobs]
  );

  // Blast rows remain useful for exposure-path detail, but they are not an
  // estate count source: this client hydrates at most ten completed jobs and
  // would otherwise display a partial/repeated severity histogram. The API's
  // posture-count spine is current-state, deduplicated, and uses the same
  // default window as /v1/findings. Imported offline reports are the one local
  // exception because no server-side canonical view exists for them.
  const importedSeverity = useMemo(() => aggregateSeverity(allBlast), [allBlast]);
  const canonicalSeverity = useMemo(() => {
    if (importedReport) return importedSeverity;
    if (counts) {
      return {
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        total: counts.total,
      };
    }
    return {
      critical: overview?.headline.critical ?? 0,
      high: overview?.headline.high ?? 0,
      medium: 0,
      low: 0,
      total: overview?.headline.critical_high ?? 0,
    };
  }, [counts, importedReport, importedSeverity, overview]);
  const kevCount = useMemo(() => allBlast.filter((b) => (b.is_kev ?? b.cisa_kev) === true).length, [allBlast]);
  const credentialExposureCount = useMemo(() => allBlast.filter((b) => blastCredentials(b).length > 0).length, [allBlast]);
  const reachableToolCount = useMemo(() => new Set(allBlast.flatMap(blastTools)).size, [allBlast]);

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
    return buildExposurePathView(topRisk, topRisk.scanId);
  }, [topRisk]);

  // The exec top-risk strip merges the scan-derived blast_radius chain with the
  // server-reconciled overview.top_risks so it stays populated AND honest for
  // hub/bulk-ingested estates that never create scan jobs (#4063).
  const exposurePaths = useMemo<ExposurePathView[]>(
    () => buildExecExposurePaths(allBlast, overview?.top_risks),
    [allBlast, overview],
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
  const summaryReady = !jobsLoading || Boolean(importedReport);
  const detailsReady = !detailLoading || Boolean(importedReport);

  const criticalCount = canonicalSeverity.critical;
  const highCount = canonicalSeverity.high;
  const displayedUniqueCVEs = importedReport
    ? uniqueCVEs
    : (overview?.domains.vuln.metric ?? 0);
  const displayedKevCount = importedReport
    ? kevCount
    : (counts?.kev ?? overview?.headline.kev ?? 0);
  const displayedCredentialExposure = importedReport
    ? credentialExposureCount
    : (overview?.headline.credential_exposed ?? 0);
  const displayedReachableTools = detailsReady ? reachableToolCount : null;
  const displayedPackages = detailsReady
    ? (totalPackages > 0 ? totalPackages : (seededEvidence ? (summaryStats?.total_packages ?? 0) : totalPackages))
    : (summaryStats?.total_packages ?? 0);

  const complianceSnapshot = useMemo(
    () => buildComplianceSnapshot(compliance),
    [compliance],
  );

  if (apiError && !importedReport) return <ApiOfflineState onImport={setImportedReport} kind={apiErrorKind} detail={apiErrorDetail} />;

  // The overview's configurable exec risk score (#3940) is authoritative for the
  // exec grade — it derives from the honest estate counts and the tenant's score
  // model. Fall back to /v1/posture only until the overview payload lands.
  const postureGrade = overview?.posture.grade ?? posture?.grade ?? "—";
  const postureScore = overview?.posture.score ?? posture?.score;
  const scoreFormat: PostureScoreFormat =
    scoreFormatOverride ?? overview?.posture.display_format ?? "percent";
  const scoreBreakdown = overview?.posture.breakdown ?? null;
  const handleScoreFormatChange = (format: PostureScoreFormat) => {
    // Optimistic local update, then persist per-tenant. A failed persist (e.g.
    // a viewer without admin) still keeps the local view; it just won't stick.
    setScoreFormatOverride(format);
    api.updateScoreConfig({ display_format: format }).catch(() => {});
  };
  const latestScanShort =
    summaryReady && effectiveRecentJobs[0]?.created_at
      ? formatShortScanTime(effectiveRecentJobs[0].created_at)
      : null;

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="command"
        title="Overview"
        subtitle="Exec briefing: posture, open issues, compliance evidence, and live surfaces. Use Findings and Investigation for engineer drill-down."
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-0.5 text-[11px] font-medium text-sky-700 dark:text-sky-200">
            {deploymentModeLabel(counts?.deployment_mode)} · {countActiveServices(counts?.services)} services live
          </span>
        }
        actions={
          <>
            {/* Exec pane leads with drill-downs, not an operational scan action
                (New Scan lives in the nav + empty states for engineers). */}
            <Link
              href="/compliance"
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500"
            >
              Compliance <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/security-graph"
              className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
            >
              Investigation <GitBranch className="h-4 w-4" />
            </Link>
            {(displayedAgentCount ?? 0) > 0 ? (
              <Link
                href="/agents/topology"
                className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
              >
                Agent mesh <Network className="h-4 w-4" />
              </Link>
            ) : (
              <Link
                href="/findings"
                className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-3 py-2 text-sm font-medium text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
              >
                Findings
              </Link>
            )}
          </>
        }
      />

      <OverviewCockpit
        grade={postureGrade}
        score={postureScore}
        scoreFormat={scoreFormat}
        scoreBreakdown={scoreBreakdown}
        onScoreFormatChange={handleScoreFormatChange}
        postureSummary={overview?.posture.summary ?? posture?.summary}
        critical={criticalCount}
        high={highCount}
        kev={summaryReady ? displayedKevCount : null}
        credentials={summaryReady ? displayedCredentialExposure : null}
        agents={displayedAgentCount}
        cves={summaryReady ? displayedUniqueCVEs : null}
        scans={summaryReady ? (counts?.scan_count ?? effectiveRecentJobs.length) : null}
        latestScan={jobsLoading ? null : latestScanShort}
        mode={deploymentModeLabel(counts?.deployment_mode)}
        summaryReady={Boolean(importedReport || counts || overview)}
        findingsScopeLabel="Current findings · configured window"
        severity={canonicalSeverity}
        domains={overview?.domains ?? null}
        coverage={overview?.coverage ?? null}
        topPath={topExposurePath}
        exposurePaths={exposurePaths}
        signals={{
          tools: summaryReady ? displayedReachableTools : null,
          packages: summaryReady ? displayedPackages : null,
          activeServices: countActiveServices(counts?.services),
          connected: hasDeploymentSignals(counts),
        }}
        compliance={complianceSnapshot}
        services={counts?.services ?? null}
      />

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

function countActiveServices(services: PostureCountsResponse["services"]): number {
  if (!services) return 0;
  return Object.values(services).filter((entry) => entry.state === "live" || entry.state === "connected").length;
}

function buildComplianceSnapshot(
  compliance: ComplianceResponse | null,
): OverviewComplianceSnapshot | null {
  if (!compliance) return null;
  const hasMcp = Boolean(compliance.has_mcp_context);
  const frameworks = complianceFrameworkSummaries(compliance, hasMcp)
    .filter((framework) => !framework.disabled)
    .map((framework) => ({
      id: framework.id,
      label: framework.label,
      pass: framework.pass,
      warn: framework.warn,
      fail: framework.fail,
      total: framework.total,
    }));
  return {
    overallScore: compliance.overall_score,
    overallStatus: compliance.overall_status,
    frameworks,
  };
}

function JobRow({ job }: { job: JobListItem }) {
  const statusColors: Record<string, string> = {
    done: "bg-emerald-500",
    failed: "bg-red-500",
    running: "bg-yellow-500 animate-pulse",
    pending: "bg-[color:var(--text-tertiary)]",
    cancelled: "bg-[color:var(--text-tertiary)]",
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
      className="flex items-center gap-4 bg-[color:var(--surface-muted)] border border-[color:var(--border-subtle)] hover:border-[color:var(--border-strong)] rounded-xl p-4 transition-colors group"
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${statusColors[job.status] ?? "bg-[color:var(--text-tertiary)]"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-[color:var(--text-secondary)]">{job.job_id.slice(0, 8)}…</span>
          {tags?.map((t) => (
            <span key={t} className="text-xs bg-[color:var(--surface-elevated)] border border-[color:var(--border-subtle)] rounded px-1.5 py-0.5 text-[color:var(--text-tertiary)]">{t}</span>
          ))}
        </div>
        <div className="text-xs text-[color:var(--text-tertiary)] flex items-center gap-1 mt-0.5">
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
              <span className="text-[color:var(--text-secondary)]">{vulnCount} vuln{vulnCount !== 1 ? "s" : ""}</span>
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
      <ArrowRight className="w-3.5 h-3.5 text-[color:var(--text-tertiary)] group-hover:text-[color:var(--text-secondary)] transition-colors flex-shrink-0" />
    </Link>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-16 border border-dashed border-[color:var(--border-subtle)] rounded-xl">
      <ShieldAlert className="w-8 h-8 text-[color:var(--text-tertiary)] mx-auto mb-3" />
      <p className="text-[color:var(--text-tertiary)] text-sm">No scans yet.</p>
      <Link
        href="/scan"
        className="inline-flex items-center gap-1.5 mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors"
      >
        New Scan
        <ArrowRight className="w-3.5 h-3.5" />
      </Link>
    </div>
  );
}
