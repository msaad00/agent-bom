"use client";

import { Suspense, Fragment, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { PaginationBar } from "@/components/pagination-bar";
import { JobPipelinePanel } from "@/components/job-pipeline-panel";
import { ScanPipeline } from "@/components/scan-pipeline";
import { api, formatDate, type JobListItem, type JobStatus, type ScanSchedule, type SourceRecord } from "@/lib/api";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Download,
  Loader2,
  Search,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function StatusIcon({ status }: { status: JobStatus }) {
  switch (status) {
    case "done":
      return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-400" />;
    case "running":
      return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
    case "cancelled":
      return <XCircle className="w-4 h-4 text-zinc-500" />;
    default:
      return <Clock className="w-4 h-4 text-zinc-500" />;
  }
}

function statusLabel(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function statusColor(s: JobStatus) {
  switch (s) {
    case "done":      return "text-emerald-400";
    case "failed":    return "text-red-400";
    case "running":   return "text-blue-400";
    case "cancelled": return "text-zinc-500";
    default:          return "text-zinc-400";
  }
}

const STATUS_TABS = ["all", "pending", "running", "done", "failed", "cancelled"];

function sourceIdForJob(job: JobListItem): string {
  const direct = typeof job.source_id === "string" ? job.source_id.trim() : "";
  if (direct) return direct;
  const requestSource = typeof job.request?.source_id === "string" ? job.request.source_id.trim() : "";
  return requestSource;
}

function sourceForJob(
  job: JobListItem,
  sourceById: Map<string, SourceRecord>,
  sourceByLastJobId: Map<string, SourceRecord>,
): SourceRecord | undefined {
  const sourceId = sourceIdForJob(job);
  if (sourceId) return sourceById.get(sourceId);
  return sourceByLastJobId.get(job.job_id);
}

function evidenceSummary(job: JobListItem): string {
  const summary = job.summary;
  if (!summary) return "No summary";
  const vulns = summary.total_vulnerabilities ?? 0;
  const critical = summary.critical_findings ?? 0;
  const packages = summary.total_packages ?? 0;
  return `${vulns} CVEs · ${critical} critical · ${packages} packages`;
}


function JobsPageContent() {
  const searchParams = useSearchParams();
  const queryParam = searchParams.get("q") ?? "";
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [search, setSearch] = useState(queryParam);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [page, setPage] = useState(1);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const PAGE_SIZE = 25;

  useEffect(() => {
    setSearch(queryParam);
    setPage(1);
  }, [queryParam]);

  const load = () => {
    setLoading(true);
    setError("");
    Promise.allSettled([
      api.listJobs({ includeDetails: true, limit: 200 }),
      api.listSources(),
      api.listSchedules(),
    ])
      .then(([jobsResult, sourcesResult, schedulesResult]) => {
        if (jobsResult.status === "fulfilled") {
          setJobs(jobsResult.value.jobs);
        } else {
          setError(jobsResult.reason instanceof Error ? jobsResult.reason.message : "Unable to load jobs");
        }
        setSources(sourcesResult.status === "fulfilled" ? sourcesResult.value.sources : []);
        setSchedules(schedulesResult.status === "fulfilled" ? schedulesResult.value : []);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Unable to load job workflow");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  async function handleDelete(jobId: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setDeleting(jobId);
    try {
      await api.deleteScan(jobId);
      setJobs((prev) => prev.filter((j) => j.job_id !== jobId));
    } finally {
      setDeleting(null);
    }
  }

  const sourceById = useMemo(() => new Map(sources.map((source) => [source.source_id, source])), [sources]);
  const sourceByLastJobId = useMemo(
    () => new Map(sources.filter((source) => source.last_job_id).map((source) => [source.last_job_id as string, source])),
    [sources],
  );
  const evidenceReadyJobs = useMemo(() => jobs.filter((job) => job.status === "done"), [jobs]);
  const featuredJob = useMemo(() => {
    const running = jobs.find((job) => job.status === "running");
    if (running) return running;
    return [...jobs]
      .filter((job) => job.status === "done" || job.status === "failed")
      .sort((left, right) => {
        const leftAt = new Date(left.completed_at ?? left.created_at).getTime();
        const rightAt = new Date(right.completed_at ?? right.created_at).getTime();
        return rightAt - leftAt;
      })[0];
  }, [jobs]);

  const filteredJobs = jobs
    .filter((j) => statusFilter === "all" || j.status === statusFilter)
    .filter((j) => {
      if (!search) return true;
      const normalized = search.toLowerCase();
      const linkedSource = sourceForJob(j, sourceById, sourceByLastJobId);
      return (
        j.job_id.toLowerCase().includes(normalized) ||
        sourceIdForJob(j).toLowerCase().includes(normalized) ||
        (linkedSource?.display_name ?? "").toLowerCase().includes(normalized) ||
        (linkedSource?.owner ?? "").toLowerCase().includes(normalized)
      );
    });
  const totalPages = Math.max(1, Math.ceil(filteredJobs.length / PAGE_SIZE));
  const pagedJobs = filteredJobs.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scan jobs</h1>
          <p className="text-zinc-400 text-sm mt-1">Completed and in-flight evidence runs</p>
        </div>
        <div className="flex items-center gap-2">
          {jobs.length > 0 && (
            <button
              onClick={() => downloadJson(filteredJobs, `jobs-${new Date().toISOString().slice(0, 10)}.json`)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm font-medium rounded-lg transition-colors"
              title="Export job list as JSON"
            >
              <Download className="w-3.5 h-3.5" />
              Export
            </button>
          )}
          <Link
            href="/scan"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            New Scan
          </Link>
        </div>
      </div>

      {loading && <p className="text-zinc-500 text-sm">Loading jobs…</p>}
      {error && (
        <div className="flex items-center gap-3 p-3 bg-red-950/30 border border-red-800/40 rounded-lg">
          <p className="text-red-400 text-sm flex-1">{error}</p>
          <button onClick={load} className="text-xs text-zinc-400 hover:text-zinc-200 px-2 py-1 border border-zinc-700 rounded">Retry</button>
        </div>
      )}

      {!loading && jobs.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Clock className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No scan jobs yet.</p>
          <p className="text-zinc-600 text-xs mt-1">
            <Link href="/scan" className="text-emerald-500 hover:text-emerald-400">Run your first scan</Link> to see results here.
          </p>
        </div>
      )}

      {!loading && (jobs.length > 0 || sources.length > 0 || schedules.length > 0) && (
        <section
          data-testid="source-job-evidence-workflow"
          className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-950 p-5"
        >
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.28em] text-emerald-400">
                Source → job → evidence
              </p>
              <h2 className="mt-1 text-base font-semibold text-zinc-100">Control-plane workflow</h2>
              <p className="mt-1 max-w-3xl text-sm text-zinc-500">
                Registered sources enqueue scan jobs. Each job runs the six-stage read-only pipeline below, then publishes findings, graph, and compliance evidence.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-zinc-400">
                <span className="rounded-full border border-zinc-800 px-2.5 py-1">
                  {sources.length} sources · {sources.filter((source) => source.enabled).length} enabled
                </span>
                <span className="rounded-full border border-zinc-800 px-2.5 py-1">
                  {jobs.filter((job) => job.status === "running").length} running · {jobs.length} total jobs
                </span>
                <span className="rounded-full border border-zinc-800 px-2.5 py-1">
                  {evidenceReadyJobs.length} evidence-ready
                </span>
                <span className="rounded-full border border-zinc-800 px-2.5 py-1">
                  {schedules.filter((schedule) => schedule.enabled).length} active schedules
                </span>
              </div>
            </div>
            <Link
              href="/sources"
              className="inline-flex items-center gap-1.5 self-start rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:border-zinc-600 hover:text-zinc-100"
            >
              Manage sources
            </Link>
          </div>

          {featuredJob ? (
            <JobPipelinePanel
              jobId={featuredJob.job_id}
              status={featuredJob.status}
              createdAt={featuredJob.created_at}
              completedAt={featuredJob.completed_at}
            />
          ) : (
            <div className="rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 p-4">
              <p className="text-sm text-zinc-400">
                Run a scan to see the live six-stage pipeline DAG with per-step timing and activity.
              </p>
              <div className="mt-4">
                <ScanPipeline steps={new Map()} className="h-[180px]" />
              </div>
            </div>
          )}
        </section>
      )}

      {jobs.length > 0 && (
        <>
          {/* Status filter tabs + search */}
          <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
            <div className="flex items-center gap-1 flex-wrap">
              {STATUS_TABS.map((s) => (
                <button
                  key={s}
                  onClick={() => { setStatusFilter(s); setPage(1); }}
                  className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                    statusFilter === s
                      ? "text-zinc-200 border-zinc-600 bg-zinc-800"
                      : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                  }`}
                >
                  {s === "all"
                    ? `All (${jobs.length})`
                    : `${statusLabel(s)} (${jobs.filter((j) => j.status === s).length})`}
                </button>
              ))}
            </div>
            <div className="relative w-full sm:w-56">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" />
              <input
                type="text"
                placeholder="Search jobs or sources…"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
          </div>

          <div className="border border-zinc-800 rounded-xl overflow-hidden overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 border-b border-zinc-800">
                <tr>
                  <th className="w-10 px-3 py-3" aria-label="Expand pipeline" />
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Job ID</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Status</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Source</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Started</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Completed</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Evidence</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {pagedJobs?.map((job) => {
                  const linkedSource = sourceForJob(job, sourceById, sourceByLastJobId);
                  const sourceId = sourceIdForJob(job);
                  const evidenceReady = job.status === "done";
                  const expanded = expandedJobId === job.job_id;
                  return (
                    <Fragment key={job.job_id}>
                    <tr
                      className="hover:bg-zinc-900 transition-colors cursor-pointer group"
                      onClick={() => setExpandedJobId((current) => (current === job.job_id ? null : job.job_id))}
                    >
                      <td className="px-3 py-3">
                        <button
                          type="button"
                          aria-label={expanded ? "Collapse pipeline" : "Expand pipeline"}
                          aria-expanded={expanded}
                          onClick={(event) => {
                            event.stopPropagation();
                            setExpandedJobId((current) => (current === job.job_id ? null : job.job_id));
                          }}
                          className="rounded p-1 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
                        >
                          {expanded ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          href={`/scan?id=${encodeURIComponent(job.job_id)}`}
                          onClick={(event) => event.stopPropagation()}
                          className="font-mono text-xs text-zinc-300 hover:text-emerald-300"
                        >
                          {job.job_id.slice(0, 8)}…
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <div className={`flex items-center gap-1.5 ${statusColor(job.status)}`}>
                          <StatusIcon status={job.status} />
                          <span className="text-xs font-medium">{statusLabel(job.status)}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="max-w-56">
                          <p className="truncate text-xs font-medium text-zinc-300">
                            {linkedSource?.display_name ?? (sourceId || "Manual / pushed scan")}
                          </p>
                          <p className="mt-0.5 truncate text-[11px] text-zinc-600">
                            {linkedSource ? `${linkedSource.kind} · ${linkedSource.owner || "unowned"}` : sourceId || "No registered source"}
                          </p>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-500">
                        {formatDate(job.created_at)}
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-500">
                        {job.completed_at ? formatDate(job.completed_at) : "—"}
                      </td>
                      <td className="px-4 py-3">
                        {evidenceReady ? (
                          <div className="space-y-2">
                            <p className="text-[11px] text-zinc-500">{evidenceSummary(job)}</p>
                            <div className="flex flex-wrap gap-1.5">
                              {[
                                { href: `/findings?scan=${encodeURIComponent(job.job_id)}`, label: "Findings" },
                                { href: `/security-graph?scan=${encodeURIComponent(job.job_id)}`, label: "Graph" },
                                { href: `/compliance?scan=${encodeURIComponent(job.job_id)}`, label: "Compliance" },
                              ].map((link) => (
                                <Link
                                  key={link.label}
                                  href={link.href}
                                  onClick={(event) => event.stopPropagation()}
                                  className="rounded-md border border-zinc-800 px-2 py-1 text-[11px] font-medium text-zinc-400 hover:border-zinc-700 hover:text-zinc-100"
                                >
                                  {link.label}
                                </Link>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <span className="text-xs text-zinc-600">Available when complete</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={(e) => handleDelete(job.job_id, e)}
                          disabled={deleting === job.job_id}
                          className="opacity-0 group-hover:opacity-100 p-1 text-zinc-600 hover:text-red-400 transition-all rounded"
                          title="Delete job"
                        >
                          {deleting === job.job_id
                            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            : <Trash2 className="w-3.5 h-3.5" />
                          }
                        </button>
                      </td>
                    </tr>
                    {expanded ? (
                      <tr key={`${job.job_id}-pipeline`} className="bg-zinc-900/40">
                        <td colSpan={8} className="px-4 py-4">
                          <JobPipelinePanel
                            jobId={job.job_id}
                            status={job.status}
                            createdAt={job.created_at}
                            completedAt={job.completed_at}
                          />
                        </td>
                      </tr>
                    ) : null}
                    </Fragment>
                  );
                })}
                {pagedJobs.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-zinc-600 text-sm">
                      No jobs match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <PaginationBar
            page={page}
            totalPages={totalPages}
            totalItems={filteredJobs.length}
            onPrevious={() => setPage((p) => Math.max(1, p - 1))}
            onNext={() => setPage((p) => Math.min(totalPages, p + 1))}
          />
        </>
      )}
    </div>
  );
}

export default function JobsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="mr-2 h-6 w-6 animate-spin" />
          Loading jobs...
        </div>
      }
    >
      <JobsPageContent />
    </Suspense>
  );
}
