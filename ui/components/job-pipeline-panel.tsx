"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Loader2,
  XCircle,
} from "lucide-react";

import { ScanPipeline } from "@/components/scan-pipeline";
import { complianceHref, findingsHref, securityGraphHref } from "@/lib/page-links";
import {
  api,
  PIPELINE_STEPS,
  type JobStatus,
  type ScanJob,
  type Summary,
} from "@/lib/api";
import { useScanStream } from "@/lib/use-scan-stream";
import {
  describeWallClock,
  formatDurationMs,
  formatStageDuration,
  mergePipelineSteps,
  parsePipelineStepsFromProgress,
  resolvePipelineTelemetry,
  summarizePipeline,
  type PipelineTelemetryState,
} from "@/lib/scan-pipeline-progress";
import {
  PIPELINE_GRAPH,
  backendStepForNode,
  type DomainLaneData,
  type ScannerDomain,
} from "@/lib/scan-pipeline-graph";
import {
  cloudIdentityCount,
  cloudResourceCount,
  domainFindingsForScan,
} from "@/lib/scan-domain-findings";

// ── Result-stat extraction ───────────────────────────────────────────────────

interface ResultStat {
  key: string;
  label: string;
  value: string;
}

interface ResultView {
  lanes: Record<ScannerDomain, DomainLaneData> | undefined;
  stats: ResultStat[];
}

/**
 * Build the reconciled result chips + scanner-lane data. The headline
 * "findings" count sums every domain that ran (CIS failures included), so it
 * agrees with the domain lanes instead of the old "0 findings / 32% CIS pass"
 * contradiction.
 */
function deriveResultView(
  job: ScanJob | null,
  fallback: Summary | undefined,
  summarized: boolean,
): ResultView {
  const result = job?.result;
  const summary = result?.summary ?? fallback;
  const { lanes, reconciled, cis } = domainFindingsForScan({ result, summary, summarized });

  const stats: ResultStat[] = [];
  if (reconciled.domainsRun > 0) {
    stats.push({ key: "findings", label: "findings", value: String(reconciled.total) });
  }
  if ((summary?.critical_findings ?? 0) > 0) {
    stats.push({ key: "critical", label: "critical", value: String(summary!.critical_findings) });
  }
  if ((summary?.total_packages ?? 0) > 0) {
    stats.push({ key: "packages", label: "packages", value: String(summary!.total_packages) });
  }

  if (result) {
    const resources = cloudResourceCount(result.cloud_inventory);
    if (resources != null) {
      stats.push({ key: "resources", label: "resources", value: String(resources) });
    }
    const identities = cloudIdentityCount(result.cloud_inventory);
    if (identities != null) {
      stats.push({ key: "identities", label: "identities", value: String(identities) });
    }
  }
  if (cis) {
    const failed = reconciled.byDomain.cis;
    if (failed != null) {
      stats.push({ key: "cis-fail", label: "CIS fail", value: String(failed) });
    }
    if (cis.passRate != null) {
      stats.push({ key: "cis-pass", label: "CIS pass", value: `${cis.passRate.toFixed(0)}%` });
    }
  }

  return { lanes, stats };
}

// Which evidence surfaces are most relevant to drill into from a given stage.
function stageLinks(stepId: string, jobId: string): { href: string; label: string }[] {
  switch (stepId) {
    case "scanning":
    case "enrichment":
      return [{ href: findingsHref({ scan: jobId }), label: "Findings" }];
    case "analysis":
      return [
        { href: securityGraphHref({ scan: jobId }), label: "Graph" },
        { href: findingsHref({ scan: jobId }), label: "Findings" },
      ];
    case "output":
      return [{ href: complianceHref({ scan: jobId }), label: "Compliance" }];
    default:
      return [];
  }
}

// ── Status banner ────────────────────────────────────────────────────────────

function StatusBanner({
  status,
  streaming,
  telemetryState,
  error,
}: {
  status: JobStatus;
  streaming: boolean;
  telemetryState: PipelineTelemetryState;
  error?: string | undefined;
}) {
  const active = status === "running" || status === "pending";
  const failed = status === "failed";
  const done = status === "done";

  const tone = failed
    ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
    : active
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
      : done
        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
        : "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-secondary)]";

  const icon = failed ? (
    <XCircle className="h-4 w-4" />
  ) : active ? (
    <Loader2 className="h-4 w-4 animate-spin" />
  ) : (
    <CheckCircle2 className="h-4 w-4" />
  );

  const label = failed
    ? error || "Scan failed"
    : active
      ? streaming
        ? "Scan running — live"
        : "Scan running"
      : done
        ? telemetryState === "unavailable"
          ? "Scan complete · stage telemetry unavailable"
          : telemetryState === "partial"
            ? "Scan complete · partial stage telemetry"
          : "Scan complete"
        : status;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${tone}`}
    >
      {icon}
      {label}
    </span>
  );
}

// ── Panel ────────────────────────────────────────────────────────────────────

export function JobPipelinePanel({
  jobId,
  status,
  createdAt,
  completedAt,
  summary: listSummary,
  className,
}: {
  jobId: string;
  status: JobStatus;
  createdAt: string;
  completedAt?: string | undefined;
  summary?: Summary | undefined;
  className?: string;
}) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(true);

  const isActive = status === "pending" || status === "running";
  const { pipelineSteps: liveSteps, streaming, messages } = useScanStream(jobId, {
    enabled: isActive,
  });

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api
      .getScan(jobId)
      .then((full) => {
        if (!cancelled) setJob(full);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load pipeline");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  const { steps, state: telemetryState } = useMemo(() => {
    const persisted = parsePipelineStepsFromProgress(job?.progress ?? []);
    const merged = mergePipelineSteps(persisted, liveSteps);
    return resolvePipelineTelemetry(merged, status);
  }, [job?.progress, liveSteps, status]);

  const summary = useMemo(
    () =>
      summarizePipeline(steps, {
        created_at: createdAt,
        started_at: job?.started_at ?? null,
        completed_at: completedAt ?? job?.completed_at ?? null,
        status,
      }),
    [steps, createdAt, completedAt, job, status],
  );

  const { lanes, stats: resultStats } = useMemo<ResultView>(
    () =>
      status === "done"
        ? deriveResultView(job, listSummary, job == null)
        : { lanes: undefined, stats: [] },
    [status, job, listSummary],
  );

  const recentMessages = useMemo(() => {
    const fromProgress = (job?.progress ?? [])
      .map((line) => {
        try {
          const event = JSON.parse(line) as { message?: string };
          return typeof event.message === "string" ? event.message : null;
        } catch {
          return line.trim() || null;
        }
      })
      .filter((line): line is string => Boolean(line));
    const merged = [...fromProgress, ...messages];
    return merged.slice(-4);
  }, [job?.progress, messages]);

  const selectedBackendStep = selectedStepId ? backendStepForNode(selectedStepId) : undefined;
  const selectedStep = selectedBackendStep ? steps.get(selectedBackendStep) : undefined;
  const selectedMeta = selectedStepId
    ? PIPELINE_GRAPH.find((node) => node.id === selectedStepId)
    : undefined;

  return (
    <div
      className={`rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4 ${className ?? ""}`}
      data-testid={`job-pipeline-${jobId}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-emerald-400">
            Scan pipeline DAG
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <StatusBanner
              status={status}
              streaming={streaming}
              telemetryState={telemetryState}
              error={job?.error}
            />
            <span className="text-sm text-[var(--text-secondary)]">
              {summary.currentStepLabel
                ? summary.currentStepLabel
                : telemetryState === "unavailable"
                  ? "Stage telemetry unavailable"
                  : telemetryState === "partial"
                    ? `${steps.size}/${summary.totalSteps} stages observed`
                    : `${summary.completedSteps}/${summary.totalSteps} stages complete`}
            </span>
          </div>
          {resultStats.length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {resultStats.map((stat) => (
                <span
                  key={stat.key}
                  className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-elevated)] px-2 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]"
                >
                  <span className="text-[var(--foreground)]">{stat.value}</span> {stat.label}
                </span>
              ))}
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--text-tertiary)]">
          <span>
            Wall clock{" "}
            <span className="font-mono text-[var(--text-secondary)]">
              {describeWallClock(summary.wallClockMs, {
                unavailable: telemetryState === "unavailable" && summary.wallClockMs == null,
                running: status === "running" || status === "pending",
              })}
            </span>
          </span>
          <Link
            href={`/scan?id=${encodeURIComponent(jobId)}`}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border-subtle)] px-2 py-1 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
          >
            Full scan
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>
      </div>

      {loading && steps.size === 0 ? (
        <div className="mt-4 flex items-center gap-2 text-sm text-[var(--text-tertiary)]">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading persisted pipeline events…
        </div>
      ) : null}
      {error ? <p className="mt-3 text-sm text-amber-300">{error}</p> : null}

      {/* DAG + drill-in detail side panel */}
      <div className="mt-4 flex flex-col gap-3 lg:flex-row">
        {telemetryState !== "observed" && !loading && !isActive ? (
          <div className="flex h-[160px] flex-1 items-center justify-center rounded-lg border border-dashed border-[var(--border-subtle)] px-6 text-center">
            <div>
              <p className="text-sm font-medium text-[var(--text-secondary)]">
                {telemetryState === "partial" ? "Partial stage telemetry" : "Per-stage telemetry unavailable"}
              </p>
              <p className="mt-1 text-xs text-[var(--text-tertiary)]">
                {telemetryState === "partial"
                  ? `${steps.size} of ${summary.totalSteps} stages emitted events. Missing stages are not inferred.`
                  : "The scan result is available, but this executor did not emit stage events or stage timestamps."}
              </p>
            </div>
          </div>
        ) : (
          <ScanPipeline
            steps={steps}
            lanes={lanes}
            className="h-[300px] flex-1 rounded-lg border border-[var(--border-subtle)]"
            selectedStepId={selectedStepId}
            onStepClick={(nodeId) =>
              setSelectedStepId((current) => (current === nodeId ? null : nodeId))
            }
          />
        )}
        {selectedStepId ? (
          <aside className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-3 lg:w-64">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                  {selectedStepId}
                </p>
                <p className="text-sm font-semibold text-[var(--foreground)]">
                  {selectedMeta?.label ?? selectedStepId}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedStepId(null)}
                className="rounded p-1 text-[var(--text-tertiary)] hover:bg-[var(--surface)] hover:text-[var(--foreground)]"
                aria-label="Close stage detail"
              >
                <XCircle className="h-4 w-4" />
              </button>
            </div>
            <p className="mt-2 text-[11px] capitalize text-[var(--text-secondary)]">
              Status: {selectedStep?.status ?? "pending"}
            </p>
            {selectedStep?.message ? (
              <p className="mt-1 text-[11px] leading-5 text-[var(--text-tertiary)]">
                {selectedStep.message}
              </p>
            ) : null}
            {selectedBackendStep && summary.stepDurationsMs[selectedBackendStep] != null ? (
              <p className="mt-1 font-mono text-[11px] text-[var(--text-tertiary)]">
                {formatDurationMs(summary.stepDurationsMs[selectedBackendStep])}
              </p>
            ) : null}
            {selectedStep?.stats && Object.keys(selectedStep.stats).length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-1">
                {Object.entries(selectedStep.stats).map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]"
                  >
                    {v} {k}
                  </span>
                ))}
              </div>
            ) : null}
            {selectedBackendStep && stageLinks(selectedBackendStep, jobId).length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {stageLinks(selectedBackendStep, jobId).map((link) => (
                  <Link
                    key={link.label}
                    href={link.href}
                    className="rounded-md border border-[var(--border-subtle)] px-2 py-1 text-[11px] font-medium text-[var(--text-secondary)] hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
                  >
                    {link.label}
                  </Link>
                ))}
              </div>
            ) : null}
          </aside>
        ) : null}
      </div>

      {/* Collapsible timing + activity */}
      <div className="mt-3">
        <button
          type="button"
          onClick={() => setDetailsOpen((open) => !open)}
          aria-expanded={detailsOpen}
          className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
        >
          {detailsOpen ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
          Timing & activity
        </button>

        {detailsOpen ? (
          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                Stage timing
              </p>
              <dl className="mt-2 space-y-1.5">
                {PIPELINE_STEPS.map((step) => {
                  const duration = summary.stepDurationsMs[step.id];
                  const stepStatus = steps.get(step.id)?.status ?? "pending";
                  return (
                    <div
                      key={step.id}
                      className="flex items-center justify-between gap-3 text-xs"
                    >
                      <dt className="text-[var(--text-secondary)]">{step.label}</dt>
                      <dd className="font-mono text-[var(--text-secondary)]">
                        {formatStageDuration(duration, stepStatus, !steps.has(step.id))}
                      </dd>
                    </div>
                  );
                })}
              </dl>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                Recent activity
              </p>
              {recentMessages.length > 0 ? (
                <ul className="mt-2 space-y-1 text-[11px] leading-5 text-[var(--text-secondary)]">
                  {recentMessages.map((message, index) => (
                    <li key={`${jobId}-msg-${index}`} className="truncate">
                      {message}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
                  Step messages appear here as the pipeline runs.
                </p>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
