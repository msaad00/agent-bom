"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ExternalLink, Loader2 } from "lucide-react";

import { ScanPipeline } from "@/components/scan-pipeline";
import { api, PIPELINE_STEPS, type JobStatus, type ScanJob } from "@/lib/api";
import { useScanStream } from "@/lib/use-scan-stream";
import {
  formatDurationMs,
  mergePipelineSteps,
  parsePipelineStepsFromProgress,
  summarizePipeline,
} from "@/lib/scan-pipeline-progress";

export function JobPipelinePanel({
  jobId,
  status,
  createdAt,
  completedAt,
  className,
}: {
  jobId: string;
  status: JobStatus;
  createdAt: string;
  completedAt?: string | undefined;
  className?: string;
}) {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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

  const steps = useMemo(() => {
    const persisted = parsePipelineStepsFromProgress(job?.progress ?? []);
    return mergePipelineSteps(persisted, liveSteps);
  }, [job?.progress, liveSteps]);

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

  return (
    <div
      className={`rounded-xl border border-zinc-800 bg-zinc-950/80 p-4 ${className ?? ""}`}
      data-testid={`job-pipeline-${jobId}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-emerald-400">
            Scan pipeline DAG
          </p>
          <p className="mt-1 text-sm text-zinc-300">
            {summary.currentStepLabel
              ? `${summary.currentStepLabel} · ${status}`
              : `${summary.completedSteps}/${summary.totalSteps} stages complete`}
            {streaming ? " · live" : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
          <span>
            Wall clock{" "}
            <span className="font-mono text-zinc-300">
              {formatDurationMs(summary.wallClockMs)}
            </span>
          </span>
          <Link
            href={`/scan?id=${encodeURIComponent(jobId)}`}
            className="inline-flex items-center gap-1 rounded-md border border-zinc-700 px-2 py-1 text-[11px] font-medium text-zinc-300 hover:border-zinc-600 hover:text-zinc-100"
          >
            Full scan
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>
      </div>

      {loading && steps.size === 0 ? (
        <div className="mt-4 flex items-center gap-2 text-sm text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading persisted pipeline events…
        </div>
      ) : null}
      {error ? <p className="mt-3 text-sm text-amber-300">{error}</p> : null}

      <div className="mt-4">
        <ScanPipeline steps={steps} className="h-[200px]" />
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
            Stage timing
          </p>
          <dl className="mt-2 space-y-1.5">
            {PIPELINE_STEPS.map((step) => {
              const duration = summary.stepDurationsMs[step.id];
              const stepStatus = steps.get(step.id)?.status ?? "pending";
              return (
                <div key={step.id} className="flex items-center justify-between gap-3 text-xs">
                  <dt className="text-zinc-400">{step.label}</dt>
                  <dd className="font-mono text-zinc-300">
                    {duration != null
                      ? formatDurationMs(duration)
                      : stepStatus === "running"
                        ? "running…"
                        : "—"}
                  </dd>
                </div>
              );
            })}
          </dl>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
            Recent activity
          </p>
          {recentMessages.length > 0 ? (
            <ul className="mt-2 space-y-1 text-[11px] leading-5 text-zinc-400">
              {recentMessages.map((message, index) => (
                <li key={`${jobId}-msg-${index}`} className="truncate">
                  {message}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-[11px] text-zinc-600">
              Step messages appear here as the pipeline runs.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
