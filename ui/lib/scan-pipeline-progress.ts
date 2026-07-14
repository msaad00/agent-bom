import { PIPELINE_STEPS, type JobStatus, type StepEvent, type StepStatus } from "@/lib/api";

const PIPELINE_STEP_IDS = new Set<string>(PIPELINE_STEPS.map((step) => step.id));

export function parsePipelineStepsFromProgress(
  progress: string[],
): Map<string, StepEvent> {
  const steps = new Map<string, StepEvent>();
  for (const line of progress) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as Partial<StepEvent>;
      if (event.type !== "step") continue;
      if (typeof event.step_id !== "string") continue;
      if (!PIPELINE_STEP_IDS.has(event.step_id)) continue;
      steps.set(event.step_id, event as StepEvent);
    } catch {
      // Legacy plain-text progress lines are ignored for DAG replay.
    }
  }
  return steps;
}

export function mergePipelineSteps(
  persisted: Map<string, StepEvent>,
  live: Map<string, StepEvent>,
): Map<string, StepEvent> {
  const merged = new Map(persisted);
  for (const [stepId, step] of live) merged.set(stepId, step);
  return merged;
}

/**
 * Cloud-connection scans (and other non-pipeline jobs) finish without ever
 * emitting the six-stage `step` events, which used to leave a completed job
 * reading "0/6 stages complete" in an all-pending gray DAG. When a job has
 * genuinely finished (`done`) but carries no per-stage events, mark all six
 * stages as done so the DAG honestly reflects a completed run. Jobs that did
 * stream real step events keep their true per-stage states untouched.
 *
 * Returns `synthesized: true` when the stages were inferred rather than
 * observed, so callers can label the timeline as summarized.
 */
export function synthesizePipelineSteps(
  steps: Map<string, StepEvent>,
  status: JobStatus,
): { steps: Map<string, StepEvent>; synthesized: boolean } {
  if (steps.size > 0 || status !== "done") {
    return { steps, synthesized: false };
  }
  const synthesized = new Map<string, StepEvent>();
  for (const step of PIPELINE_STEPS) {
    synthesized.set(step.id, {
      type: "step",
      step_id: step.id,
      status: "done",
      message: "Completed",
    });
  }
  return { steps: synthesized, synthesized: true };
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms == null || ms < 0 || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

/**
 * Honest wall-clock label. A synchronous scan (cloud-connection runs, dry
 * runs) finishes with no streamed timing, so its elapsed time collapses to
 * ~0ms — reporting "0ms" is misleading. Show "summarized" instead of faking a
 * duration, and "running…" while a live scan has no end yet.
 */
export function describeWallClock(
  wallClockMs: number | null | undefined,
  opts: { synthesized?: boolean; running?: boolean } = {},
): string {
  if (opts.synthesized) return "summarized";
  if (wallClockMs == null) return opts.running ? "running…" : "—";
  if (wallClockMs <= 0) return "summarized";
  return formatDurationMs(wallClockMs);
}

/**
 * Honest per-stage timing cell. Real streamed stages show their measured
 * duration; a summarized (synthesized) stage says so rather than claiming a
 * crisp "done" with no numbers behind it.
 */
export function formatStageDuration(
  duration: number | null | undefined,
  status: StepStatus | undefined,
  synthesized = false,
): string {
  if (duration != null) return formatDurationMs(duration);
  if (status === "running") return "running…";
  if (synthesized && (status === "done" || status === "skipped")) return "summarized";
  if (status === "done") return "done";
  if (status === "skipped") return "skipped";
  return "—";
}

export function jobWallClockMs(input: {
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}): number | null {
  const end = input.completed_at;
  if (!end) return null;
  const start = input.started_at ?? input.created_at;
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return null;
  return Math.max(0, endMs - startMs);
}

export function stepDurationMs(step: StepEvent): number | null {
  if (!step.started_at || !step.completed_at) return null;
  const startMs = new Date(step.started_at).getTime();
  const endMs = new Date(step.completed_at).getTime();
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return null;
  return Math.max(0, endMs - startMs);
}

export type PipelineSummary = {
  currentStepId: string | null;
  currentStepLabel: string | null;
  completedSteps: number;
  totalSteps: number;
  wallClockMs: number | null;
  stepDurationsMs: Record<string, number>;
};

export function summarizePipeline(
  steps: Map<string, StepEvent>,
  job: {
    created_at: string;
    started_at?: string | null;
    completed_at?: string | null;
    status: JobStatus;
  },
): PipelineSummary {
  const stepDurationsMs: Record<string, number> = {};
  let completedSteps = 0;
  let currentStepId: string | null = null;
  let currentStepLabel: string | null = null;

  for (const step of PIPELINE_STEPS) {
    const event = steps.get(step.id);
    if (!event) continue;
    const duration = stepDurationMs(event);
    if (duration != null) stepDurationsMs[step.id] = duration;
    if (event.status === "done" || event.status === "skipped") {
      completedSteps += 1;
    }
    if (event.status === "running" || event.status === "failed") {
      currentStepId = step.id;
      currentStepLabel = step.label;
    }
  }

  if (!currentStepId && (job.status === "running" || job.status === "pending")) {
    const next = PIPELINE_STEPS.find((step) => {
      const status = steps.get(step.id)?.status as StepStatus | undefined;
      return !status || status === "pending";
    });
    if (next) {
      currentStepId = next.id;
      currentStepLabel = next.label;
    }
  }

  return {
    currentStepId,
    currentStepLabel,
    completedSteps,
    totalSteps: PIPELINE_STEPS.length,
    wallClockMs: jobWallClockMs(job),
    stepDurationsMs,
  };
}
