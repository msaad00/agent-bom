import { describe, expect, it } from "vitest";

import { PIPELINE_STEPS } from "@/lib/api";

import {
  describeWallClock,
  formatDurationMs,
  formatStageDuration,
  jobWallClockMs,
  mergePipelineSteps,
  parsePipelineStepsFromProgress,
  resolvePipelineTelemetry,
  summarizePipeline,
} from "@/lib/scan-pipeline-progress";

describe("scan-pipeline-progress", () => {
  it("replays the latest event per pipeline step from persisted progress", () => {
    const progress = [
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "running",
        message: "Discovering agents",
        started_at: "2026-06-27T00:00:00Z",
      }),
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "done",
        message: "Found 3 agents",
        started_at: "2026-06-27T00:00:00Z",
        completed_at: "2026-06-27T00:00:05Z",
        stats: { agents: 3 },
      }),
      "legacy plain-text progress line",
    ];

    const steps = parsePipelineStepsFromProgress(progress);
    expect(steps.get("discovery")?.status).toBe("done");
    expect(steps.get("discovery")?.stats).toEqual({ agents: 3 });
  });

  it("merges live SSE steps over persisted replay", () => {
    const persisted = parsePipelineStepsFromProgress([
      JSON.stringify({
        type: "step",
        step_id: "scanning",
        status: "running",
        message: "Querying databases",
        started_at: "2026-06-27T00:00:10Z",
      }),
    ]);
    const live = new Map([
      [
        "scanning",
        {
          type: "step" as const,
          step_id: "scanning",
          status: "done" as const,
          message: "Scan complete",
          started_at: "2026-06-27T00:00:10Z",
          completed_at: "2026-06-27T00:00:20Z",
        },
      ],
    ]);

    const merged = mergePipelineSteps(persisted, live);
    expect(merged.get("scanning")?.status).toBe("done");
  });

  it("summarizes wall clock and per-step durations", () => {
    const steps = parsePipelineStepsFromProgress([
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "done",
        message: "done",
        started_at: "2026-06-27T00:00:00Z",
        completed_at: "2026-06-27T00:00:02Z",
      }),
      JSON.stringify({
        type: "step",
        step_id: "extraction",
        status: "running",
        message: "extracting",
        started_at: "2026-06-27T00:00:02Z",
      }),
    ]);

    const summary = summarizePipeline(steps, {
      created_at: "2026-06-27T00:00:00Z",
      started_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:30Z",
      status: "running",
    });

    expect(summary.completedSteps).toBe(1);
    expect(summary.currentStepLabel).toBe("Extraction");
    expect(summary.wallClockMs).toBe(30_000);
    expect(summary.stepDurationsMs.discovery).toBe(2_000);
    expect(formatDurationMs(2_000)).toBe("2.0s");
    expect(jobWallClockMs({
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:30Z",
    })).toBe(30_000);
  });

  it("marks finished jobs without step events unavailable instead of fabricating stages", () => {
    const { steps, state } = resolvePipelineTelemetry(new Map(), "done");
    expect(state).toBe("unavailable");
    expect(steps.size).toBe(0);

    const summary = summarizePipeline(steps, {
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:05Z",
      status: "done",
    });
    expect(summary.completedSteps).toBe(0);
    expect(summary.currentStepLabel).toBeNull();
  });

  it("distinguishes partial telemetry from a complete observed pipeline", () => {
    const partial = resolvePipelineTelemetry(
      parsePipelineStepsFromProgress([
        JSON.stringify({ type: "step", step_id: "discovery", status: "done", message: "done" }),
      ]),
      "done",
    );
    expect(partial.state).toBe("partial");

    const observed = resolvePipelineTelemetry(
      new Map(
        PIPELINE_STEPS.map((step) => [
          step.id,
          { type: "step" as const, step_id: step.id, status: "done" as const, message: "done" },
        ]),
      ),
      "done",
    );
    expect(observed.state).toBe("observed");
  });

  it("reports unavailable instead of a misleading 0ms wall clock", () => {
    // Synchronous cloud scan: created_at === completed_at → 0ms elapsed.
    expect(
      describeWallClock(0, { unavailable: true }),
    ).toBe("Unavailable");
    expect(describeWallClock(0)).toBe("Unavailable");
    expect(describeWallClock(null, { running: true })).toBe("running…");
    expect(describeWallClock(null)).toBe("—");
    expect(describeWallClock(2_000)).toBe("2.0s");
  });

  it("labels unavailable stage timing honestly rather than a bare done", () => {
    expect(formatStageDuration(2_000, "done")).toBe("2.0s");
    expect(formatStageDuration(null, "running")).toBe("running…");
    expect(formatStageDuration(null, "done", true)).toBe("Unavailable");
    expect(formatStageDuration(null, "done", false)).toBe("done");
    expect(formatStageDuration(null, "skipped", false)).toBe("skipped");
    expect(formatStageDuration(null, "pending")).toBe("—");
  });

  it("leaves real step events untouched and does not synthesize while running", () => {
    const real = parsePipelineStepsFromProgress([
      JSON.stringify({
        type: "step",
        step_id: "discovery",
        status: "done",
        message: "Found 3 agents",
      }),
    ]);
    const done = resolvePipelineTelemetry(real, "done");
    expect(done.state).toBe("partial");
    expect(done.steps.size).toBe(1);

    const running = resolvePipelineTelemetry(new Map(), "running");
    expect(running.state).toBe("unavailable");
    expect(running.steps.size).toBe(0);
  });
});
