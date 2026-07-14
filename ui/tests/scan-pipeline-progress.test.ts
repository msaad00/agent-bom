import { describe, expect, it } from "vitest";

import {
  describeWallClock,
  formatDurationMs,
  formatStageDuration,
  jobWallClockMs,
  mergePipelineSteps,
  parsePipelineStepsFromProgress,
  summarizePipeline,
  synthesizePipelineSteps,
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

  it("synthesizes all six stages as done for a finished job with no step events", () => {
    const { steps, synthesized } = synthesizePipelineSteps(new Map(), "done");
    expect(synthesized).toBe(true);
    expect(steps.size).toBe(6);
    for (const step of steps.values()) {
      expect(step.status).toBe("done");
    }

    const summary = summarizePipeline(steps, {
      created_at: "2026-06-27T00:00:00Z",
      completed_at: "2026-06-27T00:00:05Z",
      status: "done",
    });
    expect(summary.completedSteps).toBe(6);
    expect(summary.currentStepLabel).toBeNull();
  });

  it("reports summarized instead of a misleading 0ms wall clock", () => {
    // Synchronous cloud scan: created_at === completed_at → 0ms elapsed.
    expect(
      describeWallClock(0, { synthesized: true }),
    ).toBe("summarized");
    expect(describeWallClock(0)).toBe("summarized");
    expect(describeWallClock(null, { running: true })).toBe("running…");
    expect(describeWallClock(null)).toBe("—");
    expect(describeWallClock(2_000)).toBe("2.0s");
  });

  it("labels summarized stage timing honestly rather than a bare done", () => {
    expect(formatStageDuration(2_000, "done")).toBe("2.0s");
    expect(formatStageDuration(null, "running")).toBe("running…");
    expect(formatStageDuration(null, "done", true)).toBe("summarized");
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
    const done = synthesizePipelineSteps(real, "done");
    expect(done.synthesized).toBe(false);
    expect(done.steps.size).toBe(1);

    const running = synthesizePipelineSteps(new Map(), "running");
    expect(running.synthesized).toBe(false);
    expect(running.steps.size).toBe(0);
  });
});
