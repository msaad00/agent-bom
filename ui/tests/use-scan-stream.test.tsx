import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type SSEEvent } from "@/lib/api";
import { useScanStream } from "@/lib/use-scan-stream";

describe("useScanStream", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("collects progress and step events from the scan stream", () => {
    let emit: ((event: SSEEvent) => void) | undefined;
    let finish: (() => void) | undefined;
    const cleanup = vi.fn();
    const streamSpy = vi.spyOn(api, "streamScan").mockImplementation((_jobId, onMessage, onDone) => {
      emit = onMessage;
      finish = onDone;
      return cleanup;
    });

    const { result, unmount } = renderHook(() => useScanStream("job-123"));

    expect(streamSpy).toHaveBeenCalledWith("job-123", expect.any(Function), expect.any(Function));
    expect(result.current.streaming).toBe(true);

    act(() => {
      emit?.({ type: "progress", message: "discovering local configs" });
    });

    expect(result.current.messages).toEqual(["discovering local configs"]);

    act(() => {
      emit?.({
        type: "step",
        step_id: "scanning",
        status: "running",
        message: "scanning 12 packages",
        progress_pct: 45,
      });
    });

    expect(result.current.messages).toEqual(["discovering local configs", "scanning 12 packages"]);
    expect(result.current.pipelineSteps.get("scanning")?.progress_pct).toBe(45);

    act(() => {
      finish?.();
    });

    expect(result.current.streaming).toBe(false);

    unmount();
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("does not connect when disabled", () => {
    const streamSpy = vi.spyOn(api, "streamScan").mockImplementation(() => vi.fn());

    const { result } = renderHook(() => useScanStream("job-123", { enabled: false }));

    expect(streamSpy).not.toHaveBeenCalled();
    expect(result.current.streaming).toBe(false);
  });
});
