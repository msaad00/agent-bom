import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { graphFitViewOptions } from "@/lib/graph-viewport";
import { isCaptureModeSearch, useCaptureMode } from "@/lib/use-capture-mode";

describe("useCaptureMode", () => {
  it("parses capture query strings", () => {
    expect(isCaptureModeSearch("?capture=1")).toBe(true);
    expect(isCaptureModeSearch("?capture=0")).toBe(false);
    expect(isCaptureModeSearch("")).toBe(false);
  });

  it("reads capture mode synchronously on first render", () => {
    window.history.replaceState({}, "", "/mesh?capture=1");

    const { result } = renderHook(() => useCaptureMode());

    expect(result.current).toBe(true);
  });

  it("tracks browser navigation changes", () => {
    window.history.replaceState({}, "", "/mesh?capture=1");
    const { result } = renderHook(() => useCaptureMode());

    act(() => {
      window.history.pushState({}, "", "/mesh");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });

    expect(result.current).toBe(false);
  });

  it("drives capture-ready graph fit options from the initial URL", () => {
    window.history.replaceState({}, "", "/mesh?capture=1");

    const { result } = renderHook(() => {
      const captureMode = useCaptureMode();
      return graphFitViewOptions({ nodeCount: 18, edgeCount: 24, mode: "mesh", captureMode });
    });

    expect(result.current.duration).toBe(0);
    expect(result.current.maxZoom).toBeGreaterThan(
      graphFitViewOptions({ nodeCount: 18, edgeCount: 24, mode: "mesh" }).maxZoom,
    );
  });
});
