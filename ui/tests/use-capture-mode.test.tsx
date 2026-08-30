import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { graphFitViewOptions } from "@/lib/graph-viewport";
import {
  isCaptureModeSearch,
  isReferenceEvidenceLabSearch,
  useCaptureMode,
  useReferenceEvidenceLabMode,
} from "@/lib/use-capture-mode";

describe("useCaptureMode", () => {
  it("parses capture query strings", () => {
    expect(isCaptureModeSearch("?capture=1")).toBe(true);
    expect(isCaptureModeSearch("?capture=0")).toBe(false);
    expect(isCaptureModeSearch("")).toBe(false);
  });

  it("recognizes only the committed reference evidence correlation", () => {
    expect(
      isReferenceEvidenceLabSearch(
        "?capture=1&scan=reference-evidence-correlation-v1&cve=CVE-2023-4863",
      ),
    ).toBe(true);
    expect(isReferenceEvidenceLabSearch("?capture=1&scan=scan-proof-ai-platform")).toBe(false);
    expect(isReferenceEvidenceLabSearch("?scan=reference-evidence-correlation-v1")).toBe(false);
  });

  it("tracks reference-lab capture navigation", async () => {
    window.history.replaceState(
      {},
      "",
      "/security-graph?capture=1&scan=reference-evidence-correlation-v1",
    );
    const { result } = renderHook(() => useReferenceEvidenceLabMode());

    await waitFor(() => {
      expect(result.current).toBe(true);
    });

    act(() => {
      window.history.pushState({}, "", "/security-graph?capture=1&scan=scan-proof-ai-platform");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    expect(result.current).toBe(false);
  });

  it("reads capture mode after mount", async () => {
    window.history.replaceState({}, "", "/mesh?capture=1");

    const { result } = renderHook(() => useCaptureMode());

    await waitFor(() => {
      expect(result.current).toBe(true);
    });
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
