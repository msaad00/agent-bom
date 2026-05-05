import { describe, expect, it } from "vitest";

import {
  LOD_CLUSTER_MAX_ZOOM,
  LOD_CLUSTER_MIN_COLLAPSED_SHARE,
  LOD_SUMMARY_MAX_ZOOM,
  effectiveLodBandForGraph,
  lodBandForZoom,
} from "@/lib/lod-renderer";

describe("lodBandForZoom", () => {
  it("returns cluster band below the cluster threshold", () => {
    expect(lodBandForZoom(0.1)).toBe("cluster");
    expect(lodBandForZoom(0.39)).toBe("cluster");
    expect(lodBandForZoom(LOD_CLUSTER_MAX_ZOOM - 0.001)).toBe("cluster");
  });

  it("returns summary band between cluster and summary thresholds", () => {
    expect(lodBandForZoom(LOD_CLUSTER_MAX_ZOOM)).toBe("summary");
    expect(lodBandForZoom(0.5)).toBe("summary");
    expect(lodBandForZoom(0.99)).toBe("summary");
  });

  it("returns detail band at and above the summary threshold", () => {
    expect(lodBandForZoom(LOD_SUMMARY_MAX_ZOOM)).toBe("detail");
    expect(lodBandForZoom(1.5)).toBe("detail");
    expect(lodBandForZoom(2.5)).toBe("detail");
  });

  it("treats non-finite zoom as cluster band (defensive default)", () => {
    // NaN / Infinity / negative zoom should never crash the band swap;
    // we fall back to the safest renderer (cluster bubble).
    expect(lodBandForZoom(Number.NaN)).toBe("cluster");
    expect(lodBandForZoom(Number.POSITIVE_INFINITY)).toBe("cluster");
    expect(lodBandForZoom(-1)).toBe("cluster");
  });
});

describe("effectiveLodBandForGraph", () => {
  it("keeps labeled summary rendering when cluster aggregation did not collapse nodes", () => {
    expect(
      effectiveLodBandForGraph("cluster", {
        sourceNodeCount: 120,
        renderedNodeCount: 120,
        clusterCount: 0,
      }),
    ).toBe("summary");
  });

  it("keeps labeled summary rendering when aggregation collapse is too small", () => {
    const sourceNodeCount = 100;
    const renderedNodeCount = sourceNodeCount - Math.floor(sourceNodeCount * (LOD_CLUSTER_MIN_COLLAPSED_SHARE / 2));

    expect(
      effectiveLodBandForGraph("cluster", {
        sourceNodeCount,
        renderedNodeCount,
        clusterCount: 2,
      }),
    ).toBe("summary");
  });

  it("uses cluster rendering once aggregation materially compresses the graph", () => {
    expect(
      effectiveLodBandForGraph("cluster", {
        sourceNodeCount: 100,
        renderedNodeCount: 60,
        clusterCount: 4,
      }),
    ).toBe("cluster");
  });

  it("does not rewrite summary or detail bands", () => {
    expect(
      effectiveLodBandForGraph("summary", {
        sourceNodeCount: 100,
        renderedNodeCount: 50,
        clusterCount: 4,
      }),
    ).toBe("summary");
    expect(
      effectiveLodBandForGraph("detail", {
        sourceNodeCount: 100,
        renderedNodeCount: 50,
        clusterCount: 4,
      }),
    ).toBe("detail");
  });
});
