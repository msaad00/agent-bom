/**
 * The two overview renderers a large estate falls back to painted a fixed
 * near-black stage (`#050505`) with near-white labels (`#e4e4e7`), regardless
 * of theme. In light mode the rest of the page is `#e6eaf1` and the graph —
 * the largest element on the screen — was a black hole with its own private
 * palette. Canvas and WebGL cannot use CSS classes, so they have to read the
 * tokens at runtime and re-read them when the theme flips.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
  getGraphCanvasPalette,
  useGraphCanvasPalette,
} from "@/lib/graph-canvas-theme";

const UI_ROOT = process.cwd();

const CANVAS_SURFACES = [
  "components/large-graph-overview.tsx",
  "components/sigma-graph-overview.tsx",
] as const;

/** Raw hex paint. Tailwind's own `#`-free utilities are unaffected. */
const HEX_LITERAL = /#[0-9a-fA-F]{3,8}\b/g;

const TOKENS = [
  "--background",
  "--foreground",
  "--text-tertiary",
  "--text-secondary",
];

afterEach(() => {
  const root = document.documentElement;
  for (const token of TOKENS) root.style.removeProperty(token);
  delete root.dataset.theme;
});

describe("getGraphCanvasPalette", () => {
  it("paints the stage with the page background, not a private black", () => {
    document.documentElement.style.setProperty("--background", "rgb(230, 234, 241)");
    expect(getGraphCanvasPalette().stage).toBe("rgb(230, 234, 241)");
  });

  it("takes every colour from a live token so light and dark both track", () => {
    const root = document.documentElement;
    root.style.setProperty("--background", "rgb(230, 234, 241)");
    root.style.setProperty("--foreground", "rgb(18, 20, 26)");
    root.style.setProperty("--text-tertiary", "rgb(85, 98, 122)");
    root.style.setProperty("--text-secondary", "rgb(55, 65, 81)");

    const palette = getGraphCanvasPalette();
    expect(palette).toEqual({
      stage: "rgb(230, 234, 241)",
      label: "rgb(18, 20, 26)",
      selected: "rgb(18, 20, 26)",
      dimmed: "rgb(85, 98, 122)",
      defaultNode: "rgb(85, 98, 122)",
      defaultEdge: "rgb(55, 65, 81)",
    });
  });

  it("falls back to real token values, per theme, when none are computed yet", () => {
    // Server render / detached document. A single dark fallback set would
    // flash a black stage on a light first paint, which is the very defect
    // this replaces.
    const dark = getGraphCanvasPalette("dark");
    const light = getGraphCanvasPalette("light");
    for (const value of [...Object.values(dark), ...Object.values(light)]) {
      expect(value).toMatch(/^#[0-9a-f]{6}$/);
    }
    expect(light.stage).not.toBe(dark.stage);
    expect(light.label).not.toBe(dark.label);
  });
});

describe("useGraphCanvasPalette", () => {
  it("re-reads the tokens the moment the theme toggles", () => {
    const root = document.documentElement;
    root.style.setProperty("--background", "rgb(20, 22, 29)");

    const { result } = renderHook(() => useGraphCanvasPalette());
    expect(result.current.stage).toBe("rgb(20, 22, 29)");

    act(() => {
      root.dataset.theme = "light";
      root.style.setProperty("--background", "rgb(230, 234, 241)");
      window.dispatchEvent(new Event("agent-bom-theme-change"));
    });

    expect(result.current.stage).toBe("rgb(230, 234, 241)");
  });
});

describe("large graph surfaces carry no dark-only paint", () => {
  it("keeps every colour on a token in both overview renderers", () => {
    const violations: string[] = [];
    for (const rel of CANVAS_SURFACES) {
      const source = readFileSync(path.join(UI_ROOT, rel), "utf8");
      for (const match of source.matchAll(HEX_LITERAL)) {
        violations.push(`${rel}: ${match[0]}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("keeps the stage itself off a hardcoded backdrop class", () => {
    for (const rel of CANVAS_SURFACES) {
      const source = readFileSync(path.join(UI_ROOT, rel), "utf8");
      expect(source, rel).not.toMatch(/bg-\[#/);
      expect(source, rel).toContain("useGraphCanvasPalette");
    }
  });
});
