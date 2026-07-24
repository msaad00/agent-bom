import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { SEVERITY_HEX } from "@/lib/theme-colors";

const GLOBALS = path.join(process.cwd(), "app/globals.css");

/** Every semantic role the exposure-path board paints. */
const GRAPH_ROLE_TOKENS = [
  "agent",
  "server",
  "package",
  "finding",
  "credential",
  "tool",
  "environment",
  "cluster",
  "unknown",
] as const;

/**
 * Modules that paint the exposure-path board. They render inside a themed card,
 * so a literal hex here renders a near-black slab on a white surface in light
 * mode; all paint must come from CSS custom properties.
 */
const THEMED_GRAPH_SOURCES = [
  "components/exposure-path-command-center.tsx",
  "lib/exposure-path-graph-style.ts",
  "lib/exposure-path-graph-layout.ts",
];

describe("theme readability tokens", () => {
  const css = readFileSync(GLOBALS, "utf8");

  it("defines dark surface hierarchy and readable secondary text", () => {
    // Deep, non-flat canvas with a layered panel < card < elevated hierarchy.
    expect(css).toMatch(/--background:\s*#14161d;/);
    expect(css).toMatch(/--surface-panel:\s*#1b1e27;/);
    expect(css).toMatch(/--surface:\s*#22262f;/);
    expect(css).toMatch(/--surface-elevated:\s*#2c3140;/);
    expect(css).toMatch(/--text-secondary:\s*#d0d4dc;/);
    expect(css).toMatch(/--text-tertiary:\s*#a8aebc;/);
    // Brand accent stays mint; --accent-mint remains as a back-compat alias.
    expect(css).toMatch(/--accent:\s*#34d399;/);
    expect(css).toMatch(/--accent-mint:\s*var\(--accent\);/);
  });

  it("keeps severity CSS vars aligned with shared chart hex helpers", () => {
    for (const [key, hex] of Object.entries(SEVERITY_HEX)) {
      if (key === "none") continue;
      expect(css).toContain(`--severity-${key}: ${hex};`);
    }
    expect(css).toMatch(/--status-success:\s*#34d399;/);
    expect(css).toMatch(/--status-warn:\s*#fbbf24;/);
  });

  it("defines light-theme severity and surface counterparts", () => {
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--background:\s*#e6eaf1;/);
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--severity-critical:\s*#dc2626;/);
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--text-secondary:\s*#374151;/);
  });

  it("binds Tailwind dark utilities to the explicit application theme", () => {
    expect(css).toContain('@custom-variant dark (&:where([data-theme="dark"], [data-theme="dark"] *));');
  });

  it("defines a graph role palette for both themes", () => {
    const light = css.slice(css.indexOf(':root[data-theme="light"]'));
    const dark = css.slice(0, css.indexOf(':root[data-theme="light"]'));
    for (const role of GRAPH_ROLE_TOKENS) {
      expect(dark).toMatch(new RegExp(`--graph-${role}:\\s*#[0-9a-f]{6};`));
      expect(light).toMatch(new RegExp(`--graph-${role}:\\s*#[0-9a-f]{6};`));
    }
  });

  it("keeps the exposure-path board free of hardcoded hex paint", () => {
    for (const source of THEMED_GRAPH_SOURCES) {
      const contents = readFileSync(path.join(process.cwd(), source), "utf8");
      expect(contents.match(/#[0-9a-fA-F]{3,8}\b/g) ?? []).toEqual([]);
    }
  });
});
