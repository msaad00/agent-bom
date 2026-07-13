import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { SEVERITY_HEX } from "@/lib/theme-colors";

const GLOBALS = path.join(process.cwd(), "app/globals.css");

describe("theme readability tokens", () => {
  const css = readFileSync(GLOBALS, "utf8");

  it("defines dark surface hierarchy and readable secondary text", () => {
    expect(css).toMatch(/--background:\s*#181a22;/);
    expect(css).toMatch(/--surface:\s*#22262f;/);
    expect(css).toMatch(/--surface-elevated:\s*#2c3140;/);
    expect(css).toMatch(/--text-secondary:\s*#d0d4dc;/);
    expect(css).toMatch(/--text-tertiary:\s*#a8aebc;/);
    expect(css).toMatch(/--accent-mint:\s*#34d399;/);
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
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--background:\s*#e4e9f2;/);
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--severity-critical:\s*#dc2626;/);
    expect(css).toMatch(/:root\[data-theme="light"\][\s\S]*--text-secondary:\s*#374151;/);
  });
});
