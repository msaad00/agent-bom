import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { severityChipClass } from "@/lib/severity";
import { findingStatusClass } from "@/lib/findings-view";

const UI_ROOT = process.cwd();
const SCAN_DIRS = ["app", "components", "lib", "hooks"];

// A warm-hue -950 background without a `dark:` variant paints a near-black (or,
// with an alpha suffix, a muddy mid-tone) slab behind red/orange/amber text in
// the light theme — the severity chips axe flagged as unreadable.
const DARK_ONLY_WARM_BG =
  /(?:^|[\s"'`([{])(?![\w-]*dark:)(?:[\w-]+:)*bg-(?:red|orange|yellow|amber)-950(?:\/\d+)?\b/g;

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out = out.concat(walk(full));
    else if (/\.(tsx?|jsx?|css)$/.test(entry)) out.push(full);
  }
  return out;
}

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.replace("#", ""), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function luminance([r, g, b]: [number, number, number]): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(a: [number, number, number], b: [number, number, number]): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

function lightBlock(css: string): string {
  const start = css.indexOf(':root[data-theme="light"]');
  return css.slice(start, css.indexOf("}", start));
}

describe("severity chip tokens", () => {
  it("has no dark-only warm -950 backgrounds anywhere in the UI source", () => {
    const violations: string[] = [];
    for (const dir of SCAN_DIRS) {
      for (const file of walk(path.join(UI_ROOT, dir))) {
        const source = readFileSync(file, "utf8");
        for (const match of source.matchAll(DARK_ONLY_WARM_BG)) {
          violations.push(`${path.relative(UI_ROOT, file)}: ${match[0].trim()}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("keeps light-theme severity text at AA contrast on its own chip tint", () => {
    const light = lightBlock(readFileSync(path.join(UI_ROOT, "app/globals.css"), "utf8"));
    for (const sev of ["critical", "high", "medium", "low"]) {
      const fg = light.match(new RegExp(`--severity-${sev}:\\s*(#[0-9a-f]{6});`))?.[1];
      const bg = light.match(
        new RegExp(`--severity-${sev}-bg:\\s*rgba\\((\\d+),\\s*(\\d+),\\s*(\\d+),\\s*([\\d.]+)\\)`),
      );
      expect(fg, sev).toBeDefined();
      expect(bg, sev).not.toBeNull();
      const alpha = Number(bg![4]);
      // Composite the tint over the white card surface.
      const tint = [1, 2, 3].map((i) => Math.round(Number(bg![i]) * alpha + 255 * (1 - alpha))) as [
        number,
        number,
        number,
      ];
      expect(contrast(hexToRgb(fg!), tint), sev).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("builds chip classes from theme tokens, never raw dark palette steps", () => {
    for (const sev of ["critical", "high", "medium", "low"] as const) {
      const cls = severityChipClass(sev);
      expect(cls).toContain(`var(--severity-${sev})`);
      expect(cls).toContain(`var(--severity-${sev}-bg)`);
      expect(cls).toContain(`var(--severity-${sev}-border)`);
      expect(cls).not.toMatch(/-950/);
    }
    expect(severityChipClass("unknown")).toContain("var(--text-tertiary)");
  });

  it("renders finding lifecycle chips readable in both themes", () => {
    for (const status of ["open", "resolved", "reopened"]) {
      const cls = findingStatusClass(status);
      for (const token of cls.split(/\s+/)) {
        if (/-950\b/.test(token)) expect(token.startsWith("dark:"), `${status}: ${token}`).toBe(true);
      }
    }
  });
});
