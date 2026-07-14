import { readFileSync } from "node:fs";
import path from "node:path";

import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { getChartTheme, useChartTheme } from "@/lib/theme-colors";

// Chart chrome (tooltips/axes/grids) and series fills are JS style props, so
// the class-based light-theme sweep could not reach them. They must instead be
// driven off the CSS tokens in globals.css so they render legibly in BOTH
// themes and follow the light/dark toggle. These tests lock that contract in.

const UI_ROOT = process.cwd();

// Chart surfaces whose Recharts style props must be fully tokenized — no raw
// hex chrome or series colors may creep back in.
const TOKENIZED_CHART_FILES = [
  "app/fleet/page.tsx",
  "app/gateway/GatewayDashboard.tsx",
  "app/activity/page.tsx",
  "app/governance/page.tsx",
  "app/proxy/ProxyDashboard.tsx",
] as const;

const HEX_LITERAL = /#[0-9a-fA-F]{6}\b/g;

function resetRoot() {
  const root = document.documentElement;
  root.removeAttribute("data-theme");
  root.removeAttribute("style");
  try {
    window.localStorage.clear();
  } catch {
    // ignore
  }
}

afterEach(resetRoot);

describe("getChartTheme", () => {
  it("exposes chrome, severity, status and accent color maps", () => {
    const theme = getChartTheme();
    expect(theme).toMatchObject({
      bg: expect.any(String),
      border: expect.any(String),
      grid: expect.any(String),
      text: expect.any(String),
      accent: expect.any(String),
      severity: {
        critical: expect.any(String),
        high: expect.any(String),
        medium: expect.any(String),
        low: expect.any(String),
        unrated: expect.any(String),
      },
      status: {
        success: expect.any(String),
        warn: expect.any(String),
        danger: expect.any(String),
      },
      tooltip: {
        bg: expect.any(String),
        border: expect.any(String),
        text: expect.any(String),
      },
    });
  });

  it("reads live CSS token values instead of a baked palette", () => {
    const root = document.documentElement;
    root.style.setProperty("--surface", "rgb(255, 255, 255)");
    root.style.setProperty("--severity-critical", "rgb(220, 38, 38)");
    root.style.setProperty("--accent-mint", "rgb(5, 150, 105)");

    const theme = getChartTheme();
    expect(theme.bg).toBe("rgb(255, 255, 255)");
    expect(theme.severity.critical).toBe("rgb(220, 38, 38)");
    expect(theme.accent).toBe("rgb(5, 150, 105)");
  });
});

describe("useChartTheme", () => {
  it("re-reads token values when the theme mode toggles", () => {
    const root = document.documentElement;
    root.style.setProperty("--surface", "rgb(34, 38, 47)");

    const { result } = renderHook(() => useChartTheme());
    expect(result.current.bg).toBe("rgb(34, 38, 47)");

    act(() => {
      // Mirror ThemeToggle.applyTheme: flip the mode + swap the token, then
      // notify subscribers. The hook must re-render and read the new value.
      root.dataset.theme = "light";
      root.style.setProperty("--surface", "rgb(255, 255, 255)");
      window.dispatchEvent(new Event("agent-bom-theme-change"));
    });

    expect(result.current.bg).toBe("rgb(255, 255, 255)");
  });
});

describe("chart hex regression guard", () => {
  it("keeps tokenized chart surfaces free of raw hex style props", () => {
    const violations: string[] = [];
    for (const rel of TOKENIZED_CHART_FILES) {
      const source = readFileSync(path.join(UI_ROOT, rel), "utf8");
      for (const match of source.matchAll(HEX_LITERAL)) {
        violations.push(`${rel}: ${match[0]}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("keeps the graph minimap background on a theme token", () => {
    const source = readFileSync(path.join(UI_ROOT, "lib/graph-utils.ts"), "utf8");
    expect(source).toMatch(/export const MINIMAP_BG = "var\(--[\w-]+\)";/);
  });
});
