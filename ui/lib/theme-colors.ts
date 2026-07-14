/**
 * Shared theme color helpers for SVG/canvas surfaces that cannot use CSS
 * class tokens directly. Hex fallbacks must stay aligned with
 * `ui/app/globals.css` severity and surface variables.
 */

import { useThemeMode } from "./theme-mode";

export const SEVERITY_HEX = {
  critical: "#ff6b6b",
  high: "#ff9f4a",
  medium: "#f0c84a",
  low: "#6ba3ff",
  none: "#8b93a7",
} as const;

export type SeverityHexKey = keyof typeof SEVERITY_HEX;

export function severityHex(severity: string | null | undefined): string {
  const key = String(severity ?? "none").toLowerCase() as SeverityHexKey;
  return SEVERITY_HEX[key] ?? SEVERITY_HEX.none;
}

export function readThemeColor(varName: string, fallback: string): string {
  if (typeof document === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
  return value || fallback;
}

/**
 * Recharts/SVG chrome + data colors — reads live CSS vars so light/dark stay
 * aligned. `bg`/`border`/`grid`/`text`/`tooltip` style the chart chrome; the
 * `severity`/`status`/`accent` maps drive series fills off the same tokens so
 * bars, pies, and areas track the theme instead of a hardcoded dark palette.
 */
export function getChartTheme() {
  return {
    bg: readThemeColor("--surface", "#22262f"),
    border: readThemeColor("--border-subtle", "rgba(110, 118, 138, 0.78)"),
    grid: readThemeColor("--border-subtle", "rgba(110, 118, 138, 0.78)"),
    text: readThemeColor("--text-tertiary", "#a8aebc"),
    accent: readThemeColor("--accent-mint", "#34d399"),
    severity: {
      critical: readThemeColor("--severity-critical", SEVERITY_HEX.critical),
      high: readThemeColor("--severity-high", SEVERITY_HEX.high),
      medium: readThemeColor("--severity-medium", SEVERITY_HEX.medium),
      low: readThemeColor("--severity-low", SEVERITY_HEX.low),
      unrated: readThemeColor("--severity-unrated", SEVERITY_HEX.none),
    },
    status: {
      success: readThemeColor("--status-success", "#34d399"),
      warn: readThemeColor("--status-warn", "#fbbf24"),
      danger: readThemeColor("--status-danger", SEVERITY_HEX.critical),
    },
    tooltip: {
      bg: readThemeColor("--surface-elevated", "#2c3140"),
      border: readThemeColor("--border-strong", "rgba(140, 148, 168, 0.92)"),
      text: readThemeColor("--foreground", "#f4f5f8"),
    },
  };
}

export type ChartTheme = ReturnType<typeof getChartTheme>;

/**
 * Hook variant of {@link getChartTheme}. Subscribes to the theme mode so any
 * chart reading these colors re-renders (and re-reads the CSS vars) the moment
 * the user flips light/dark — a bare `getChartTheme()` call would otherwise
 * keep stale chrome until the next data-driven render.
 */
export function useChartTheme(): ChartTheme {
  useThemeMode();
  return getChartTheme();
}
