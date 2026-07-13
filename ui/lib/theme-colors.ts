/**
 * Shared theme color helpers for SVG/canvas surfaces that cannot use CSS
 * class tokens directly. Hex fallbacks must stay aligned with
 * `ui/app/globals.css` severity and surface variables.
 */

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

/** Recharts/SVG chrome — reads live CSS vars so light/dark stay aligned. */
export function getChartTheme() {
  return {
    bg: readThemeColor("--surface", "#22262f"),
    border: readThemeColor("--border-subtle", "rgba(110, 118, 138, 0.78)"),
    grid: readThemeColor("--border-subtle", "rgba(110, 118, 138, 0.78)"),
    text: readThemeColor("--text-tertiary", "#a8aebc"),
    tooltip: {
      bg: readThemeColor("--surface-elevated", "#2c3140"),
      border: readThemeColor("--border-strong", "rgba(140, 148, 168, 0.92)"),
      text: readThemeColor("--foreground", "#f4f5f8"),
    },
  };
}
