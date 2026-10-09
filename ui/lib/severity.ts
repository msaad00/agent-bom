export const SEVERITY_ORDER: Readonly<Record<string, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
  unknown: -1,
};

export function severityRank(severity: string | null | undefined): number {
  return SEVERITY_ORDER[(severity ?? "unknown").toLowerCase()] ?? -1;
}

// Literal class strings so Tailwind's source scan generates every utility.
const SEVERITY_CHIP_CLASS: Readonly<Record<string, string>> = {
  critical:
    "border-[color:var(--severity-critical-border)] bg-[color:var(--severity-critical-bg)] text-[color:var(--severity-critical)]",
  high: "border-[color:var(--severity-high-border)] bg-[color:var(--severity-high-bg)] text-[color:var(--severity-high)]",
  medium:
    "border-[color:var(--severity-medium-border)] bg-[color:var(--severity-medium-bg)] text-[color:var(--severity-medium)]",
  low: "border-[color:var(--severity-low-border)] bg-[color:var(--severity-low-bg)] text-[color:var(--severity-low)]",
};

const NEUTRAL_CHIP_CLASS =
  "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-tertiary)]";

/** Theme-aware chip classes (text, tint, border) for a severity, from globals.css tokens. */
export function severityChipClass(severity: string | null | undefined): string {
  return SEVERITY_CHIP_CLASS[(severity ?? "").toLowerCase()] ?? NEUTRAL_CHIP_CLASS;
}

export function severityAtOrAbove(severity: string | null | undefined, threshold: string): boolean {
  return severityRank(severity) >= severityRank(threshold);
}
