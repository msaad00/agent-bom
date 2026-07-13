import type { ReactNode } from "react";

export type StatAccent = "neutral" | "critical" | "high" | "medium" | "info";

const ACCENT_GRADIENT: Record<StatAccent, string> = {
  neutral: "",
  critical: "stat-critical",
  high: "stat-high",
  medium: "stat-medium",
  info: "stat-info",
};

const ACCENT_VALUE: Record<StatAccent, string> = {
  neutral: "text-[color:var(--foreground)]",
  critical: "text-[color:var(--severity-critical)]",
  high: "text-[color:var(--severity-high)]",
  medium: "text-[color:var(--severity-medium)]",
  info: "text-[color:var(--status-success)]",
};

type StatCardProps = {
  label: ReactNode;
  value: ReactNode;
  /** Accent uses the globals.css stat-* gradient tokens for the card wash. */
  accent?: StatAccent;
  /**
   * When the value is a number, only apply the accent value color above this
   * threshold (default 0). Mirrors the prior MiniStat behavior where a zero
   * "Critical" count stays neutral instead of glowing red.
   */
  accentThreshold?: number;
  className?: string;
};

/**
 * Single KPI tile. Replaces ad-hoc stat blocks (e.g. scan-result's MiniStat)
 * with one token-based component that reads the stat-* gradient washes from
 * globals.css and stays theme-aware via CSS vars.
 */
export function StatCard({
  label,
  value,
  accent = "neutral",
  accentThreshold = 0,
  className = "",
}: StatCardProps) {
  const tinted =
    accent !== "neutral" && (typeof value !== "number" || value > accentThreshold);
  const valueClass = tinted ? ACCENT_VALUE[accent] : "text-[color:var(--foreground)]";
  return (
    <div
      className={`rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4 text-center ${ACCENT_GRADIENT[accent]} ${className}`}
    >
      <div className={`font-mono text-2xl font-bold ${valueClass}`}>{value}</div>
      <div className="mt-1 text-xs text-[color:var(--text-tertiary)]">{label}</div>
    </div>
  );
}
