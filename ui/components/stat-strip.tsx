"use client";

import Link from "next/link";
import type { ElementType, ReactNode } from "react";

import { ICON_SIZE } from "@/lib/icon-sizes";

export type StatAccent =
  | "neutral"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "success"
  | "warn";

const ACCENT_VALUE: Record<StatAccent, string> = {
  neutral: "text-[color:var(--foreground)]",
  critical: "text-[color:var(--severity-critical)]",
  high: "text-[color:var(--severity-high)]",
  medium: "text-[color:var(--severity-medium)]",
  low: "text-[color:var(--severity-low)]",
  success: "text-[color:var(--status-success)]",
  warn: "text-[color:var(--status-warn)]",
};

export type StatStripItem = {
  label: ReactNode;
  value: ReactNode;
  /** Optional secondary line (delta, unit, context). */
  hint?: ReactNode;
  accent?: StatAccent;
  /** Only tint the value when it is a number above this threshold. */
  accentThreshold?: number;
  icon?: ElementType;
  /** Makes the cell a link. */
  href?: string;
  /** Makes the cell a button. */
  onClick?: () => void;
};

export type StatStripProps = {
  items: StatStripItem[];
  className?: string | undefined;
  "data-testid"?: string | undefined;
};

/**
 * Dense KPI row — replaces big, empty stat cards with a single compact strip of
 * hairline-divided metrics. Wraps on narrow screens, token-styled for both
 * themes, and each cell can drill in via `href`/`onClick`.
 *
 * @example
 * ```tsx
 * <StatStrip
 *   items={[
 *     { label: "Critical", value: 4, accent: "critical", href: "/findings?sev=critical" },
 *     { label: "High", value: 12, accent: "high" },
 *     { label: "Packages", value: 231 },
 *     { label: "Coverage", value: "92%", accent: "success", hint: "+3 vs last scan" },
 *   ]}
 * />
 * ```
 */
export function StatStrip({ items, className, "data-testid": testId }: StatStripProps) {
  return (
    <div
      className={`grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--border-subtle)] elev-1 sm:grid-cols-3 lg:grid-cols-[repeat(auto-fit,minmax(9rem,1fr))] ${className ?? ""}`}
      data-testid={testId}
    >
      {items.map((item, index) => (
        <StatCell key={typeof item.label === "string" ? item.label : index} item={item} />
      ))}
    </div>
  );
}

function StatCell({ item }: { item: StatStripItem }) {
  const {
    label,
    value,
    hint,
    accent = "neutral",
    accentThreshold = 0,
    icon: Icon,
    href,
    onClick,
  } = item;

  const tinted =
    accent !== "neutral" && (typeof value !== "number" || value > accentThreshold);
  const valueClass = tinted ? ACCENT_VALUE[accent] : "text-[color:var(--foreground)]";

  const inner = (
    <>
      <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em] text-[color:var(--text-tertiary)]">
        {Icon ? <Icon className={ICON_SIZE.xs} aria-hidden="true" /> : null}
        <span className="truncate">{label}</span>
      </div>
      <div className={`mt-1 font-mono text-2xl font-semibold tabular-figures ${valueClass}`}>
        {value}
      </div>
      {hint ? (
        <div className="mt-0.5 truncate text-xs text-[color:var(--text-tertiary)]">{hint}</div>
      ) : null}
    </>
  );

  const base =
    "block bg-[color:var(--surface)] px-4 py-3 text-left transition-colors";

  if (href) {
    return (
      <Link href={href} className={`${base} hover:bg-[color:var(--surface-elevated)]`}>
        {inner}
      </Link>
    );
  }
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={`${base} w-full hover:bg-[color:var(--surface-elevated)]`}
      >
        {inner}
      </button>
    );
  }
  return <div className={base}>{inner}</div>;
}
