"use client";

import Link from "next/link";
import { useState } from "react";

export interface PostureDimension {
  score: number;
  label: string;
  details?: string;
}

interface PostureGradeProps {
  grade: string;  // A, B, C, D, F, or N/A
  score: number;  // 0-100
  dimensions?: Record<string, PostureDimension>;
  drilldown?: boolean;
  summary?: string;
  variant?: "compact" | "panel";
  defaultExpanded?: boolean;
}

export function postureDimensionTone(score: number) {
  if (score >= 80) {
    return {
      label: "strong",
      badge: "border border-emerald-800 bg-emerald-950/60 text-emerald-300",
      bar: "bg-emerald-500",
    };
  }
  if (score >= 60) {
    return {
      label: "watch",
      badge: "border border-yellow-800 bg-yellow-950/60 text-yellow-300",
      bar: "bg-yellow-500",
    };
  }
  return {
    label: "critical",
    badge: "border border-red-800 bg-red-950/60 text-red-300",
    bar: "bg-red-500",
  };
}

export function postureDimensionHref(key: string, label: string) {
  const text = `${key} ${label}`.toLowerCase();
  if (text.includes("vuln") || text.includes("package") || text.includes("fix")) return "/findings";
  if (text.includes("credential") || text.includes("tool")) return "/mesh";
  if (text.includes("agent") || text.includes("server")) return "/agents";
  if (text.includes("trust") || text.includes("framework") || text.includes("compliance")) return "/compliance";
  if (text.includes("runtime") || text.includes("proxy") || text.includes("watch")) return "/proxy";
  return "/graph";
}

export function postureDimensionHint(key: string, label: string) {
  const text = `${key} ${label}`.toLowerCase();
  if (text.includes("vuln") || text.includes("package")) return "packages and CVEs";
  if (text.includes("credential") || text.includes("tool")) return "reach and exposure";
  if (text.includes("agent") || text.includes("server")) return "discovery and trust";
  if (text.includes("trust") || text.includes("framework") || text.includes("compliance")) return "policy and controls";
  if (text.includes("runtime") || text.includes("proxy")) return "live telemetry";
  return "open evidence";
}

export function PostureGrade({
  grade,
  score,
  dimensions,
  drilldown = false,
  summary,
  variant = "compact",
  defaultExpanded = false,
}: PostureGradeProps) {
  // Color based on grade — matches architecture diagram semantics
  const gradeColor = {
    A: "#3fb950", // green  — output/governance layer
    B: "#58a6ff", // blue   — discover layer
    C: "#d29922", // amber  — analyze layer
    D: "#f97316", // orange — degraded
    F: "#f85149", // red    — scan/critical layer
  }[grade] ?? "#71717a";

  // SVG radial progress ring (120px)
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (score / 100) * circumference;
  const orderedDimensions = Object.entries(dimensions ?? {})
    .sort((left, right) => right[1].score - left[1].score)
    .slice(0, 6);
  const [expanded, setExpanded] = useState(defaultExpanded);

  if (variant === "panel") {
    return (
      <div
        className="rounded-2xl border p-5"
        style={{ backgroundColor: "var(--surface)", borderColor: "var(--border-subtle)" }}
      >
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start">
          <div className="flex shrink-0 items-center gap-4 lg:min-w-[180px]">
            <div className="relative h-[108px] w-[108px]">
              <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
                <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--border-subtle)" strokeWidth="8" />
                <circle cx="60" cy="60" r={radius} fill="none" stroke={gradeColor} strokeWidth="8"
                  strokeDasharray={circumference} strokeDashoffset={dashOffset}
                  strokeLinecap="round" className="transition-all duration-700" />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold" style={{ color: gradeColor }}>{grade}</span>
                <span className="text-xs text-[var(--text-tertiary)]">{score}/100</span>
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                Security posture
              </div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-semibold" style={{ color: gradeColor }}>
                  {grade}
                </span>
                <span
                  className="rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.14em] text-[var(--text-secondary)]"
                  style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
                >
                  {score.toFixed(1)} / 100
                </span>
              </div>
              <div className="text-xs text-[var(--text-tertiary)]">
                Unified score with evidence drilldown
              </div>
            </div>
          </div>
          <div className="min-w-0 flex-1 space-y-4">
            {summary && (
              <p className="text-sm leading-6 text-[var(--text-secondary)]">{summary}</p>
            )}
            {orderedDimensions.length > 0 && (
              <>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {orderedDimensions.map(([key, dim]) => (
                    <CompactDimensionCard
                      key={key}
                      dimensionKey={key}
                      dimension={dim}
                      drilldown={drilldown}
                    />
                  ))}
                </div>
                <div className="border-t border-[var(--border-subtle)] pt-4">
                  <button
                    type="button"
                    onClick={() => setExpanded((current) => !current)}
                    className="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--foreground)]"
                    style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
                  >
                    {expanded ? "Hide evidence breakdown" : "Show evidence breakdown"}
                  </button>
                </div>
                {expanded && (
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                    {orderedDimensions.map(([key, dim]) => (
                      <DimensionRow
                        key={key}
                        dimensionKey={key}
                        dimension={dim}
                        drilldown={drilldown}
                      />
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative w-[120px] h-[120px]">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--border-subtle)" strokeWidth="8" />
          <circle cx="60" cy="60" r={radius} fill="none" stroke={gradeColor} strokeWidth="8"
            strokeDasharray={circumference} strokeDashoffset={dashOffset}
            strokeLinecap="round" className="transition-all duration-700" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color: gradeColor }}>{grade}</span>
          <span className="text-xs text-[var(--text-tertiary)]">{score}/100</span>
        </div>
      </div>
      {orderedDimensions.length > 0 && (
        <div
          className="w-full min-w-[240px] max-w-sm rounded-2xl border p-3"
          style={{ backgroundColor: "var(--surface)", borderColor: "var(--border-subtle)" }}
        >
          <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
            Score breakdown
          </div>
          <div className="space-y-2">
            {orderedDimensions.map(([key, dim]) => (
              <DimensionRow
                key={key}
                dimensionKey={key}
                dimension={dim}
                drilldown={drilldown}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CompactDimensionCard({
  dimensionKey,
  dimension,
  drilldown,
}: {
  dimensionKey: string;
  dimension: PostureDimension;
  drilldown: boolean;
}) {
  const tone = postureDimensionTone(dimension.score);
  const content = (
    <>
      <div className="flex items-center justify-between gap-3">
        <span className="truncate text-xs font-medium text-zinc-200">{dimension.label}</span>
        <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${tone.badge}`}>
          {tone.label}
        </span>
      </div>
      <div className="mt-2 flex items-baseline justify-between gap-3">
        <span className="font-mono text-lg text-zinc-100">{dimension.score}/100</span>
        <span className="text-[11px] text-[var(--text-tertiary)]">{postureDimensionHint(dimensionKey, dimension.label)}</span>
      </div>
      <div className="mt-2 h-1.5 rounded-full bg-[var(--surface-muted)]">
        <div
          className={`h-full rounded-full transition-all duration-500 ${tone.bar}`}
          style={{ width: `${dimension.score}%` }}
        />
      </div>
    </>
  );

  if (drilldown) {
    return (
      <Link
        href={postureDimensionHref(dimensionKey, dimension.label)}
        className="block rounded-xl border px-3 py-3 transition-colors hover:border-[var(--border-strong)]"
        style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
      >
        {content}
      </Link>
    );
  }

  return (
    <div
      className="rounded-xl border px-3 py-3"
      style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
    >
      {content}
    </div>
  );
}

function DimensionRow({
  dimensionKey,
  dimension,
  drilldown,
}: {
  dimensionKey: string;
  dimension: PostureDimension;
  drilldown: boolean;
}) {
  const tone = postureDimensionTone(dimension.score);
  const content = (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-zinc-300">{dimension.label}</span>
        <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${tone.badge}`}>
          {tone.label}
        </span>
      </div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-xs text-[var(--text-secondary)]">{dimension.score}/100</span>
        <span className="text-[11px] text-[var(--text-tertiary)]">{postureDimensionHint(dimensionKey, dimension.label)}</span>
      </div>
      {dimension.details && (
        <p className="text-[11px] leading-5 text-[var(--text-tertiary)]">{dimension.details}</p>
      )}
      <div className="h-1.5 rounded-full bg-[var(--surface-muted)]">
        <div
          className={`h-full rounded-full transition-all duration-500 ${tone.bar}`}
          style={{
            width: `${dimension.score}%`,
          }}
        />
      </div>
    </div>
  );

  if (drilldown) {
    return (
      <Link
        href={postureDimensionHref(dimensionKey, dimension.label)}
        className="block rounded-xl border px-3 py-2.5 transition-colors hover:border-[var(--border-strong)]"
        style={{ backgroundColor: "var(--surface-elevated)", borderColor: "var(--border-subtle)" }}
      >
        {content}
      </Link>
    );
  }

  return (
    <div className="rounded-xl border border-transparent px-3 py-2.5">
      {content}
    </div>
  );
}
