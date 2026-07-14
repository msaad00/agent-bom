"use client";

import { Activity, AlertTriangle, GitBranch, Network, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { GraphUxDimension, GraphUxEvaluation } from "@/lib/graph-ux-evaluation";

interface GraphEvaluationSummaryProps {
  evaluation: GraphUxEvaluation;
}

const dimensionIcon = {
  entities: Network,
  relationships: GitBranch,
  paths: Activity,
  evidence: ShieldCheck,
  readability: Network,
} satisfies Record<GraphUxDimension["id"], LucideIcon>;

export function GraphEvaluationSummary({ evaluation }: GraphEvaluationSummaryProps) {
  const gradeClass = gradeTone(evaluation.grade);
  return (
    <section
      aria-label="Graph evaluation"
      className="mt-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/70 p-3"
      data-testid="graph-evaluation-summary"
    >
      <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-[0.22em] text-emerald-400">Graph evaluation</span>
            <span className={`rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${gradeClass}`}>
              {evaluation.grade}
            </span>
          </div>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-[var(--text-secondary)]">
            Scores whether this graph view has enough entity variety, relationships, path signal, evidence, and readable rendering for review.
          </p>
        </div>
        <div className="flex shrink-0 items-baseline gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/70 px-3 py-2">
          <span className="text-2xl font-semibold tabular-nums text-[var(--foreground)]">{Math.round(evaluation.score)}</span>
          <span className="text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">score</span>
        </div>
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        {evaluation.dimensions.map((dimension) => {
          const Icon = dimensionIcon[dimension.id];
          return (
            <div key={dimension.id} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/60 p-2.5">
              <div className="flex items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <Icon className="h-3.5 w-3.5 shrink-0 text-[var(--text-tertiary)]" />
                  <span className="truncate text-xs font-medium text-[var(--foreground)]">{dimension.label}</span>
                </div>
                <span className="text-xs font-semibold tabular-nums text-[var(--foreground)]">{Math.round(dimension.score)}</span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-elevated)]">
                <div
                  className={`h-full rounded-full ${barTone(dimension.score)}`}
                  style={{ width: `${Math.max(6, Math.min(100, dimension.score))}%` }}
                />
              </div>
              <p className="mt-2 break-words text-[11px] leading-4 text-[var(--text-tertiary)]">{dimension.detail}</p>
            </div>
          );
        })}
      </div>

      {evaluation.warnings.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {evaluation.warnings.slice(0, 3).map((warning) => (
            <span
              key={warning}
              className="inline-flex max-w-full items-start gap-1.5 rounded-lg border border-amber-500/25 bg-amber-500/10 px-2.5 py-1 text-[11px] leading-4 text-amber-100"
            >
              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-300" />
              <span className="break-words">{warning}</span>
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

function gradeTone(grade: GraphUxEvaluation["grade"]): string {
  if (grade === "excellent" || grade === "strong") {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
  }
  if (grade === "usable") {
    return "border-sky-500/30 bg-sky-500/10 text-sky-200";
  }
  if (grade === "weak") {
    return "border-amber-500/30 bg-amber-500/10 text-amber-200";
  }
  return "border-red-500/30 bg-red-500/10 text-red-200";
}

function barTone(score: number): string {
  if (score >= 82) return "bg-emerald-400";
  if (score >= 68) return "bg-sky-400";
  if (score >= 50) return "bg-amber-400";
  return "bg-red-400";
}
