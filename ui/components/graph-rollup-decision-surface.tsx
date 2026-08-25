"use client";

import { ChevronLeft, ChevronRight, GitBranch, Layers, Network, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import type {
  GraphCompleteness,
  GraphRollupContainer,
  GraphRollupEdge,
  GraphRollupEdgeCountMetadata,
} from "@/lib/api-types";

export const ROLLUP_DECISION_THRESHOLD = 24;
const PAGE_SIZE = 12;

type RiskFilter = "priority" | "exposed" | "all";

function isPriority(item: GraphRollupContainer): boolean {
  return (
    item.aggregate.worst_severity_rank >= 4 ||
    item.aggregate.internet_exposed ||
    item.aggregate.toxic_combo
  );
}

function severityTone(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "border-red-500/35 bg-red-500/10 text-red-700 dark:text-red-200";
    case "high":
      return "border-orange-500/35 bg-orange-500/10 text-orange-700 dark:text-orange-200";
    case "medium":
      return "border-amber-500/35 bg-amber-500/10 text-amber-800 dark:text-amber-200";
    default:
      return "border-[var(--border-subtle)] bg-[var(--surface-muted)] text-[var(--text-secondary)]";
  }
}

function relationEvidence(itemId: string, edges: GraphRollupEdge[]): {
  containers: number;
  relationships: number;
} {
  const neighbors = new Set<string>();
  let relationships = 0;
  for (const edge of edges) {
    if (edge.source === itemId) {
      neighbors.add(edge.target);
      relationships += edge.count;
    } else if (edge.target === itemId) {
      neighbors.add(edge.source);
      relationships += edge.count;
    }
  }
  return { containers: neighbors.size, relationships };
}

export function GraphRollupDecisionSurface({
  items,
  edges,
  completeness,
  edgeCountMetadata,
  onDrill,
  onInvestigate,
  onShowMap,
}: {
  items: GraphRollupContainer[];
  edges: GraphRollupEdge[];
  completeness?: GraphCompleteness | undefined;
  edgeCountMetadata?: GraphRollupEdgeCountMetadata | undefined;
  onDrill: (item: GraphRollupContainer) => void;
  onInvestigate: (item: GraphRollupContainer) => void;
  onShowMap: () => void;
}) {
  const [filter, setFilter] = useState<RiskFilter>("priority");
  const [page, setPage] = useState(0);
  const priorityCount = useMemo(() => items.filter(isPriority).length, [items]);
  const exposedCount = useMemo(
    () => items.filter((item) => item.aggregate.internet_exposed).length,
    [items],
  );
  const filtered = useMemo(() => {
    if (filter === "all") return items;
    if (filter === "exposed") {
      return items.filter((item) => item.aggregate.internet_exposed);
    }
    const priority = items.filter(isPriority);
    return priority.length > 0 ? priority : items;
  }, [filter, items]);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const nodeScopeLabel = completeness?.truncated
    ? `${items.length.toLocaleString()} returned from a bounded node scope`
    : `${items.length.toLocaleString()} containers`;
  const edgeScopeLabel = edgeCountMetadata
    ? edgeCountMetadata.source_truncated
      ? `${edgeCountMetadata.returned.toLocaleString()}${edgeCountMetadata.returned < edgeCountMetadata.source_total ? ` of ${edgeCountMetadata.source_total.toLocaleString()}` : ""} aggregated relationship rows returned from a bounded source graph · estate total unavailable`
      : edgeCountMetadata.truncated
        ? `${edgeCountMetadata.returned.toLocaleString()} of ${edgeCountMetadata.source_total.toLocaleString()} aggregated relationship rows returned`
      : `${edgeCountMetadata.returned.toLocaleString()} aggregated relationship rows · complete for this scope`
    : `${edges.length.toLocaleString()} aggregated relationship rows returned · completeness unavailable`;

  useEffect(() => {
    setPage(0);
  }, [filter, items]);

  return (
    <section
      data-testid="graph-rollup-decision-surface"
      className="flex h-full min-h-[32rem] flex-col overflow-hidden rounded-2xl bg-[var(--surface)]"
      aria-label="Risk-prioritized estate scopes"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-4 py-3">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--foreground)]">
            <Layers className="h-4 w-4 text-emerald-600 dark:text-emerald-300" />
            Risk-prioritized scopes
          </p>
          <p className="mt-1 text-xs text-[var(--text-secondary)]">
            {nodeScopeLabel} collapsed from the current evidence snapshot. Drill into a scope or isolate its traversal.
          </p>
          <p
            className="mt-1 text-[11px] text-[var(--text-tertiary)]"
            data-testid="graph-rollup-relationship-completeness"
            title={edgeCountMetadata?.reason ? edgeCountMetadata.reason.replaceAll("_", " ") : undefined}
          >
            {edgeScopeLabel}
          </p>
        </div>
        <button type="button" onClick={onShowMap} className="graph-page-action">
          <Network className="h-3.5 w-3.5" /> Relationship map
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border-subtle)] px-4 py-2.5 text-xs">
        {(
          [
            ["priority", `Priority ${priorityCount}`],
            ["exposed", `Internet exposed ${exposedCount}`],
            ["all", `All ${items.length}`],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={filter === value}
            onClick={() => setFilter(value)}
            className={
              filter === value
                ? "graph-chip-emerald"
                : "graph-chip-neutral hover:border-[var(--border-strong)]"
            }
          >
            {label}
          </button>
        ))}
        <span className="ml-auto text-[11px] text-[var(--text-tertiary)]">
          Page {page + 1} of {pages}
        </span>
      </div>

      <div className="grid flex-1 auto-rows-fr gap-2 overflow-y-auto p-4 md:grid-cols-2 xl:grid-cols-3">
        {visible.map((item) => {
          const relation = relationEvidence(item.id, edges);
          const severity = item.aggregate.worst_severity || item.severity || "none";
          const critical = item.aggregate.severity_counts.critical ?? 0;
          const high = item.aggregate.severity_counts.high ?? 0;
          return (
            <article
              key={item.id}
              className="flex min-h-[10.5rem] flex-col rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] p-3 shadow-sm transition hover:border-emerald-500/40"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-[var(--foreground)]" title={item.label}>
                    {item.label}
                  </p>
                  <p className="mt-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
                    {item.entity_type.replaceAll("_", " ")}
                  </p>
                </div>
                <span className={`rounded-md border px-2 py-1 text-[10px] font-semibold uppercase ${severityTone(severity)}`}>
                  {severity === "none" ? "No severity" : severity}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-[var(--text-tertiary)]">Assets</p>
                  <p className="mt-0.5 font-semibold tabular-nums text-[var(--foreground)]">{item.aggregate.descendant_count}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-[var(--text-tertiary)]">Critical / high</p>
                  <p className="mt-0.5 font-semibold tabular-nums text-[var(--foreground)]">{critical} / {high}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-[var(--text-tertiary)]">Relations</p>
                  <p className="mt-0.5 font-semibold tabular-nums text-[var(--foreground)]" title={`${relation.relationships} aggregated relationship evidence records`}>
                    {relation.containers} scopes
                  </p>
                </div>
              </div>

              <div className="mt-3 flex min-h-6 flex-wrap gap-1.5 text-[10px]">
                {item.aggregate.toxic_combo ? (
                  <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-red-700 dark:text-red-200">Toxic combination</span>
                ) : null}
                {item.aggregate.internet_exposed ? (
                  <span className="rounded border border-orange-500/30 bg-orange-500/10 px-1.5 py-0.5 text-orange-700 dark:text-orange-200">Internet exposed</span>
                ) : null}
              </div>

              <div className="mt-auto flex items-center justify-between gap-2 border-t border-[var(--border-subtle)] pt-2.5">
                <button type="button" onClick={() => onInvestigate(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-sky-700 hover:text-sky-600 dark:text-sky-300">
                  <GitBranch className="h-3.5 w-3.5" /> Traverse
                </button>
                {item.has_children ? (
                  <button type="button" onClick={() => onDrill(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-600 dark:text-emerald-300">
                    Drill in <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : (
                  <button type="button" onClick={() => onInvestigate(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-600 dark:text-emerald-300">
                    Inspect <ShieldAlert className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </div>

      <div className="flex items-center justify-between border-t border-[var(--border-subtle)] px-4 py-2.5">
        <p className="text-[11px] text-[var(--text-tertiary)]">
          Showing {visible.length} of {filtered.length} matching scopes
        </p>
        <div className="flex gap-2">
          <button type="button" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))} className="graph-page-action disabled:cursor-not-allowed disabled:opacity-40" aria-label="Previous scope page">
            <ChevronLeft className="h-3.5 w-3.5" /> Previous
          </button>
          <button type="button" disabled={page + 1 >= pages} onClick={() => setPage((current) => Math.min(pages - 1, current + 1))} className="graph-page-action disabled:cursor-not-allowed disabled:opacity-40" aria-label="Next scope page">
            Next <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </section>
  );
}
