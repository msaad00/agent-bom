"use client";

/**
 * Drift lens legend + filter chips (#3192).
 *
 * A first-class UI surface for asset-lifecycle drift. Given the change-kind
 * counts the client derives from the `/v1/graph/diff` index, it renders:
 *   - a toggle that arms/disarms the lens (inert when no diff is available),
 *   - focus chips (all / new / changed / critical / removed),
 *   - a colour legend so the node rings on the canvas are self-explanatory.
 *
 * Purely presentational — all classification lives in graph-utils/filter-algebra
 * so this component stays reusable across the ReactFlow and WebGL renderers.
 */

import { GitCompareArrows } from "lucide-react";
import { GraphLensLegend } from "./graph-lens-legend";

import {
  CHANGE_KIND_META,
  CHANGE_KIND_ORDER,
  type ChangeKind,
} from "@/lib/graph-utils";
import {
  DRIFT_LENS_FILTERS,
  type DriftLensFilter,
} from "@/lib/filter-algebra";

const CHIP_LABELS: Record<DriftLensFilter, string> = {
  all: "All",
  new: "New",
  changed: "Changed",
  critical: "Critical change",
  removed: "Removed",
};

function chipCount(
  filter: DriftLensFilter,
  counts: Record<ChangeKind, number>,
  criticalCount: number,
): number {
  if (filter === "all") {
    return counts.new + counts.changed + counts.removed + counts.unchanged;
  }
  if (filter === "critical") return criticalCount;
  return counts[filter];
}

export interface GraphDriftLegendProps {
  active: boolean;
  onToggleActive: (next: boolean) => void;
  filter: DriftLensFilter;
  onFilterChange: (filter: DriftLensFilter) => void;
  counts: Record<ChangeKind, number>;
  criticalCount: number;
  /** Short id of the older snapshot this diff compares against, if any. */
  comparedLabel?: string | undefined;
  /** Canonical config-drift summaries from attribute-aware diff (#3192). */
  attributeSummaries?: string[] | undefined;
}

export function GraphDriftLegend({
  active,
  onToggleActive,
  filter,
  onFilterChange,
  counts,
  criticalCount,
  comparedLabel,
  attributeSummaries,
}: GraphDriftLegendProps) {
  return (
    <GraphLensLegend id="graph-drift" title="Drift lens" icon={GitCompareArrows} tone="sky"
      active={active} onToggleActive={onToggleActive} filter={filter} onFilterChange={onFilterChange}
      switchToggle groupLabel="Drift focus"
      chips={DRIFT_LENS_FILTERS.map(id => ({ id, label: CHIP_LABELS[id], count: chipCount(id, counts, criticalCount) }))}
      inactiveContent={<>Turn the lens on to classify this snapshot against{" "}
        {comparedLabel ? <span className="font-mono">{comparedLabel}</span> : "the previous snapshot"}{" "}
        — new, changed, and removed assets get distinct rings and chips.</>}
    >
          <div
            className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5"
            data-testid="graph-drift-legend-items"
          >
            {CHANGE_KIND_ORDER.map((kind) => {
              const meta = CHANGE_KIND_META[kind];
              return (
                <div
                  key={kind}
                  className="flex items-center gap-1.5"
                  title={meta.description}
                  data-testid={`graph-drift-legend-item-${kind}`}
                >
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: meta.color }}
                  />
                  <span className="text-[11px] text-ink-secondary">{meta.label}</span>
                  <span className="font-mono text-[11px] text-ink-tertiary">
                    {counts[kind]}
                  </span>
                </div>
              );
            })}
          </div>

          {attributeSummaries && attributeSummaries.length > 0 ? (
            <div
              className="mt-3 flex flex-wrap gap-2"
              data-testid="graph-drift-attribute-summaries"
            >
              {attributeSummaries.map((summary) => (
                <span
                  key={summary}
                  className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] text-amber-800 dark:text-amber-100"
                >
                  {summary}
                </span>
              ))}
            </div>
          ) : null}
    </GraphLensLegend>
  );
}
