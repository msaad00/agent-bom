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
    <div
      data-testid="graph-drift-legend"
      className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <GitCompareArrows className="h-4 w-4 text-sky-400" />
          <span className="text-[10px] uppercase tracking-[0.24em] text-sky-400">
            Drift lens
          </span>
          {comparedLabel ? (
            <span className="text-xs text-zinc-500">
              vs <span className="font-mono">{comparedLabel}</span>
            </span>
          ) : null}
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={active}
          data-testid="graph-drift-toggle"
          onClick={() => onToggleActive(!active)}
          className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
            active
              ? "border-sky-500/60 bg-sky-500/15 text-sky-200"
              : "border-zinc-700 bg-zinc-900/60 text-zinc-400 hover:text-zinc-200"
          }`}
        >
          {active ? "Lens on" : "Lens off"}
        </button>
      </div>

      {active ? (
        <>
          <div
            className="mt-3 flex flex-wrap gap-2"
            data-testid="graph-drift-chips"
            role="group"
            aria-label="Drift focus"
          >
            {DRIFT_LENS_FILTERS.map((chip) => {
              const selected = chip === filter;
              const count = chipCount(chip, counts, criticalCount);
              return (
                <button
                  key={chip}
                  type="button"
                  aria-pressed={selected}
                  data-testid={`graph-drift-chip-${chip}`}
                  onClick={() => onFilterChange(chip)}
                  className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                    selected
                      ? "border-sky-500/60 bg-sky-500/15 text-sky-100"
                      : "border-zinc-700 bg-zinc-900/60 text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  {CHIP_LABELS[chip]}
                  <span className="ml-1.5 font-mono text-[11px] text-zinc-500">
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

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
                  <span className="text-[11px] text-zinc-300">{meta.label}</span>
                  <span className="font-mono text-[11px] text-zinc-500">
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
                  className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-[11px] text-amber-100"
                >
                  {summary}
                </span>
              ))}
            </div>
          ) : null}
        </>
      ) : (
        <p className="mt-2 text-xs text-zinc-500">
          Turn the lens on to classify this snapshot against{" "}
          {comparedLabel ? (
            <span className="font-mono">{comparedLabel}</span>
          ) : (
            "the previous snapshot"
          )}{" "}
          — new, changed, and removed assets get distinct rings and chips.
        </p>
      )}
    </div>
  );
}
