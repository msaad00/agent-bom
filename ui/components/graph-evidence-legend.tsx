"use client";

/**
 * Runtime evidence overlay lens (#3192 / #3610).
 *
 * Focus overlay for nodes tagged with `evidence_tier` — static scan vs runtime
 * observed vs runtime blocked. Mirrors the drift lens interaction model.
 */

import { Radar } from "lucide-react";

import {
  EVIDENCE_LENS_FILTERS,
  type EvidenceLensFilter,
} from "@/lib/filter-algebra";

const CHIP_LABELS: Record<EvidenceLensFilter, string> = {
  all: "All evidence",
  runtime_observed: "Runtime observed",
  runtime_blocked: "Runtime blocked",
  static_scan: "Static scan",
};

export interface GraphEvidenceLegendProps {
  active: boolean;
  onToggleActive: (next: boolean) => void;
  filter: EvidenceLensFilter;
  onFilterChange: (filter: EvidenceLensFilter) => void;
  counts: Record<EvidenceLensFilter, number>;
}

export function GraphEvidenceLegend({
  active,
  onToggleActive,
  filter,
  onFilterChange,
  counts,
}: GraphEvidenceLegendProps) {
  return (
    <div
      data-testid="graph-evidence-legend"
      className="mt-3 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Radar className="h-4 w-4 text-violet-400" />
          <span className="text-[10px] uppercase tracking-[0.24em] text-violet-400">
            Evidence lens
          </span>
        </div>
        <button
          type="button"
          data-testid="graph-evidence-toggle"
          aria-pressed={active}
          onClick={() => onToggleActive(!active)}
          className={`rounded-full border px-3 py-1 text-xs transition-colors ${
            active
              ? "border-violet-500/60 bg-violet-500/15 text-violet-100"
              : "border-zinc-700 bg-zinc-900/60 text-zinc-400 hover:text-zinc-200"
          }`}
        >
          {active ? "Lens on" : "Lens off"}
        </button>
      </div>

      {active ? (
        <div className="mt-3 flex flex-wrap gap-2" data-testid="graph-evidence-chips">
          {EVIDENCE_LENS_FILTERS.map((chip) => {
            const selected = filter === chip;
            return (
              <button
                key={chip}
                type="button"
                aria-pressed={selected}
                data-testid={`graph-evidence-chip-${chip}`}
                onClick={() => onFilterChange(chip)}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  selected
                    ? "border-violet-500/60 bg-violet-500/15 text-violet-100"
                    : "border-zinc-700 bg-zinc-900/60 text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {CHIP_LABELS[chip]}
                <span className="ml-1.5 font-mono text-[11px] text-zinc-500">
                  {counts[chip]}
                </span>
              </button>
            );
          })}
        </div>
      ) : (
        <p className="mt-2 text-xs text-zinc-500">
          Turn the lens on to highlight nodes backed by runtime observed or blocked
          evidence instead of static scan inference alone.
        </p>
      )}
    </div>
  );
}
