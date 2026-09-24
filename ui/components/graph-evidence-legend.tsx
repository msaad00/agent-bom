"use client";

/**
 * Runtime evidence overlay lens (#3192 / #3610).
 *
 * Focus overlay for nodes tagged with `evidence_tier` — static scan vs runtime
 * observed vs runtime blocked. Mirrors the drift lens interaction model.
 */

import { Radar } from "lucide-react";
import { GraphLensLegend } from "./graph-lens-legend";

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
  return <GraphLensLegend
    id="graph-evidence" title="Evidence lens" icon={Radar} tone="violet"
    active={active} onToggleActive={onToggleActive} filter={filter} onFilterChange={onFilterChange}
    chips={EVIDENCE_LENS_FILTERS.map(id => ({ id, label: CHIP_LABELS[id], count: counts[id] }))}
    inactiveContent="Turn the lens on to highlight nodes backed by runtime observed or blocked evidence instead of static scan inference alone."
  />;
}
