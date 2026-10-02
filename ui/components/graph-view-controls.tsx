"use client";

import { useId, useState, type ComponentProps } from "react";
import { RotateCcw, SlidersHorizontal } from "lucide-react";
import {
  FilterPanel,
  graphScopeLabelForFilters,
  graphScopePresetForFilters,
  createImmediateGraphFilters,
  createFocusedGraphFilters,
  createExpandedGraphFilters,
  createCloudEstateGraphFilters,
  createRepositoryGraphFilters,
  createEnvironmentGraphFilters,
  createAssetLifecycleDriftGraphFilters,
} from "@/components/lineage-filter";

type Props = Pick<
  ComponentProps<typeof FilterPanel>,
  "filters" | "onChange" | "agentNames" | "validValues" | "onReset"
> & { estateSummary?: boolean; focusedPath?: boolean };

/** One canonical filter model drives both this control and shareable graph URLs. */
export function GraphViewControls({ filters, onChange, agentNames, validValues, onReset, estateSummary = false, focusedPath = false }: Props) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const selected = graphScopePresetForFilters(filters);
  const agent = filters.agentName ?? agentNames[0] ?? null;
  const layers = Object.values(filters.layers);
  const presets = [
    { id: "immediate", label: "Immediate", create: () => createImmediateGraphFilters(agent) },
    { id: "relevant", label: "Relevant paths", create: () => createFocusedGraphFilters(agent) },
    { id: "expanded", label: "Expanded topology", create: () => createExpandedGraphFilters(null) },
    { id: "cloudEstate", label: "Cloud estate", create: createCloudEstateGraphFilters },
    { id: "repository", label: "Repository", create: createRepositoryGraphFilters },
    { id: "environment", label: "Environment", create: createEnvironmentGraphFilters },
    { id: "assetDrift", label: "Asset lifecycle drift", create: () => createAssetLifecycleDriftGraphFilters(filters.agentName) },
  ];

  return (
    <section aria-label="Graph view and layers" className="rounded-xl border border-outline bg-surface" data-testid="graph-view-controls">
      <div className="flex flex-wrap items-center gap-1 py-0.5 pl-1 pr-28">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen(!open)}
          className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs font-medium text-foreground hover:bg-surface-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500"
        >
          <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
          View &amp; layers
        </button>
        <div className={`${open ? "order-last flex w-full" : "sr-only"} min-w-0 flex-wrap gap-x-3 gap-y-1 text-[11px] text-ink-secondary sm:not-sr-only sm:order-none sm:flex sm:w-auto sm:flex-1`} aria-label="Active graph filters">
          {estateSummary ? (
            <span>Estate summary · {filters.severity ? `${filters.severity}+ severity` : "all severities"}. Choose a view or layer to open filtered topology.</span>
          ) : focusedPath ? (
            <span>Focused path · all hop layers shown. Choose a view or layer to return to filtered topology.</span>
          ) : <>
          <span>{graphScopeLabelForFilters(filters)}</span>
          <span>{layers.filter(Boolean).length}/{layers.length} layers</span>
          {filters.severity && <span>{filters.severity}+ severity</span>}
          {filters.relationshipScope !== "all" && <span>{filters.relationshipScope} relationships</span>}
          {filters.runtimeMode !== "all" && <span>{filters.runtimeMode} evidence</span>}
          {filters.vulnOnly && <span>Vulnerable only</span>}
          <span>Depth {filters.maxDepth} · {filters.pageSize} ranked nodes</span>
          </>}
        </div>
        <button type="button" onClick={onReset} className="graph-chip-neutral" aria-label="Reset graph view">
          <RotateCcw className="h-3.5 w-3.5 sm:hidden" aria-hidden="true" />
          <span className="sr-only sm:not-sr-only">Reset view</span>
        </button>
      </div>
      {open && (
        <div id={panelId} className="space-y-3 border-t border-outline p-3">
          <p className="text-xs text-ink-secondary">
            Choose the evidence to display. Hidden layers and bounded pages can omit context; these controls do not change stored evidence.
          </p>
          <div className="flex flex-wrap gap-2" aria-label="Graph scope presets">
            {presets.map(preset => (
              <button
                key={preset.id}
                type="button"
                aria-pressed={selected === preset.id}
                onClick={() => onChange(preset.create())}
                className={selected === preset.id ? "graph-chip-neutral border-emerald-500 bg-emerald-500/10 text-foreground" : "graph-chip-neutral"}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <FilterPanel
            filters={filters}
            onChange={onChange}
            agentNames={agentNames}
            {...(validValues ? { validValues } : {})}
            variant="panel"
            initialLayersOpen
          />
        </div>
      )}
    </section>
  );
}
