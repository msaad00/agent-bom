"use client";

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, RotateCcw } from "lucide-react";

import type { LineageNodeType } from "./lineage-nodes";
import type { FilterValidValues } from "@/lib/filter-algebra";

export interface FilterState {
  layers: Record<LineageNodeType, boolean>;
  severity: string | null;
  agentName: string | null;
  vulnOnly: boolean;
  runtimeMode: "all" | "static" | "dynamic";
  relationshipScope: "all" | "inventory" | "attack" | "runtime" | "governance";
  maxDepth: number;
  pageSize: number;
}

export const FOCUSED_LAYER_DEFAULTS: Record<LineageNodeType, boolean> = {
  provider: false,
  agent: true,
  server: true,
  sharedServer: true,
  package: true,
  model: false,
  dataset: false,
  container: false,
  cloudResource: false,
  environment: false,
  fleet: false,
  cluster: false,
  user: false,
  group: false,
  serviceAccount: false,
  vulnerability: true,
  misconfiguration: true,
  credential: true,
  tool: true,
};

export const EXPANDED_LAYER_DEFAULTS: Record<LineageNodeType, boolean> = {
  provider: true,
  agent: true,
  server: true,
  sharedServer: true,
  package: true,
  model: true,
  dataset: true,
  container: true,
  cloudResource: true,
  environment: true,
  fleet: true,
  cluster: true,
  user: true,
  group: true,
  serviceAccount: true,
  vulnerability: true,
  misconfiguration: true,
  credential: true,
  tool: true,
};

export type GraphScopePreset = "immediate" | "relevant" | "expanded";

export const GRAPH_SCOPE_LABELS: Record<GraphScopePreset, string> = {
  immediate: "Immediate",
  relevant: "Relevant paths",
  expanded: "Expanded",
};

export const GRAPH_SCOPE_DESCRIPTIONS: Record<GraphScopePreset, string> = {
  immediate: "One-hop triage around a selected agent.",
  relevant: "Default fix-first graph with bounded path context.",
  expanded: "Broader topology review with lower-priority context included.",
};

export function createImmediateGraphFilters(agentName: string | null = null): FilterState {
  return {
    layers: { ...FOCUSED_LAYER_DEFAULTS },
    severity: "high",
    agentName,
    vulnOnly: true,
    runtimeMode: "all",
    relationshipScope: "all",
    maxDepth: 1,
    pageSize: 25,
  };
}

export function createFocusedGraphFilters(agentName: string | null = null): FilterState {
  return {
    layers: { ...FOCUSED_LAYER_DEFAULTS },
    severity: "high",
    agentName,
    vulnOnly: true,
    runtimeMode: "all",
    relationshipScope: "all",
    maxDepth: 2,
    pageSize: 50,
  };
}

export function createExpandedGraphFilters(agentName: string | null = null): FilterState {
  return {
    layers: { ...EXPANDED_LAYER_DEFAULTS },
    severity: null,
    agentName,
    vulnOnly: false,
    runtimeMode: "all",
    relationshipScope: "all",
    maxDepth: 3,
    pageSize: 250,
  };
}

export const DEFAULT_FILTERS: FilterState = createFocusedGraphFilters();

export function graphScopePresetForFilters(filters: FilterState): GraphScopePreset {
  if (filters.maxDepth <= 1 && filters.pageSize <= 25 && filters.vulnOnly) return "immediate";
  if (filters.maxDepth <= 2 && filters.pageSize <= 50 && filters.vulnOnly && filters.severity === "high") {
    return "relevant";
  }
  return "expanded";
}

export function graphScopeLabelForFilters(filters: FilterState): string {
  return GRAPH_SCOPE_LABELS[graphScopePresetForFilters(filters)];
}

interface FilterPanelProps {
  filters: FilterState;
  onChange: (f: FilterState) => void;
  agentNames: string[];
  /** Constraint-propagation valid values from filter-algebra. When omitted, every value is enabled. */
  validValues?: FilterValidValues;
  /** Click handler for the reset button at the panel header. */
  onReset?: () => void;
}

const DISABLED_TOOLTIP = "no nodes match this combination";

const SEVERITY_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "All" },
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High + critical" },
  { value: "medium", label: "Medium + above" },
  { value: "low", label: "Low + above" },
];

const RELATIONSHIP_SCOPE_OPTIONS: Array<{ value: FilterState["relationshipScope"]; label: string }> = [
  { value: "all", label: "All relationships" },
  { value: "inventory", label: "Inventory only" },
  { value: "attack", label: "Attack / lateral" },
  { value: "runtime", label: "Runtime only" },
  { value: "governance", label: "Governance only" },
];

/** Edge-kind sets used to decide whether a relationship-scope option is reachable. */
const SCOPE_RELATIONSHIPS: Record<Exclude<FilterState["relationshipScope"], "all">, string[]> = {
  inventory: [
    "hosts",
    "uses",
    "depends_on",
    "provides_tool",
    "exposes_cred",
    "reaches_tool",
    "serves_model",
    "contains",
  ],
  attack: [
    "affects",
    "vulnerable_to",
    "exploitable_via",
    "remediates",
    "triggers",
    "shares_server",
    "shares_cred",
    "lateral_path",
  ],
  runtime: ["invoked", "accessed", "delegated_to"],
  governance: ["manages", "owns", "part_of", "member_of"],
};

/** Severity rank used to decide whether a min-severity option is reachable. */
const SEVERITY_RANK_MAP: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  informational: 1,
  none: 0,
  unknown: 0,
};

const LAYER_LABELS: { key: LineageNodeType; label: string; color: string }[] = [
  { key: "provider", label: "Providers", color: "bg-zinc-500" },
  { key: "agent", label: "Agents", color: "bg-emerald-500" },
  { key: "server", label: "Servers", color: "bg-blue-500" },
  { key: "package", label: "Packages", color: "bg-zinc-500" },
  { key: "model", label: "Models", color: "bg-violet-500" },
  { key: "dataset", label: "Datasets", color: "bg-cyan-500" },
  { key: "container", label: "Containers", color: "bg-indigo-500" },
  { key: "cloudResource", label: "Cloud", color: "bg-sky-500" },
  { key: "environment", label: "Environments", color: "bg-teal-500" },
  { key: "fleet", label: "Fleets", color: "bg-cyan-500" },
  { key: "cluster", label: "Clusters", color: "bg-sky-400" },
  { key: "user", label: "Users", color: "bg-emerald-400" },
  { key: "group", label: "Groups", color: "bg-fuchsia-500" },
  { key: "serviceAccount", label: "Svc Accounts", color: "bg-amber-400" },
  { key: "vulnerability", label: "CVEs", color: "bg-red-500" },
  { key: "misconfiguration", label: "Misconfigs", color: "bg-orange-500" },
  { key: "credential", label: "Credentials", color: "bg-amber-500" },
  { key: "tool", label: "Tools", color: "bg-purple-500" },
];

const AGENT_OPTION_HEIGHT = 32;
const AGENT_VISIBLE_ROWS = 8;
const AGENT_OVERSCAN_ROWS = 4;

export function FilterPanel({ filters, onChange, agentNames, validValues, onReset }: FilterPanelProps) {
  const [openSections, setOpenSections] = useState({
    layers: false,
    severity: true,
    edges: false,
    traversal: false,
    agent: true,
    pageSize: false,
  });
  const toggle = (key: LineageNodeType) =>
    onChange({ ...filters, layers: { ...filters.layers, [key]: !filters.layers[key] } });
  const toggleSection = (key: keyof typeof openSections) =>
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));

  const isLayerEnabled = (key: LineageNodeType): boolean => {
    if (!validValues) return true;
    return validValues.layers.has(key);
  };
  const isSeverityEnabled = (value: string): boolean => {
    if (!validValues) return true;
    if (!value) return true; // "All" is always selectable
    // A severity option enables iff there's at least one node with severity >= value.
    const minRank = SEVERITY_RANK_MAP[value] ?? 0;
    for (const sev of validValues.severities) {
      const rank = SEVERITY_RANK_MAP[sev] ?? 0;
      if (rank >= minRank) return true;
    }
    return false;
  };
  const isAgentEnabled = (name: string): boolean => {
    if (!validValues) return true;
    return validValues.agents.has(name);
  };
  const isScopeEnabled = (value: FilterState["relationshipScope"]): boolean => {
    if (!validValues || value === "all") return true;
    const required = SCOPE_RELATIONSHIPS[value] ?? [];
    return required.some((r) => validValues.relationships.has(r));
  };

  return (
    <div className="w-48 bg-zinc-950/90 backdrop-blur-sm border-r border-zinc-800 p-3 space-y-4 overflow-y-auto text-xs">
      <div className="flex items-center justify-between -mt-1 -mx-1 mb-1">
        <span className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 px-1">Filters</span>
        {onReset && (
          <button
            type="button"
            onClick={onReset}
            title="Reset to the bounded graph scope"
            className="flex items-center gap-1 rounded border border-zinc-800 bg-zinc-900/80 px-2 py-1 text-[10px] text-zinc-400 transition hover:border-emerald-600/40 hover:text-emerald-200"
          >
            <RotateCcw className="h-3 w-3" />
            Reset
          </button>
        )}
      </div>

      <FilterSection
        title="Layers"
        open={openSections.layers}
        onToggle={() => toggleSection("layers")}
        summary={`${Object.values(filters.layers).filter(Boolean).length} visible`}
      >
        <div className="space-y-1.5">
          {LAYER_LABELS?.map(({ key, label, color }) => {
            const enabled = isLayerEnabled(key);
            const checked = filters.layers[key];
            return (
              <label
                key={key}
                title={enabled ? undefined : DISABLED_TOOLTIP}
                className={`flex items-center gap-2 ${
                  enabled || checked
                    ? "cursor-pointer text-zinc-400 hover:text-zinc-200"
                    : "cursor-not-allowed text-zinc-600 opacity-50"
                }`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={!enabled && !checked}
                  onChange={() => toggle(key)}
                  className="accent-emerald-500 w-3 h-3"
                />
                <span className={`w-2 h-2 rounded-full ${color}`} />
                {label}
              </label>
            );
          })}
        </div>
      </FilterSection>

      <FilterSection
        title="Severity"
        open={openSections.severity}
        onToggle={() => toggleSection("severity")}
        summary={filters.severity ? `${filters.severity}+` : "all"}
      >
        <select
          value={filters.severity ?? ""}
          onChange={(e) => onChange({ ...filters, severity: e.target.value || null })}
          className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          {SEVERITY_OPTIONS.map(({ value, label }) => {
            const enabled = isSeverityEnabled(value);
            return (
              <option
                key={value || "__all__"}
                value={value}
                disabled={!enabled}
                title={enabled ? undefined : DISABLED_TOOLTIP}
              >
                {label}
                {!enabled ? " — no matches" : ""}
              </option>
            );
          })}
        </select>
      </FilterSection>

      <FilterSection
        title="Edges"
        open={openSections.edges}
        onToggle={() => toggleSection("edges")}
        summary={filters.relationshipScope === "all" ? "all" : filters.relationshipScope}
      >
        <select
          value={filters.relationshipScope}
          onChange={(e) =>
            onChange({
              ...filters,
              relationshipScope: e.target.value as FilterState["relationshipScope"],
            })
          }
          className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          {RELATIONSHIP_SCOPE_OPTIONS.map(({ value, label }) => {
            const enabled = isScopeEnabled(value);
            return (
              <option
                key={value}
                value={value}
                disabled={!enabled}
                title={enabled ? undefined : DISABLED_TOOLTIP}
              >
                {label}
                {!enabled ? " — no matches" : ""}
              </option>
            );
          })}
        </select>
      </FilterSection>

      <FilterSection
        title="Traversal"
        open={openSections.traversal}
        onToggle={() => toggleSection("traversal")}
        summary={`${filters.runtimeMode === "all" ? "static + runtime" : filters.runtimeMode} · ${graphScopeLabelForFilters(filters)}`}
      >
        <div className="space-y-2">
          <select
            value={filters.runtimeMode}
            onChange={(e) =>
              onChange({
                ...filters,
                runtimeMode: e.target.value as FilterState["runtimeMode"],
              })
            }
            className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            <option value="all">Static + runtime</option>
            <option value="static">Static only</option>
            <option value="dynamic">Runtime only</option>
          </select>

          <select
            value={String(filters.maxDepth)}
            onChange={(e) =>
              onChange({
                ...filters,
                maxDepth: Number(e.target.value),
              })
            }
            className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            <option value="1">Depth 1</option>
            <option value="2">Depth 2</option>
            <option value="3">Depth 3</option>
            <option value="4">Depth 4</option>
          </select>
        </div>
      </FilterSection>

      {agentNames.length > 1 && (
        <FilterSection
          title="Agent"
          open={openSections.agent}
          onToggle={() => toggleSection("agent")}
          summary={filters.agentName ?? "all agents"}
        >
          <VirtualizedAgentPicker
            agentNames={agentNames}
            selectedAgent={filters.agentName}
            isAgentEnabled={isAgentEnabled}
            onSelect={(agentName) => onChange({ ...filters, agentName })}
          />
        </FilterSection>
      )}

      <div>
        <label className="flex items-center gap-2 cursor-pointer text-zinc-400 hover:text-zinc-200">
          <input
            type="checkbox"
            checked={filters.vulnOnly}
            onChange={(e) => onChange({ ...filters, vulnOnly: e.target.checked })}
            className="accent-emerald-500 w-3 h-3"
          />
          Vulnerable only
        </label>
      </div>

      <FilterSection
        title="Page size"
        open={openSections.pageSize}
        onToggle={() => toggleSection("pageSize")}
        summary={`${filters.pageSize} nodes`}
      >
        <select
          value={String(filters.pageSize)}
          onChange={(e) => onChange({ ...filters, pageSize: Number(e.target.value) })}
          className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="25">25 nodes</option>
          <option value="50">50 nodes</option>
          <option value="100">100 nodes</option>
          <option value="250">250 nodes</option>
          <option value="500">500 nodes</option>
        </select>
      </FilterSection>
    </div>
  );
}

function VirtualizedAgentPicker({
  agentNames,
  selectedAgent,
  onSelect,
  isAgentEnabled,
}: {
  agentNames: string[];
  selectedAgent: string | null;
  onSelect: (agentName: string | null) => void;
  isAgentEnabled?: (name: string) => boolean;
}) {
  const [query, setQuery] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredAgents = useMemo(
    () =>
      normalizedQuery
        ? agentNames.filter((agentName) => agentName.toLowerCase().includes(normalizedQuery))
        : agentNames,
    [agentNames, normalizedQuery],
  );
  const listHeight = AGENT_VISIBLE_ROWS * AGENT_OPTION_HEIGHT;
  const visibleCount = AGENT_VISIBLE_ROWS + AGENT_OVERSCAN_ROWS * 2;
  const startIndex = Math.max(0, Math.floor(scrollTop / AGENT_OPTION_HEIGHT) - AGENT_OVERSCAN_ROWS);
  const visibleAgents = filteredAgents.slice(startIndex, startIndex + visibleCount);
  const topPadding = startIndex * AGENT_OPTION_HEIGHT;
  const bottomPadding = Math.max(0, (filteredAgents.length - startIndex - visibleAgents.length) * AGENT_OPTION_HEIGHT);

  return (
    <div className="space-y-2">
      <input
        type="search"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
          setScrollTop(0);
        }}
        placeholder={`Filter ${agentNames.length.toLocaleString()} agents`}
        aria-label="Filter graph agents"
        className="w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-300 placeholder:text-zinc-600 focus:border-emerald-600 focus:outline-none"
      />
      <button
        type="button"
        onClick={() => onSelect(null)}
        className={`flex h-8 w-full items-center rounded px-2 text-left text-[11px] transition ${
          selectedAgent === null
            ? "border border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
            : "border border-zinc-800 bg-zinc-900/70 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
        }`}
      >
        All agents
      </button>
      <div
        className="overflow-y-auto rounded border border-zinc-800 bg-zinc-950/70"
        style={{ height: listHeight }}
        onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        role="listbox"
        aria-label="Graph agent selector"
      >
        <div style={{ paddingTop: topPadding, paddingBottom: bottomPadding }}>
          {visibleAgents.map((agentName) => {
            const enabled = isAgentEnabled ? isAgentEnabled(agentName) : true;
            const isSelected = selectedAgent === agentName;
            return (
              <button
                key={agentName}
                type="button"
                role="option"
                aria-selected={isSelected}
                disabled={!enabled && !isSelected}
                onClick={() => onSelect(agentName)}
                className={`block h-8 w-full truncate px-2 text-left font-mono text-[11px] transition ${
                  isSelected
                    ? "bg-emerald-500/15 text-emerald-200"
                    : enabled
                      ? "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
                      : "cursor-not-allowed text-zinc-600 opacity-50"
                }`}
                title={enabled ? agentName : DISABLED_TOOLTIP}
              >
                {agentName}
              </button>
            );
          })}
          {visibleAgents.length === 0 && (
            <div className="px-2 py-3 text-[11px] text-zinc-500">No agents match this filter.</div>
          )}
        </div>
      </div>
      <p className="text-[10px] text-zinc-600">
        Showing {visibleAgents.length.toLocaleString()} of {filteredAgents.length.toLocaleString()} matches.
      </p>
    </div>
  );
}

function FilterSection({
  title,
  open,
  onToggle,
  summary,
  children,
}: {
  title: string;
  open: boolean;
  onToggle: () => void;
  summary?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-950/50">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between px-3 py-2 text-left"
      >
        <div>
          <h3 className="font-semibold text-zinc-300 uppercase tracking-wider text-[10px]">{title}</h3>
          {summary ? <p className="mt-1 text-[10px] text-zinc-600">{summary}</p> : null}
        </div>
        {open ? <ChevronDown className="h-3.5 w-3.5 text-zinc-500" /> : <ChevronRight className="h-3.5 w-3.5 text-zinc-500" />}
      </button>
      {open ? <div className="border-t border-zinc-800 px-3 py-3">{children}</div> : null}
    </section>
  );
}
