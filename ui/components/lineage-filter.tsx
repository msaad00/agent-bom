"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

import type { LineageNodeType } from "./lineage-nodes";

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

export function createFocusedGraphFilters(agentName: string | null = null): FilterState {
  return {
    layers: { ...FOCUSED_LAYER_DEFAULTS },
    severity: "high",
    agentName,
    vulnOnly: true,
    runtimeMode: "all",
    relationshipScope: "all",
    maxDepth: 3,
    pageSize: 250,
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
    maxDepth: 6,
    pageSize: 1000,
  };
}

export const DEFAULT_FILTERS: FilterState = createFocusedGraphFilters();

interface FilterPanelProps {
  filters: FilterState;
  onChange: (f: FilterState) => void;
  agentNames: string[];
}

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

export function FilterPanel({ filters, onChange, agentNames }: FilterPanelProps) {
  const [openSections, setOpenSections] = useState({
    layers: true,
    severity: true,
    edges: false,
    traversal: true,
    agent: true,
    pageSize: false,
  });
  const toggle = (key: LineageNodeType) =>
    onChange({ ...filters, layers: { ...filters.layers, [key]: !filters.layers[key] } });
  const toggleSection = (key: keyof typeof openSections) =>
    setOpenSections((current) => ({ ...current, [key]: !current[key] }));

  return (
    <div className="w-48 bg-zinc-950/90 backdrop-blur-sm border-r border-zinc-800 p-3 space-y-4 overflow-y-auto text-xs">
      <FilterSection
        title="Layers"
        open={openSections.layers}
        onToggle={() => toggleSection("layers")}
        summary={`${Object.values(filters.layers).filter(Boolean).length} visible`}
      >
        <div className="space-y-1.5">
          {LAYER_LABELS?.map(({ key, label, color }) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer text-zinc-400 hover:text-zinc-200">
              <input
                type="checkbox"
                checked={filters.layers[key]}
                onChange={() => toggle(key)}
                className="accent-emerald-500 w-3 h-3"
              />
              <span className={`w-2 h-2 rounded-full ${color}`} />
              {label}
            </label>
          ))}
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
          <option value="">All</option>
          <option value="critical">Critical only</option>
          <option value="high">High + critical</option>
          <option value="medium">Medium + above</option>
          <option value="low">Low + above</option>
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
          <option value="all">All relationships</option>
          <option value="inventory">Inventory only</option>
          <option value="attack">Attack / lateral</option>
          <option value="runtime">Runtime only</option>
          <option value="governance">Governance only</option>
        </select>
      </FilterSection>

      <FilterSection
        title="Traversal"
        open={openSections.traversal}
        onToggle={() => toggleSection("traversal")}
        summary={`${filters.runtimeMode === "all" ? "static + runtime" : filters.runtimeMode} · depth ${filters.maxDepth}`}
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
            <option value="2">Depth 2</option>
            <option value="3">Depth 3</option>
            <option value="4">Depth 4</option>
            <option value="6">Depth 6</option>
            <option value="8">Depth 8</option>
            <option value="10">Depth 10</option>
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
          <select
            value={filters.agentName ?? ""}
            onChange={(e) => onChange({ ...filters, agentName: e.target.value || null })}
            className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            <option value="">All agents</option>
            {agentNames?.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
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
          <option value="250">250 nodes</option>
          <option value="500">500 nodes</option>
          <option value="1000">1,000 nodes</option>
          <option value="2500">2,500 nodes</option>
          <option value="5000">5,000 nodes</option>
        </select>
      </FilterSection>
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
