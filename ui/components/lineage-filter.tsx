"use client";

import type { LineageNodeType } from "./lineage-nodes";

export interface FilterState {
  layers: Record<LineageNodeType, boolean>;
  severity: string | null;
  agentName: string | null;
  vulnOnly: boolean;
}

export const DEFAULT_FILTERS: FilterState = {
  layers: {
    agent: true,
    server: true,
    sharedServer: true,
    package: true,
    vulnerability: true,
    credential: true,
    tool: true,
  },
  severity: null,
  agentName: null,
  vulnOnly: false,
};

interface FilterPanelProps {
  filters: FilterState;
  onChange: (f: FilterState) => void;
  agentNames: string[];
}

const LAYER_LABELS: { key: LineageNodeType; label: string; color: string }[] = [
  { key: "agent", label: "Agents", color: "bg-emerald-500" },
  { key: "server", label: "Servers", color: "bg-blue-500" },
  { key: "package", label: "Packages", color: "bg-zinc-500" },
  { key: "vulnerability", label: "CVEs", color: "bg-red-500" },
  { key: "credential", label: "Credentials", color: "bg-amber-500" },
  { key: "tool", label: "Tools", color: "bg-purple-500" },
];

export function FilterPanel({ filters, onChange, agentNames }: FilterPanelProps) {
  const toggle = (key: LineageNodeType) =>
    onChange({ ...filters, layers: { ...filters.layers, [key]: !filters.layers[key] } });

  return (
    <div className="w-48 bg-zinc-950/90 backdrop-blur-sm border-r border-zinc-800 p-3 space-y-4 overflow-y-auto text-xs">
      <div>
        <h3 className="font-semibold text-zinc-300 mb-2 uppercase tracking-wider text-[10px]">Layers</h3>
        <div className="space-y-1.5">
          {LAYER_LABELS.map(({ key, label, color }) => (
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
      </div>

      <div>
        <h3 className="font-semibold text-zinc-300 mb-2 uppercase tracking-wider text-[10px]">Severity</h3>
        <select
          value={filters.severity ?? ""}
          onChange={(e) => onChange({ ...filters, severity: e.target.value || null })}
          className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
        >
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {agentNames.length > 1 && (
        <div>
          <h3 className="font-semibold text-zinc-300 mb-2 uppercase tracking-wider text-[10px]">Agent</h3>
          <select
            value={filters.agentName ?? ""}
            onChange={(e) => onChange({ ...filters, agentName: e.target.value || null })}
            className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-emerald-600"
          >
            <option value="">All agents</option>
            {agentNames.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>
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
    </div>
  );
}
