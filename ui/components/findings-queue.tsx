"use client";

import { ChevronDown, ChevronRight, ChevronUp, ExternalLink, ShieldOff } from "lucide-react";

import { severityColor, severityDot } from "@/lib/api";
import type { EnrichedVuln, SortKey } from "@/lib/findings-view";

function ReachabilityBadge({
  reachable,
  hops,
}: {
  reachable: boolean | null | undefined;
  hops: number | null | undefined;
}) {
  if (reachable === true) {
    const hopLabel = typeof hops === "number" && hops > 0 ? ` · ${hops} hop${hops === 1 ? "" : "s"}` : "";
    return (
      <span
        title="An agent's USES/DEPENDS_ON closure reaches this package"
        className="text-xs font-mono bg-amber-950 border border-amber-800 text-amber-300 rounded px-1.5 py-0.5"
      >
        Reachable{hopLabel}
      </span>
    );
  }
  if (reachable === false) {
    return (
      <span
        title="Package is in inventory but no agent traversal reaches it"
        className="text-xs font-mono bg-zinc-900 border border-zinc-700 text-zinc-500 rounded px-1.5 py-0.5"
      >
        Unreachable
      </span>
    );
  }
  return null;
}

function CisaKevBadge() {
  return (
    <span className="text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">
      KEV
    </span>
  );
}

function SortButton({
  label,
  field,
  current,
  dir,
  onClick,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: "asc" | "desc";
  onClick: (f: SortKey) => void;
}) {
  const active = current === field;
  return (
    <button
      onClick={() => onClick(field)}
      className={`flex items-center gap-0.5 text-xs font-medium uppercase tracking-wide transition-colors ${
        active ? "text-zinc-200" : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
      {active ? (
        dir === "desc" ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />
      ) : null}
    </button>
  );
}

function renderScoreValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toFixed(1);
  }
  return (
    <span className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-500" title={missingLabel}>
      N/A
    </span>
  );
}

function renderPercentValue(value: number | undefined, missingLabel: string) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${(value * 100).toFixed(1)}%`;
  }
  return (
    <span className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-500" title={missingLabel}>
      N/A
    </span>
  );
}

export function FindingsQueueTable({
  vulns,
  sortKey,
  sortDir,
  handleSort,
  suppressed,
  onMarkFP,
  selectedId,
  onSelect,
}: {
  vulns: EnrichedVuln[];
  sortKey: SortKey;
  sortDir: "asc" | "desc";
  handleSort: (f: SortKey) => void;
  suppressed: Set<string>;
  onMarkFP: (vulnId: string, packageName: string) => void;
  selectedId: string | null;
  onSelect: (vulnId: string | null) => void;
}) {
  return (
    <div className="border border-zinc-800 rounded-xl overflow-hidden overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-zinc-900 border-b border-zinc-800">
          <tr>
            <th className="text-left px-4 py-3">
              <SortButton label="CVE" field="id" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="Severity" field="severity" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="CVSS" field="cvss" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3">
              <SortButton label="EPSS" field="epss" current={sortKey} dir={sortDir} onClick={handleSort} />
            </th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Packages</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Agents</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Fix</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 bg-zinc-950">
          {vulns?.map((v) => {
            const isSelected = selectedId === v.id;
            return (
              <tr
                key={v.id}
                className={`cursor-pointer transition-colors ${isSelected ? "bg-zinc-900/90 ring-1 ring-inset ring-emerald-900/60" : "hover:bg-zinc-900"}`}
                onClick={() => onSelect(v.id)}
              >
                <td className="px-4 py-3">
                  <div className="flex items-start gap-2">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect(v.id);
                      }}
                      className="mt-0.5 rounded p-0.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                      aria-label={`Open details for ${v.id}`}
                    >
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(v.severity)}`} />
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              onSelect(v.id);
                            }}
                            className="font-mono text-xs text-zinc-200 transition-colors hover:text-emerald-400"
                          >
                            {v.id}
                          </button>
                          <a
                            href={`https://osv.dev/vulnerability/${v.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(event) => event.stopPropagation()}
                            className="inline-flex items-center gap-1 rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] font-medium text-zinc-400 transition-colors hover:border-zinc-600 hover:text-zinc-200"
                          >
                            OSV
                            <ExternalLink className="h-3 w-3" />
                          </a>
                          {(v.is_kev ?? v.cisa_kev) && <CisaKevBadge />}
                          <ReachabilityBadge
                            reachable={v.graph_reachable}
                            hops={v.graph_min_hop_distance}
                          />
                        </div>
                        {(v.summary ?? v.description) && (
                          <p className="text-xs text-zinc-600 mt-0.5 ml-3.5 line-clamp-1 max-w-xs">
                            {v.summary ?? v.description}
                          </p>
                        )}
                      </div>
                    </div>
                  </td>
                <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(v.severity)}`}>
                      {v.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {renderScoreValue(v.cvss_score, "CVSS not published by the current advisory")}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {renderPercentValue(v.epss_score, "EPSS not available for this advisory")}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {v.packages.slice(0, 3).map((p) => (
                        <span key={p} className="text-xs font-mono bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-400">
                          {p}
                        </span>
                      ))}
                      {v.packages.length > 3 && (
                        <span className="text-xs text-zinc-600">+{v.packages.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">
                    {v.agents.slice(0, 2).join(", ")}
                    {v.agents.length > 2 && <span className="text-zinc-600"> +{v.agents.length - 2}</span>}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-emerald-500">
                    {v.fixed_version ?? "N/A"}
                  </td>
                  <td className="px-4 py-3">
                    {suppressed.has(v.id) ? (
                      <span className="text-xs font-medium px-2 py-0.5 rounded border bg-zinc-800 border-zinc-700 text-zinc-400">
                        Suppressed
                      </span>
                    ) : (
                      <button
                        onClick={(event) => {
                          event.stopPropagation();
                          onMarkFP(v.id, v.packages[0] ?? "");
                        }}
                        className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-zinc-700 hover:bg-zinc-600 text-zinc-300 transition-colors"
                      >
                        <ShieldOff className="w-3 h-3" />
                        Mark FP
                      </button>
                    )}
                  </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {vulns.length === 0 && (
        <div className="px-4 py-8 text-center text-zinc-600 text-sm">
          No vulnerabilities match your filters.
        </div>
      )}
    </div>
  );
}
