"use client";

import Link from "next/link";
import { AlertTriangle, ExternalLink, Route, SearchX } from "lucide-react";

import type { LineageNodeData } from "./lineage-nodes";

export function GraphControlGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[10px] uppercase tracking-[0.2em] text-zinc-600">{label}</span>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

export function GraphEmptyState({
  title,
  detail,
  suggestions,
}: {
  title: string;
  detail: string;
  suggestions: string[];
}) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="max-w-xl rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 text-left shadow-lg shadow-zinc-950/40">
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-2">
            <SearchX className="h-5 w-5 text-zinc-400" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-zinc-100">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-zinc-400">{detail}</p>
          </div>
        </div>
        <ul className="mt-4 space-y-2 text-sm text-zinc-500">
          {suggestions.map((suggestion) => (
            <li key={suggestion} className="flex items-start gap-2">
              <span className="mt-1 h-1.5 w-1.5 rounded-full bg-zinc-600" />
              <span>{suggestion}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function GraphFindingsFallback({
  nodes,
  onSelect,
}: {
  nodes: Array<{ id: string; data: LineageNodeData }>;
  onSelect: (id: string, data: LineageNodeData) => void;
}) {
  return (
    <div className="h-full overflow-y-auto">
      <div className="border-b border-zinc-800 bg-zinc-950/60 px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-orange-400">Findings scope</p>
            <h3 className="mt-1 text-sm font-semibold text-zinc-100">This filter currently resolves to findings only</h3>
            <p className="mt-1 max-w-3xl text-xs leading-5 text-zinc-500">
              You are looking at the vulnerability slice without enough surrounding package, server, or agent context to form a topology.
              Use this list for evidence and remediation, or relax the scope to recover the graph.
            </p>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-2 text-xs text-zinc-400">
            {nodes.length} finding{nodes.length !== 1 ? "s" : ""} in scope
          </div>
        </div>
      </div>

      <div className="grid gap-3 p-4 lg:grid-cols-2">
        {nodes.map(({ id, data }) => {
          const severity = data.severity?.toUpperCase() ?? "UNKNOWN";
          const cvss = typeof data.cvssScore === "number" ? data.cvssScore.toFixed(1) : "N/A";
          const epss = typeof data.epssScore === "number" ? `${(data.epssScore * 100).toFixed(1)}%` : "N/A";
          const tone =
            data.severity === "critical"
              ? "border-red-800 bg-red-950/20"
              : data.severity === "high"
                ? "border-orange-800 bg-orange-950/20"
                : "border-zinc-800 bg-zinc-950/60";

          return (
            <div key={id} className={`rounded-2xl border p-4 ${tone}`}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="rounded-lg border border-zinc-700 bg-zinc-900/80 px-2 py-0.5 text-[10px] font-medium tracking-[0.16em] text-zinc-400">
                      {severity}
                    </span>
                    {data.isKev && (
                      <span className="rounded-lg border border-red-800 bg-red-950/70 px-2 py-0.5 text-[10px] font-medium tracking-[0.16em] text-red-300">
                        KEV
                      </span>
                    )}
                  </div>
                  <h4 className="mt-2 font-mono text-sm font-semibold text-zinc-100">{data.label}</h4>
                  {data.description && (
                    <p className="mt-2 text-sm leading-6 text-zinc-400">{data.description}</p>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => onSelect(id, data)}
                  className="rounded-xl border border-zinc-700 bg-zinc-900/80 px-3 py-2 text-xs font-medium text-zinc-200 transition hover:border-zinc-500 hover:text-zinc-100"
                >
                  Open evidence
                </button>
              </div>

              <div className="mt-4 grid gap-2 sm:grid-cols-3">
                <Stat label="CVSS" value={cvss} />
                <Stat label="EPSS" value={epss} />
                <Stat label="Risk" value={typeof data.riskScore === "number" ? data.riskScore.toFixed(1) : "N/A"} />
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Link
                  href={`/vulns?cve=${encodeURIComponent(data.label)}`}
                  className="inline-flex items-center gap-1 rounded-lg border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors hover:bg-emerald-950/70"
                >
                  <Route className="h-3 w-3" />
                  Open in vulnerabilities
                </Link>
                <a
                  href={`https://osv.dev/vulnerability/${encodeURIComponent(data.label)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:border-zinc-600 hover:text-zinc-100"
                >
                  View on OSV
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-500">{label}</div>
      <div className="mt-1 text-sm font-mono text-zinc-100">{value}</div>
    </div>
  );
}
