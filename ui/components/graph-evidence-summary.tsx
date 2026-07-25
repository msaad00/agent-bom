"use client";

import { Clock3, Database, GitBranch } from "lucide-react";

function countLabel(value: number | null, total: number | null, noun: string): string {
  if (value === null || total === null) return "Unavailable";
  return `${value.toLocaleString()} of ${total.toLocaleString()} ${noun}`;
}

function capturedLabel(value: string | null): string {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString();
}

export function GraphEvidenceSummary({
  capturedAt,
  returnedNodes,
  totalNodes,
  evidencedEdges,
  totalEdges,
  completeness,
}: {
  capturedAt: string | null;
  returnedNodes: number | null;
  totalNodes: number | null;
  evidencedEdges: number | null;
  totalEdges: number | null;
  completeness: string | null;
}) {
  const items = [
    {
      label: "Snapshot freshness",
      value: capturedLabel(capturedAt),
      detail: capturedAt ? "Captured" : undefined,
      Icon: Clock3,
    },
    {
      label: "Completeness",
      value: countLabel(returnedNodes, totalNodes, "nodes"),
      detail: completeness ? completeness.replaceAll("_", " ") : "Unavailable",
      Icon: Database,
    },
    {
      label: "Relationship provenance",
      value: countLabel(evidencedEdges, totalEdges, "relationships"),
      detail: evidencedEdges === null ? "Evidence metadata not reported" : "with evidence metadata",
      Icon: GitBranch,
    },
  ];

  return (
    <section aria-label="Graph evidence status" className="grid gap-2 md:grid-cols-3">
      {items.map(({ label, value, detail, Icon }) => (
        <div key={label} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)]/70 px-3 py-2">
          <div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
            {label}
          </div>
          <p className="mt-1 truncate text-xs font-medium text-[var(--foreground)]" title={value}>{value}</p>
          {detail ? <p className="mt-0.5 text-[10px] capitalize text-[var(--text-tertiary)]">{detail}</p> : null}
        </div>
      ))}
    </section>
  );
}
