"use client";

import { ChevronLeft, ChevronRight, GitBranch, Layers, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import type {
  GraphCompleteness,
  GraphRollupContainer,
  GraphRollupEdge,
  GraphRollupEdgeCountMetadata,
} from "@/lib/api-types";

export const ROLLUP_DECISION_THRESHOLD = 24;
const PAGE_SIZE = 12;

export function InvestigationViewSwitch({ summary, onSummary, onGraph }: {
  summary: boolean; onSummary: () => void; onGraph: () => void;
}) {
  return <div role="group" aria-label="Investigation view" className="flex flex-wrap items-center gap-2">
    <button type="button" aria-pressed={summary} onClick={onSummary} className={summary ? "graph-chip-emerald" : "graph-chip-neutral"}>Summary</button>
    <button type="button" aria-pressed={!summary} onClick={onGraph} className={!summary ? "graph-chip-emerald" : "graph-chip-neutral"}>Graph</button>
  </div>;
}

type RiskFilter = "priority" | "exposed" | "all";

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function effectiveSeverity(item: GraphRollupContainer): string {
  const own = (item.severity || "none").toLowerCase();
  const contained = (item.aggregate.worst_severity || "none").toLowerCase();
  return (SEVERITY_RANK[own] ?? 0) > (SEVERITY_RANK[contained] ?? 0) ? own : contained;
}

function isPriority(item: GraphRollupContainer): boolean {
  return (
    (SEVERITY_RANK[effectiveSeverity(item)] ?? 0) >= 4 ||
    item.aggregate.internet_exposed ||
    item.aggregate.toxic_combo
  );
}

function severityTone(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "border-red-500/35 bg-red-500/10 text-red-700 dark:text-red-200";
    case "high":
      return "border-orange-500/35 bg-orange-500/10 text-orange-700 dark:text-orange-200";
    case "medium":
      return "border-amber-500/35 bg-amber-500/10 text-amber-800 dark:text-amber-200";
    default:
      return "border-outline bg-surface-muted text-ink-secondary";
  }
}

function relationEvidence(itemId: string, edges: GraphRollupEdge[]): {
  containers: number;
  relationships: number;
} {
  const neighbors = new Set<string>();
  let relationships = 0;
  for (const edge of edges) {
    if (edge.source === itemId) {
      neighbors.add(edge.target);
      relationships += edge.count;
    } else if (edge.target === itemId) {
      neighbors.add(edge.source);
      relationships += edge.count;
    }
  }
  return { containers: neighbors.size, relationships };
}

export function GraphRollupDecisionSurface({
  items,
  edges,
  completeness,
  edgeCountMetadata,
  onDrill,
  onInvestigate,
}: {
  items: GraphRollupContainer[];
  edges: GraphRollupEdge[];
  completeness?: GraphCompleteness | undefined;
  edgeCountMetadata?: GraphRollupEdgeCountMetadata | undefined;
  onDrill: (item: GraphRollupContainer) => void;
  onInvestigate: (item: GraphRollupContainer) => void;
}) {
  const [filter, setFilter] = useState<RiskFilter>("priority");
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState("");
  const [entityType, setEntityType] = useState("");
  const types = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) counts.set(item.entity_type, (counts.get(item.entity_type) ?? 0) + 1);
    return [...counts].sort(([a], [b]) => a.localeCompare(b));
  }, [items]);
  const nodesById = useMemo(() => new Map(items.map((item) => [item.id, item])), [items]);
  const incident = useMemo(() => {
    const index = new Map<string, GraphRollupEdge[]>();
    for (const edge of edges) {
      for (const id of new Set([edge.source, edge.target])) {
        const rows = index.get(id) ?? [];
        rows.push(edge);
        index.set(id, rows);
      }
    }
    return index;
  }, [edges]);
  const priorityCount = useMemo(() => items.filter(isPriority).length, [items]);
  const exposedCount = useMemo(
    () => items.filter((item) => item.aggregate.internet_exposed).length,
    [items],
  );
  const filtered = useMemo(() => {
    const search = query.trim().toLowerCase();
    const ranked = items.filter((item) =>
      (!entityType || item.entity_type === entityType) &&
      (!search || [item.label, item.id, ...Object.values(item.context ?? {})]
        .some((value) => String(value).toLowerCase().includes(search))),
    ).sort((a, b) =>
      (SEVERITY_RANK[effectiveSeverity(b)] ?? 0) - (SEVERITY_RANK[effectiveSeverity(a)] ?? 0));
    if (filter === "all") return ranked;
    if (filter === "exposed") {
      return ranked.filter((item) => item.aggregate.internet_exposed);
    }
    const priority = ranked.filter(isPriority);
    return priorityCount > 0 ? priority : ranked;
  }, [filter, items, query, entityType, priorityCount]);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const compactLayout = visible.length <= 3;
  const cardGridClass = "grid-cols-1 content-start";
  const nodeScopeLabel = completeness?.truncated
    ? `${items.length.toLocaleString()} returned from a bounded node scope`
    : `${items.length.toLocaleString()} nodes and scopes`;
  const edgeScopeLabel = edgeCountMetadata
    ? edgeCountMetadata.source_truncated
      ? `${edgeCountMetadata.returned.toLocaleString()}${edgeCountMetadata.returned < edgeCountMetadata.source_total ? ` of ${edgeCountMetadata.source_total.toLocaleString()}` : ""} aggregated relationship rows returned from a bounded source graph · estate total unavailable`
      : edgeCountMetadata.truncated
        ? `${edgeCountMetadata.returned.toLocaleString()} of ${edgeCountMetadata.source_total.toLocaleString()} aggregated relationship rows returned`
      : `${edgeCountMetadata.returned.toLocaleString()} aggregated relationship rows · complete for this scope`
    : `${edges.length.toLocaleString()} aggregated relationship rows returned · completeness unavailable`;

  useEffect(() => {
    setPage(0);
  }, [filter, items, query, entityType]);

  return (
    <section
      data-testid="graph-rollup-decision-surface"
      data-layout={compactLayout ? "compact" : "paged"}
      className="flex min-h-0 flex-col overflow-hidden rounded-2xl bg-surface"
      aria-label="Risk-prioritized estate scopes"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-outline px-4 py-3">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Layers className="h-4 w-4 text-emerald-600 dark:text-emerald-300" />
            Prioritized findings and scopes
          </p>
          <p className="mt-1 text-xs text-ink-secondary">
            {nodeScopeLabel} in this snapshot. Inspect the highest-severity nodes or expand their contained assets.
          </p>
          <p
            className="mt-1 text-[11px] text-ink-tertiary"
            data-testid="graph-rollup-relationship-completeness"
            title={edgeCountMetadata?.reason ? edgeCountMetadata.reason.replaceAll("_", " ") : undefined}
          >
            {edgeScopeLabel}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-outline px-4 py-2.5 text-xs">
        {(
          [
            ["priority", `Priority ${priorityCount}`],
            ["exposed", `Exposure in scope ${exposedCount}`],
            ["all", `All ${items.length}`],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={(filter === "priority" && priorityCount === 0 ? "all" : filter) === value}
            onClick={() => setFilter(value)}
            className={
              (filter === "priority" && priorityCount === 0 ? "all" : filter) === value
                ? "graph-chip-emerald"
                : "graph-chip-neutral hover:border-outline-strong"
            }
          >
            {label}
          </button>
        ))}
        <span className="ml-auto text-[11px] text-ink-tertiary">
          Page {page + 1} of {pages}
        </span>
      </div>

      <details className="border-b border-outline px-4 py-2 text-xs">
        <summary className="cursor-pointer text-ink-secondary">Filter nodes and scopes{query || entityType ? " · active" : ""}</summary>
        <div className="mt-2 flex flex-wrap gap-3">
          <label className="flex min-w-0 basis-full flex-col gap-1 sm:flex-1 sm:basis-0">Search this scope
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name, ID or environment" className="min-w-0 rounded border border-outline bg-background p-2 text-foreground" />
          </label>
          <label className="flex flex-col gap-1">Asset type
            <select value={entityType} onChange={(event) => setEntityType(event.target.value)} className="rounded border border-outline bg-background p-2 text-foreground">
              <option value="">All types ({items.length})</option>
              {types.map(([type, count]) => <option key={type} value={type}>{type.replaceAll("_", " ")} ({count})</option>)}
            </select>
          </label>
          <button type="button" onClick={() => { setQuery(""); setEntityType(""); }} className="graph-chip-neutral self-end">Clear filters</button>
        </div>
        <p className="mt-2 text-ink-tertiary">Type counts cover returned nodes at this level, before filters.</p>
      </details>
      {filtered.length === 0 && <p role="status" className="p-4 text-sm text-ink-secondary">No nodes match these filters in the returned scope.</p>}
      <div
        data-testid="graph-rollup-card-grid"
        className={`grid max-h-[min(60vh,34rem)] gap-2 overflow-y-auto p-3 ${cardGridClass}`}
      >
        {visible.map((item) => {
          const itemEdges = incident.get(item.id) ?? [];
          const relation = relationEvidence(item.id, itemEdges);
          const severity = effectiveSeverity(item);
          const critical = item.aggregate.severity_counts.critical ?? 0;
          const high = item.aggregate.severity_counts.high ?? 0;
          return (
            <article
              key={item.id}
              className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 rounded-lg border border-outline bg-background px-3 py-2 md:grid-cols-[minmax(0,2fr)_minmax(0,2fr)_auto]"
            >
              <div className="col-span-2 flex min-w-0 items-start justify-between gap-3 md:col-span-1">
                <div className="min-w-0">
                  <p className="break-words text-sm font-semibold text-foreground [overflow-wrap:anywhere]" title={item.label}>
                    {item.label}
                  </p>
                  <p className="text-[11px] text-ink-secondary">
                    {item.entity_type.replaceAll("_", " ")}
                  </p>
                  {item.context && Object.keys(item.context).length > 0 && (
                    <p className="mt-1 break-words text-xs text-ink-secondary [overflow-wrap:anywhere]">
                      {Object.entries(item.context).map(([kind, value]) => `${kind}: ${value}`).join(" · ")}
                    </p>
                  )}
                  <details className="text-[11px] text-ink-tertiary">
                    <summary className="cursor-pointer">Node ID</summary>
                    <code className="block break-all select-all">{item.id}</code>
                  </details>
                </div>
                <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${severityTone(severity)}`}>
                  {severity === "none" ? "Not rated" : severity}
                </span>
              </div>

              <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                {item.has_children && <div>
                  <p className="text-ink-secondary">Contains <span className="font-semibold tabular-nums text-foreground">{item.aggregate.descendant_count} nodes</span></p>
                </div>}
                {item.has_children && <div>
                  <p className="text-ink-secondary">Contained critical / high <span className="font-semibold tabular-nums text-foreground">{critical} / {high}</span></p>
                </div>}
                <div>
                  <p className="tabular-nums text-ink-secondary" title={`${relation.relationships} aggregated relationship evidence records`}>
                    {relation.containers} connected {relation.containers === 1 ? "node" : "nodes"}
                  </p>
                </div>
              </div>



              <div className="flex items-center justify-end gap-3">
                {item.has_children && <button type="button" onClick={() => onInvestigate(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-sky-700 hover:text-sky-600 dark:text-sky-300">
                  <GitBranch className="h-3.5 w-3.5" /> Traverse
                </button>}
                {item.has_children ? (
                  <button type="button" onClick={() => onDrill(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-600 dark:text-emerald-300">
                    Drill in <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                ) : (
                  <button type="button" aria-label={`Inspect ${item.label} (${item.id})`} onClick={() => onInvestigate(item)} className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-600 dark:text-emerald-300">
                    Inspect <ShieldAlert className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              <details className="col-span-2 text-xs text-ink-secondary md:col-span-3">
                <summary className="cursor-pointer">Recorded relationships ({itemEdges.length} {itemEdges.length === 1 ? "row" : "rows"})</summary>
                <p className="my-2 text-ink-tertiary">Returned relationships only. These do not establish runtime execution or authorized access.</p>
                <ul className="max-h-48 space-y-2 overflow-y-auto">
                  {itemEdges.slice(0, 12).map((edge, index) => <li key={`${edge.source}:${edge.target}:${index}`} className="break-words [overflow-wrap:anywhere]">
                    {[edge.source, edge.target].map((id, endpoint) => {
                      const node = nodesById.get(id);
                      return <span key={`${endpoint}:${id}`}>
                        {endpoint === 1 && <span aria-label="to"> → </span>}
                        {node ? <button type="button" onClick={() => onInvestigate(node)} aria-label={`Inspect relationship endpoint ${node.label} (${id})`} title={id} className="text-sky-700 underline underline-offset-2 dark:text-sky-300">{node.label}</button> : <span title="Endpoint details are outside the returned scope">{id}</span>}
                      </span>;
                    })}
                    <span className="block text-ink-tertiary">{edge.relationships.map((kind) => kind.replaceAll("_", " ")).join(", ")} · {edge.count} underlying relationships</span>
                  </li>)}
                </ul>
                {itemEdges.length > 12 && <p className="mt-2">Showing 12 of {itemEdges.length} rows.</p>}
                {itemEdges.length > 12 && <button type="button" onClick={() => onInvestigate(item)} className="mt-2 text-sky-700 underline dark:text-sky-300">Inspect connections for {item.label}</button>}
                {itemEdges.length === 0 && <p>No relationship rows returned for this node. Coverage may be incomplete.</p>}
              </details>
              {(item.aggregate.toxic_combo || item.aggregate.internet_exposed) && <div className="col-span-2 flex flex-wrap gap-1.5 text-[10px] md:col-span-3">
                {item.aggregate.toxic_combo ? (
                  <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-red-700 dark:text-red-200">{item.has_children ? "Toxic combination in scope" : "Toxic combination"}</span>
                ) : null}
                {item.aggregate.internet_exposed ? (
                  <span className="rounded border border-orange-500/30 bg-orange-500/10 px-1.5 py-0.5 text-orange-700 dark:text-orange-200">{item.has_children ? "Exposure in scope" : "Internet exposed"}</span>
                ) : null}
              </div>}
            </article>
          );
        })}
      </div>

      <div className="flex items-center justify-between border-t border-outline px-4 py-2.5">
        <p className="text-[11px] text-ink-tertiary">
          Showing {visible.length} of {filtered.length} matching nodes and scopes
        </p>
        <div className="flex gap-2">
          <button type="button" disabled={page === 0} onClick={() => setPage((current) => Math.max(0, current - 1))} className="graph-page-action disabled:cursor-not-allowed disabled:opacity-40" aria-label="Previous scope page">
            <ChevronLeft className="h-3.5 w-3.5" /> Previous
          </button>
          <button type="button" disabled={page + 1 >= pages} onClick={() => setPage((current) => Math.min(pages - 1, current + 1))} className="graph-page-action disabled:cursor-not-allowed disabled:opacity-40" aria-label="Next scope page">
            Next <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </section>
  );
}
