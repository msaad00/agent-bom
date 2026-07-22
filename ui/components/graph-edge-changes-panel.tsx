"use client";

/**
 * Edge lifecycle drill-down for the drift lens (#3192 tail).
 *
 * Surfaces `/v1/graph/edges/changes` alongside the node diff so operators can
 * see which relationships were added, removed, or materially changed between
 * snapshots — including before/after fingerprints on shared edges.
 */

import { ArrowRightLeft, Loader2 } from "lucide-react";

import type {
  GraphEdgeChangePair,
  GraphEdgeChangesResponse,
  GraphEdgeHistoryRecord,
} from "@/lib/api-types";
import {
  graphEdgeChangeHeadingClass,
  graphEdgeChangeMetaClass,
  graphEdgeChangeRowClass,
  type GraphEdgeChangeTone,
} from "@/lib/graph-edge-change-tones";

function edgeKey(edge: GraphEdgeHistoryRecord): string {
  return `${edge.source_id} → ${edge.target_id} (${edge.relationship})`;
}

function EdgeRow({
  edge,
  tone,
}: {
  edge: GraphEdgeHistoryRecord;
  tone: GraphEdgeChangeTone;
}) {
  return (
    <li
      className={`rounded-lg border px-2.5 py-1.5 font-mono text-[11px] ${graphEdgeChangeRowClass(tone)}`}
      data-testid={`graph-edge-change-${tone}`}
    >
      {edgeKey(edge)}
    </li>
  );
}

function ChangedEdgeRow({ pair }: { pair: GraphEdgeChangePair }) {
  return (
    <li
      className={`rounded-lg border px-2.5 py-1.5 text-[11px] ${graphEdgeChangeRowClass("changed")}`}
      data-testid="graph-edge-change-changed"
    >
      <div className="font-mono">{edgeKey(pair.after)}</div>
      <div className={`mt-1 text-[10px] ${graphEdgeChangeMetaClass("changed")}`}>
        weight {pair.before.weight} → {pair.after.weight}
        {pair.before.traversable !== pair.after.traversable
          ? ` · traversable ${String(pair.before.traversable)} → ${String(pair.after.traversable)}`
          : null}
      </div>
    </li>
  );
}

export interface GraphEdgeChangesPanelProps {
  changes: GraphEdgeChangesResponse | null;
  loading: boolean;
  error: string | null;
  comparedLabel?: string | undefined;
}

export function GraphEdgeChangesPanel({
  changes,
  loading,
  error,
  comparedLabel,
}: GraphEdgeChangesPanelProps) {
  const summary = changes?.summary;
  const hasDrillDown =
    Boolean(summary) &&
    (summary!.added > 0 || summary!.removed > 0 || summary!.changed > 0);

  return (
    <div
      data-testid="graph-edge-changes-panel"
      className="mt-3 rounded-2xl border border-[var(--border-subtle)] bg-[var(--background)]/70 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="h-4 w-4 text-violet-600 dark:text-violet-400" />
          <span className="text-[10px] uppercase tracking-[0.24em] text-violet-700 dark:text-violet-400">
            Edge changes
          </span>
          {comparedLabel ? (
            <span className="text-xs text-[var(--text-tertiary)]">
              vs <span className="font-mono">{comparedLabel}</span>
            </span>
          ) : null}
        </div>
        {loading ? (
          <span className="flex items-center gap-1 text-xs text-violet-700 dark:text-violet-300">
            <Loader2 className="h-3 w-3 animate-spin" />
            loading
          </span>
        ) : summary ? (
          <span className="font-mono text-[11px] text-[var(--text-tertiary)]">
            +{summary.added} −{summary.removed} ~{summary.changed}
          </span>
        ) : null}
      </div>

      {error ? (
        <p className="mt-2 text-xs text-amber-700 dark:text-amber-200">{error}</p>
      ) : loading && !changes ? (
        <p className="mt-2 text-xs text-[var(--text-tertiary)]">Loading edge lifecycle diff…</p>
      ) : !hasDrillDown ? (
        <p className="mt-2 text-xs text-[var(--text-tertiary)]">
          No relationship additions, removals, or material changes between
          snapshots.
        </p>
      ) : (
        <div className="mt-3 grid gap-3 lg:grid-cols-3">
          {changes!.edges_added.length > 0 ? (
            <div>
              <p className={`mb-1.5 text-[10px] uppercase tracking-[0.18em] ${graphEdgeChangeHeadingClass("added")}`}>
                Added ({changes!.edges_added.length})
              </p>
              <ul className="space-y-1.5">
                {changes!.edges_added.slice(0, 8).map((edge) => (
                  <EdgeRow key={edgeKey(edge)} edge={edge} tone="added" />
                ))}
              </ul>
            </div>
          ) : null}
          {changes!.edges_removed.length > 0 ? (
            <div>
              <p className={`mb-1.5 text-[10px] uppercase tracking-[0.18em] ${graphEdgeChangeHeadingClass("removed")}`}>
                Removed ({changes!.edges_removed.length})
              </p>
              <ul className="space-y-1.5">
                {changes!.edges_removed.slice(0, 8).map((edge) => (
                  <EdgeRow key={edgeKey(edge)} edge={edge} tone="removed" />
                ))}
              </ul>
            </div>
          ) : null}
          {changes!.edges_changed.length > 0 ? (
            <div>
              <p className={`mb-1.5 text-[10px] uppercase tracking-[0.18em] ${graphEdgeChangeHeadingClass("changed")}`}>
                Changed ({changes!.edges_changed.length})
              </p>
              <ul className="space-y-1.5">
                {changes!.edges_changed.slice(0, 8).map((pair) => (
                  <ChangedEdgeRow key={edgeKey(pair.after)} pair={pair} />
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
