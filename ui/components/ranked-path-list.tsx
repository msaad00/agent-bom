"use client";

import { ChevronRight } from "lucide-react";

export interface RankedPathRow {
  /** Collision-free React key (index-suffixed) for stable list rendering. */
  key: string;
  /** Selection key shared with the command-center panel's selected path. */
  selectionKey: string;
  rank: number;
  title: string;
  cve: string | null;
  riskScore: number;
  hops: number;
  agents: number;
}

/**
 * Compact, scannable list of ranked exposure paths. One row per path — the
 * DAG for the active row renders once in the command-center panel above, not
 * per-card here, so the surface scales to many paths without a tall stack of
 * duplicate node diagrams. Selecting a row promotes it into that single panel.
 */
export function RankedPathList({
  rows,
  selectedKey,
  onSelect,
  onKeyDown,
}: {
  rows: RankedPathRow[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
  onKeyDown?: ((event: React.KeyboardEvent<HTMLDivElement>) => void) | undefined;
}) {
  return (
    <div
      className="mt-4 max-h-[28rem] space-y-1.5 overflow-y-auto pr-1 outline-none"
      tabIndex={0}
      onKeyDown={onKeyDown}
      aria-label="Attack path queue"
    >
      {rows.map((row) => {
        const active = row.selectionKey === selectedKey;
        return (
          <button
            key={row.key}
            type="button"
            aria-pressed={active}
            onClick={() => onSelect(row.selectionKey)}
            className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition ${
              active
                ? "border-orange-400/70 bg-orange-500/10 ring-1 ring-orange-400/60"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            <span
              className={`shrink-0 rounded-md px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
                row.rank === 1
                  ? "bg-orange-500/15 text-orange-300"
                  : "bg-[color:var(--surface)] text-[color:var(--text-tertiary)]"
              }`}
            >
              {row.rank === 1 ? "#1 fix first" : `#${row.rank}`}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-[color:var(--foreground)]">
                {row.cve ? `${row.cve} · ` : ""}
                {row.title}
              </span>
              <span className="mt-0.5 block text-[11px] text-[color:var(--text-tertiary)]">
                {row.hops} hop{row.hops === 1 ? "" : "s"} · {row.agents} agent{row.agents === 1 ? "" : "s"}
              </span>
            </span>
            <span className="shrink-0 rounded-lg border border-red-900/60 bg-red-950/30 px-2.5 py-1 text-right">
              <span className="block text-[9px] font-semibold uppercase tracking-[0.14em] text-red-300/80">
                Path risk
              </span>
              <span className="block font-mono text-sm font-semibold leading-4 text-red-200">
                {row.riskScore.toFixed(1)}
              </span>
            </span>
            <ChevronRight
              className={`h-4 w-4 shrink-0 transition ${
                active ? "text-orange-300" : "text-[color:var(--text-tertiary)]"
              }`}
              aria-hidden="true"
            />
          </button>
        );
      })}
    </div>
  );
}
