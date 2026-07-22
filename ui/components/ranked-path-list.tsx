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
  /** MCP tool capability tags (read/write/exec/net) feeding path scoring. */
  capabilityTags?: string[] | undefined;
  /** Environments seen on path hops (prod weighting explainability). */
  environmentTags?: string[] | undefined;
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
            className={`grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2 rounded-xl border px-3 py-2.5 text-left transition sm:grid-cols-[auto_minmax(0,1fr)_auto_auto] sm:items-center sm:gap-3 ${
              active
                ? "border-orange-400/70 bg-orange-500/10 ring-1 ring-orange-400/60"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            <span
              className={`shrink-0 rounded-md px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
                row.rank === 1
                  ? "bg-orange-500/15 text-orange-700 dark:text-orange-300"
                  : "bg-[color:var(--surface)] text-[color:var(--text-tertiary)]"
              }`}
            >
              {row.rank === 1 ? "#1 fix first" : `#${row.rank}`}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block break-words text-sm font-medium leading-snug text-[color:var(--foreground)]">
                {row.cve ? `${row.cve} · ` : ""}
                {row.title}
              </span>
              <span className="mt-0.5 block text-[11px] text-[color:var(--text-tertiary)]">
                {row.hops} hop{row.hops === 1 ? "" : "s"} · {row.agents} agent{row.agents === 1 ? "" : "s"}
              </span>
              {(row.capabilityTags?.length || row.environmentTags?.length) ? (
                <span className="mt-1 flex flex-wrap gap-1">
                  {(row.environmentTags ?? []).slice(0, 2).map((tag) => (
                    <span
                      key={`env-${tag}`}
                      className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-[0.12em] text-sky-800 dark:text-sky-200"
                    >
                      {tag}
                    </span>
                  ))}
                  {(row.capabilityTags ?? []).slice(0, 4).map((tag) => (
                    <span
                      key={`cap-${tag}`}
                      className="rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-[0.12em] text-violet-800 dark:text-violet-200"
                    >
                      {tag === "execute" ? "exec" : tag === "network" ? "net" : tag}
                    </span>
                  ))}
                </span>
              ) : null}
            </span>
            <span className="col-span-2 col-start-2 justify-self-start rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-left sm:col-span-1 sm:col-start-auto sm:justify-self-auto sm:text-right">
              <span className="block text-[9px] font-semibold uppercase tracking-[0.14em] text-red-300/80">
                Path risk
              </span>
              <span className="block font-mono text-sm font-semibold leading-4 text-red-200">
                {row.riskScore.toFixed(1)}
              </span>
            </span>
            <ChevronRight
              className={`col-start-3 row-start-1 h-4 w-4 shrink-0 self-center transition sm:col-start-auto sm:row-start-auto ${
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
