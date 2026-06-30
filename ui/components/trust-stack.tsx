"use client";

import Link from "next/link";

export type TrustLayerNum = 1 | 2 | 3 | 4;

/** Real, observed signal feeding one trust layer. */
export interface TrustLayerSignal {
  /** Count of connected/populated items observed for this layer. */
  count: number;
}

export type TrustStackSignals = Record<TrustLayerNum, TrustLayerSignal>;

const LAYERS = [
  {
    num: 4,
    name: "Trust",
    desc: "Supply Chain Integrity",
    href: "/compliance",
    color: "emerald",
    noun: "packages",
  },
  {
    num: 3,
    name: "Agent-Build",
    desc: "Tool & Framework Security",
    href: "/mesh",
    color: "blue",
    noun: "tools",
  },
  {
    num: 2,
    name: "Semantic",
    desc: "Data Context & Meaning",
    href: "/governance",
    color: "purple",
    noun: "contexts",
  },
  {
    num: 1,
    name: "Data",
    desc: "Storage & Pipelines",
    href: "/agents",
    color: "amber",
    noun: "sources",
  },
] as const;

type LayerColor = (typeof LAYERS)[number]["color"];

const colorMap: Record<LayerColor, { border: string; bg: string; hoverBg: string; text: string; accent: string }> = {
  emerald: {
    border: "border-emerald-700",
    bg: "bg-emerald-950/40",
    hoverBg: "hover:bg-emerald-950/70",
    text: "text-emerald-400",
    accent: "text-emerald-300",
  },
  blue: {
    border: "border-blue-700",
    bg: "bg-blue-950/40",
    hoverBg: "hover:bg-blue-950/70",
    text: "text-blue-400",
    accent: "text-blue-300",
  },
  purple: {
    border: "border-purple-700",
    bg: "bg-purple-950/40",
    hoverBg: "hover:bg-purple-950/70",
    text: "text-purple-400",
    accent: "text-purple-300",
  },
  amber: {
    border: "border-amber-700",
    bg: "bg-amber-950/40",
    hoverBg: "hover:bg-amber-950/70",
    text: "text-amber-400",
    accent: "text-amber-300",
  },
};

const EMPTY_SIGNALS: TrustStackSignals = {
  1: { count: 0 },
  2: { count: 0 },
  3: { count: 0 },
  4: { count: 0 },
};

/**
 * Layered coverage view of the AI trust stack. Each layer's badge is derived
 * from a real observed `count` (data sources, governance context, tools, and
 * supply-chain packages) instead of a hardcoded Full/Partial label — so an
 * empty deployment honestly reads as "Not connected" until evidence exists.
 */
export function TrustStack({ signals = EMPTY_SIGNALS }: { signals?: TrustStackSignals }) {
  return (
    <div className="space-y-2">
      {LAYERS.map((layer) => {
        const c = colorMap[layer.color];
        const count = signals[layer.num as TrustLayerNum]?.count ?? 0;
        const active = count > 0;
        return (
          <Link
            key={layer.num}
            href={layer.href}
            className={`flex items-center gap-4 rounded-xl border px-5 py-3.5 transition-all duration-200 group ${
              active
                ? `${c.border} ${c.bg} ${c.hoverBg}`
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] hover:bg-[color:var(--surface-elevated)]"
            }`}
          >
            {/* Layer number + name */}
            <div className="flex items-center gap-3 min-w-[160px]">
              <span className={`text-lg font-bold font-mono ${active ? c.text : "text-[color:var(--text-tertiary)]"}`}>
                L{layer.num}
              </span>
              <span className={`text-sm font-semibold ${active ? c.accent : "text-[color:var(--text-secondary)]"}`}>
                {layer.name}
              </span>
            </div>

            {/* Description */}
            <div className="flex-1 text-sm text-[color:var(--text-secondary)] group-hover:text-[color:var(--foreground)] transition-colors">
              {layer.desc}
            </div>

            {/* Data-driven coverage badge */}
            {active ? (
              <span className="rounded-full border border-emerald-700 bg-emerald-900/60 px-2.5 py-1 text-xs font-medium tabular-nums text-emerald-300">
                {count.toLocaleString()} {layer.noun}
              </span>
            ) : (
              <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-xs font-medium text-[color:var(--text-tertiary)]">
                Not connected
              </span>
            )}
          </Link>
        );
      })}
    </div>
  );
}
