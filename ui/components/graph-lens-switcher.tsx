"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { InsightLayerToggle } from "@/components/insight-layer-toggle";
import { GraphLegendDock } from "@/components/graph-chrome";
import { ASSET_DRIFT_GRAPH_SCOPE_PARAM } from "@/components/lineage-filter";
import type { LegendItem } from "@/lib/graph-utils";

// One security-graph surface, several lenses. Attack Paths keeps its own
// `/security-graph` route; Lineage, Asset Drift, Agent Mesh, and Context are all
// hosted on the single `/graph` surface and switched via URL params (`?scope=`
// for drift, `?lens=` for mesh/context) — no separate route per lens. The nav
// exposes one "Security Graph" entry and users switch lenses from this bar.
interface GraphLens {
  id: string;
  label: string;
  icon: string;
  href: string;
  match: (path: string, scope: string | null, lens: string | null) => boolean;
}

const isGraphPath = (p: string) => p === "/graph" || p.startsWith("/graph/");

const GRAPH_LENSES: GraphLens[] = [
  {
    id: "attack-path",
    label: "Attack Paths",
    icon: "🎯",
    href: "/security-graph",
    match: (p) => p.startsWith("/security-graph"),
  },
  {
    id: "lineage",
    label: "Lineage",
    icon: "🌿",
    href: "/graph",
    match: (p, scope, lens) =>
      isGraphPath(p) && scope !== ASSET_DRIFT_GRAPH_SCOPE_PARAM && !lens,
  },
  {
    id: "asset-drift",
    label: "Asset Drift",
    icon: "📐",
    href: `/graph?scope=${ASSET_DRIFT_GRAPH_SCOPE_PARAM}`,
    match: (p, scope) =>
      isGraphPath(p) && scope === ASSET_DRIFT_GRAPH_SCOPE_PARAM,
  },
  {
    id: "mesh",
    label: "Agent Mesh",
    icon: "🕸️",
    href: "/graph?lens=mesh",
    match: (p, _scope, lens) => isGraphPath(p) && lens === "mesh",
  },
  {
    id: "context",
    label: "Context",
    icon: "🗺️",
    href: "/graph?lens=context",
    match: (p, _scope, lens) => isGraphPath(p) && lens === "context",
  },
];

const SHARED_INVESTIGATION_PARAMS = [
  "scan",
  "agent",
  "cve",
  "package",
  "root",
  "root_label",
  "investigate",
  "q",
  "rollup",
  "rollup_node",
] as const;

export function buildInvestigationLensHref(
  targetHref: string,
  current: { get(name: string): string | null },
): string {
  const [pathname, targetQuery = ""] = targetHref.split("?", 2);
  const params = new URLSearchParams();
  for (const key of SHARED_INVESTIGATION_PARAMS) {
    const value = current.get(key);
    if (value) params.set(key, value);
  }
  // Target-owned parameters (for example the Asset Drift scope) are
  // authoritative and replace any context inherited from the current lens.
  for (const [key, value] of new URLSearchParams(targetQuery)) {
    params.set(key, value);
  }
  const query = params.toString();
  return query ? `${pathname}?${query}` : (pathname ?? targetHref);
}

interface GraphLensSwitcherProps {
  variant?: "inline" | "floating" | "compact";
  legendItems?: LegendItem[];
  legendDefaultOpen?: boolean;
}

export function GraphLensSwitcher({
  variant = "inline",
  legendItems,
  legendDefaultOpen = false,
}: GraphLensSwitcherProps) {
  const path = usePathname() ?? "/security-graph";
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = searchParams?.get("scope") ?? null;
  const activeLens = searchParams?.get("lens") ?? null;

  const layers = GRAPH_LENSES.map((lens) => ({
    id: lens.id,
    label: lens.label,
    icon: lens.icon,
    active: lens.match(path, scope, activeLens),
  }));

  const onToggle = (id: string) => {
    const lens = GRAPH_LENSES.find((l) => l.id === id);
    if (!lens || lens.match(path, scope, activeLens)) return;
    router.push(buildInvestigationLensHref(lens.href, searchParams));
  };

  const content = (
    <div
      className={
        variant === "floating"
          ? "pointer-events-auto flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-2xl border border-[var(--border-subtle)]/80 bg-[var(--background)]/85 px-3 py-2 shadow-2xl shadow-black/40 backdrop-blur"
          : variant === "compact"
            ? "flex flex-col gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--background)]/80 px-3 py-2"
            : "flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3"
      }
    >
      {variant !== "compact" && (
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[color:var(--text-tertiary)]">
            {variant === "floating" ? "Security Graph Lens" : "Security Graph"}
          </p>
          <p
            className={`mt-0.5 text-xs text-[color:var(--text-secondary)] ${
              variant === "floating" ? "hidden sm:block" : ""
            }`}
          >
            One graph, multiple lenses — switch how you read the same inventory.
          </p>
        </div>
      )}
      <InsightLayerToggle layers={layers} onToggle={onToggle} />
      {legendItems && legendItems.length > 0 ? (
        <GraphLegendDock items={legendItems} defaultOpen={legendDefaultOpen} />
      ) : null}
    </div>
  );

  if (variant === "floating") {
    return (
      <div
        data-testid="graph-lens-floating-bar"
        className="pointer-events-none absolute left-1/2 top-3 z-30 w-[min(760px,calc(100%-2rem))] -translate-x-1/2"
      >
        {content}
      </div>
    );
  }

  return content;
}
