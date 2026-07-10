"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { InsightLayerToggle } from "@/components/insight-layer-toggle";
import { ASSET_DRIFT_GRAPH_SCOPE_PARAM } from "@/components/lineage-filter";

// One security-graph surface, several lenses. Each lens is a deep route that keeps
// working on its own (deep links + e2e), but the nav now exposes a single
// "Security Graph" entry and users switch lenses from this bar instead of hunting
// through five separate sidebar links.
interface GraphLens {
  id: string;
  label: string;
  icon: string;
  href: string;
  match: (path: string, scope: string | null) => boolean;
}

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
    match: (p, scope) =>
      (p === "/graph" || p.startsWith("/graph/")) &&
      scope !== ASSET_DRIFT_GRAPH_SCOPE_PARAM,
  },
  {
    id: "asset-drift",
    label: "Asset Drift",
    icon: "📐",
    href: `/graph?scope=${ASSET_DRIFT_GRAPH_SCOPE_PARAM}`,
    match: (p, scope) =>
      (p === "/graph" || p.startsWith("/graph/")) &&
      scope === ASSET_DRIFT_GRAPH_SCOPE_PARAM,
  },
  {
    id: "mesh",
    label: "Agent Mesh",
    icon: "🕸️",
    href: "/mesh",
    match: (p) => p.startsWith("/mesh"),
  },
  {
    id: "context",
    label: "Context",
    icon: "🗺️",
    href: "/context",
    match: (p) => p.startsWith("/context"),
  },
];

interface GraphLensSwitcherProps {
  variant?: "inline" | "floating" | "compact";
}

export function GraphLensSwitcher({
  variant = "inline",
}: GraphLensSwitcherProps) {
  const path = usePathname() ?? "/security-graph";
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = searchParams?.get("scope") ?? null;

  const layers = GRAPH_LENSES.map((lens) => ({
    id: lens.id,
    label: lens.label,
    icon: lens.icon,
    active: lens.match(path, scope),
  }));

  const onToggle = (id: string) => {
    const lens = GRAPH_LENSES.find((l) => l.id === id);
    if (!lens || lens.match(path, scope)) return;
    router.push(lens.href);
  };

  const content = (
    <div
      className={
        variant === "floating"
          ? "pointer-events-auto flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-2xl border border-zinc-700/80 bg-zinc-950/85 px-3 py-2 shadow-2xl shadow-black/40 backdrop-blur"
          : variant === "compact"
            ? "flex flex-wrap items-center justify-between gap-2 rounded-xl border border-zinc-800 bg-zinc-950/80 px-3 py-2"
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
