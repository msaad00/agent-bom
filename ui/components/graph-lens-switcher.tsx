"use client";

import { usePathname, useRouter } from "next/navigation";
import { InsightLayerToggle } from "@/components/insight-layer-toggle";

// One security-graph surface, several lenses. Each lens is a deep route that keeps
// working on its own (deep links + e2e), but the nav now exposes a single
// "Security Graph" entry and users switch lenses from this bar instead of hunting
// through five separate sidebar links.
interface GraphLens {
  id: string;
  label: string;
  icon: string;
  href: string;
  match: (path: string) => boolean;
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
    match: (p) => p === "/graph" || p.startsWith("/graph/"),
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

export function GraphLensSwitcher() {
  const path = usePathname() ?? "/security-graph";
  const router = useRouter();

  const layers = GRAPH_LENSES.map((lens) => ({
    id: lens.id,
    label: lens.label,
    icon: lens.icon,
    active: lens.match(path),
  }));

  const onToggle = (id: string) => {
    const lens = GRAPH_LENSES.find((l) => l.id === id);
    if (!lens || lens.match(path)) return;
    router.push(lens.href);
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-3">
      <div className="min-w-0">
        <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[color:var(--text-tertiary)]">
          Security Graph
        </p>
        <p className="mt-0.5 text-xs text-[color:var(--text-secondary)]">
          One graph, multiple lenses — switch how you read the same estate.
        </p>
      </div>
      <InsightLayerToggle layers={layers} onToggle={onToggle} />
    </div>
  );
}
