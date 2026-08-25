"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { InsightLayerToggle } from "@/components/insight-layer-toggle";
import { GraphLegendDock } from "@/components/graph-chrome";
import { ASSET_DRIFT_GRAPH_SCOPE_PARAM } from "@/components/lineage-filter";
import type { LegendItem } from "@/lib/graph-utils";

// One security-graph route, several lenses. URL params switch the composed
// surface without tearing down shared investigation context. `/graph` remains
// a compatible direct entry point for existing links.
interface GraphLens {
  id: string;
  label: string;
  icon: string;
  href: string;
  preserveContext?: boolean;
  match: (
    path: string,
    scope: string | null,
    lens: string | null,
    hasLegacyAttackFocus: boolean,
  ) => boolean;
}

const isLegacyGraphPath = (p: string) => p === "/graph" || p.startsWith("/graph/");
const isSecurityGraphPath = (p: string) => p.startsWith("/security-graph");

const CANONICAL_GRAPH_LENSES: GraphLens[] = [
  {
    id: "estate",
    label: "Estate",
    icon: "◫",
    href: "/security-graph?lens=estate&rollup=1",
    match: (p, _scope, lens, hasLegacyAttackFocus) =>
      isSecurityGraphPath(p) &&
      (lens === "estate" || (!lens && !hasLegacyAttackFocus)),
  },
  {
    id: "cloud",
    label: "Cloud",
    icon: "☁",
    href: "/security-graph?lens=cloud",
    match: (p, _scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) && lens === "cloud",
  },
  {
    id: "repository",
    label: "Repository",
    icon: "⌘",
    href: "/security-graph?lens=repository",
    match: (p, _scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) && lens === "repository",
  },
  {
    id: "identity",
    label: "Identity",
    icon: "◎",
    href: "/security-graph?lens=identity",
    match: (p, _scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) && lens === "identity",
  },
  {
    id: "lineage",
    label: "Lineage",
    icon: "🌿",
    href: "/security-graph?lens=lineage",
    match: (p, scope, lens) =>
      scope !== ASSET_DRIFT_GRAPH_SCOPE_PARAM &&
      ((isSecurityGraphPath(p) && lens === "lineage") || (isLegacyGraphPath(p) && !lens)),
  },
  {
    id: "attack-path",
    label: "Attack Paths",
    icon: "🎯",
    href: "/security-graph?lens=attack-path",
    match: (p, _scope, lens, hasLegacyAttackFocus) =>
      isSecurityGraphPath(p) &&
      (lens === "attack-path" || (!lens && hasLegacyAttackFocus)),
  },
  {
    id: "asset-drift",
    label: "Asset Drift",
    icon: "📐",
    href: `/security-graph?lens=asset-drift&scope=${ASSET_DRIFT_GRAPH_SCOPE_PARAM}`,
    match: (p, scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) &&
      scope === ASSET_DRIFT_GRAPH_SCOPE_PARAM &&
      (lens === "asset-drift" || !lens),
  },
];

const SPECIALIZED_GRAPH_VIEWS: GraphLens[] = [
  {
    id: "mesh",
    label: "Agent Mesh",
    icon: "🕸️",
    href: "/security-graph?lens=mesh",
    preserveContext: false,
    match: (p, _scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) && lens === "mesh",
  },
  {
    id: "context",
    label: "Context",
    icon: "🗺️",
    href: "/security-graph?lens=context",
    preserveContext: false,
    match: (p, _scope, lens) =>
      (isSecurityGraphPath(p) || isLegacyGraphPath(p)) && lens === "context",
  },
];

const ALL_GRAPH_VIEWS = [...CANONICAL_GRAPH_LENSES, ...SPECIALIZED_GRAPH_VIEWS];

const LEGACY_ATTACK_FOCUS_PARAMS = ["agent", "cve", "finding", "node", "package", "trace"] as const;

const SHARED_INVESTIGATION_PARAMS = [
  "scan",
  "agent",
  "cve",
  "finding",
  "node",
  "package",
  "root",
  "root_label",
  "investigate",
  "q",
  "rollup",
  "rollup_node",
  "trace",
  "scenario",
  "state",
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
  const targetParams = new URLSearchParams(targetQuery);
  const targetLens = targetParams.get("lens");
  if (targetLens && targetLens !== "estate") {
    // Roll-up is the Estate lens' composition state, not investigation
    // identity. Carrying it into Cloud/Repository/Identity would make those
    // buttons render the unfiltered estate roll-up and mislabel the canvas.
    params.delete("rollup");
    params.delete("rollup_node");
  }
  // Target-owned parameters (for example the Asset Drift scope) are
  // authoritative and replace any context inherited from the current lens.
  for (const [key, value] of targetParams) {
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
  const hasLegacyAttackFocus =
    !activeLens && LEGACY_ATTACK_FOCUS_PARAMS.some((key) => Boolean(searchParams?.get(key)));

  const canonicalLayers = CANONICAL_GRAPH_LENSES.map((lens) => ({
    id: lens.id,
    label: lens.label,
    icon: lens.icon,
    active: lens.match(path, scope, activeLens, hasLegacyAttackFocus),
  }));
  const specializedViews = SPECIALIZED_GRAPH_VIEWS.map((lens) => ({
    id: lens.id,
    label: lens.label,
    icon: lens.icon,
    active: lens.match(path, scope, activeLens, hasLegacyAttackFocus),
  }));
  const specializedViewActive = specializedViews.some((view) => view.active);

  const onToggle = (id: string) => {
    const lens = ALL_GRAPH_VIEWS.find((candidate) => candidate.id === id);
    if (!lens || lens.match(path, scope, activeLens, hasLegacyAttackFocus)) return;
    router.push(
      lens.preserveContext === false
        ? lens.href
        : buildInvestigationLensHref(lens.href, searchParams),
    );
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
            Canonical lenses share one persisted estate snapshot and its exact counts.
          </p>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
        <InsightLayerToggle layers={canonicalLayers} onToggle={onToggle} />
        <details
          className="group relative"
          open={specializedViewActive}
        >
          <summary className="graph-chip-neutral cursor-pointer select-none whitespace-nowrap text-[10px] font-semibold uppercase tracking-[0.12em] hover:border-[color:var(--border-strong)]">
            More views
          </summary>
          <div className="absolute right-0 top-[calc(100%+0.5rem)] z-40 flex min-w-72 flex-wrap items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--background)] p-3 shadow-xl">
            <InsightLayerToggle
              layers={specializedViews}
              label="Views"
              onToggle={onToggle}
            />
            <span className="text-[10px] text-[color:var(--text-tertiary)]">
              Scan-specific views; not canonical estate lenses.
            </span>
          </div>
        </details>
      </div>
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
