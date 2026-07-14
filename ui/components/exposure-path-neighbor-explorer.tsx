"use client";

import { useCallback, useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { Bot, Bug, ChevronRight, Database, KeyRound, Loader2, Package, Server, ShieldAlert, Wrench } from "lucide-react";
import { api, type GraphNodeNeighborsResponse } from "@/lib/api";
import type { UnifiedNode } from "@/lib/graph-schema";
import { exposureRoleForEntityType } from "@/lib/attack-paths";
import { formatExposureEntityDisplay } from "@/lib/entity-display";
import type { ExposureEntityRole, ExposurePath } from "@/lib/exposure-path";

/**
 * Progressive-disclosure layer for the exposure path. The command-center graph
 * renders the fixed Agent→Server→Package→Finding chain; this explorer lets an
 * analyst expand any package/server/agent hop to pull that node's *direct*
 * graph neighbors inline — the dependencies and dependents that never fit in
 * the fixed chain — then collapse them again. Neighbors are lazy-loaded on
 * expand (one hop, one level at a time) and fan-out is bounded so a
 * high-degree hub never explodes the view.
 */

const EXPANDABLE_ROLES: ReadonlySet<ExposureEntityRole> = new Set(["agent", "server", "package"]);
const NEIGHBOR_LIMIT = 12;

const ROLE_STYLE: Record<ExposureEntityRole, { icon: LucideIcon; chip: string; accent: string }> = {
  agent: { icon: Bot, chip: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200", accent: "text-emerald-300" },
  server: { icon: Server, chip: "border-sky-500/30 bg-sky-500/10 text-sky-200", accent: "text-sky-300" },
  package: { icon: Package, chip: "border-amber-500/30 bg-amber-500/10 text-amber-200", accent: "text-amber-300" },
  finding: { icon: Bug, chip: "border-red-500/30 bg-red-500/10 text-red-200", accent: "text-red-300" },
  credential: { icon: KeyRound, chip: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-200", accent: "text-fuchsia-300" },
  tool: { icon: Wrench, chip: "border-purple-500/30 bg-purple-500/10 text-purple-200", accent: "text-purple-300" },
  environment: { icon: Database, chip: "border-cyan-500/30 bg-cyan-500/10 text-cyan-200", accent: "text-cyan-300" },
  cluster: { icon: Database, chip: "border-indigo-500/30 bg-indigo-500/10 text-indigo-200", accent: "text-indigo-300" },
  unknown: {
    icon: ShieldAlert,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]",
    accent: "text-[color:var(--text-tertiary)]",
  },
};

type NeighborLoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; data: GraphNodeNeighborsResponse };

interface NeighborEntry {
  id: string;
  role: ExposureEntityRole;
  title: string;
  subtitle?: string | undefined;
  relationship: string;
  kind: "dependency" | "dependent";
}

function humanizeRelationship(value: string): string {
  return value
    .replace(/[_:]+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function neighborRefFromNode(node: UnifiedNode): { role: ExposureEntityRole; title: string; subtitle?: string | undefined } {
  const role = exposureRoleForEntityType(String(node.entity_type));
  const display = formatExposureEntityDisplay(node.label, role, node.attributes ?? {});
  return { role, title: display.title, subtitle: display.subtitle };
}

function toNeighborEntries(hopId: string, data: GraphNodeNeighborsResponse): NeighborEntry[] {
  const relationshipByNeighbor = new Map<string, { relationship: string; kind: "dependency" | "dependent" }>();
  for (const edge of data.edges) {
    if (edge.source === hopId && edge.target !== hopId) {
      relationshipByNeighbor.set(edge.target, { relationship: edge.relationship, kind: "dependency" });
    } else if (edge.target === hopId && edge.source !== hopId) {
      // Keep an out-edge classification if we already have one; only fill in when absent.
      if (!relationshipByNeighbor.has(edge.source)) {
        relationshipByNeighbor.set(edge.source, { relationship: edge.relationship, kind: "dependent" });
      }
    }
  }

  return data.neighbors.map((node) => {
    const ref = neighborRefFromNode(node);
    const edgeInfo = relationshipByNeighbor.get(node.id);
    return {
      id: node.id,
      role: ref.role,
      title: ref.title,
      subtitle: ref.subtitle,
      relationship: humanizeRelationship(edgeInfo?.relationship ?? "related"),
      kind: edgeInfo?.kind ?? "dependency",
    };
  });
}

function NeighborChip({ entry }: { entry: NeighborEntry }) {
  const style = ROLE_STYLE[entry.role] ?? ROLE_STYLE.unknown;
  const Icon = style.icon;
  return (
    <div className={`flex min-w-0 items-center gap-2 rounded-lg border px-2.5 py-1.5 ${style.chip}`}>
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <p className="truncate text-[11px] font-medium text-[color:var(--foreground)]">{entry.title}</p>
        <p className="truncate text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
          {entry.relationship}
        </p>
      </div>
    </div>
  );
}

function HopRow({ hop, scanId }: { hop: ExposurePath["hops"][number]; scanId?: string | undefined }) {
  const [expanded, setExpanded] = useState(false);
  const [load, setLoad] = useState<NeighborLoadState | null>(null);
  const style = ROLE_STYLE[hop.role] ?? ROLE_STYLE.unknown;
  const Icon = style.icon;
  const expandable = EXPANDABLE_ROLES.has(hop.role);

  const fetchNeighbors = useCallback(async () => {
    setLoad({ status: "loading" });
    try {
      const data = await api.getGraphNodeNeighbors(hop.id, { scanId, limit: NEIGHBOR_LIMIT, direction: "both" });
      setLoad({ status: "ready", data });
    } catch (error) {
      setLoad({ status: "error", message: error instanceof Error ? error.message : "Could not load neighbors" });
    }
  }, [hop.id, scanId]);

  const onToggle = useCallback(() => {
    setExpanded((prev) => {
      const next = !prev;
      // Lazy-load once, on first expand; cached afterwards so collapse/expand is free.
      if (next && load === null) void fetchNeighbors();
      return next;
    });
  }, [fetchNeighbors, load]);

  const entries = useMemo(
    () => (load?.status === "ready" ? toNeighborEntries(hop.id, load.data) : []),
    [hop.id, load],
  );
  const dependencies = entries.filter((entry) => entry.kind === "dependency");
  const dependents = entries.filter((entry) => entry.kind === "dependent");
  const moreCount =
    load?.status === "ready" && load.data.truncated ? Math.max(0, load.data.total_neighbors - load.data.neighbors.length) : 0;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/60">
      <div className="flex items-center gap-2 px-3 py-2">
        <span className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 ${style.chip}`}>
          <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span className="min-w-0">
            <span className="block truncate text-[11px] font-medium text-[color:var(--foreground)]">{hop.label}</span>
            <span className="block text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{hop.role}</span>
          </span>
        </span>
        <span className="flex-1" />
        {expandable ? (
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={expanded}
            aria-label={expanded ? `Collapse neighbors of ${hop.label}` : `Expand neighbors of ${hop.label}`}
            className="flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1.5 text-[11px] font-medium text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            <ChevronRight
              className={`h-3.5 w-3.5 shrink-0 transition-transform ${expanded ? "rotate-90" : ""}`}
              aria-hidden="true"
            />
            <span>{expanded ? "Hide neighbors" : "Expand neighbors"}</span>
          </button>
        ) : (
          <span className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">leaf</span>
        )}
      </div>

      {expanded && (
        <div className="space-y-3 border-t border-[color:var(--border-subtle)] px-3 py-3">
          {load?.status === "loading" && (
            <div className="flex items-center gap-2 text-[11px] text-[color:var(--text-secondary)]">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              Loading neighbors…
            </div>
          )}
          {load?.status === "error" && (
            <div className="text-[11px] text-red-400">Could not load neighbors: {load.message}</div>
          )}
          {load?.status === "ready" && entries.length === 0 && (
            <div className="text-[11px] text-[color:var(--text-secondary)]">No direct graph neighbors recorded for this node.</div>
          )}
          {load?.status === "ready" && dependencies.length > 0 && (
            <NeighborGroup label="Dependencies" entries={dependencies} />
          )}
          {load?.status === "ready" && dependents.length > 0 && (
            <NeighborGroup label="Dependents" entries={dependents} />
          )}
          {moreCount > 0 && (
            <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
              +{moreCount} more neighbor{moreCount === 1 ? "" : "s"} not shown
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function NeighborGroup({ label, entries }: { label: string; entries: NeighborEntry[] }) {
  return (
    <div className="space-y-1.5">
      <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {entries.map((entry) => (
          <NeighborChip key={`${entry.kind}-${entry.id}`} entry={entry} />
        ))}
      </div>
    </div>
  );
}

export function ExposurePathNeighborExplorer({ path, scanId }: { path: ExposurePath; scanId?: string | undefined }) {
  const hops = path.hops;
  if (hops.length === 0) return null;
  const anyExpandable = hops.some((hop) => EXPANDABLE_ROLES.has(hop.role));
  if (!anyExpandable) return null;

  return (
    <section aria-label="Expand path neighbors" className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Expand path neighbors</div>
        <div className="text-[10px] text-[color:var(--text-tertiary)]">Direct dependencies &amp; dependents · loaded on demand</div>
      </div>
      <div className="space-y-2">
        {hops.map((hop) => (
          <HopRow key={hop.id} hop={hop} scanId={scanId} />
        ))}
      </div>
    </section>
  );
}
