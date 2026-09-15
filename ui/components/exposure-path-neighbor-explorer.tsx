"use client";

import { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import { Bot, Bug, ChevronRight, Database, KeyRound, Loader2, Package, Server, ShieldAlert, Wrench } from "lucide-react";
import { api, type GraphNodeNeighborsResponse } from "@/lib/api";
import type { UnifiedNode } from "@/lib/graph-schema";
import { buildGraphInvestigationHref, exposureRoleForEntityType } from "@/lib/attack-paths";
import { formatExposureEntityDisplay } from "@/lib/entity-display";
import type { ExposureEntityRole, ExposurePath } from "@/lib/exposure-path";

/**
 * Progressive-disclosure layer for the exposure path. The command-center graph
 * renders the fixed Agent→Server→Package→Finding chain; this explorer lets an
 * analyst expand any canonical graph hop to pull that node's *direct*
 * graph neighbors inline — the dependencies and dependents that never fit in
 * the fixed chain — then collapse them again. Neighbors are lazy-loaded on
 * expand (one hop, one level at a time) and fan-out is bounded so a
 * high-degree hub never explodes the view.
 */

const NEIGHBOR_LIMIT = 12;

const ROLE_STYLE: Record<ExposureEntityRole, { icon: LucideIcon; chip: string; accent: string }> = {
  agent: { icon: Bot, chip: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200", accent: "text-emerald-300" },
  server: { icon: Server, chip: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200", accent: "text-sky-300" },
  package: { icon: Package, chip: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200", accent: "text-amber-300" },
  finding: { icon: Bug, chip: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-200", accent: "text-red-300" },
  credential: { icon: KeyRound, chip: "border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-200", accent: "text-fuchsia-300" },
  tool: { icon: Wrench, chip: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200", accent: "text-purple-300" },
  environment: { icon: Database, chip: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-200", accent: "text-cyan-300" },
  cluster: { icon: Database, chip: "border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-200", accent: "text-indigo-300" },
  unknown: {
    icon: ShieldAlert,
    chip: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]",
    accent: "text-[color:var(--text-tertiary)]",
  },
};

type NeighborLoadState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; data: GraphNodeNeighborsResponse };

interface NeighborEntry {
  id: string;
  role: ExposureEntityRole;
  title: string;
  subtitle?: string | undefined;
  relationship: string;
  kind: "dependency" | "dependent" | "related";
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
  const neighbors = new Map(data.neighbors.map((node) => [node.id, node]));
  const groups = new Map<string, { node: UnifiedNode; kind: NeighborEntry["kind"]; relationships: Set<string> }>();
  for (const edge of data.edges) {
    const id = edge.source === hopId ? edge.target : edge.target === hopId ? edge.source : null;
    const node = id ? neighbors.get(id) : undefined;
    if (!node || id === hopId) continue;
    const kind = edge.source === hopId ? "dependency" : "dependent";
    const key = `${kind}:${id}`;
    const group = groups.get(key) ?? { node, kind, relationships: new Set<string>() };
    group.relationships.add(humanizeRelationship(edge.relationship));
    groups.set(key, group);
  }
  const linked = new Set([...groups.values()].map((group) => group.node.id));
  for (const node of neighbors.values()) {
    if (!linked.has(node.id)) groups.set(`related:${node.id}`, { node, kind: "related", relationships: new Set(["Relationship unavailable"]) });
  }
  return [...groups.values()].map(({ node, kind, relationships }) => {
    const ref = neighborRefFromNode(node);
    return { id: node.id, role: ref.role, title: ref.title, subtitle: ref.subtitle,
      relationship: [...relationships].sort().join(" · "), kind };
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
  const expandable = Boolean(hop.id);

  const fetchNeighbors = useCallback(async () => {
    setLoad({ status: "loading" });
    try {
      const data = await api.getGraphNodeNeighbors(hop.id, { scanId, limit: NEIGHBOR_LIMIT, direction: "both" });
      setLoad({ status: "ready", data });
    } catch {
      setLoad({ status: "error" });
    }
  }, [hop.id, scanId]);

  const onToggle = useCallback(() => {
    // Keep network effects outside state updaters (React may replay them).
    if (!expanded && load === null) void fetchNeighbors();
    setExpanded(!expanded);
  }, [expanded, fetchNeighbors, load]);

  const entries = useMemo(
    () => (load?.status === "ready" ? toNeighborEntries(hop.id, load.data) : []),
    [hop.id, load],
  );
  const dependencies = entries.filter((entry) => entry.kind === "dependency");
  const dependents = entries.filter((entry) => entry.kind === "dependent");
  const related = entries.filter((entry) => entry.kind === "related");
  const moreCount =
    load?.status === "ready" && load.data.truncated ? Math.max(0, load.data.total_neighbors - load.data.neighbors.length) : 0;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]/60">
      <div className="flex items-center gap-2 px-3 py-2">
        <span className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 ${style.chip}`}>
          <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span className="min-w-0">
            <span className="block truncate text-[11px] font-medium text-[color:var(--foreground)]">{hop.label}</span>
            <span className="block text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{hop.kindLabel ?? hop.role}</span>
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
          <span className="text-[10px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Node ID unavailable</span>
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
            <div className="flex items-center gap-3 text-[11px] text-ink-secondary">
              Could not load neighbors.
              <button type="button" onClick={() => void fetchNeighbors()} className="underline">Retry neighbor lookup</button>
            </div>
          )}
          {load?.status === "ready" && entries.length === 0 && (
            <div className="text-[11px] text-[color:var(--text-secondary)]">{!load.data.found ? "Node unavailable in this snapshot." : load.data.truncated ? "No neighbors returned in this partial context." : "No direct graph neighbors recorded for this node."}</div>
          )}
          {load?.status === "ready" && dependencies.length > 0 && (
            <NeighborGroup label="Outgoing relationships" entries={dependencies} />
          )}
          {load?.status === "ready" && dependents.length > 0 && (
            <NeighborGroup label="Incoming relationships" entries={dependents} />
          )}
          {related.length > 0 && <NeighborGroup label="Other returned neighbors" entries={related} />}
          {moreCount > 0 && (
            <p className="text-[10px] uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
              +{moreCount} more neighbor{moreCount === 1 ? "" : "s"} not shown
            </p>
          )}
          {load?.status === "ready" && (
            <Link
              href={buildGraphInvestigationHref({
                scanId,
                rootId: hop.id,
                rootLabel: hop.label,
              })}
              aria-label={`Traverse from ${hop.label}`}
              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-2.5 py-1.5 text-[11px] font-medium text-sky-800 transition hover:border-sky-500/60 dark:text-sky-200"
            >
              Traverse from this hop
              <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
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
  const anyExpandable = hops.some((hop) => Boolean(hop.id));
  if (!anyExpandable) return null;

  return (
    <section aria-label="Expand path neighbors" className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-[10px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">Expand path neighbors</div>
        <div className="text-[10px] text-[color:var(--text-tertiary)]">Direct relationships · loaded on demand</div>
      </div>
      <div className="space-y-2">
        {hops.map((hop) => (
          <HopRow key={`${scanId}:${hop.id}`} hop={hop} scanId={scanId} />
        ))}
      </div>
    </section>
  );
}
