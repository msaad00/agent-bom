"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useAuthState } from "@/components/auth-provider";
import { useIncidentNeighborhood } from "@/hooks/use-incident-neighborhood";
import { contextRelationshipLabel } from "@/lib/context-graph";

type Props = { scanId: string; nodeId: string; onInspectNode?: ((id: string) => void) | undefined };

type RelationshipState = ReturnType<typeof useIncidentNeighborhood> & { activate: () => void };
const RelationshipContext = createContext<RelationshipState | null>(null);

/** Keep bounded evidence alive when responsive layouts move the visible panel. */
export function GraphRecordedRelationshipScope({ children, ...props }: Props & { children: ReactNode }) {
  const { session, loading } = useAuthState();
  if (loading || !session) return children;
  const owner = JSON.stringify(session);
  return <RelationshipScope key={JSON.stringify([owner, props.scanId, props.nodeId])} {...props} owner={owner}>{children}</RelationshipScope>;
}

function RelationshipScope({ scanId, nodeId, owner, children }: Props & { owner: string; children: ReactNode }) {
  const [enabled, setEnabled] = useState(false);
  const graph = useIncidentNeighborhood(scanId, nodeId, "both", owner, enabled);
  const activate = useCallback(() => setEnabled(true), []);
  return <RelationshipContext.Provider value={{ ...graph, activate }}>{children}</RelationshipContext.Provider>;
}

export function GraphRecordedRelationships({ nodeId, onInspectNode }: Props) {
  const graph = useContext(RelationshipContext);
  const activate = graph?.activate;
  useEffect(() => { activate?.(); }, [activate]);
  if (!graph) return <p role="status" className="text-xs text-ink-secondary">Resolving access to recorded relationships…</p>;
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  // Keep rows whose endpoints could not be hydrated. Their canonical IDs are
  // still evidence, while an unavailable label is never inferred from the ID.
  const edges = [...new Map(graph.pages.flatMap(page => page.edges).map(edge => [JSON.stringify([edge.source, edge.target, edge.relationship]), edge])).values()];
  const lastPage = graph.pages.at(-1);
  const missingLabels = edges.some(edge => !nodes.has(edge.source) || !nodes.has(edge.target));
  return <div className="space-y-3 text-xs">
    <p role="status" className="text-ink-secondary">
      {graph.busy && !lastPage ? "Loading recorded relationships…" : `${edges.length} loaded relationships · total unknown`}
    </p>
    {graph.error && <div role="alert" className="space-y-2 text-ink-secondary">
      <p>{graph.error}</p>
      <button type="button" className="rounded border border-outline px-3 py-2" disabled={graph.busy} onClick={() => graph.stale ? graph.restart() : void graph.load(nodeId, lastPage?.next_cursor ?? undefined)}>Retry relationships</button>
    </div>}
    {missingLabels && <p className="text-ink-secondary">Some endpoint labels are unavailable. Canonical identifiers are shown where needed.</p>}
    <ul className="max-h-80 space-y-2 overflow-y-auto">
      {edges.map(edge => {
        const neighborId = edge.source === nodeId ? edge.target : edge.source;
        const label = nodes.get(neighborId)?.label || neighborId;
        const direction = edge.source === edge.target ? "Self relationship" : edge.direction === "bidirectional" ? "Bidirectional ↔" : edge.direction === "directed" ? (edge.source === nodeId ? "Outgoing →" : "← Incoming") : "Related";
        const relationship = edge.relationship === "uses" ? "Recorded connection" : contextRelationshipLabel(edge.relationship);
        return <li key={JSON.stringify([edge.source, edge.target, edge.relationship])} className="rounded-lg border border-outline p-3 [overflow-wrap:anywhere]">
          <p className="mb-1 text-ink-secondary">{direction} · {relationship}</p>
          {onInspectNode ? <button type="button" onClick={() => onInspectNode(neighborId)} className="block w-full break-words text-left text-sm font-medium text-emerald-800 dark:text-emerald-300">{label}</button> : <p className="break-words text-sm font-medium">{label}</p>}
          <details className="mt-2 text-ink-secondary"><summary className="cursor-pointer">Canonical identifiers</summary>
            <dl className="mt-2 space-y-1 break-all"><dt>Source</dt><dd>{edge.source}</dd><dt>Relationship</dt><dd>{edge.relationship}</dd><dt>Target</dt><dd>{edge.target}</dd></dl>
          </details>
        </li>;
      })}
    </ul>
    {lastPage?.next_cursor && !graph.error && <button type="button" disabled={graph.busy || graph.capped} onClick={() => void graph.load(nodeId, lastPage.next_cursor!)} className="rounded-lg border border-outline px-3 py-2 disabled:opacity-50">{graph.busy ? "Loading relationships…" : "Load more recorded relationships"}</button>}
    {graph.capped && lastPage?.next_cursor && <p className="text-ink-secondary">Display limit reached. Focus on a connected entity to continue investigating.</p>}
    {lastPage && !lastPage.next_cursor && !graph.error && <p className="text-ink-secondary">End of recorded pages. Source collection coverage remains separate.</p>}
    <p className="text-ink-secondary">Recorded relationships do not establish execution or successful data access.</p>
  </div>;
}
