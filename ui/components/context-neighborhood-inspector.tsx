"use client";

import type { ContextGraphNode, ContextGraphEdge } from "@/lib/context-graph";
import { contextRelationshipLabel } from "@/lib/context-graph";

/** Inspect only the recorded projection; no identity or permission inference. */
export function ContextNeighborhoodInspector({ nodes, edges, selectedId, selectedEdge, hiddenCount, onSelect, onExpand, onClose }: {
  nodes: ContextGraphNode[]; edges: ContextGraphEdge[]; selectedId: string | null;
  selectedEdge: { source: string; target: string; relationship: string; package?: string | undefined } | null;
  hiddenCount: number; onSelect: (id: string) => void; onExpand: () => void; onClose: () => void;
}) {
  const node = nodes.find(item => item.id === selectedId);
  const related = node ? edges.filter(edge => edge.source === node.id || edge.target === node.id) : [];
  const groups = new Map<string, ContextGraphNode[]>();
  for (const item of nodes) groups.set(item.kind, [...(groups.get(item.kind) ?? []), item]);
  const label = (id: string) => nodes.find(item => item.id === id)?.label ?? id;
  return <aside aria-label="Agent neighborhood inspector" className="context-inspector">
    <div className="flex items-start justify-between gap-3">
      <div><p className="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Recorded neighborhood</p><h2 className="mt-1 break-words text-lg font-semibold">{selectedEdge ? contextRelationshipLabel(selectedEdge.relationship) : node?.label ?? "Explore connections"}</h2></div>
      {(node || selectedEdge) && <button className="shrink-0 text-sm underline" onClick={onClose}>Close inspection</button>}
    </div>
    {selectedEdge ? <div className="mt-4 space-y-3">
      <p className="break-words">{label(selectedEdge.source)} <span aria-label="to">→</span> {label(selectedEdge.target)}</p>
      <span className="context-evidence-badge">Recorded configuration</span>
      {selectedEdge.package && <p className="break-words">Affected package: {selectedEdge.package}</p>}
      <dl className="context-facts"><div><dt>Permission</dt><dd>Not established</dd></div><div><dt>Execution</dt><dd>Not established</dd></div><div><dt>Local exploitability</dt><dd>Not assessed</dd></div></dl>
      <p className="text-sm text-[var(--text-secondary)]">The arrow follows the recorded relationship. It does not prove a successful call or resource access.</p>
    </div> : node ? <div className="mt-4 space-y-3">
      <span className="context-evidence-badge">{node.kind.replaceAll("_", " ")} · scan evidence</span>
      <p className="text-sm text-[var(--text-secondary)]">{related.length} visible relationships · {hiddenCount} additional neighbors in loaded evidence</p>
      <button disabled={!hiddenCount} onClick={onExpand} className="context-action w-full">Expand connections</button>
      <details><summary className="cursor-pointer py-2 text-sm">Recorded identifier</summary><code className="break-all text-xs">{node.id}</code></details>
      <h3 className="font-semibold">Incoming &amp; outgoing</h3>
      {related.slice(0, 12).map((edge, i) => <button key={`${edge.source}:${edge.target}:${i}`} className="context-connection" onClick={() => onSelect(edge.source === node.id ? edge.target : edge.source)}>
        <span className="text-xs text-[var(--text-tertiary)]">{edge.source === node.id ? "Outgoing →" : "← Incoming"} {contextRelationshipLabel(edge.relationship ?? edge.kind)}</span>
        <span className="block break-words">{label(edge.source === node.id ? edge.target : edge.source)}</span>
      </button>)}
      {related.length > 12 && <p className="text-sm">Showing 12 of {related.length} relationships. Select a neighbor to continue.</p>}
    </div> : <div className="mt-4 space-y-3">
      <p className="text-sm text-[var(--text-secondary)]">Select a node or relationship. Expand a group to locate an entity without zooming out.</p>
      {[...groups].map(([kind, items]) => <details key={kind} className="rounded-lg border border-[var(--border-subtle)] px-3" open={groups.size <= 3}>
        <summary className="cursor-pointer py-3 capitalize">{kind.replaceAll("_", " ")} <span className="float-right text-[var(--text-secondary)]">{items.length}</span></summary>
        <div className="max-h-48 overflow-y-auto pb-2">{items.map(item => <button key={item.id} onClick={() => onSelect(item.id)} className="context-connection">{item.label}</button>)}</div>
      </details>)}
    </div>}
    <details className="mt-5 border-t border-[var(--border-subtle)] pt-3" open>
      <summary className="cursor-pointer font-semibold">Evidence gaps</summary>
      <p className="mt-2 text-sm text-[var(--text-secondary)]">This view contains scan relationships. Collect permission decisions and runtime event identities to establish authorized or observed activity. Shared infrastructure is not proof that agents communicated.</p>
    </details>
  </aside>;
}
