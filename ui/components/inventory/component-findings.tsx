"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuthState } from "@/components/auth-provider";
import { SeverityBadge } from "@/components/severity-badge";
import { useIncidentNeighborhood } from "@/hooks/use-incident-neighborhood";
import { FINDING_ENTITY_TYPES } from "@/lib/graph-schema";
import { buildGraphInvestigationBundle, downloadGraphInvestigation } from "@/lib/graph-investigation-bundle";

/** Explicit component scope never falls back to the tenant-wide finding queue. */
export function ComponentFindings({ assetId, scanId }: { assetId: string; scanId: string }) {
  const { session, loading } = useAuthState();
  if (!assetId || !scanId) return <p role="alert" className="p-6">Choose a component and a retained scan snapshot from inventory to inspect its finding evidence.</p>;
  if (loading || !session) return <p role="status" className="p-6">Resolving access to component findings…</p>;
  const owner = JSON.stringify(session);
  return <ComponentFindingEvidence key={JSON.stringify([owner, assetId, scanId])} assetId={assetId} scanId={scanId} owner={owner} />;
}

function ComponentFindingEvidence({ assetId, scanId, owner }: { assetId: string; scanId: string; owner: string }) {
  const graph = useIncidentNeighborhood(scanId, assetId, "both", owner);
  const [exportError, setExportError] = useState(false);
  const component = graph.nodes.find(node => node.id === assetId);
  const adjacent = new Set(graph.edges.flatMap(edge => edge.source === assetId ? [edge.target] : edge.target === assetId ? [edge.source] : []));
  const findings = graph.nodes.filter(node => node.id !== assetId && adjacent.has(node.id)
    && [...FINDING_ENTITY_TYPES].some(type => type === node.entity_type));
  const last = graph.pages.at(-1);
  const graphParams = new URLSearchParams({ lens: "estate", node: assetId, scan: scanId });
  const hasGaps = graph.pages.some(page => (page.completeness.missing_endpoint_count ?? 0) > 0);
  return <div className="space-y-5 p-6">
    <header className="space-y-2">
      <p className="text-xs uppercase tracking-wide text-ink-secondary">Component finding evidence</p>
      <h1 className="break-words text-2xl font-semibold">{component?.label || assetId}</h1>
      <p className="break-all text-sm text-ink-secondary">{assetId} · Snapshot {scanId}</p>
      <p className="max-w-3xl text-sm text-ink-secondary">Findings connected by recorded relationships to this exact component. These records do not establish exploitation or include findings elsewhere in the component chain.</p>
      <Link className="inline-block text-sm underline underline-offset-2" href={`/security-graph?${graphParams}`}>Investigate the component chain</Link>
    </header>
    <p role="status" className="text-sm text-ink-secondary">{graph.busy && !last ? "Loading component evidence…" : `${findings.length} linked finding records in ${graph.edges.length} loaded relationships`}</p>
    {graph.error && <div role="alert" className="space-y-2 rounded-lg border border-outline p-4">
      <p>{graph.error}</p>
      <button type="button" className="rounded border border-outline px-3 py-2" disabled={graph.busy}
        onClick={() => graph.stale ? graph.restart() : void graph.load(assetId, last?.next_cursor ?? undefined)}>Retry component evidence</button>
    </div>}
    {hasGaps && <p className="text-sm text-ink-secondary">Some relationship endpoints are missing. Finding coverage is incomplete.</p>}
    <ul aria-label="Component finding records" className="space-y-3">
      {findings.map(finding => {
        const params = new URLSearchParams({ lens: "estate", node: finding.id, scan: scanId });
        const relationships = graph.edges.filter(edge => (edge.source === assetId && edge.target === finding.id) || (edge.target === assetId && edge.source === finding.id));
        return <li key={finding.id} className="space-y-2 rounded-xl border border-outline bg-surface p-4">
          <div className="flex items-start justify-between gap-4"><Link href={`/security-graph?${params}`} className="break-words font-semibold underline underline-offset-2">{finding.label || finding.id}</Link><SeverityBadge severity={finding.severity || "unknown"} /></div>
          <p className="text-sm text-ink-secondary">{finding.entity_type} · Last seen: {finding.last_seen || "Not recorded"}</p>
          <p className="text-sm text-ink-secondary">Sources: {finding.data_sources?.join(", ") || "Not recorded"}</p>
          <details className="text-xs text-ink-secondary"><summary className="cursor-pointer">Recorded association</summary>
            <p className="mt-2 break-all">Finding node: {finding.id}</p>
            {relationships.map(edge => <p key={JSON.stringify([edge.source, edge.target, edge.relationship])} className="mt-1 break-all">{edge.source} → {edge.relationship} → {edge.target}</p>)}
          </details>
        </li>;
      })}
    </ul>
    {last && !graph.error && findings.length === 0 && <p className="text-sm">No finding records are linked in the loaded pages. This does not establish a clean component.</p>}
    {last?.next_cursor && !graph.error && <button type="button" className="rounded border border-outline px-3 py-2 disabled:opacity-50"
      disabled={graph.busy || graph.capped} onClick={() => void graph.load(assetId, last.next_cursor!)}>{graph.busy ? "Loading…" : "Load more component relationships"}</button>}
    {graph.capped && last?.next_cursor && <p className="text-sm">Display limit reached. Continue in the component chain to inspect connected entities.</p>}
    {last && !last.next_cursor && !graph.error && <p className="text-sm text-ink-secondary">End of recorded relationship pages. Source collection coverage remains unknown.</p>}
    <details className="rounded-lg border border-outline p-4 text-sm">
      <summary className="cursor-pointer font-medium">Export component evidence</summary>
      <p className="my-2 text-ink-secondary">Exports the loaded relationships, finding nodes, source metadata, snapshot generation and completeness receipts. This is an unsigned local evidence bundle.</p>
      <button type="button" className="rounded border border-outline px-3 py-2 disabled:opacity-50" disabled={!last || graph.busy || Boolean(graph.error)} onClick={() => {
        setExportError(false);
        try { downloadGraphInvestigation(buildGraphInvestigationBundle(scanId, assetId, graph.pages, window.location.href)); }
        catch { setExportError(true); }
      }}>Download component evidence</button>
      {exportError && <p role="alert">Unable to export evidence. Reload the component and retry.</p>}
    </details>
  </div>;
}
