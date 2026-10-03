"use client";

import Link from "next/link";
import { useState } from "react";
import { useAuthState } from "@/components/auth-provider";
import { useIncidentNeighborhood } from "@/hooks/use-incident-neighborhood";
import { componentControlEvidence } from "@/lib/component-compliance-evidence";
import { buildGraphInvestigationBundle, downloadGraphInvestigation } from "@/lib/graph-investigation-bundle";

export function ComponentCompliance({ assetId, scanId }: { assetId: string; scanId: string }) {
  const { session, loading } = useAuthState();
  if (!assetId || !scanId) return <p role="alert" className="p-6">Choose a component and a retained scan snapshot from inventory to inspect control evidence.</p>;
  if (loading || !session) return <p role="status" className="p-6">Resolving access to component control evidence…</p>;
  const owner = JSON.stringify(session);
  return <ControlEvidence key={JSON.stringify([owner, assetId, scanId])} assetId={assetId} scanId={scanId} owner={owner} />;
}

function ControlEvidence({ assetId, scanId, owner }: { assetId: string; scanId: string; owner: string }) {
  const graph = useIncidentNeighborhood(scanId, assetId, "both", owner);
  const [exportError, setExportError] = useState(false);
  const rows = componentControlEvidence(assetId, graph.nodes, graph.edges);
  const last = graph.pages.at(-1);
  const component = graph.nodes.find(node => node.id === assetId);
  const params = new URLSearchParams({ asset: assetId, scan: scanId });
  const gaps = graph.pages.some(page => (page.completeness.missing_endpoint_count ?? 0) > 0);
  return <div className="space-y-5 p-6">
    <header className="space-y-2">
      <p className="text-xs uppercase tracking-wide text-ink-secondary">Component control evidence</p>
      <h1 className="break-words text-2xl font-semibold">{component?.label || assetId}</h1>
      <p className="break-all text-sm text-ink-secondary">{assetId} · Snapshot {scanId}</p>
      <p className="max-w-3xl text-sm text-ink-secondary">Control mappings and directly linked check evidence for this component. Tags alone are not evaluated controls. Account checks apply at account scope; no result is inherited from a parent.</p>
      <Link href={`/findings?${params}`} className="inline-block text-sm underline underline-offset-2">Inspect component findings</Link>
    </header>
    <p role="status" className="text-sm text-ink-secondary">{graph.busy && !last ? "Loading control evidence…" : `${rows.length} control evidence records in ${graph.edges.length} loaded relationships`}</p>
    {graph.error && <div role="alert" className="space-y-2 rounded-lg border border-outline p-4"><p>{graph.error}</p>
      <button type="button" className="rounded border border-outline px-3 py-2" disabled={graph.busy}
        onClick={() => graph.stale ? graph.restart() : void graph.load(assetId, last?.next_cursor ?? undefined)}>Retry control evidence</button></div>}
    {gaps && <p className="text-sm">Some relationship endpoints are missing. Control evidence coverage is incomplete.</p>}
    <ul aria-label="Component control records" className="space-y-3">
      {rows.map(row => <li key={JSON.stringify([row.tag, row.node.id])} className="space-y-2 rounded-xl border border-outline bg-surface p-4">
        <div className="flex flex-wrap items-start justify-between gap-3"><h2 className="break-words font-semibold">{row.tag}</h2>
          <span className="text-sm font-medium">{row.status === "recorded_fail" ? "Recorded failed check" : "Mapped · Not evaluated"}</span></div>
        <Link className="break-words text-sm underline underline-offset-2" href={`/security-graph?${new URLSearchParams({ lens: "estate", node: row.node.id, scan: scanId })}`}>{row.node.label || row.node.id}</Link>
        <p className="text-sm text-ink-secondary">Scope: {row.scope.replaceAll("_", " ")} · Last seen: {row.node.last_seen || "Not recorded"}</p>
        <p className="text-sm text-ink-secondary">Sources: {row.node.data_sources?.join(", ") || "Not recorded"}</p>
        <details className="text-sm"><summary className="cursor-pointer">Supporting evidence</summary>
          <p className="mt-2 break-all text-xs text-ink-secondary">Node: {row.node.id}</p>
          <p className="mt-2 break-words">{typeof row.node.attributes?.evidence === "string" && row.node.attributes.evidence ? row.node.attributes.evidence : "Supporting check detail was not recorded."}</p>
        </details>
      </li>)}
    </ul>
    {last && !graph.error && rows.length === 0 && <p className="text-sm">No control evidence is recorded in the loaded pages. This does not establish compliance.</p>}
    {last?.next_cursor && !graph.error && <button type="button" className="rounded border border-outline px-3 py-2 disabled:opacity-50" disabled={graph.busy || graph.capped}
      onClick={() => void graph.load(assetId, last.next_cursor!)}>{graph.busy ? "Loading…" : "Load more control evidence"}</button>}
    {graph.capped && last?.next_cursor && <p className="text-sm">Display limit reached. Additional relationships may contain control evidence.</p>}
    {last && !last.next_cursor && !graph.error && <p className="text-sm text-ink-secondary">End of recorded relationship pages. Collection coverage and evidence freshness are not assessed.</p>}
    <details className="rounded-lg border border-outline p-4 text-sm"><summary className="cursor-pointer font-medium">Export control evidence</summary>
      <p className="my-2 text-ink-secondary">Includes the loaded source records, explicit check attributes, snapshot generation and completeness receipts. This unsigned local export is not a compliance certification.</p>
      <button type="button" className="rounded border border-outline px-3 py-2 disabled:opacity-50" disabled={!last || graph.busy || Boolean(graph.error)} onClick={() => {
        setExportError(false);
        try { downloadGraphInvestigation(buildGraphInvestigationBundle(scanId, assetId, graph.pages, window.location.href)); }
        catch { setExportError(true); }
      }}>Download control evidence</button>
      {exportError && <p role="alert">Unable to export evidence. Reload the component and retry.</p>}
    </details>
  </div>;
}
