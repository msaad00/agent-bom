"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowRight, ArrowUpRight, FileSearch, Shield } from "lucide-react";
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
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const rows = componentControlEvidence(assetId, graph.nodes, graph.edges);
  const keyOf = (row: (typeof rows)[number]) => JSON.stringify([row.tag, row.node.id]);
  const selected = rows.find(row => keyOf(row) === selectedKey) ?? rows[0];
  const last = graph.pages.at(-1);
  const component = graph.nodes.find(node => node.id === assetId);
  const label = component?.label || assetId;
  const params = new URLSearchParams({ asset: assetId, scan: scanId });
  const graphHref = (node: string) => `/security-graph?${new URLSearchParams({ lens: "estate", node, scan: scanId })}`;
  const gaps = graph.pages.some(page => (page.completeness.missing_endpoint_count ?? 0) > 0);
  const failed = selected?.status === "recorded_fail";
  const onComponent = selected?.node.id === assetId;
  return <div className="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
    <header className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="rounded-lg border border-outline bg-surface p-2 text-accent"><Shield size={20} aria-hidden="true" /></span>
          <div className="min-w-0"><p className="text-xs font-medium text-ink-secondary">Component investigation</p>
            <h1 className="break-words text-xl font-semibold">{label}</h1></div>
        </div>
        <Link href={graphHref(assetId)} className="inline-flex items-center gap-1 rounded-lg border border-outline px-3 py-2 text-xs font-medium hover:bg-surface">View component chain <ArrowUpRight size={14} aria-hidden="true" /></Link>
      </div>
      <nav aria-label="Component investigation" className="flex gap-5 border-b border-outline text-sm">
        <Link href={`/findings?${params}`} className="pb-2 text-ink-secondary hover:text-foreground">Findings</Link>
        <Link href={`/compliance?${params}`} aria-current="page" className="border-b-2 border-accent pb-2 font-semibold text-accent">Control evidence</Link>
      </nav>
    </header>
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h2 className="text-sm font-semibold">Which controls relate to this component?</h2>
      <p role="status" className="text-xs text-ink-secondary">{graph.busy && !last ? "Loading control evidence…" : `${rows.length} ${rows.length === 1 ? "record" : "records"} · ${graph.edges.length} loaded relationships`}</p>
    </div>
    {graph.error && <div role="alert" className="space-y-2 rounded-lg border border-outline p-4"><p>{graph.error}</p>
      <button type="button" className="rounded border border-outline px-3 py-2" disabled={graph.busy}
        onClick={() => graph.stale ? graph.restart() : void graph.load(assetId, last?.next_cursor ?? undefined)}>Retry control evidence</button></div>}
    {gaps && <p className="text-sm">Some relationship endpoints are missing. Control evidence coverage is incomplete.</p>}
    {selected && <div className="grid overflow-hidden rounded-xl border border-outline bg-surface md:grid-cols-[240px_minmax(0,1fr)]">
      <section className="border-b border-outline bg-surface-muted md:border-r md:border-b-0" aria-label="Select control evidence">
        <p className="border-b border-outline px-4 py-3 text-xs font-medium text-ink-secondary">Controls in loaded evidence</p>
        <ul aria-label="Component control records" className="max-h-80 overflow-y-auto p-2">
          {rows.map(row => <li key={keyOf(row)}><button type="button" aria-label={`${row.tag} ${row.node.label || row.node.id} ${row.status === "recorded_fail" ? "Failed check" : "Mapping only"}`} aria-pressed={keyOf(selected) === keyOf(row)}
            onClick={() => setSelectedKey(keyOf(row))}
            className={`mb-1 w-full rounded-lg border p-3 text-left transition-colors ${keyOf(selected) === keyOf(row) ? "border-accent bg-[var(--accent-soft)]" : "border-transparent hover:bg-surface"}`}>
            <span className="flex items-center justify-between gap-2 text-sm font-semibold"><span className="break-all">{row.tag}</span><ArrowRight size={14} className="shrink-0" aria-hidden="true" /></span>
            <span className="mt-1 block break-words text-xs text-ink-secondary">{row.node.label || row.node.id}</span>
            <span className="mt-2 block text-xs">{row.status === "recorded_fail" ? "Failed check" : "Mapping only"}</span>
          </button></li>)}
        </ul>
      </section>
      <section aria-label="Selected control evidence" className="min-w-0 space-y-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div><h3 className="break-all text-lg font-semibold">{selected.tag}</h3></div>
          <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${failed ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300" : "border-outline bg-surface-muted text-ink-secondary"}`}>{failed ? "Recorded failed check" : "Mapped · Not evaluated"}</span>
        </div>
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-ink-secondary">Why this is linked</h4>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="break-all rounded border border-outline px-2 py-1">{label}</span>
            {!onComponent && <><ArrowRight size={14} className="text-ink-secondary" aria-hidden="true" /><Link className="break-all font-medium text-accent underline underline-offset-2" href={graphHref(selected.node.id)}>{selected.node.label || selected.node.id}</Link></>}
            <ArrowRight size={14} className="text-ink-secondary" aria-hidden="true" /><span className="break-all font-medium">{selected.tag}</span>
          </div>
          <p className="text-sm leading-relaxed text-ink-secondary">{failed
            ? `A recorded check affecting this component failed at ${selected.scope} scope. Its control tags link it to this reference.`
            : onComponent ? "This component carries a control tag. The tag records a mapping; it does not show whether the control passed or failed."
              : "A finding linked to this component carries this control tag. The tag records a mapping; it does not show whether the control passed or failed."}</p>
        </div>
        <div className="rounded-lg border border-outline bg-surface-muted p-3">
          <h4 className="flex items-center gap-2 text-sm font-semibold"><FileSearch size={15} aria-hidden="true" />{failed ? "Review the failed check" : "Assessment still needed"}</h4>
          <p className="mt-1 text-sm leading-relaxed text-ink-secondary">{failed ? "Inspect the supporting check detail, correct the affected configuration, then collect a new check for the same scope." : "Collect a scoped control check before making a compliance decision."}</p>
          <Link href={onComponent ? graphHref(assetId) : graphHref(selected.node.id)} className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-accent">Inspect source evidence <ArrowUpRight size={13} aria-hidden="true" /></Link>
        </div>
        <dl className="grid gap-x-4 gap-y-2 text-xs sm:grid-cols-3">
          <div><dt className="text-ink-secondary">Scope</dt><dd className="mt-1">{selected.scope.replaceAll("_", " ")}</dd></div>
          <div><dt className="text-ink-secondary">Last seen</dt><dd className="mt-1 break-all">{selected.node.last_seen || "Not recorded"}</dd></div>
          <div><dt className="text-ink-secondary">Sources</dt><dd className="mt-1 break-words">{selected.node.data_sources?.join(", ") || "Not recorded"}</dd></div>
        </dl>
        <details className="border-t border-outline pt-3 text-xs"><summary className="cursor-pointer font-medium">Supporting evidence</summary>
          <p className="mt-2 break-all text-ink-secondary">Node: {selected.node.id}</p>
          <p className="mt-2 break-words">{typeof selected.node.attributes?.evidence === "string" && selected.node.attributes.evidence ? selected.node.attributes.evidence : "Supporting check detail was not recorded."}</p>
        </details>
      </section>
    </div>}
    {last && !graph.error && rows.length === 0 && <p className="rounded-lg border border-outline p-4 text-sm">No control evidence is recorded in the loaded pages. This does not establish compliance.</p>}
    {last?.next_cursor && !graph.error && <button type="button" className="rounded border border-outline px-3 py-2 text-sm disabled:opacity-50" disabled={graph.busy || graph.capped}
      onClick={() => void graph.load(assetId, last.next_cursor!)}>{graph.busy ? "Loading…" : "Load more control evidence"}</button>}
    {graph.capped && last?.next_cursor && <p className="text-xs">Display limit reached. Additional relationships may contain control evidence.</p>}
    <footer className="space-y-3 text-xs text-ink-secondary">
      {last && !last.next_cursor && !graph.error && <p>All recorded relationship pages loaded. Collection coverage and evidence freshness are not assessed.</p>}
      <div className="grid gap-3 sm:grid-cols-2">
        <details className="rounded-lg border border-outline px-3 py-2"><summary className="cursor-pointer font-medium">Snapshot &amp; scope</summary>
          <p className="mt-2 break-all">Component: {assetId}</p><p className="mt-1 break-all">{scanId.startsWith("current-estate:") ? "Current tenant estate" : `Snapshot: ${scanId}`}</p>
          <p className="mt-2">Only this component and its directly linked evidence are included. Account checks apply at account scope; no result is inherited from a parent.</p>
        </details>
        <details className="rounded-lg border border-outline px-3 py-2"><summary className="cursor-pointer font-medium">Export control evidence</summary>
          <p className="my-2">Includes loaded source records, check attributes and snapshot receipts. This unsigned local export is not a compliance certification.</p>
          <button type="button" className="rounded border border-outline px-3 py-2 disabled:opacity-50" disabled={!last || graph.busy || Boolean(graph.error)} onClick={() => {
            setExportError(false);
            try { downloadGraphInvestigation(buildGraphInvestigationBundle(scanId, assetId, graph.pages, window.location.href)); }
            catch { setExportError(true); }
          }}>Download control evidence</button>
          {exportError && <p role="alert">Unable to export evidence. Reload the component and retry.</p>}
        </details>
      </div>
    </footer>
  </div>;
}
