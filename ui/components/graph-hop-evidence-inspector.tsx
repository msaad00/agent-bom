"use client";

import { useId, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import type { GraphHopEvidence } from "@/lib/graph-schema";
import { GraphHopAuthority } from "@/components/graph-hop-authority";

const PAGE_SIZE = 8;
const humanize = (value: string | undefined) => (typeof value === "string" && value ? value : "unknown").replaceAll("_", " ");

function receiptLabel(receipt: GraphHopEvidence | undefined): string {
  if (!receipt) return "Receipt unavailable";
  if (receipt.runtime_observed_state === "blocked" || receipt.runtime_outcome === "blocked") return "Blocked attempt";
  if (receipt.runtime_outcome === "failed") return "Failed outcome";
  if (String(receipt.freshness ?? "unknown").startsWith("stale")) return "Stale evidence";
  if (!receipt.complete || receipt.truncated || receipt.freshness !== "fresh") return "Evidence incomplete";
  return "Receipt recorded";
}

/** Inspect existing ordered receipts. Filtering never computes reachability. */
export function GraphHopEvidenceInspector({
  hops,
  receipts = [],
}: {
  hops: Array<{ id: string; label: string }>;
  receipts?: GraphHopEvidence[] | undefined;
}) {
  const id = useId();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const rows = useMemo(() => hops.slice(0, -1).map((source, index) => {
    const target = hops[index + 1]!;
    const candidate = receipts[index];
    const receipt = candidate?.source_node_id === source.id && candidate.target_node_id === target.id ? candidate : undefined;
    return { source, target, index, receipt, status: receiptLabel(receipt) };
  }), [hops, receipts]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return rows.filter(row => !needle || [row.source.label, row.target.label, row.receipt?.relationship, row.status,
      row.receipt?.evidence_tier, row.receipt?.freshness,
      ...(Array.isArray(row.receipt?.authority?.decisions) ? row.receipt.authority.decisions.map(item => item?.action) : []),
      ...(Array.isArray(row.receipt?.authority?.native_grants) ? row.receipt.authority.native_grants.flatMap(item => [item?.privilege, item?.role, item?.object_fqn, item?.account]) : [])].join(" ").toLocaleLowerCase().includes(needle));
  }, [query, rows]);
  const safePage = Math.min(page, Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1));
  const visible = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  return <section aria-label="Hop evidence inspector" className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
    <div className="flex flex-wrap items-center justify-between gap-3 p-3">
      <div className="min-w-0">
        <h3 className="text-sm font-semibold">Evidence at each hop</h3>
        <p className="text-xs text-[color:var(--text-secondary)]">{filtered.length} of {rows.length} relationships · inspect one hop at a time</p>
      </div>
      <label className="flex min-w-0 items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] px-2 py-1.5">
        <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
        <span className="sr-only">Filter hop evidence</span>
        <input value={query} onChange={event => { setQuery(event.target.value); setPage(0); setSelected(null); }}
          placeholder="Find a hop or evidence state" className="min-w-0 w-52 max-w-full bg-transparent text-sm outline-none focus-visible:ring-2 focus-visible:ring-emerald-500" />
      </label>
    </div>
    <p className="px-3 pb-3 text-xs text-[color:var(--text-secondary)]">Relationships describe the recorded path. An observed call does not prove permission, exploitation, or a successful downstream action.</p>
    <ol className="divide-y divide-[color:var(--border-subtle)] border-t border-[color:var(--border-subtle)]">
      {visible.map(({ source, target, index, receipt, status }) => {
        const open = selected === index;
        const panelId = `${id}-hop-${index}`;
        const negative = status === "Blocked attempt" || status === "Failed outcome";
        const snapshots = Array.isArray(receipt?.source_snapshot_ids) ? receipt.source_snapshot_ids.filter(item => typeof item === "string") : [];
        const reasons = Array.isArray(receipt?.reason_codes) ? receipt.reason_codes.filter(item => typeof item === "string") : [];
        return <li key={`${source.id}:${target.id}:${index}`} className="min-w-0">
          <button type="button" aria-expanded={open} aria-controls={panelId} onClick={() => setSelected(open ? null : index)}
            className="flex w-full min-w-0 items-start gap-2 p-3 text-left hover:bg-[color:var(--surface-elevated)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-500">
            {open ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />}
            <span className="min-w-0 flex-1">
              <span className="block break-words text-sm font-medium [overflow-wrap:anywhere]">{index + 1}. {source.label} → {target.label}</span>
              <span className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[color:var(--text-secondary)]">
                <span>{receipt ? humanize(receipt.relationship) : "Relationship evidence unavailable"}</span>
                <span className={`rounded-full border px-2 py-0.5 ${negative ? "border-red-500/40 text-red-700 dark:text-red-300" : "border-[color:var(--border-subtle)]"}`}>{status}</span>
              </span>
            </span>
          </button>
          {open && <div id={panelId} className="space-y-3 border-t border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-sm">
            {!receipt ? <p>Receipt unavailable for this hop. Collect source evidence before assessing the relationship.</p> : <>
              <dl className="grid gap-3 sm:grid-cols-2">
                {[
                  ["Evidence basis", humanize(receipt.evidence_tier)],
                  ["Freshness", humanize(receipt.freshness)],
                  ["Direction", humanize(receipt.direction)],
                  ["Traversal", receipt.traversable === true ? "Eligible for graph traversal" : receipt.traversable === false ? "Not traversable" : "unknown"],
                  ["Runtime observation", humanize(receipt.runtime_observed_state)],
                  ["Downstream outcome", humanize(receipt.runtime_outcome)],
                  ["Relationship provenance", humanize(receipt.relationship_provenance)],
                  ["Identity correlation", humanize(receipt.correlation_identity_status)],
                ].map(([label, value]) => <div key={label}><dt className="text-xs text-[color:var(--text-secondary)]">{label}</dt><dd className="mt-0.5 break-words">{value}</dd></div>)}
              </dl>
              <div><p className="text-xs text-[color:var(--text-secondary)]">Source snapshots</p>
                {snapshots.length ? <ul className="mt-1 space-y-1">{snapshots.map((snapshot, snapshotIndex) => <li key={`${snapshot}:${snapshotIndex}`} className="break-all font-mono text-xs">{snapshot}</li>)}</ul> : <p>Not recorded</p>}
              </div>
              {reasons.length ? <p className="break-words text-xs text-[color:var(--text-secondary)]">{reasons.map(humanize).join(" · ")}</p> : null}
              <div><p className="text-xs text-[color:var(--text-secondary)]">Runtime event references</p>
                {Array.isArray(receipt.runtime_references) && receipt.runtime_references.length > 0
                  ? <ul className="mt-1 space-y-1">{receipt.runtime_references.filter(reference => reference && typeof reference === "object").slice(0, 8).map((reference, referenceIndex) => <li key={referenceIndex} className="break-all font-mono text-xs">
                    {typeof reference.event_id === "string" ? `Event: ${reference.event_id}` : ""}
                    {typeof reference.trace_id === "string" ? ` Trace: ${reference.trace_id}` : ""}
                  </li>)}</ul> : <p>No exact event reference attached.</p>}
              </div>
              {receipt.authority && typeof receipt.authority === "object" ? <GraphHopAuthority evidence={receipt.authority} /> : null}
              {negative && <p className="text-red-700 dark:text-red-300">This receipt cannot establish a successful downstream action. Other paths require separate evidence.</p>}
            </>}
          </div>}
        </li>;
      })}
    </ol>
    {!visible.length && <p className="p-3 text-sm text-[color:var(--text-secondary)]">{rows.length ? "No hops match this filter. The path is unchanged." : "This path has no relationships to inspect."}</p>}
    {filtered.length > PAGE_SIZE && <nav aria-label="Hop evidence pages" className="flex flex-wrap items-center justify-between gap-2 border-t border-[color:var(--border-subtle)] p-3 text-sm">
      <button type="button" disabled={safePage === 0} onClick={() => { setPage(safePage - 1); setSelected(null); }} className="rounded border px-3 py-1 disabled:opacity-40">Previous hops</button>
      <span>Page {safePage + 1} of {Math.ceil(filtered.length / PAGE_SIZE)}</span>
      <button type="button" disabled={(safePage + 1) * PAGE_SIZE >= filtered.length} onClick={() => { setPage(safePage + 1); setSelected(null); }} className="rounded border px-3 py-1 disabled:opacity-40">Next hops</button>
    </nav>}
  </section>;
}
