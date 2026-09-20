"use client";

import { useState } from "react";
import type { HopAuthorityEvidence } from "@/lib/graph-schema";

const text = (value: unknown) => typeof value === "string" && value ? value : "Not recorded";
const strings = (value: unknown) => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const PAGE_SIZE = 4;

/** Display recorded source decisions; never evaluate access in the browser. */
export function GraphHopAuthority({ evidence }: { evidence: HopAuthorityEvidence }) {
  const [page, setPage] = useState(0);
  const decisions = Array.isArray(evidence.decisions) ? evidence.decisions.filter(item => item && typeof item === "object").slice(0, 16) : [];
  const witnesses = Array.isArray(evidence.derivation?.paths) ? evidence.derivation.paths.filter(item => item && typeof item === "object").slice(0, 16) : [];
  const records = [...decisions.map(item => ({ decision: item, witness: null })), ...witnesses.map(item => ({ decision: null, witness: item }))];
  const current = Math.min(page, Math.max(0, Math.ceil(records.length / PAGE_SIZE) - 1));
  return <section aria-label="Recorded authority" className="scroll-mt-20 space-y-2 border-t border-outline pt-3">
    <h4 className="text-sm font-semibold">Recorded authority</h4>
    <p className="text-xs text-ink-secondary">{decisions.length} action receipts · {witnesses.length} source witnesses{evidence.status === "partial" ? " · Partial evidence" : ""}</p>
    <p className="text-xs text-ink-secondary">Snapshot evidence, not a current permission check. Conditions, expiry and revocation require re-evaluation. A grant does not prove successful execution.</p>
    <ol tabIndex={0} aria-label="Authority receipts" className="max-h-72 overflow-y-auto overscroll-contain divide-y divide-outline focus-visible:outline-2 focus-visible:outline-emerald-500">
      {records.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE).map(({ decision, witness }, index) => <li key={current * PAGE_SIZE + index} className="min-w-0 space-y-2 py-2">
        {decision ? <>
          <p className="break-words font-medium [overflow-wrap:anywhere]">{text(decision.action)} · {text(decision.decision).replaceAll("_", " ")}</p>
          <dl className="grid gap-2 text-xs sm:grid-cols-2">
            {[["Principal", decision.principal_id], ["Resource", decision.resource], ["Provider", decision.provider], ["Observed at", decision.observed_at]].map(([label, value]) => <div key={label}><dt className="text-ink-secondary">{label}</dt><dd className="break-words [overflow-wrap:anywhere]">{text(value)}</dd></div>)}
          </dl>
          <details className="text-xs"><summary className="cursor-pointer">Source bindings ({strings(decision.binding_ids).length})</summary>
            <ul className="mt-1 space-y-1">{strings(decision.binding_ids).map((binding, i) => <li key={i} className="break-all font-mono">{binding}</li>)}</ul>
          </details>
        </> : witness ? <>
          <p className="text-xs">{text(witness.access).replaceAll("_", " ")} · Grant principal: <span className="break-all font-mono">{text(witness.grant_principal_id)}</span></p>
          <p className="break-all text-xs">Source snapshot: {text(evidence.derivation?.source_scan_id)}</p>
          <details className="text-xs"><summary className="cursor-pointer">Ordered source relationships ({strings(witness.source_edge_ids).length})</summary>
            <ol className="mt-1 list-inside list-decimal space-y-1">{strings(witness.source_edge_ids).map((edge, i) => <li key={i} className="break-all font-mono">{edge}</li>)}</ol>
            <p className="mt-2 break-all">Grant relationship: {text(witness.grant_edge_id)}</p>
          </details>
          <p className="text-xs text-ink-secondary">Selected shortest witness per grant and access type; other paths may exist. Action scope is not inferred from these relationships.</p>
        </> : null}
      </li>)}
    </ol>
    {!records.length ? <p className="text-xs">No valid authority receipts in this projection.</p> : null}
    {strings(evidence.reason_codes).length ? <p className="break-words text-xs text-ink-secondary">{strings(evidence.reason_codes).map(reason => reason.replaceAll("_", " ")).join(" · ")}</p> : null}
    {records.length > PAGE_SIZE ? <nav aria-label="Authority receipt pages" className="flex items-center justify-between gap-2 text-xs">
      <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded border px-2 py-1 disabled:opacity-40">Previous receipts</button>
      <span>Page {current + 1} of {Math.ceil(records.length / PAGE_SIZE)}</span>
      <button type="button" disabled={(current + 1) * PAGE_SIZE >= records.length} onClick={() => setPage(current + 1)} className="rounded border px-2 py-1 disabled:opacity-40">Next receipts</button>
    </nav> : null}
  </section>;
}
