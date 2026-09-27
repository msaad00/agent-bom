"use client";

import { useRef, useState } from "react";
import { api, type AgentLifecyclePage } from "@/lib/api";

/** Mounted with a scan/agent key so requests cannot populate another subject. */
export function AgentBomHistory({ jobId, agentId }: { jobId: string; agentId: string }) {
  const [page, setPage] = useState<AgentLifecyclePage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [comparison, setComparison] = useState("");
  const epoch = useRef(0);

  async function load(save = false, offset = 0) {
    const current = ++epoch.current;
    setBusy(true); setError(""); setComparison("");
    try {
      if (save) await api.captureAgentSnapshot(jobId, agentId);
      const value = await api.agentLifecycleHistory(agentId, offset);
      if (current === epoch.current) setPage(value);
    } catch {
      if (current === epoch.current) setError("Snapshot history unavailable. Saving requires configuration access and a completed scan.");
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }

  async function compare() {
    const first = page?.items[0], second = page?.items[1];
    if (!first || !second) return;
    const current = ++epoch.current;
    setBusy(true); setError("");
    try {
      const result = await api.compareAgentSnapshots(first.record_id, second.record_id);
      if (current !== epoch.current) return;
      setComparison(result.composition_changed ? "Recorded composition changed." : result.snapshot_changed ? "Snapshot changed; recorded composition is unchanged. Review evidence, coverage and subject metadata." : "Both references identify the same snapshot.");
    } catch {
      if (current === epoch.current) setError("Snapshot comparison unavailable.");
    } finally {
      if (current === epoch.current) setBusy(false);
    }
  }

  return <details className="mt-3 rounded-lg border border-outline p-3">
    <summary className="cursor-pointer font-medium text-foreground">Saved BOM history</summary>
    <p className="mt-2 text-ink-secondary">Retain exact scan evidence independently of the scan record. Registration is operator recorded; runtime execution remains unverified.</p>
    <div className="my-3 flex flex-wrap gap-2">
      <button disabled={busy} onClick={() => void load(true)} className="rounded-lg border border-outline px-3 py-2 text-foreground disabled:opacity-50">Save this snapshot</button>
      <button disabled={busy} onClick={() => void load()} className="rounded-lg border border-outline px-3 py-2 text-foreground disabled:opacity-50">Load history</button>
    </div>
    {busy ? <p role="status" className="text-ink-secondary">Loading snapshot evidence…</p> : null}
    {error ? <p role="alert" className="text-red-700 dark:text-red-300">{error}</p> : null}
    {page?.items.length === 0 ? <p className="text-ink-secondary">No saved snapshots for this exact agent.</p> : null}
    {page ? <>
      <ol className="space-y-2">
        {page.items.map((item) => <li key={item.record_id} className="rounded-lg bg-surface-elevated p-2 text-ink-secondary">
          <p className="break-all font-mono text-foreground">{item.record_id}</p>
          <p>Captured: {item.observed_at ? new Date(item.observed_at).toLocaleString() : "Unknown"}</p>
          <p>Retained: {new Date(item.recorded_at).toLocaleString()}</p>
        </li>)}
      </ol>
      {page.items.length > 1 ? <button disabled={busy} onClick={() => void compare()} className="mt-3 rounded-lg border border-outline px-3 py-2 text-foreground disabled:opacity-50">Compare first two snapshots on this page</button> : null}
      {comparison ? <p role="status" className="mt-2 text-ink-secondary">{comparison}</p> : null}
      {page.next_offset !== null ? <button disabled={busy} onClick={() => void load(false, page.next_offset ?? 0)} className="mt-3 rounded-lg border border-outline px-3 py-2 text-foreground disabled:opacity-50">Next history page</button> : null}
      {page.history_limit_reached ? <p className="mt-2 text-amber-700 dark:text-amber-300">History exceeds the browsing limit. Additional retained snapshots are not shown.</p> : null}
      {page.items.length ? <p className="mt-2 text-ink-secondary">Oldest first · up to 20 snapshots per page. Full evidence is available through the snapshot export API.</p> : null}
    </> : null}
  </details>;
}
