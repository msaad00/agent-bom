"use client";

import { useEffect, useRef, useState } from "react";
import { useAuthState } from "@/components/auth-provider";
import { api } from "@/lib/api";
import type { GraphCompromiseResponse } from "@/lib/api-types";

type Props = { nodeId: string; scanId: string; snapshotGeneration?: string | null | undefined; findingRoot?: boolean };

export function GraphCompromisePanel(props: Props) {
  const { session, loading } = useAuthState();
  if (loading || !session) return null;
  return <AssessmentForm key={JSON.stringify([session, props.nodeId, props.scanId, props.snapshotGeneration])} {...props} />;
}

function AssessmentForm({ nodeId, scanId, snapshotGeneration, findingRoot = false }: Props) {
  const [control, setControl] = useState(false);
  const [exploitation, setExploitation] = useState(false);
  const [affected, setAffected] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const [result, setResult] = useState<GraphCompromiseResponse | null>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);

  async function assess() {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setPending(true); setError(false); setResult(null);
    try {
      const response = await api.assessCompromise({
        root_node_id: nodeId, scan_id: scanId, assume_control: true,
        snapshot_generation: snapshotGeneration ?? null,
        affected_node_id: findingRoot ? affected.trim() : null,
        assume_exploitation: findingRoot && exploitation,
        max_relationships: 128, max_evidence_age_seconds: 3600,
      }, { signal: controller.signal });
      if (!controller.signal.aborted) setResult(response);
    } catch {
      if (!controller.signal.aborted) setError(true);
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }

  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "compromise-assessment.json"; link.click();
    URL.revokeObjectURL(url);
  }

  return <details className="rounded-lg border border-outline bg-surface-muted p-3 text-xs text-ink-secondary">
    <summary className="cursor-pointer font-semibold text-ink">Assess assumed compromise</summary>
    <p className="mt-2">Inspect recorded actions under a hypothetical control assumption. This does not perform exploitation or verify current access.</p>
    <form className="mt-3 space-y-3" onSubmit={(event) => { event.preventDefault(); void assess(); }}>
      <label className="flex items-start gap-2"><input disabled={pending} type="checkbox" checked={control} onChange={(event) => { setControl(event.target.checked); setResult(null); }} />Assume control of this node</label>
      {findingRoot && <>
        <label className="block">Affected component node ID<input disabled={pending} className="mt-1 w-full rounded border border-outline bg-surface p-2 text-ink" value={affected} onChange={(event) => { setAffected(event.target.value); setResult(null); }} /></label>
        <label className="flex items-start gap-2"><input disabled={pending} type="checkbox" checked={exploitation} onChange={(event) => { setExploitation(event.target.checked); setResult(null); }} />Assume exploitation of this finding</label>
      </>}
      <button type="submit" className="rounded border border-outline bg-surface px-3 py-2 font-medium text-ink disabled:opacity-50" disabled={pending || !control || (findingRoot && (!affected.trim() || !exploitation))}>{pending ? "Assessing…" : "Assess evidence"}</button>
    </form>
    {error && <p role="alert" className="mt-3 text-severity-high">Assessment unavailable. Reload the graph and verify the snapshot and assumptions before retrying.</p>}
    {result && <section aria-label="Compromise assessment result" className="mt-3 space-y-2">
      <p>Historical permission receipts only. Successful execution is not established. Collection coverage remains unknown.</p>
      <p className="break-all font-mono text-[10px]">Snapshot {result.scan_id} · revision {result.snapshot_generation}</p>
      <p>Relationships examined: {result.relationships_examined}{result.truncated ? " · truncated assessment" : ""}.</p>
      {result.actions.length === 0 && <p>No direct action receipts were returned. This does not establish safety.</p>}
      <ul className="max-h-72 space-y-2 overflow-auto">
        {result.actions.slice(0, 20).map((action, index) => <li key={`${action.source_edge_id}:${index}`} className="rounded border border-outline bg-surface p-2">
          <p className="font-medium text-ink">{action.permission.replaceAll("_", " ")}</p>
          <p className="break-all">{action.action ?? "Action unknown"} · {action.resource ?? action.target_node_id}</p>
          <p>Observation: {action.observation.replaceAll("_", " ")}</p>
          <details className="mt-1"><summary className="cursor-pointer">Evidence and limits</summary><p className="break-all">Edge: {action.source_edge_id}</p><p>Observed: {action.observed_at ?? "unknown"}</p><p className="break-all">Bindings: {(action.binding_ids ?? []).join(", ") || "not recorded"}</p><p>{(action.reason_codes ?? []).map((reason) => reason.replaceAll("_", " ")).join("; ")}</p></details>
        </li>)}
      </ul>
      {result.actions.length > 20 && <p>Showing 20 of {result.actions.length} actions. Export the assessment for all returned receipts.</p>}
      <button type="button" className="rounded border border-outline px-3 py-2 text-ink" onClick={download}>Export assessment JSON</button>
    </section>}
  </details>;
}
