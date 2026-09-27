"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AgentBomHistory } from "@/components/agent-bom-history";
import { api, type Agent, type ScanResult } from "@/lib/api";

/** Only unambiguous recorded IDs are selectable. Never join by display name. */
export function selectableScanAgents(agents: Agent[]): Array<{ id: string; name: string }> {
  const counts = new Map<string, number>();
  for (const agent of agents) {
    for (const id of new Set([agent.canonical_id, agent.stable_id])) {
      if (typeof id === "string" && id.trim()) counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  return agents.flatMap((agent) => {
    const ids = [agent.canonical_id, agent.stable_id].filter((id) => id !== undefined && id !== null);
    const id = ids[0];
    if (typeof id !== "string" || !id.trim() || id.length > 512 || ids.some((value) => value !== id) || counts.get(id) !== 1) return [];
    return [{ id, name: agent.name }];
  });
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function ScanEvidencePanel({ jobId, result }: { jobId: string; result: ScanResult }) {
  const agents = useMemo(() => selectableScanAgents(result.agents ?? []), [result.agents]);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  useEffect(() => {
    generation.current += 1;
    setBusy(false);
    return () => { generation.current += 1; };
  }, [jobId, result]);
  const selectedId = selected || (agents.length === 1 ? (agents[0]?.id ?? "") : "");
  const eligible = agents.some((agent) => agent.id === selectedId);
  const matches = agents.filter((agent) => `${agent.name} ${agent.id}`.toLowerCase().includes(query.toLowerCase()));
  const options = matches.slice(0, 50);
  const selectedAgent = agents.find((agent) => agent.id === selectedId);
  if (selectedAgent && !options.some((agent) => agent.id === selectedId)) options.unshift(selectedAgent);
  const run = result.scan_run;
  const requested = count(run?.requested_scope_count);
  const complete = count(run?.complete_scope_count);
  const incomplete = count(run?.incomplete_scope_count);
  const consistent = requested !== null && complete !== null && incomplete !== null && complete + incomplete === requested;
  const outcome = run?.outcome === "complete" ? "Collection complete" : run?.outcome === "partial" ? "Collection partial" : run?.outcome === "failed" ? "Collection failed" : "Collection coverage unknown";
  const timestamp = result.generated_at || result.scan_timestamp;
  const captured = timestamp ? new Date(timestamp) : null;
  const excluded = (result.agents?.length ?? 0) - agents.length;

  async function download() {
    if (!eligible || busy) return;
    const epoch = generation.current;
    setBusy(true);
    setError("");
    try {
      const blob = await api.downloadScanAgentBom(jobId, selectedId);
      if (epoch !== generation.current) return;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "agent.bom.json";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      if (epoch === generation.current) setError("BOM export unavailable. Check access and the scan's recorded identity and source timestamp, then retry.");
    } finally {
      if (epoch === generation.current) setBusy(false);
    }
  }

  return (
    <details className="rounded-2xl border border-outline bg-surface p-4" aria-label="Scan evidence and agent BOM">
      <summary className="cursor-pointer text-sm font-semibold text-foreground">
        Evidence &amp; agent BOM <span className="ml-2 font-normal text-ink-secondary">{outcome}</span>
      </summary>
      <div className="mt-4 grid gap-5 lg:grid-cols-2">
        <div className="space-y-2 text-xs text-ink-secondary">
          <p className="font-medium text-foreground">Collection receipt</p>
          <p>Captured: {captured && !Number.isNaN(captured.getTime()) ? captured.toLocaleString() : "Unavailable"}</p>
          <p>{consistent ? `${complete} of ${requested} requested scopes complete · ${incomplete} incomplete` : "Scope denominator unavailable or inconsistent"}</p>
          <p>Sources: {result.scan_sources?.length ? result.scan_sources.join(", ") : "Not reported"}</p>
          <p>Collection status describes this requested scan scope. It does not establish complete estate coverage, effective permissions, or compliance.</p>
          <p>Source freshness and runtime enforcement require their own evidence. An empty finding list is not a clean verdict.</p>
        </div>
        <div className="min-w-0 space-y-2 text-xs">
          <p className="font-medium text-foreground">Export one agent’s composition</p>
          <label className="block text-ink-secondary">Find an agent by name or recorded ID
            <input value={query} onChange={(event) => setQuery(event.target.value)} className="mt-1 w-full rounded-lg border border-outline bg-surface-elevated p-2 text-foreground" placeholder="Filter this scan’s inventory" />
          </label>
          <label className="block text-ink-secondary">Agent identity
            <select value={eligible ? selectedId : ""} disabled={busy} onChange={(event) => { setSelected(event.target.value); setError(""); }} className="mt-1 w-full rounded-lg border border-outline bg-surface-elevated p-2 text-foreground">
              <option value="">Select a recorded identity</option>
              {options.map((agent) => <option key={agent.id} value={agent.id}>{agent.name} · {agent.id}</option>)}
            </select>
          </label>
          {matches.length > 50 ? <p className="text-ink-secondary">Showing the first 50 matches. Refine the filter to find an identity.</p> : null}
          {excluded > 0 ? <p className="text-amber-700 dark:text-amber-300">{excluded} records unavailable: missing, conflicting, or duplicate IDs. Recollect with scoped identity evidence.</p> : null}
          {eligible ? <p className="break-all font-mono text-ink-secondary">{selectedId}</p> : null}
          <button disabled={!eligible || busy} onClick={() => void download()} className="rounded-lg border border-outline px-3 py-2 font-medium text-foreground hover:bg-surface-elevated disabled:opacity-50">{busy ? "Exporting…" : "Download agent BOM"}</button>
          {error ? <p role="alert" className="text-red-700 dark:text-red-300">{error}</p> : null}
          {eligible ? <AgentBomHistory key={`${jobId}:${selectedId}`} jobId={jobId} agentId={selectedId} /> : null}
          <p className="text-ink-secondary">Experimental profile · observed identity · partial composition. Grants, runtime, controls and cost are not assessed by this export.</p>
        </div>
      </div>
    </details>
  );
}
